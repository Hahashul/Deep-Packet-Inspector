"""Inline blocking with WinDivert (pydivert), Windows only.

Outbound TCP 80/443 and UDP 443 packets pass through this thread. The first packets of each flow
are read for the name (TLS ClientHello SNI, HTTP Host, QUIC Initial). If a block rule matches,
the flow is marked blocked and every packet of it is dropped. QUIC is handled directly, so no
UDP/443 firewall shield is needed. For TCP we also send a RST to our own stack so the browser
fails at once instead of waiting for a timeout. Anything unexpected lets the packet through.
When the process exits the WinDivert handle closes and traffic flows normally: nothing to clean up.
"""
import os
import threading
import time
import traceback

from .sni import parse_client_hello, parse_http_host
from .reassembly import Reassembler, MAX_BUFFER
from .quic import QuicSni

FILTER = "outbound and !loopback and (tcp.DstPort == 443 or tcp.DstPort == 80 or udp.DstPort == 443)"
PENDING, ALLOW, BLOCK = 0, 1, 2
IDLE_SECONDS = 120
MAX_FLOWS = 50000
MAX_QUIC_TRIES = 8
MAX_RST = 3


class _Flow:
    __slots__ = ("state", "name", "ip", "rule", "parser", "last", "rsts")

    def __init__(self, ip, now):
        self.state, self.name, self.ip, self.rule = PENDING, "", ip, ""
        self.parser, self.last, self.rsts = None, now, 0


def make_rst(p):
    """RST from the server to our own stack, at the sequence number the client expects next."""
    import pydivert
    r = pydivert.Packet(bytes(p.raw), p.interface, pydivert.Direction.INBOUND)
    r.src_addr, r.dst_addr = p.dst_addr, p.src_addr
    r.src_port, r.dst_port = p.dst_port, p.src_port
    r.payload = b""
    t = r.tcp
    t.seq_num, t.ack_num = p.tcp.ack_num, 0
    t.syn = t.fin = t.psh = t.ack = False
    t.rst = True
    return r


class Blocker:
    def __init__(self, decide, on_block=None, send_rst=True):
        """decide(name, ip) -> rule key to block with, or '' to allow.
        on_block(rule, name, ip) is called once each time a flow becomes blocked."""
        self.decide = decide
        self.on_block = on_block or (lambda *a: None)
        self.send_rst = send_rst and os.environ.get("DIVERT_RST", "1") != "0"
        self.flows = {}
        self.lock = threading.Lock()
        self.active = False
        self.error = ""
        self.dropped = 0
        self.handle = None
        self._clean = time.time()

    # ---- per-packet logic (pure; unit-tested without WinDivert) ----
    def process(self, p):
        """Return True to forward the packet, False to drop it."""
        tcp, udp = p.tcp, p.udp
        key = (udp is not None, p.src_addr, p.src_port, p.dst_addr, p.dst_port)
        now = time.time()
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                if len(self.flows) >= MAX_FLOWS:
                    self._purge(now, 0)
                f = self.flows[key] = _Flow(p.dst_addr, now)
                rule = self.decide("", p.dst_addr)          # IP rules need no name
                if rule:
                    self._block(f, rule, p.dst_addr)
            f.last = now
            if f.state == ALLOW:
                return True
            if f.state == PENDING:
                self._inspect(f, p, tcp, udp)
            if f.state != BLOCK:
                return True
            self.dropped += 1
            if tcp is not None and self.send_rst and f.rsts < MAX_RST and tcp.ack and not tcp.rst:
                f.rsts += 1
                self._rst(p)
            return False

    def _block(self, f, rule, name):
        f.state, f.rule, f.parser = BLOCK, rule, None
        if name:
            f.name = name
        self.on_block(rule, f.name, f.ip)

    def _verdict(self, f, name):
        f.name, f.parser = name, None
        rule = self.decide(name, f.ip) if name else ""
        if rule:
            self._block(f, rule, name)
        else:
            f.state = ALLOW

    def _inspect(self, f, p, tcp, udp):
        data = p.payload
        if not data:
            return                                          # SYN / bare ACK: keep waiting
        if tcp is not None:
            if f.parser is None:
                f.parser = Reassembler()
            r = f.parser
            r.add(tcp.seq_num, data)
            buf = r.assemble()
            if len(buf) < 6:
                return
            status, sni = parse_client_hello(buf)
            if status == "ok":
                self._verdict(f, sni or "")
            elif status == "no":
                self._verdict(f, parse_http_host(buf) or "")
            elif r.size > MAX_BUFFER:
                self._verdict(f, "")
        else:
            if not data[0] & 0x80:                          # short header: not a handshake packet
                self._verdict(f, "")
                return
            if f.parser is None:
                f.parser = QuicSni()
            q = f.parser
            status, sni = q.add(bytes(data))
            if status == "ok":
                self._verdict(f, sni or "")
            elif status == "no" or q.tries >= MAX_QUIC_TRIES:
                self._verdict(f, "")

    def _rst(self, p):
        try:
            self.handle.send(make_rst(p))
        except Exception:
            pass                                            # the drop alone is enough

    def reevaluate(self):
        """Rules changed: apply them to flows already open, and release flows no rule blocks now."""
        with self.lock:
            for f in self.flows.values():
                rule = self.decide(f.name, f.ip)
                if rule and f.state != BLOCK:
                    self._block(f, rule, f.name)
                elif not rule and f.state == BLOCK:
                    f.state, f.rule, f.rsts = ALLOW, "", 0

    def _purge(self, now, idle=IDLE_SECONDS):
        for k in [k for k, f in self.flows.items() if now - f.last > idle]:
            del self.flows[k]

    # ---- WinDivert plumbing ----
    def start(self):
        try:
            import pydivert
        except ImportError:
            self.error = "pydivert is not installed"
            return False
        try:
            self.handle = pydivert.WinDivert(FILTER)
            self.handle.open()
        except Exception as e:
            self.error = f"WinDivert could not start ({e}). Run as Administrator."
            return False
        self.active, self.error = True, ""
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self):
        h, n = self.handle, 0
        while self.active:
            try:
                p = h.recv()
            except Exception as e:
                if self.active:
                    self.active, self.error = False, f"WinDivert stopped: {e}"
                return
            try:
                ok = self.process(p)
            except Exception:
                traceback.print_exc()
                ok = True                                   # fail open
            if ok:
                try:
                    h.send(p)
                except Exception:
                    pass
            n += 1
            if n % 2000 == 0 and time.time() - self._clean > 10:
                self._clean = time.time()
                with self.lock:
                    self._purge(self._clean)

    def stop(self):
        self.active = False
        try:
            if self.handle:
                self.handle.close()
        except Exception:
            pass
        self.handle = None
        self.flows.clear()
