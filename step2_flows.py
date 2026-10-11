import sys
from dataclasses import dataclass
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

WELL_KNOWN = {80, 443}

# --- expiry tuning ---
TCP_IDLE_TIMEOUT = 120   # seconds with no packets
UDP_IDLE_TIMEOUT = 30
CLOSED_GRACE = 10        # after RST / both FINs, keep briefly for trailing ACKs
SWEEP_INTERVAL = 5       # seconds of *packet time* between sweeps

@dataclass
class Flow:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    first_seen: float
    last_seen: float
    bytes_sent: int = 0   # client -> server
    bytes_recv: int = 0   # server -> client
    packets: int = 0
    sni: str = ""
    http_host: str = ""
    app: str = "Unknown"
    flagged: bool = False
    matched_rule: str = ""
    dns_name: str = ""      # fallback name learned from DNS (weaker than SNI)
    dns_app: str = ""
    fin_client: bool = False
    fin_server: bool = False
    closed_at: float = 0.0

    
    def update(self, ts, size, from_client):
        self.last_seen = ts
        self.packets += 1
        if from_client:
            self.bytes_sent += size
        else:
            self.bytes_recv += size

    @property
    def total_bytes(self):
        return self.bytes_sent + self.bytes_recv


class FlowManager:
    def __init__(self, expire=False):
        self.flows = {}
        self.expire = expire        # off by default so pcap/offline use is unchanged
        self.finished = []          # evicted flows waiting to be reaped
        self.clock = 0.0            # latest packet timestamp seen
        self._last_sweep = 0.0

    def process(self, pkt):
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            return
        if TCP in pkt:
            proto, l4 = "TCP", pkt[TCP]
        elif UDP in pkt:
            proto, l4 = "UDP", pkt[UDP]
        else:
            return

        src, sport = ip.src, l4.sport
        dst, dport = ip.dst, l4.dport
        ts = float(pkt.time)
        size = len(pkt)
        self.clock = max(self.clock, ts)

        # Same key for both directions
        key = (proto, *sorted([(src, sport), (dst, dport)]))
        flow = self.flows.get(key)

        # Port reuse: a fresh SYN on a closed flow starts a new connection
        if (self.expire and flow is not None and flow.closed_at
                and proto == "TCP" and (int(l4.flags) & 0x12) == 0x02):
            self.finished.append(self.flows.pop(key))
            flow = None

        if flow is None:
            src_is_server = sport in WELL_KNOWN and dport not in WELL_KNOWN
            if src_is_server:
                flow = Flow(dst, dport, src, sport, proto, ts, ts)
            else:
                flow = Flow(src, sport, dst, dport, proto, ts, ts)
            self.flows[key] = flow

        from_client = (src, sport) == (flow.client_ip, flow.client_port)
        flow.update(ts, size, from_client)

        if proto == "TCP":
            flags = int(l4.flags)
            if flags & 0x04:                      # RST closes immediately
                flow.closed_at = ts
            elif flags & 0x01:                    # FIN: closed once both sides sent one
                if from_client:
                    flow.fin_client = True
                else:
                    flow.fin_server = True
                if flow.fin_client and flow.fin_server:
                    flow.closed_at = ts

        self._maybe_sweep()
        return flow

    def _maybe_sweep(self):
        if not self.expire or self.clock - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = self.clock
        dead = []
        for key, f in self.flows.items():
            limit = TCP_IDLE_TIMEOUT if f.protocol == "TCP" else UDP_IDLE_TIMEOUT
            if (self.clock - f.last_seen > limit
                    or (f.closed_at and self.clock - f.closed_at > CLOSED_GRACE)):
                dead.append(key)
        for key in dead:
            self.finished.append(self.flows.pop(key))


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def main(path):
    packets = rdpcap(path)
    fm = FlowManager()
    for pkt in packets:
        fm.process(pkt)

    flows = sorted(fm.flows.values(), key=lambda f: f.total_bytes, reverse=True)
    print(f"{len(packets)} packets -> {len(flows)} flows\n")
    print(f"{'PROTO':5} {'CLIENT':>28}  {'SERVER':<28} {'PKTS':>5} {'UP':>9} {'DOWN':>9} {'DUR':>7}")
    for f in flows[:20]:
        client = f"{f.client_ip}:{f.client_port}"
        server = f"{f.server_ip}:{f.server_port}"
        dur = f.last_seen - f.first_seen
        print(f"{f.protocol:5} {client[-28:]:>28}  {server[-28:]:<28} {f.packets:>5} "
              f"{fmt_bytes(f.bytes_sent):>9} {fmt_bytes(f.bytes_recv):>9} {dur:>6.1f}s")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")