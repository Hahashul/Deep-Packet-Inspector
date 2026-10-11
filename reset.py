"""Domain-aware blocking: kill a connection by injecting a TCP RST.

When a flow's SNI / Host matches a block rule, we send a RST to the *server*,
spoofing nothing (it carries the client's real IP/port) but injected straight
onto the wire with Scapy/Npcap. The server drops its side of the connection,
and the client's next packet is answered with a RST by the server.

Caveat: this races the real traffic. The ClientHello has already left, so the
server may answer before the RST lands; the client then sees a failed or
truncated handshake. Retries are reset the same way. Only TCP is covered.
"""
import queue
import threading
from scapy.all import Ether, IP, IPv6, TCP, send, sendp

MAX_PER_FLOW = 5            # cap RSTs per flow
sent = 0                    # total RSTs actually sent
_q = queue.Queue()
_iface = None
_send = send                # layer-3 fallback, overridable in tests
_sendp = sendp              # layer-2 (Npcap), used when MACs are known


def build_rst(flow):
    """RST from the client's side of the flow, at the client's next sequence number."""
    if ":" in flow.client_ip:
        ip = IPv6(src=flow.client_ip, dst=flow.server_ip)
    else:
        ip = IP(src=flow.client_ip, dst=flow.server_ip)
    pkt = ip / TCP(sport=flow.client_port, dport=flow.server_port,
                   flags="R", seq=flow.next_seq)
    if flow.l2_src and flow.l2_dst:       # send as a raw frame: Windows blocks raw TCP sockets
        pkt = Ether(src=flow.l2_src, dst=flow.l2_dst) / pkt
    return pkt


def reset_flow(flow):
    """Queue a RST for this flow. Returns True if one was queued."""
    if flow.protocol != "TCP" or not flow.next_seq:
        return False
    if flow.rst_sent >= MAX_PER_FLOW or flow.rst_seq == flow.next_seq:
        return False                      # capped, or already reset at this seq
    flow.rst_sent += 1
    flow.rst_seq = flow.next_seq
    _q.put(build_rst(flow))
    print(f"[reset] queued RST -> {flow.server_ip}:{flow.server_port} "
          f"({flow.sni or flow.http_host}) seq={flow.next_seq}")
    return True


def _run():
    global sent
    while True:
        pkt = _q.get()
        try:
            if Ether in pkt:
                _sendp(pkt, iface=_iface, verbose=0)
            else:
                _send(pkt, iface=_iface, verbose=0)
            sent += 1
        except Exception as e:
            print(f"[reset] send failed: {e}")


def start(iface=None):
    global _iface
    _iface = iface
    threading.Thread(target=_run, daemon=True).start()
