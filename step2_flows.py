import sys
from dataclasses import dataclass
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

WELL_KNOWN = {80, 443}

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
    def __init__(self):
        self.flows = {}

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

        # Same key for both directions
        key = (proto, *sorted([(src, sport), (dst, dport)]))
        flow = self.flows.get(key)

        if flow is None:
            src_is_server = sport in WELL_KNOWN and dport not in WELL_KNOWN
            if src_is_server:
                flow = Flow(dst, dport, src, sport, proto, ts, ts)
            else:
                flow = Flow(src, sport, dst, dport, proto, ts, ts)
            self.flows[key] = flow

        from_client = (src, sport) == (flow.client_ip, flow.client_port)
        flow.update(ts, size, from_client)
        return flow


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