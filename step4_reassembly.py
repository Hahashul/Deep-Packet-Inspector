import sys
from scapy.all import rdpcap, TCP, IP, IPv6
from step2_flows import FlowManager, fmt_bytes
from step3_sni import parse_client_hello, parse_http_host

MAX_BUFFER = 32 * 1024


class Reassembler:
    """Collects one direction of a TCP stream, ordered by sequence number."""
    def __init__(self):
        self.segments = {}      # seq -> payload
        self.size = 0
        self.done = False

    def add(self, seq, payload):
        old = self.segments.get(seq, b"")
        if len(payload) > len(old):
            self.segments[seq] = payload
            self.size += len(payload) - len(old)

    def assemble(self):
        """Contiguous bytes from the lowest seq; stops at the first gap."""
        seqs = sorted(self.segments)
        cursor = seqs[0]
        out = b""
        for s in seqs:
            if s > cursor:
                break
            data = self.segments[s]
            skip = cursor - s
            if skip < len(data):
                out += data[skip:]
                cursor = s + len(data)
        return out


def main(path):
    packets = rdpcap(path)
    fm = FlowManager()
    states = {}          # id(flow) -> Reassembler
    outcome = {}         # id(flow) -> 'named' | 'no_sni' | 'not_tls' | 'gave_up'

    for pkt in packets:
        flow = fm.process(pkt)
        if flow is None or TCP not in pkt:
            continue
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        if (ip.src, pkt[TCP].sport) != (flow.client_ip, flow.client_port):
            continue                      # only the client -> server direction
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue

        r = states.setdefault(id(flow), Reassembler())
        if r.done:
            continue
        r.add(pkt[TCP].seq, payload)
        data = r.assemble()
        if len(data) < 6:
            continue                      # too short to judge yet

        status, sni = parse_client_hello(data)
        if status == "ok":
            r.done = True
            if sni:
                flow.sni = sni
                outcome[id(flow)] = "named"
            else:
                outcome[id(flow)] = "no_sni"      # complete hello, no SNI (ECH etc.)
        elif status == "no":
            r.done = True
            host = parse_http_host(data)
            if host:
                flow.http_host = host
                outcome[id(flow)] = "named"
            else:
                outcome[id(flow)] = "not_tls"     # e.g. capture began mid-connection
        elif r.size > MAX_BUFFER:
            r.done = True
            outcome[id(flow)] = "gave_up"

    flows = sorted(fm.flows.values(), key=lambda f: f.total_bytes, reverse=True)
    print(f"{'PROTO':5} {'SERVER':<26} {'NAME':<38} {'UP':>9} {'DOWN':>9}")
    for f in flows[:25]:
        server = f"{f.server_ip}:{f.server_port}"
        name = f.sni or f.http_host or "-"
        print(f"{f.protocol:5} {server[-26:]:<26} {name[:38]:<38} "
              f"{fmt_bytes(f.bytes_sent):>9} {fmt_bytes(f.bytes_recv):>9}")

    tcp = [f for f in flows if f.protocol == "TCP"]
    named = sum(1 for f in tcp if f.sni or f.http_host)
    count = lambda k: sum(1 for f in tcp if outcome.get(id(f)) == k)
    incomplete = sum(1 for f in tcp
                     if id(f) in states and not states[id(f)].done)
    print(f"\nTCP flows: {len(tcp)} | named: {named}")
    print(f"  complete hello, no SNI: {count('no_sni')} | "
          f"not a TLS start (mid-connection): {count('not_tls')} | "
          f"still incomplete/gave up: {incomplete + count('gave_up')}")
    print(f"  no client data seen at all: {len(tcp) - len(states)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")