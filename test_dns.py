"""How much does the DNS fallback help, and how reliable is it?

    python test_dns.py big.pcap

Reliability check: for flows where BOTH an SNI/Host and a DNS name exist,
how often do they agree? (SNI is the ground truth here.)
"""
import sys
from scapy.all import PcapReader
from analyzer import TrafficAnalyzer


def parent(name):                      # rough "registrable domain": last two labels
    return ".".join(name.split(".")[-2:])


def main(path):
    an = TrafficAnalyzer()
    with PcapReader(path) as rd:
        for p in rd:
            an.process(p)

    flows = list(an.fm.flows.values())
    tcp = [f for f in flows if f.protocol == "TCP"]
    udp = [f for f in flows if f.protocol == "UDP"]
    named = lambda f: f.sni or f.http_host
    unnamed = [f for f in tcp if not named(f)]
    rescued = [f for f in unnamed if f.dns_name]
    tb = lambda L: sum(f.total_bytes for f in L)

    print(f"DNS responses learned from : {an.dns.responses}  (A/AAAA records: {an.dns.records})")
    print(f"IPs in DNS cache           : {len(an.dns.map)}\n")

    print("=== Naming coverage (TCP) ===")
    print(f"TCP flows                  : {len(tcp)}")
    print(f"named by SNI/Host          : {len(tcp) - len(unnamed)}")
    print(f"unnamed                    : {len(unnamed)}  ({tb(unnamed)} bytes)")
    print(f"  rescued by DNS fallback  : {len(rescued)}  ({tb(rescued)} bytes)")
    if unnamed:
        print(f"  = {100*len(rescued)/len(unnamed):.1f}% of unnamed flows, "
              f"{100*tb(rescued)/max(1,tb(unnamed)):.1f}% of unnamed bytes")
    print(f"still unnamed              : {len(unnamed) - len(rescued)}\n")

    both = [f for f in tcp if named(f) and f.dns_name]
    exact = [f for f in both if named(f).lower() == f.dns_name]
    near = [f for f in both if parent(named(f).lower()) == parent(f.dns_name)]
    print("=== DNS reliability (flows with both SNI and a DNS name) ===")
    print(f"flows compared             : {len(both)}")
    if both:
        print(f"exact same name            : {len(exact)}  ({100*len(exact)/len(both):.1f}%)")
        print(f"same parent domain (approx): {len(near)}  ({100*len(near)/len(both):.1f}%)")
        bad = [f for f in both if parent(named(f).lower()) != parent(f.dns_name)]
        for f in bad[:6]:
            print(f"  disagree: {f.server_ip}  SNI={named(f)}  DNS={f.dns_name}")
    print()

    u = [f for f in udp if f.dns_name]
    print("=== UDP (QUIC etc.) ===")
    print(f"UDP flows (non-DNS)        : {len(udp)}  | with a DNS name: {len(u)}")
    for f in sorted(u, key=lambda f: -f.total_bytes)[:5]:
        print(f"  {f.server_ip}:{f.server_port} -> {f.dns_name}  ({f.total_bytes} B)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample2.pcap")
