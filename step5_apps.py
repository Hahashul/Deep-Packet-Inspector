import sys
from collections import defaultdict
from scapy.all import rdpcap
from analyzer import TrafficAnalyzer
from step2_flows import fmt_bytes


def main(path):
    an = TrafficAnalyzer()
    for pkt in rdpcap(path):
        an.process(pkt)

    apps = defaultdict(lambda: [0, 0, 0])      # flows, up, down
    unmapped = defaultdict(int)
    for f in an.fm.flows.values():
        a = apps[f.app]
        a[0] += 1
        a[1] += f.bytes_sent
        a[2] += f.bytes_recv
        if f.app == "Other":
            unmapped[f.sni or f.http_host] += f.total_bytes

    print(f"{'APP':<30} {'FLOWS':>6} {'UP':>10} {'DOWN':>10} {'TOTAL':>10}")
    for app, (n, up, down) in sorted(apps.items(),
                                     key=lambda kv: kv[1][1] + kv[1][2],
                                     reverse=True):
        print(f"{app:<30} {n:>6} {fmt_bytes(up):>10} {fmt_bytes(down):>10} "
              f"{fmt_bytes(up + down):>10}")

    print("\nTop domains not in the app map:")
    for dom, total in sorted(unmapped.items(), key=lambda kv: kv[1],
                             reverse=True)[:10]:
        print(f"  {dom:<45} {fmt_bytes(total):>10}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")