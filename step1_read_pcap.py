import sys
from collections import Counter
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def summarize(pkt):
    """Return (src, dst, proto, sport, dport) or None if not IP traffic."""
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None

    if TCP in pkt:
        return ip.src, ip.dst, "TCP", pkt[TCP].sport, pkt[TCP].dport
    if UDP in pkt:
        return ip.src, ip.dst, "UDP", pkt[UDP].sport, pkt[UDP].dport
    return ip.src, ip.dst, "OTHER", 0, 0

def main(path):
    packets = rdpcap(path)
    print(f"Loaded {len(packets)} packets from {path}\n")

    counts = Counter()
    for i, pkt in enumerate(packets):
        info = summarize(pkt)
        if info is None:
            counts["non-IP"] += 1
            continue
        src, dst, proto, sport, dport = info
        counts[proto] += 1
        if i < 15:
            print(f"{proto:5} {src}:{sport} -> {dst}:{dport}  ({len(pkt)} bytes)")

    print("\nProtocol counts:", dict(counts))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")