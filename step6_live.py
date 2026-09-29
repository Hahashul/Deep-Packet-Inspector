import os
import sys
import time
import queue
from collections import defaultdict
from scapy.all import AsyncSniffer, conf
from analyzer import TrafficAnalyzer
from step2_flows import fmt_bytes

BPF = "tcp port 80 or tcp port 443"
REFRESH = 2.0

q = queue.Queue(maxsize=20000)
dropped = [0]


def enqueue(pkt):
    try:
        q.put_nowait(pkt)
    except queue.Full:
        dropped[0] += 1


def pick_iface(name):
    if not name:
        return conf.iface
    for i in conf.ifaces.values():
        text = f"{i.name} {getattr(i, 'description', '')}".lower()
        if name.lower() in text:
            return i
    sys.exit(f"No interface matching '{name}'. Try: python step6_live.py --list")


def render(an, iface):
    os.system("cls" if os.name == "nt" else "clear")
    flows = list(an.fm.flows.values())
    print(f"Live capture on {iface} | filter: {BPF}")
    print(f"flows: {len(flows)} | queue: {q.qsize()} | dropped: {dropped[0]} "
          f"| Ctrl+C to stop\n")

    apps = defaultdict(lambda: [0, 0])
    for f in flows:
        apps[f.app][0] += 1
        apps[f.app][1] += f.total_bytes
    print(f"{'APP':<28} {'FLOWS':>6} {'TOTAL':>10}")
    for app, (n, b) in sorted(apps.items(), key=lambda kv: kv[1][1],
                              reverse=True)[:8]:
        print(f"{app:<28} {n:>6} {fmt_bytes(b):>10}")

    print(f"\n{'APP':<16} {'NAME':<40} {'UP':>9} {'DOWN':>9}")
    top = sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:12]
    for f in top:
        name = f.sni or f.http_host or f"{f.server_ip}:{f.server_port}"
        print(f"{f.app[:16]:<16} {name[:40]:<40} "
              f"{fmt_bytes(f.bytes_sent):>9} {fmt_bytes(f.bytes_recv):>9}")


def main():
    if "--list" in sys.argv:
        for i in conf.ifaces.values():
            print(f"{i.name:<25} {getattr(i, 'description', '')}")
        return

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    iface = pick_iface(args[0] if args else None)

    an = TrafficAnalyzer()
    sniffer = AsyncSniffer(iface=iface, filter=BPF, prn=enqueue, store=False)
    sniffer.start()

    last = 0.0
    try:
        while True:
            try:
                an.process(q.get(timeout=0.5))
            except queue.Empty:
                pass
            if time.time() - last > REFRESH:
                render(an, iface)
                last = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        render(an, iface)
        print("\nStopped.")


if __name__ == "__main__":
    main()