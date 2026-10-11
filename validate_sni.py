"""
Cross-validate the analyzer's SNI / HTTP Host extraction against Wireshark (tshark).

    python validate_sni.py sample2.pcap
    python validate_sni.py sample2.pcap --csv report.csv
    python validate_sni.py sample2.pcap --tshark "C:\\Program Files\\Wireshark\\tshark.exe"

Ground truth = tshark's own dissection (it reassembles TCP and parses TLS/HTTP
independently of this project). Flows are matched by their 5-tuple.

Reported separately:
  * TCP flows      -> the in-scope accuracy numbers (precision / recall)
  * QUIC (UDP) flows -> tshark can name these (it decrypts QUIC Initial packets);
                       this analyzer cannot, by design. Counted, not scored.
"""
import argparse
import csv
import os
import shutil
import subprocess
import sys
from collections import Counter

from scapy.all import PcapReader

from analyzer import TrafficAnalyzer

WIN_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"
FIELDS = [
    "frame.number",
    "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport",
    "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport",
    "tls.handshake.extensions_server_name", "http.host",
]
DISPLAY_FILTER = "tls.handshake.type == 1 || http.request"


def find_tshark(explicit):
    if explicit:
        return explicit
    found = shutil.which("tshark")
    if found:
        return found
    if os.path.exists(WIN_DEFAULT):
        return WIN_DEFAULT
    sys.exit("tshark not found. Install Wireshark or pass --tshark <path>.")


def norm(name):
    return (name or "").strip().lower().rstrip(".")


def flow_key(proto, a, b):
    return (proto, *sorted([a, b]))


def tshark_truth(tshark, pcap, tls_ports=()):
    """Returns {key: name} for TCP and UDP flows tshark could name.
    tls_ports: extra TCP ports on which to force TLS decoding."""
    cmd = [tshark, "-r", pcap, "-Y", DISPLAY_FILTER, "-T", "fields",
           "-E", "separator=/t"]
    for port in sorted(set(tls_ports)):
        cmd += ["-d", f"tcp.port=={port},tls"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    if out.returncode != 0 and not out.stdout:
        sys.exit(f"tshark failed:\n{out.stderr}")

    truth = {}
    for line in out.stdout.splitlines():
        p = (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
        _, ip4s, ip6s, tsp, usp, ip4d, ip6d, tdp, udp, sni, host = p
        src, dst = ip4s or ip6s, ip4d or ip6d
        if tsp and tdp:
            proto, sp, dp = "TCP", tsp, tdp
        elif usp and udp:
            proto, sp, dp = "UDP", usp, udp
        else:
            continue
        if proto == "UDP":
            name = norm(sni.split(",")[0])      # only real SNI = QUIC (not SSDP etc.)
        else:
            name = norm(sni.split(",")[0]) or norm(host.split(",")[0])
        if not name:
            continue
        key = flow_key(proto, (src, int(sp)), (dst, int(dp)))
        truth.setdefault(key, name)          # first name seen for the flow
    return truth


def analyzer_results(pcap):
    """Runs the analyzer offline (no expiry) -> ({key: name}, {key: bytes}, {key: server_port})."""
    an = TrafficAnalyzer()
    with PcapReader(pcap) as rd:
        for p in rd:
            an.process(p)
    names, sizes, sports = {}, {}, {}
    for f in an.fm.flows.values():
        key = flow_key(f.protocol, (f.client_ip, f.client_port),
                       (f.server_ip, f.server_port))
        sizes[key] = f.total_bytes
        sports[key] = f.server_port
        n = norm(f.sni or f.http_host)
        if n:
            names[key] = n
    return names, sizes, sports


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--tshark")
    ap.add_argument("--csv", help="write per-flow disagreements to this CSV")
    ap.add_argument("--examples", type=int, default=8)
    args = ap.parse_args()

    tshark = find_tshark(args.tshark)
    print(f"tshark : {tshark}")
    print(f"pcap   : {args.pcap}\n")

    ours, sizes, sports = analyzer_results(args.pcap)
    o_tcp = {k: v for k, v in ours.items() if k[0] == "TCP"}

    def compare(truth):
        t_tcp = {k: v for k, v in truth.items() if k[0] == "TCP"}
        correct, wrong, missed, extra = [], [], [], []
        for k, name in t_tcp.items():
            if k not in o_tcp:
                missed.append((k, name, ""))
            elif o_tcp[k] == name:
                correct.append((k, name, name))
            else:
                wrong.append((k, name, o_tcp[k]))
        for k, name in o_tcp.items():
            if k not in t_tcp:
                extra.append((k, "", name))
        return t_tcp, correct, wrong, missed, extra

    truth = tshark_truth(tshark, args.pcap)
    t_tcp, correct, wrong, missed, extra = compare(truth)

    # tshark only decodes TLS on standard ports; this analyzer parses any port.
    # Re-check analyzer-only flows with TLS forced on their server port.
    forced = {sports[k] for k, _, _ in extra if sports[k] not in (80, 443)}
    if forced:
        before = len(extra)
        truth = tshark_truth(tshark, args.pcap, forced)
        t_tcp, correct, wrong, missed, extra = compare(truth)
        print(f"re-checked {before} analyzer-only flow(s) with TLS forced on "
              f"port(s) {sorted(forced)}: {before - len(extra)} confirmed by tshark\n")
    t_udp = {k: v for k, v in truth.items() if k[0] == "UDP"}

    recall = pct(len(correct), len(t_tcp))
    precision = pct(len(correct), len(o_tcp))

    tcp_bytes = sum(v for k, v in sizes.items() if k[0] == "TCP")
    truth_bytes = sum(sizes.get(k, 0) for k in t_tcp)
    ours_bytes = sum(sizes.get(k, 0) for k in o_tcp)
    correct_bytes = sum(sizes.get(k, 0) for k, _, _ in correct)

    print("=== TCP (in scope) ===")
    print(f"flows named by tshark          : {len(t_tcp)}")
    print(f"flows named by analyzer        : {len(o_tcp)}")
    print(f"  identical name               : {len(correct)}")
    print(f"  different name               : {len(wrong)}")
    print(f"  missed (tshark only)         : {len(missed)}")
    print(f"  extra  (analyzer only)       : {len(extra)}")
    print(f"RECALL    (found / tshark found) : {recall}")
    print(f"PRECISION (correct / we named)   : {precision}")
    print(f"byte-weighted: {pct(correct_bytes, truth_bytes)} of tshark-named TCP "
          f"traffic is correctly named by the analyzer")
    print(f"TCP traffic tshark can name    : {pct(truth_bytes, tcp_bytes)} of all TCP bytes\n")

    print("=== QUIC / UDP (out of scope, not scored) ===")
    udp_bytes = sum(sizes.get(k, 0) for k in t_udp)
    print(f"flows tshark names via QUIC    : {len(t_udp)}")
    print(f"bytes in those flows           : {udp_bytes}")
    if t_udp:
        top = Counter(t_udp.values()).most_common(5)
        print("top QUIC names                 : " + ", ".join(f"{n} ({c})" for n, c in top))
    print()

    def show(title, rows):
        if not rows:
            return
        print(f"--- {title} (first {args.examples}) ---")
        for k, t, o in rows[:args.examples]:
            c = f"{k[1][0]}:{k[1][1]}"
            s = f"{k[2][0]}:{k[2][1]}"
            print(f"  {c} <-> {s}\n     tshark={t or '-'}  analyzer={o or '-'}")
        print()

    show("DIFFERENT NAME", wrong)
    show("MISSED by analyzer", missed)
    show("EXTRA (analyzer only)", extra)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["category", "endpoint_a", "endpoint_b", "tshark", "analyzer"])
            for cat, rows in (("different", wrong), ("missed", missed), ("extra", extra)):
                for k, t, o in rows:
                    w.writerow([cat, f"{k[1][0]}:{k[1][1]}", f"{k[2][0]}:{k[2][1]}", t, o])
        print(f"wrote {args.csv}")


if __name__ == "__main__":
    main()
