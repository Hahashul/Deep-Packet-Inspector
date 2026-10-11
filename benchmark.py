"""Throughput benchmark: Scapy dissection + analyzer, as in live sniffing. Run: python benchmark.py"""
import os, time, tracemalloc
from scapy.all import Ether, IP, TCP, Raw
import quic, test_quic
from analyzer import TrafficAnalyzer

HOSTS = ["www.youtube.com", "i.ytimg.com", "github.com", "www.google.com", "api.openai.com", "cdn.example.net"]


def build(nflows):
    pkts, t = [], 1000.0
    for i in range(nflows):
        cip, sip, sport, seq = "10.0.%d.%d" % (i // 250 % 250, i % 250 + 1), "34.%d.%d.%d" % (i % 200, i // 200 % 250, i % 250), 20000 + i % 40000, 5000
        hello = test_quic._hello(HOSTS[i % len(HOSTS)], pad=200)
        rec = b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello
        def mk(src, dst, sp, dp, fl, sq, pl=b""):
            nonlocal t
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=fl, seq=sq) / (Raw(pl) if pl else b"")
            t += 0.0004; p.time = t; return p
        pkts.append(mk(cip, sip, sport, 443, "S", seq)); seq += 1
        pkts.append(mk(cip, sip, sport, 443, "PA", seq, rec)); seq += len(rec)
        for k in range(10):
            if k % 2 == 0: pkts.append(mk(sip, cip, 443, sport, "A", 9000 + k * 1400, b"x" * 1400))
            else: pkts.append(mk(cip, sip, sport, 443, "A", seq, b"y" * 100)); seq += 100
    return pkts


if __name__ == "__main__":
    raws = [(bytes(p), p.time) for p in build(1000)]            # 12,000 packets as they would arrive off the wire
    t0 = time.perf_counter(); dis = []
    for r, t in raws:
        p = Ether(r); p.time = t; dis.append(p)
    d = time.perf_counter() - t0
    an = TrafficAnalyzer(expire=True); t0 = time.perf_counter()
    for p in dis: an.process(p)
    a = time.perf_counter() - t0; n = len(dis)
    print(f"packets {n}: dissect {d / n * 1e6:.0f} us, analyze {a / n * 1e6:.0f} us, end-to-end {n / (d + a):.0f} pkt/s "
          f"(~{n / (d + a) * 1500 * 8 / 1e6:.0f} Mbit/s of 1500-byte packets)")
    tracemalloc.start(); an2 = TrafficAnalyzer(expire=True)
    for p in dis: an2.process(p)
    cur, _ = tracemalloc.get_traced_memory(); tracemalloc.stop()
    print(f"analyzer state: {cur / 1e6:.1f} MB for {len(an2.fm.flows)} flows ({cur / 1024 / len(an2.fm.flows):.1f} KB/flow)")
    dg = [test_quic._build_initial(test_quic._crypto(0, test_quic._hello(HOSTS[i % 6], pad=400)), os.urandom(8), 0) for i in range(400)]
    t0 = time.perf_counter(); ok = sum(quic.QuicSni().add(x)[0] == "ok" for x in dg); q = time.perf_counter() - t0
    print(f"QUIC Initial decrypt+parse: {q / len(dg) * 1000:.2f} ms each, {ok}/{len(dg)} named")
