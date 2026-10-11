"""Replay a pcap with expiry off vs on; byte totals must match exactly."""
import sys
from scapy.all import PcapReader
import step2_flows
from analyzer import TrafficAnalyzer


def run(path, tcp_idle=None, udp_idle=None, grace=None, sweep=None):
    if tcp_idle is not None: step2_flows.TCP_IDLE_TIMEOUT = tcp_idle
    if udp_idle is not None: step2_flows.UDP_IDLE_TIMEOUT = udp_idle
    if grace is not None:    step2_flows.CLOSED_GRACE = grace
    if sweep is not None:    step2_flows.SWEEP_INTERVAL = sweep

    a = TrafficAnalyzer()
    b = TrafficAnalyzer(expire=True)
    first = last = None
    peak_live = 0
    n = 0
    with PcapReader(path) as rd:
        for p in rd:
            n += 1
            t = float(p.time)
            first = t if first is None else first
            last = t
            a.process(p)
            b.process(p)
            b.reap()
            peak_live = max(peak_live, len(b.fm.flows))

    tot_a = sum(f.total_bytes for f in a.fm.flows.values())
    tot_b = sum(f.total_bytes for f in b.fm.flows.values()) + b.retired_bytes
    named_a = sum(1 for f in a.fm.flows.values() if f.sni or f.http_host)
    ok = tot_a == tot_b
    print(f"  packets={n}  duration={last-first:.0f}s")
    print(f"  bytes   no-expiry={tot_a}  expiry={tot_b}  -> {'MATCH' if ok else 'MISMATCH'}")
    print(f"  flows   no-expiry={len(a.fm.flows)}  expiry={len(b.fm.flows) + b.retired_flows}")
    print(f"  expiry: live={len(b.fm.flows)} retired={b.retired_flows} peak_live={peak_live} "
          f"reassembly_states={len(b.states)} (no-expiry states={len(a.states)})")
    print(f"  named flows (no-expiry run)={named_a}")
    # leak check: every state must belong to a live flow
    live_ids = {id(f) for f in b.fm.flows.values()}
    leaked = [k for k in b.states if k not in live_ids]
    print(f"  leaked reassembly states: {len(leaked)}")
    return ok and not leaked


if __name__ == "__main__":
    path = sys.argv[1]
    print(f"== {path}: default timeouts ==")
    r1 = run(path)
    print(f"== {path}: aggressive (tcp 3s, udp 1s, grace 1s, sweep 1s) ==")
    r2 = run(path, 3, 1, 1, 1)
    sys.exit(0 if (r1 and r2) else 1)
