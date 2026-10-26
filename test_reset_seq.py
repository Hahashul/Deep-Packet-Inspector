"""next_seq must be monotonic (the value a RST is built from), and the RST cap must escalate
to a firewall block instead of silently giving up on a connection. Run: python test_reset_seq.py"""
from scapy.all import IP, TCP, Raw
from analyzer import TrafficAnalyzer
import reset


def pkt(seq, payload, ts, flags="PA"):
    p = IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=5000, dport=443, flags=flags, seq=seq) / Raw(payload)
    p.time = ts
    return p


def test_next_seq_ignores_a_late_retransmit_of_an_earlier_segment():
    an = TrafficAnalyzer()
    an.process(pkt(1000, b"A" * 500, 1.0))
    an.process(pkt(1500, b"B" * 500, 1.1))
    f = list(an.fm.flows.values())[0]
    assert f.next_seq == 2000
    an.process(pkt(1000, b"A" * 500, 1.2))      # a retransmit of the FIRST segment, arriving late
    assert f.next_seq == 2000, f"next_seq moved backward to {f.next_seq}"


def test_next_seq_still_advances_normally():
    an = TrafficAnalyzer()
    an.process(pkt(1000, b"A" * 10, 1.0))
    an.process(pkt(1010, b"B" * 10, 1.1))
    assert list(an.fm.flows.values())[0].next_seq == 1020


def test_next_seq_handles_32_bit_wraparound():
    an = TrafficAnalyzer()
    near_max = (2**32) - 5
    an.process(pkt(near_max, b"A" * 5, 1.0))     # ends exactly at the wrap point -> next_seq = 0
    f = list(an.fm.flows.values())[0]
    assert f.next_seq == 0
    an.process(pkt(0, b"B" * 10, 1.1))           # genuinely newer, just past the wrap
    assert f.next_seq == 10, f"wraparound not handled, got {f.next_seq}"


def test_reset_cap_then_capped_flag():
    """Each new chunk of data advances next_seq, which is what makes reset_flow fire again
    (a repeated call with the same next_seq is a no-op, not a retry)."""
    from step2_flows import Flow
    f = Flow("10.0.0.2", 5000, "1.2.3.4", 443, "TCP", 1.0, 1.0)
    sent = []
    for i in range(reset.MAX_PER_FLOW + 2):
        f.next_seq = 100 + i * 10               # the connection keeps sending data
        sent.append(reset.reset_flow(f))
    assert sum(sent) == reset.MAX_PER_FLOW        # cap enforced
    assert reset.is_capped(f) is True
    assert reset.reset_flow(f) is False           # capped: no further RSTs, ever


if __name__ == "__main__":
    for n, fn in list(globals().items()):
        if n.startswith("test_"):
            fn(); print("ok", n)
