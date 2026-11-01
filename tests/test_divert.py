"""WinDivert blocker logic, tested with fake packets (no driver, runs anywhere)."""
import os
from types import SimpleNamespace
from unittest import mock
from trafficanalyzer import server
from trafficanalyzer.divert import Blocker
from tests.test_quic import _hello, _build_initial, _crypto

IP = "142.250.1.1"


def tls_record(sni):
    h = _hello(sni)
    return b"\x16\x03\x01" + len(h).to_bytes(2, "big") + h


def tcp(payload=b"", sport=5000, seq=100, ack=True, syn=False, dst=IP):
    t = SimpleNamespace(seq_num=seq, ack_num=777, ack=ack, rst=False, syn=syn)
    return SimpleNamespace(tcp=t, udp=None, payload=payload, src_addr="10.0.0.2", src_port=sport,
                           dst_addr=dst, dst_port=443)


def udp(payload, sport=6000, dst=IP):
    return SimpleNamespace(tcp=None, udp=object(), payload=payload, src_addr="10.0.0.2",
                           src_port=sport, dst_addr=dst, dst_port=443)


def make(rules_blocked=("youtube.com",)):
    hits, rsts = [], []
    def decide(name, ip):
        if ip == "6.6.6.6":
            return "ip:6.6.6.6"
        return next((f"domain:{d}" for d in decide.blocked if name == d or name.endswith("." + d)), "")
    decide.blocked = set(rules_blocked)
    b = Blocker(decide, lambda *a: hits.append(a))
    b.handle = SimpleNamespace(send=lambda r: rsts.append(r))
    return b, decide, hits, rsts


def test_tcp_domain_blocked_then_rest_of_flow_dropped_with_rst():
    b, _, hits, rsts = make()
    with mock.patch("trafficanalyzer.divert.make_rst", lambda p: "RST"):
        assert b.process(tcp(syn=True, ack=False, seq=99)) is True      # handshake passes
        assert b.process(tcp(tls_record("www.youtube.com"))) is False    # hello never leaves
        assert b.process(tcp(b"more", seq=500)) is False                 # rest of flow dropped
    assert hits == [("domain:youtube.com", "www.youtube.com", IP)]       # counted once
    assert rsts == ["RST", "RST"]


def test_other_sites_untouched_and_fast_path():
    b, *_ = make()
    assert b.process(tcp(tls_record("example.org"), sport=5001)) is True
    assert b.process(tcp(b"x", sport=5001, seq=900)) is True


def test_hello_split_over_two_segments_is_still_blocked():
    b, *_ = make()
    rec = tls_record("www.youtube.com" + "a" * 0)
    cut = 30
    assert b.process(tcp(rec[:cut], sport=5002, seq=100)) is True        # name not complete yet
    assert b.process(tcp(rec[cut:], sport=5002, seq=100 + cut)) is False


def test_http_host_blocked():
    b, *_ = make()
    assert b.process(tcp(b"GET / HTTP/1.1\r\nHost: m.youtube.com\r\n\r\n", sport=5003)) is False


def test_quic_blocked_directly():
    b, _, hits, _ = make()
    pkt = _build_initial(_crypto(0, _hello("www.youtube.com")), os.urandom(8), 0)
    assert b.process(udp(pkt)) is False
    assert b.process(udp(b"\x40" + b"\x00" * 40)) is False               # later packets dropped too
    assert hits[0][0] == "domain:youtube.com"
    ok = _build_initial(_crypto(0, _hello("github.com")), os.urandom(8), 0)
    assert b.process(udp(ok, sport=6001)) is True


def test_ip_rule_blocks_without_a_name():
    b, *_ = make()
    assert b.process(tcp(syn=True, ack=False, dst="6.6.6.6")) is False


def test_rule_added_and_deleted_applies_to_open_flows():
    b, decide, hits, _ = make(rules_blocked=())
    assert b.process(tcp(tls_record("www.youtube.com"), sport=5004)) is True   # allowed at first
    decide.blocked = {"youtube.com"}; b.reevaluate()                           # rule added
    assert b.process(tcp(b"x", sport=5004, seq=900)) is False
    decide.blocked = set(); b.reevaluate()                                     # rule deleted
    assert b.process(tcp(b"x", sport=5004, seq=901)) is True


def test_fail_open_when_unavailable():
    b = Blocker(lambda n, i: "")
    assert b.start() is False and b.active is False and b.error        # no pydivert / no driver here


def test_server_uses_block_over_flag():
    server.rules.rules.clear()
    server.rules.add("app", "youtube", action="flag")
    server.rules.add("domain", "youtube.com", action="block")
    assert server.divert_decide("www.youtube.com", IP) == "domain:youtube.com"
    server.rules.rules.clear()
    server.rules.add("app", "youtube", action="flag")
    assert server.divert_decide("www.youtube.com", IP) == ""           # flag never blocks


if __name__ == "__main__":
    for n, fn in list(globals().items()):
        if n.startswith("test_"):
            fn(); print("ok", n)
