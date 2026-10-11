"""Robustness tests: malformed input must never raise. Deterministic (fixed seed). Run: python test_robustness.py"""
import inspect, os, random
from scapy.all import IP, TCP, UDP, Raw
import quic, test_quic
from analyzer import TrafficAnalyzer
from step3_sni import parse_client_hello, parse_http_host

HELLO = b"\x16\x03\x01\x00\x00" + test_quic._hello("www.youtube.com", pad=100)


def test_clienthello_truncated_at_every_byte():
    for i in range(len(HELLO) + 1):
        parse_client_hello(HELLO[:i]); parse_http_host(HELLO[:i])


def test_clienthello_mutated_and_random():
    rnd = random.Random(7)
    for _ in range(20000):
        b = bytearray(HELLO)
        for _k in range(rnd.randint(1, 6)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        parse_client_hello(bytes(b))
        parse_client_hello(bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 300))))


def test_quic_initial_mutated_and_random():
    rnd = random.Random(8)
    good = test_quic._build_initial(test_quic._crypto(0, test_quic._hello("github.com")), os.urandom(8), 0)
    for _ in range(3000):
        b = bytearray(good)
        for _k in range(rnd.randint(1, 8)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        quic.QuicSni().add(bytes(b))
        quic.QuicSni().add(bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 1400))))


def test_whole_pipeline_random_dns_quic_tcp():
    rnd, an = random.Random(9), TrafficAnalyzer(expire=True)
    for i in range(5000):
        pl = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 400)))
        k = i % 4
        if k == 0: p = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=5353 + i % 100, dport=53) / Raw(pl)
        elif k == 1: p = IP(src="8.8.8.8", dst="10.0.0.2") / UDP(sport=53, dport=5353) / Raw(pl)
        elif k == 2: p = IP(src="10.0.0.2", dst="1.2.3.4") / UDP(sport=40000 + i % 50, dport=443) / Raw(pl)
        else: p = IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=40000 + i % 50, dport=443, flags="PA", seq=i) / Raw(pl)
        p.time = 5000 + i * 0.01
        an.process(p)


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_") and inspect.isfunction(f):
            f(); print("ok", n)
