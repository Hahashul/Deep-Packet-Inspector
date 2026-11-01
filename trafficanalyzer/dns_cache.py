"""Learns IP -> domain mappings from plaintext DNS responses (UDP/53 and TCP/53).

Used as a *fallback* name for flows whose TLS ClientHello / HTTP Host was never
seen. A DNS name is weaker evidence than SNI (shared CDN IPs, cached lookups),
so callers keep it separate from SNI.

DNS over TCP carries a 2-byte length before each message. Messages that are fully
contained in one TCP segment are handled (normal for small answers); a message
split across segments is skipped.
"""
from collections import OrderedDict
from scapy.all import DNS, TCP, UDP

MAX_ENTRIES = 20000          # bound memory on long captures (oldest dropped first)


def is_dns(pkt):
    if UDP in pkt:
        return pkt[UDP].sport == 53 or pkt[UDP].dport == 53
    if TCP in pkt:
        return pkt[TCP].sport == 53 or pkt[TCP].dport == 53
    return False


class DnsCache:
    def __init__(self, max_entries=MAX_ENTRIES):
        self.map = OrderedDict()     # ip -> most recently queried name
        self.max = max_entries
        self.responses = 0           # responses we learned from
        self.records = 0             # A/AAAA records stored

    def learn(self, pkt):
        if UDP in pkt and pkt[UDP].sport == 53 and DNS in pkt:
            self._learn_msg(pkt[DNS])
        elif TCP in pkt and pkt[TCP].sport == 53:
            data = bytes(pkt[TCP].payload)
            while len(data) >= 2:                    # [len][dns message] ...
                n = int.from_bytes(data[:2], "big")
                if n == 0 or len(data) < 2 + n:
                    break
                try:
                    self._learn_msg(DNS(data[2:2 + n]))
                except Exception:
                    pass
                data = data[2 + n:]

    def _learn_msg(self, d):
        if d.qr != 1 or d.rcode != 0 or not d.ancount or not d.qd:
            return
        qd = d.qd[0] if isinstance(d.qd, list) else d.qd
        name = qd.qname.decode("ascii", "ignore").rstrip(".").lower()
        if not name:
            return
        learned = False
        for i in range(d.ancount):
            rr = d.an[i]
            if rr.type in (1, 28) and isinstance(rr.rdata, str):   # A / AAAA
                self._put(rr.rdata, name)
                learned = True
        if learned:
            self.responses += 1

    def _put(self, ip, name):
        self.map[ip] = name
        self.map.move_to_end(ip)
        self.records += 1
        if len(self.map) > self.max:
            self.map.popitem(last=False)

    def lookup(self, ip):
        return self.map.get(ip, "")
