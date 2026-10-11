from collections import defaultdict
from scapy.all import TCP, IP, IPv6
from step2_flows import FlowManager
from step3_sni import parse_client_hello, parse_http_host
from step4_reassembly import Reassembler, MAX_BUFFER
from classifier import classify


class TrafficAnalyzer:
    def __init__(self, expire=False):
        self.fm = FlowManager(expire=expire)
        self.states = {}      # id(flow) -> Reassembler
        # running totals for flows that have already expired
        self.retired_flows = 0
        self.retired_bytes = 0
        self.retired_apps = defaultdict(lambda: {"flows": 0, "bytes": 0})
        self.retired_domains = defaultdict(int)

    def reap(self):
        """Clean up expired flows, roll their totals into the retired counters,
        and return them so the caller can persist them."""
        done = self.fm.finished
        if not done:
            return []
        self.fm.finished = []
        for f in done:
            self.states.pop(id(f), None)
            self.retired_flows += 1
            self.retired_bytes += f.total_bytes
            a = self.retired_apps[f.app]
            a["flows"] += 1
            a["bytes"] += f.total_bytes
            name = f.sni or f.http_host
            if name:
                self.retired_domains[name] += f.total_bytes
        return done

    def process(self, pkt):
        flow = self.fm.process(pkt)
        if flow is None or TCP not in pkt:
            return flow

        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        tcp = pkt[TCP]
        if (ip.src, tcp.sport) != (flow.client_ip, flow.client_port):
            return flow                       # client -> server only
        payload = bytes(tcp.payload)
        if not payload:
            return flow

        r = self.states.setdefault(id(flow), Reassembler())
        if r.done:
            return flow
        r.add(tcp.seq, payload)
        data = r.assemble()
        if len(data) < 6:
            return flow

        status, sni = parse_client_hello(data)
        if status == "ok":
            r.done = True
            if sni:
                flow.sni = sni
                flow.app = classify(sni)
        elif status == "no":
            r.done = True
            host = parse_http_host(data)
            if host:
                flow.http_host = host
                flow.app = classify(host)
        elif r.size > MAX_BUFFER:
            r.done = True
        return flow