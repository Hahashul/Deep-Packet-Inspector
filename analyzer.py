from scapy.all import TCP, IP, IPv6
from step2_flows import FlowManager
from step3_sni import parse_client_hello, parse_http_host
from step4_reassembly import Reassembler, MAX_BUFFER
from classifier import classify


class TrafficAnalyzer:
    def __init__(self):
        self.fm = FlowManager()
        self.states = {}      # id(flow) -> Reassembler

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