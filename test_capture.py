"""Start/stop capture logic, with the sniffer, firewall and RST sender mocked."""
import server
from db import Database
from step2_flows import Flow


class FakeSniffer:
    made = []
    def __init__(self, **kw):
        self.running = False
        FakeSniffer.made.append(self)
    def start(self): self.running = True
    def stop(self): self.running = False


calls = {"rst": 0, "block": 0, "unblock": 0}
server.AsyncSniffer = FakeSniffer
server.db = Database(":memory:")
server.iface = "test"
server.block_udp443_all = lambda: calls.__setitem__("shield_on", calls.get("shield_on", 0) + 1) or True
server.unblock_udp443_all = lambda: calls.__setitem__("shield_off", calls.get("shield_off", 0) + 1) or True
server.reset.reset_flow = lambda f: calls.__setitem__("rst", calls["rst"] + 1)
server.block_ip = lambda ip: calls.__setitem__("block", calls["block"] + 1)
server.unblock_ip = lambda ip: calls.__setitem__("unblock", calls["unblock"] + 1)
server.session_id = server.db.start_session("test", "bpf")


def add_flow(app="Netflix"):
    f = Flow("10.0.0.2", 5000, "1.2.3.4", 443, "TCP", 1.0, 1.0)
    f.sni, f.app = "x.example.com", app
    server.an.fm.flows[("k", len(server.an.fm.flows))] = f
    return f


def test_all():
    server.start_sniffer()
    assert server.capture_state()["capturing"]
    server.rules.add("ip", "9.9.9.9", action="block")
    server.blocked["9.9.9.9"] = "ip:9.9.9.9"          # an existing firewall block
    f = add_flow()
    server.rules.add("domain", "example.com", action="block")

    # stop: sniffer halted, firewall block kept, no enforcement while stopped
    s = server.capture_stop()
    assert not s["capturing"] and not FakeSniffer.made[0].running
    assert "9.9.9.9" in server.blocked and calls["unblock"] == 0
    server.rules.evaluate(f)
    server.enforce_if_block(f)
    assert calls["rst"] == 0 and calls["block"] == 0
    server.capture_stop()                              # idempotent

    # start (continue): same session, flows kept, rules applied again
    sid = server.session_id
    s = server.capture_start(fresh=False)
    assert s["capturing"] and s["session_id"] == sid and s["flows"] == 1
    assert calls["rst"] == 1 and len(FakeSniffer.made) == 2
    server.capture_start(fresh=True)                   # already running: no-op
    assert len(FakeSniffer.made) == 2 and server.session_id == sid

    # fresh: new session, flows cleared, firewall blocks still tracked
    server.capture_stop()
    s = server.capture_start(fresh=True)
    assert s["capturing"] and s["flows"] == 0 and s["session_id"] != sid
    assert "9.9.9.9" in server.blocked
    assert server.snapshot()["stats"]["capturing"] is True

    # QUIC shield: on while a domain/app block rule exists and capture runs; kept while paused
    assert server.shield[0] and calls["shield_on"] == 1
    server.capture_stop()
    assert server.shield[0] and calls.get("shield_off", 0) == 0
    server.capture_start(fresh=False)
    assert calls["shield_on"] == 1                      # not re-added
    for r in server.rules.list():
        server.rules.remove(r["id"])
    with server.lock:
        server.recheck_all()
    assert not server.shield[0] and calls["shield_off"] == 1 and server.blocked == {}
    print("ok test_capture")


def test_midstream():
    from scapy.all import IP, TCP
    from step2_flows import FlowManager
    fm = FlowManager()
    syn = IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=5000, dport=443, flags="S")
    ack = IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=5001, dport=443, flags="A")
    assert fm.process(syn).midstream is False
    assert fm.process(ack).midstream is True
    print("ok test_midstream")


if __name__ == "__main__":
    test_all()
    test_midstream()
