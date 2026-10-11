"""Block bookkeeping: rule-owned blocks are removed when the rule is deleted."""
from types import SimpleNamespace
from unittest import mock
import server
server.capturing = True      # enforcement only runs while capture is on


def test_block_then_unblock_on_rule_delete():
    server.blocked.clear()
    r = server.rules.add("ip", "1.2.3.4", action="block")
    flow = SimpleNamespace(server_ip="1.2.3.4", matched_rule="ip:1.2.3.4")
    with mock.patch.object(server, "block_ip") as b, mock.patch.object(server, "unblock_ip") as u:
        server.enforce_if_block(flow)
        server.enforce_if_block(flow)          # second call must not re-block
        assert b.call_count == 1 and server.blocked == {"1.2.3.4": "ip:1.2.3.4"}
        server.rules.remove(r["id"])
        server.sync_blocks()
        u.assert_called_once_with("1.2.3.4")
        assert server.blocked == {}


def test_flag_rule_never_blocks():
    server.blocked.clear()
    server.rules.add("app", "youtube", action="flag")
    flow = SimpleNamespace(server_ip="5.6.7.8", matched_rule="app:youtube")
    with mock.patch.object(server, "block_ip") as b:
        server.enforce_if_block(flow)
        b.assert_not_called()


def _pkt(sport, dport, flags, seq, payload=b"", src="10.0.0.2", dst="9.9.9.9"):
    from scapy.all import IP, TCP, Raw
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    p.time = 1.0
    return p / Raw(payload) if payload else p


def test_domain_block_sends_rst_at_next_seq():
    import reset
    from analyzer import TrafficAnalyzer
    server.blocked.clear()
    server.rules.rules.clear()
    server.rules.add("domain", "example.com", action="block")
    an = TrafficAnalyzer()
    an.process(_pkt(5000, 443, "S", 100))
    flow = an.process(_pkt(5000, 443, "A", 101, b"x" * 10))
    assert flow.next_seq == 111
    flow.l2_src, flow.l2_dst = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
    flow.sni, flow.matched_rule, flow.flagged = "a.example.com", "domain:example.com", True
    reset._q.queue.clear()
    with mock.patch.object(server, "block_ip") as b:
        server.enforce_if_block(flow)
        server.enforce_if_block(flow)          # same seq: no duplicate RST
        b.assert_not_called()                  # domain rules never touch the firewall
    assert reset._q.qsize() == 1
    rst = reset._q.get()
    assert rst["Ether"].dst == "aa:bb:cc:dd:ee:02"
    assert rst["TCP"].flags == "R" and rst["TCP"].seq == 111
    assert rst["IP"].src == "10.0.0.2" and rst["TCP"].dport == 443


def test_quic_flow_blocks_udp443_only_and_unblocks():
    server.blocked.clear(); server.rules.rules.clear()
    r = server.rules.add("domain", "youtube.com", action="block")
    flow = SimpleNamespace(protocol="UDP", server_ip="142.250.1.1", server_port=443,
                           matched_rule="domain:youtube.com")
    with mock.patch.object(server, "block_udp443") as b, mock.patch.object(server, "unblock_udp443") as u, \
            mock.patch.object(server, "block_ip") as bi:
        server.enforce_if_block(flow); server.enforce_if_block(flow)
        assert b.call_count == 1 and bi.call_count == 0
        assert server.blocked == {"udp:142.250.1.1": "domain:youtube.com"}
        server.rules.remove(r["id"]); server.sync_blocks()
        u.assert_called_once_with("142.250.1.1"); assert server.blocked == {}


if __name__ == "__main__":
    test_block_then_unblock_on_rule_delete(); test_flag_rule_never_blocks(); test_domain_block_sends_rst_at_next_seq(); test_quic_flow_blocks_udp443_only_and_unblocks(); print("ok")
