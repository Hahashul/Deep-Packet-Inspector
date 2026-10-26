"""Firewall blocks across server start / frontend Stop / server shutdown.
Windows commands are recorded, never executed. Run: python test_persistence.py (or pytest)."""
import subprocess
from unittest import mock

import enforce
import reset
import server
from db import Database


class FakeSniffer:
    def __init__(self, **kw): pass
    def start(self): pass
    def stop(self): pass


def run_server(seed_rules=(), steps=None, **env_patches):
    """Start the real lifespan, call steps(client) inside it, shut down.
    Returns (commands_at_start, commands_during, commands_at_shutdown)."""
    from fastapi.testclient import TestClient
    cmds = []

    def fake_run(cmd, **kw):
        cmds.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, "Ok.", "")

    db = Database(":memory:")
    for r in seed_rules:
        db.save_rule(r)
    marks = []
    # Pin the real enforcement functions: other test modules replace them on `server` at import.
    pinned = [mock.patch.object(server, n, getattr(enforce, n)) for n in (
        "block_ip", "unblock_ip", "block_udp443", "unblock_udp443", "block_udp443_all",
        "unblock_udp443_all", "cleanup_stale", "cleanup_quic_rules")]
    for pn in pinned:
        pn.start()
    try:
        return _run_inside(cmds, fake_run, db, marks, steps, env_patches)
    finally:
        for pn in pinned:
            pn.stop()


def _run_inside(cmds, fake_run, db, marks, steps, env_patches):
    from fastapi.testclient import TestClient
    with mock.patch("subprocess.run", fake_run), mock.patch.object(server, "db", db), \
            mock.patch.object(server, "AsyncSniffer", FakeSniffer), \
            mock.patch.object(server, "pick_iface", lambda n: "t"), \
            mock.patch.object(reset, "start", lambda iface=None: None), \
            mock.patch.object(server, "rules", type(server.rules)()), \
            mock.patch.object(server, "session_id", None), \
            mock.patch.dict(server.os.environ, env_patches.get("env", {})), \
            mock.patch.object(server, "KEEP_IP_BLOCKS", env_patches.get("keep", True)):
        server.blocked.clear(); server.shield[0] = False
        with TestClient(server.app) as c:
            marks.append(len(cmds))
            if steps:
                steps(c)
            marks.append(len(cmds))
        server.blocked.clear(); server.shield[0] = False
    return cmds[:marks[0]], cmds[marks[0]:marks[1]], cmds[marks[1]:]


IP_RULE = {"id": 1, "type": "ip", "value": "8.8.8.8", "action": "block"}
ADD = "netsh advfirewall firewall add rule name=TrafficAnalyzer-Block-8.8.8.8"
DEL = "netsh advfirewall firewall delete rule name=TrafficAnalyzer-Block-8.8.8.8"


def test_start_restores_saved_ip_block_once_and_keeps_it_on_shutdown():
    start, _, end = run_server([IP_RULE])
    assert sum(c.startswith(ADD) for c in start) == 1          # rule exists exactly once
    assert start.index(next(c for c in start if c.startswith(DEL))) < \
        start.index(next(c for c in start if c.startswith(ADD)))   # delete-then-add: never duplicated
    assert not any(DEL in c for c in end)                      # stays after the server stops


def test_start_never_wipes_all_rules():
    start, _, _ = run_server([IP_RULE])
    assert not any("TrafficAnalyzer-Block-*'" in c for c in start)       # old behaviour: delete everything
    assert any("TrafficAnalyzer-Block-udp443-*" in c for c in start)     # only QUIC leftovers


def test_frontend_stop_touches_no_firewall_rule():
    _, during, _ = run_server([IP_RULE], steps=lambda c: c.post("/capture/stop"))
    assert during == []


def test_quic_shield_is_released_on_shutdown_but_ip_block_stays():
    def steps(c):
        c.post("/rules", json={"type": "domain", "value": "example.com", "action": "block"})
    start, _, end = run_server([IP_RULE], steps=steps)
    assert any("udp443-all" in c and " delete " in c for c in end)       # shield removed
    assert not any(DEL in c for c in end)                                # ip block kept


def test_remove_blocks_on_exit_restores_the_old_behaviour():
    _, _, end = run_server([IP_RULE], keep=False)
    assert any(DEL in c for c in end)


def test_clean_start_wipes_everything_when_asked():
    start, _, _ = run_server(env={"CLEAN_START": "1"})
    assert any("TrafficAnalyzer-Block-*'" in c for c in start)


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
