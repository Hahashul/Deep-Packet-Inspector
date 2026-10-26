"""Security and rule-engine regression tests for the final milestone (KI-01, KI-02, KI-07, KI-08)."""
import os
os.environ["API_TOKEN"] = "test-token"
os.environ["ALLOWED_HOSTS"] = "testserver"
import tempfile
from types import SimpleNamespace
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
import server
from rules import RuleEngine

H = {"X-API-Token": "test-token"}
c = TestClient(server.app)          # no lifespan: no capture, no firewall


def flow(sni="www.youtube.com", app="YouTube", ip="1.2.3.4"):
    return SimpleNamespace(sni=sni, http_host="", app=app, server_ip=ip, flagged=False, matched_rule="")


def test_block_beats_flag():                                   # KI-01
    r = RuleEngine()
    r.add("app", "youtube", action="flag")
    r.add("domain", "youtube.com", action="block")
    f = flow()
    r.evaluate(f)
    assert f.matched_rule == "domain:youtube.com", f.matched_rule
    r2 = RuleEngine()                                          # order must not matter
    r2.add("domain", "youtube.com", action="block")
    r2.add("app", "youtube", action="flag")
    f2 = flow(); r2.evaluate(f2)
    assert f2.matched_rule == "domain:youtube.com"


def test_flag_still_works_alone():
    r = RuleEngine(); r.add("app", "youtube", action="flag")
    f = flow(); assert r.evaluate(f) and f.matched_rule == "app:youtube"


def test_ip_validation():                                      # KI-07
    r = RuleEngine()
    for bad in ["not-an-ip", "999.1.1.1", "1.2.3"]:
        try:
            r.add("ip", bad); assert False, bad
        except ValueError:
            pass
    assert r.add("ip", "2001:0DB8:0:0:0:0:0:1")["value"] == "2001:db8::1"
    assert r.add("ip", " 8.8.8.8 ")["value"] == "8.8.8.8"


def test_api_requires_token():                                 # KI-02
    for path in ["/flows", "/rules", "/stats", "/sessions", "/blocked"]:
        assert c.get(path).status_code == 401, path
    assert c.get("/rules", headers={"X-API-Token": "wrong"}).status_code == 401
    assert c.get("/rules", headers=H).status_code == 200
    assert c.post("/rules", json={"type": "ip", "value": "x", "action": "flag"}).status_code == 401


def test_foreign_origin_rejected():                            # KI-02
    r = c.get("/rules", headers={**H, "Origin": "http://evil.example"})
    assert r.status_code == 403
    assert c.get("/rules", headers={**H, "Origin": "http://testserver"}).status_code == 200


def test_websocket_guarded():                                  # KI-02
    for url, hdr in [("/ws", {}), ("/ws?token=wrong", {}),
                     ("/ws?token=test-token", {"origin": "http://evil.example"})]:
        try:
            with c.websocket_connect(url, headers=hdr) as ws:
                ws.receive_json()
            assert False, f"accepted {url}"
        except WebSocketDisconnect:
            pass


def test_bad_ip_rule_rejected_by_api():                        # KI-07 over HTTP
    assert c.post("/rules", headers=H, json={"type": "ip", "value": "not-an-ip"}).status_code == 400


def test_dashboard_served_from_any_cwd():                      # KI-08
    old = os.getcwd(); os.chdir(tempfile.gettempdir())
    try:
        r = c.get("/")
        assert r.status_code == 200 and "test-token" in r.text
    finally:
        os.chdir(old)


def test_dns_rebinding_host_rejected():                        # KI-02 hardening
    for path in ["/", "/health", "/rules"]:
        r = c.get(path, headers={**H, "Host": "evil.example"})
        assert r.status_code == 403, (path, r.status_code)
    assert c.get("/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert c.get("/health", headers={"Host": "localhost:8000"}).status_code == 200


def test_health_is_public():
    assert c.get("/health").json()["status"] == "ok"


if __name__ == "__main__":
    for n, fn in list(globals().items()):
        if n.startswith("test_"):
            fn(); print("ok", n)
