import asyncio
import atexit
import hmac
import os
import secrets
import queue
import threading
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from scapy.all import AsyncSniffer

from analyzer import TrafficAnalyzer
from db import Database, flow_id, flow_row
from rules import RuleEngine
from step6_live import pick_iface

from enforce import (block_ip, unblock_ip, block_udp443, unblock_udp443,
                     block_udp443_all, unblock_udp443_all, cleanup_stale)
import reset
import traceback

# QUIC: only client/server *Initial* packets (long header, type bits 0b00/0b01) so video streams stay cheap
QUIC_INITIAL = "(udp port 443 and ((ip and udp[8] & 0xe0 = 0xc0) or (ip6 and ip6[48] & 0xe0 = 0xc0)))"
BPF = "tcp port 80 or tcp port 443 or port 53 or " + QUIC_INITIAL   # port 53 = DNS (UDP+TCP) for the name fallback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
an = TrafficAnalyzer(expire=True)
rules = RuleEngine()
db = Database()
session_id = None
lock = threading.Lock()
q = queue.Queue(maxsize=20000)
stop = threading.Event()
blocked = {}          # ip -> rule key ('type:value') that caused the block
dropped = [0]
sniffer = None
iface = None
capturing = False   # True while the sniffer is running
ctl = threading.Lock()   # serialises start/stop requests
# QUIC shield: while a domain/app block rule exists, firewall-block all UDP/443 so browsers use TCP.
# Set QUIC_SHIELD=0 to disable (e.g. if you rely on a VPN that runs over UDP/443).
QUIC_SHIELD = os.environ.get("QUIC_SHIELD", "1") != "0"
shield = [False]
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))   # KI-10

# ---- KI-02: per-run API token + Origin allow-list ----
# The dashboard page is the only place the token is handed out, and a foreign web page cannot
# read it (no CORS headers are sent). Set API_TOKEN to pin a value, AUTH=0 to disable (tests only).
AUTH = os.environ.get("AUTH", "1") != "0"
API_TOKEN = os.environ.get("API_TOKEN") or secrets.token_urlsafe(24)
EXTRA_ORIGINS = {o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()}


# Host allow-list: stops DNS-rebinding (a hostile site re-pointing its name at 127.0.0.1)
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"} | {
    h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}


def host_ok(host):
    name = (host or "").lower()
    name = name.rsplit(":", 1)[0] if not name.endswith("]") and ":" in name else name
    return name in ALLOWED_HOSTS


def origin_ok(origin, host):
    """No Origin (curl, scripts) is allowed; a browser Origin must be the server's own host."""
    if not origin:
        return True
    return origin in EXTRA_ORIGINS or origin.split("://", 1)[-1] == host


def token_ok(value):
    return bool(value) and hmac.compare_digest(value, API_TOKEN)


# ---- KI-03: firewall (netsh) calls run on their own thread, never on the packet worker ----
fw_q = queue.Queue()
fw_on = threading.Event()          # set once the worker thread is running


def fw(fn, *args):
    if fw_on.is_set():
        fw_q.put((fn, args))       # normal run: off the packet thread
    else:
        fn(*args)                  # tests / before startup: run inline


def fw_worker():
    fw_on.set()
    while True:
        item = fw_q.get()
        if item is None:
            return
        fn, args = item
        try:
            fn(*args)
        except Exception:
            traceback.print_exc()
        finally:
            fw_q.task_done()


def enqueue(pkt):
    try:
        q.put_nowait(pkt)
    except queue.Full:
        dropped[0] += 1


def recheck_all():
    for f in an.fm.flows.values():
        was = f.flagged
        now = rules.evaluate(f)
        if now and not was:
            db.add_alert(session_id, flow_id(f), f.matched_rule)
        if now:
            enforce_if_block(f)
        f.status_label = ("blocked" if matched_action(f) == "block" else "flagged") if now else "allowed"
    sync_blocks()
    sync_shield()


def sync_shield():
    """Engage/release the QUIC shield. Releasing is always allowed; engaging only while capturing."""
    need = QUIC_SHIELD and any(r["action"] == "block" and r["type"] in ("domain", "app")
                              for r in rules.list())
    if shield[0] and not need:
        fw(unblock_udp443_all)
        shield[0] = False
    elif need and not shield[0] and capturing:
        fw(block_udp443_all)
        shield[0] = True


def block_rule(flow):
    for r in rules.list():
        if r["action"] == "block" and f"{r['type']}:{r['value']}" == flow.matched_rule:
            return r


def enforce_if_block(flow):
    """ip rules -> firewall; domain/app rules -> TCP RST on this connection.
    Paused while capture is stopped (existing firewall blocks stay in place)."""
    if not capturing:
        return
    r = block_rule(flow)
    if not r:
        return
    if r["type"] == "ip":
        if flow.server_ip not in blocked:
            fw(block_ip, flow.server_ip)
            blocked[flow.server_ip] = flow.matched_rule
    elif flow.protocol == "UDP":
        if flow.server_port == 443 and "udp:" + flow.server_ip not in blocked:
            fw(block_udp443, flow.server_ip)                  # force fallback to TCP
            blocked["udp:" + flow.server_ip] = flow.matched_rule
    else:
        reset.reset_flow(flow)


def sync_blocks():
    """Unblock IPs whose owning block rule no longer exists."""
    live = {f"{r['type']}:{r['value']}" for r in rules.list() if r["action"] == "block"}
    for key, hit in list(blocked.items()):
        if hit not in live:
            if key.startswith("udp:"):
                fw(unblock_udp443, key[4:])
            else:
                fw(unblock_ip, key)
            del blocked[key]


def worker():
    while not stop.is_set():
        try:
            pkt = q.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            with lock:
                flow = an.process(pkt)
                if flow is not None:
                    if not flow.flagged and rules.evaluate(flow):
                        db.add_alert(session_id, flow_id(flow), flow.matched_rule)
                    if flow.flagged:
                        enforce_if_block(flow)
                        flow.status_label = "blocked" if matched_action(flow) == "block" else "flagged"
                done = an.reap()
        except Exception:
            traceback.print_exc()             # never let one bad packet kill the worker
            continue
        if done:
            db.save_flows([flow_row(session_id, f) for f in done])

def save_now():
    with lock:
        rows = [flow_row(session_id, f) for f in an.fm.flows.values()]
    db.save_flows(rows)


def saver():
    while not stop.wait(5):
        save_now()


def start_sniffer():
    global sniffer, capturing
    sniffer = AsyncSniffer(iface=iface, filter=BPF, prn=enqueue, store=False)
    sniffer.start()
    capturing = True


def stop_sniffer():
    global capturing
    capturing = False                     # first, so no new enforcement starts
    try:
        if sniffer is not None:
            sniffer.stop()
    except Exception:
        traceback.print_exc()


@asynccontextmanager
async def lifespan(app):
    global iface, session_id
    iface = pick_iface(os.environ.get("IFACE"))
    for r in db.load_rules():
        rules.add(r["type"], r["value"], r["id"], r.get("action", "flag"))
    threading.Thread(target=fw_worker, daemon=True).start()
    cleanup_stale()                       # drop firewall rules left by earlier runs
    atexit.register(cleanup_stale)        # KI-04: also runs on Ctrl+C / console close / unhandled errors
    if AUTH:
        print(f"[security] dashboard token is generated per run; open http://127.0.0.1:8000/ to use it")
    reset.start(iface)
    purged = db.purge_older_than(RETENTION_DAYS)
    if purged:
        print(f"[db] retention: removed {purged} flows older than {RETENTION_DAYS} days")
    session_id = db.start_session(str(iface), BPF)
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=saver, daemon=True).start()
    start_sniffer()
    yield
    stop.set()
    stop_sniffer()
    with lock:
        for key in list(blocked):
            fw(unblock_udp443, key[4:]) if key.startswith("udp:") else fw(unblock_ip, key)
        blocked.clear()
        if shield[0]:
            fw(unblock_udp443_all)
            shield[0] = False
    fw_q.join()
    save_now()
    db.end_session(session_id)


app = FastAPI(title="Traffic Analyzer", lifespan=lifespan)

PUBLIC_PATHS = {"/", "/health"}


@app.middleware("http")
async def guard(request, call_next):
    """KI-02: every API call needs the per-run token and, if a browser sent an Origin, the right one."""
    if AUTH and not host_ok(request.headers.get("host")):
        return JSONResponse({"detail": "host not allowed"}, status_code=403)
    if AUTH and request.url.path not in PUBLIC_PATHS and not request.url.path.startswith("/ws"):
        if not origin_ok(request.headers.get("origin"), request.headers.get("host")):
            return JSONResponse({"detail": "origin not allowed"}, status_code=403)
        if not token_ok(request.headers.get("x-api-token", "")):
            return JSONResponse({"detail": "missing or invalid API token"}, status_code=401)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok", "capturing": capturing}


def matched_action(f):
    """'block' / 'flag' for a flow that matches a rule, else ''."""
    if not f.flagged:
        return ""
    for r in rules.list():
        if f"{r['type']}:{r['value']}" == f.matched_rule:
            return r["action"]
    return "flag"


def flow_dict(f):
    return {
        "id": flow_id(f),
        "client": f"{f.client_ip}:{f.client_port}",
        "server": f"{f.server_ip}:{f.server_port}",
        "protocol": f.protocol,
        "name": f.sni or f.http_host or "",
        "dns_name": f.dns_name,
        "app": f.app,
        "bytes_sent": f.bytes_sent,
        "bytes_recv": f.bytes_recv,
        "total_bytes": f.total_bytes,
        "packets": f.packets,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "midstream": f.midstream,
        "flagged": f.flagged,
        "matched_rule": f.matched_rule,
        "action": matched_action(f),
    }


def snapshot(limit=50, app_filter=None):
    with lock:
        flows = list(an.fm.flows.values())
        if app_filter:
            shown = [f for f in flows if f.app.lower() == app_filter.lower()]
        else:
            shown = flows
        shown = sorted(shown, key=lambda f: f.total_bytes, reverse=True)[:limit]
        top = [flow_dict(f) for f in shown]

        apps = defaultdict(lambda: {"flows": 0, "bytes": 0})
        for k, v in an.retired_apps.items():
            apps[k]["flows"] += v["flows"]
            apps[k]["bytes"] += v["bytes"]
        domains = defaultdict(int, an.retired_domains)
        for f in flows:
            apps[f.app]["flows"] += 1
            apps[f.app]["bytes"] += f.total_bytes
            name = f.sni or f.http_host
            if name:
                domains[name] += f.total_bytes

        stats = {
            "active_flows": len(flows),
            "expired_flows": an.retired_flows,
            "total_flows": len(flows) + an.retired_flows,
            "total_bytes": sum(f.total_bytes for f in flows) + an.retired_bytes,
            "queue": q.qsize(),
            "dropped": dropped[0],
            "flagged_flows": sum(1 for f in flows if f.flagged),
            "blocked_flows": sum(1 for f in flows if matched_action(f) == "block"),
            "bytes_up": sum(f.bytes_sent for f in flows) + an.retired_up,
            "bytes_down": sum(f.bytes_recv for f in flows) + an.retired_down,
            "capturing": capturing,
            "session_id": session_id,
            "rst_sent": reset.sent,
            "firewall_blocks": len(blocked) + (1 if shield[0] else 0),
            "quic_shield": shield[0],
            "apps": sorted(
                ({"app": k, **v} for k, v in apps.items()),
                key=lambda a: a["bytes"], reverse=True),
            "top_domains": sorted(
                ({"domain": k, "bytes": v} for k, v in domains.items()),
                key=lambda d: d["bytes"], reverse=True)[:10],
        }
    return {"stats": stats, "flows": top}


@app.get("/flows")
def get_flows(limit: int = 50, app: str | None = None):
    return snapshot(limit, app)["flows"]


@app.get("/stats")
def get_stats():
    return snapshot(limit=0)["stats"]


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    if AUTH and (not host_ok(websocket.headers.get("host"))
                 or not origin_ok(websocket.headers.get("origin"), websocket.headers.get("host"))
                 or not token_ok(websocket.query_params.get("token", ""))):
        await websocket.close(code=1008)          # policy violation
        return
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(snapshot())
            await asyncio.sleep(1)
    except (WebSocketDisconnect, RuntimeError):
        pass


class RuleIn(BaseModel):
    type: str
    value: str
    action: str = "flag"
    

@app.get("/rules")
def list_rules():
    return rules.list()


@app.post("/rules")
def add_rule(r: RuleIn):
    try:
        rule = rules.add(r.type, r.value, action=r.action)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    db.save_rule(rule)
    with lock:
        recheck_all()
    return rule


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int):
    if not rules.remove(rule_id):
        raise HTTPException(status_code=404, detail="no such rule")
    db.delete_rule(rule_id)
    with lock:
        recheck_all()
    return {"deleted": rule_id}


# ---- history (from the database) ----
@app.get("/sessions")
def get_sessions():
    return db.sessions()


@app.get("/sessions/{sid}/flows")
def get_session_flows(sid: int, limit: int = 100):
    return db.session_flows(sid, limit)


@app.get("/alerts")
def get_alerts(limit: int = 100):
    return db.alerts(limit)


@app.get("/")
def index():
    with open(os.path.join(BASE_DIR, "static", "index.html"), encoding="utf-8") as fh:
        page = fh.read()
    # the page, and only the page, learns the token (a foreign site cannot read this response)
    return HTMLResponse(page.replace("__API_TOKEN__", API_TOKEN if AUTH else ""))


def capture_state():
    with lock:
        return {"capturing": capturing, "session_id": session_id,
                "flows": len(an.fm.flows)}


@app.get("/capture")
def get_capture():
    return capture_state()


@app.post("/capture/stop")
def capture_stop():
    """Pause sniffing and RST injection. Firewall blocks already in place stay."""
    with ctl:
        if capturing:
            stop_sniffer()
            save_now()
        return capture_state()


@app.post("/capture/start")
def capture_start(fresh: bool = False):
    """Resume sniffing. fresh=true archives the current session and starts a new one."""
    global an, session_id
    with ctl:
        if capturing:
            return capture_state()
        if fresh:
            save_now()
            db.end_session(session_id)
            with lock:
                an = TrafficAnalyzer(expire=True)
                dropped[0] = 0
                reset.sent = 0
                try:
                    while True:
                        q.get_nowait()
                except queue.Empty:
                    pass
            session_id = db.start_session(str(iface), BPF)
        try:
            start_sniffer()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"cannot start capture: {e}")
        with lock:
            recheck_all()                 # apply rules that changed while stopped
        return capture_state()


@app.get("/resets")
def get_resets():
    return {"rst_sent": reset.sent}


@app.get("/blocked")
def get_blocked():
    return blocked