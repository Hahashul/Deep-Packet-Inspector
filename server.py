import asyncio
import os
import queue
import threading
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from scapy.all import AsyncSniffer

from analyzer import TrafficAnalyzer
from db import Database, flow_id, flow_row
from rules import RuleEngine
from step6_live import pick_iface

BPF = "tcp port 80 or tcp port 443"

an = TrafficAnalyzer()
rules = RuleEngine()
db = Database()
session_id = None
lock = threading.Lock()
q = queue.Queue(maxsize=20000)
stop = threading.Event()
dropped = [0]
sniffer = None


def enqueue(pkt):
    try:
        q.put_nowait(pkt)
    except queue.Full:
        dropped[0] += 1


def recheck_all():
    """Re-evaluate every flow (call with `lock` held). Log newly flagged ones."""
    for f in an.fm.flows.values():
        was = f.flagged
        if rules.evaluate(f) and not was:
            db.add_alert(session_id, flow_id(f), f.matched_rule)


def worker():
    while not stop.is_set():
        try:
            pkt = q.get(timeout=0.5)
        except queue.Empty:
            continue
        with lock:
            flow = an.process(pkt)
            if flow is not None and not flow.flagged:
                if rules.evaluate(flow):
                    db.add_alert(session_id, flow_id(flow), flow.matched_rule)


def save_now():
    with lock:
        rows = [flow_row(session_id, f) for f in an.fm.flows.values()]
    db.save_flows(rows)


def saver():
    while not stop.wait(5):
        save_now()


@asynccontextmanager
async def lifespan(app):
    global sniffer, session_id
    iface = pick_iface(os.environ.get("IFACE"))
    for r in db.load_rules():
        rules.add(r["type"], r["value"], r["id"])
    session_id = db.start_session(str(iface), BPF)
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=saver, daemon=True).start()
    sniffer = AsyncSniffer(iface=iface, filter=BPF, prn=enqueue, store=False)
    sniffer.start()
    yield
    stop.set()
    sniffer.stop()
    save_now()
    db.end_session(session_id)


app = FastAPI(title="Traffic Analyzer", lifespan=lifespan)


def flow_dict(f):
    return {
        "id": flow_id(f),
        "client": f"{f.client_ip}:{f.client_port}",
        "server": f"{f.server_ip}:{f.server_port}",
        "protocol": f.protocol,
        "name": f.sni or f.http_host or "",
        "app": f.app,
        "bytes_sent": f.bytes_sent,
        "bytes_recv": f.bytes_recv,
        "total_bytes": f.total_bytes,
        "packets": f.packets,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "flagged": f.flagged,
        "matched_rule": f.matched_rule,
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
        domains = defaultdict(int)
        for f in flows:
            apps[f.app]["flows"] += 1
            apps[f.app]["bytes"] += f.total_bytes
            name = f.sni or f.http_host
            if name:
                domains[name] += f.total_bytes

        stats = {
            "total_flows": len(flows),
            "total_bytes": sum(f.total_bytes for f in flows),
            "queue": q.qsize(),
            "dropped": dropped[0],
            "flagged_flows": sum(1 for f in flows if f.flagged),
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


@app.get("/rules")
def list_rules():
    return rules.list()


@app.post("/rules")
def add_rule(r: RuleIn):
    try:
        rule = rules.add(r.type, r.value)
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
    return FileResponse("static/index.html")