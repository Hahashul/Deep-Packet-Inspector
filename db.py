import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id INTEGER PRIMARY KEY AUTOINCREMENT,
  start_time REAL, end_time REAL, interface TEXT, bpf_filter TEXT);
CREATE TABLE IF NOT EXISTS flows (
  session_id INTEGER, flow_id TEXT,
  src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protocol TEXT,
  first_seen REAL, last_seen REAL,
  bytes_sent INTEGER, bytes_recv INTEGER, packet_count INTEGER,
  sni TEXT, http_host TEXT, app_label TEXT, status TEXT,
  PRIMARY KEY (session_id, flow_id));
CREATE TABLE IF NOT EXISTS rules (
  rule_id INTEGER PRIMARY KEY, type TEXT, value TEXT, action TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER, flow_id TEXT, rule TEXT, timestamp REAL);
"""


def flow_id(f):
    return f"{f.protocol}-{f.client_ip}:{f.client_port}-{f.server_ip}:{f.server_port}"


def flow_row(session_id, f):
    return (session_id, flow_id(f), f.client_ip, f.client_port, f.server_ip,
            f.server_port, f.protocol, f.first_seen, f.last_seen,
            f.bytes_sent, f.bytes_recv, f.packets, f.sni, f.http_host,
            f.app, "flagged" if f.flagged else "allowed")


class Database:
    def __init__(self, path="analyzer.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def _run(self, sql, params=(), many=False):
        with self.lock:
            cur = (self.conn.executemany if many else self.conn.execute)(sql, params)
            self.conn.commit()
            return cur

    def _query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    # sessions
    def start_session(self, iface, bpf):
        cur = self._run("INSERT INTO sessions (start_time, interface, bpf_filter) "
                        "VALUES (?,?,?)", (time.time(), iface, bpf))
        return cur.lastrowid

    def end_session(self, sid):
        self._run("UPDATE sessions SET end_time=? WHERE session_id=?",
                  (time.time(), sid))

    def sessions(self):
        return self._query(
            "SELECT s.*, (SELECT COUNT(*) FROM flows f WHERE f.session_id=s.session_id) "
            "AS flow_count FROM sessions s ORDER BY session_id DESC")

    # flows
    def save_flows(self, rows):
        if not rows:
            return
        self._run(
            "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(session_id, flow_id) DO UPDATE SET "
            "last_seen=excluded.last_seen, bytes_sent=excluded.bytes_sent, "
            "bytes_recv=excluded.bytes_recv, packet_count=excluded.packet_count, "
            "sni=excluded.sni, http_host=excluded.http_host, "
            "app_label=excluded.app_label, status=excluded.status",
            rows, many=True)

    def session_flows(self, sid, limit=100):
        return self._query(
            "SELECT * FROM flows WHERE session_id=? "
            "ORDER BY bytes_sent+bytes_recv DESC LIMIT ?", (sid, limit))

    # rules
    def load_rules(self):
        return self._query("SELECT rule_id AS id, type, value FROM rules ORDER BY rule_id")

    def save_rule(self, rule):
        self._run("INSERT OR REPLACE INTO rules VALUES (?,?,?,?,?)",
                  (rule["id"], rule["type"], rule["value"], rule["action"], time.time()))

    def delete_rule(self, rule_id):
        self._run("DELETE FROM rules WHERE rule_id=?", (rule_id,))

    # alerts
    def add_alert(self, sid, fid, rule):
        self._run("INSERT INTO alerts (session_id, flow_id, rule, timestamp) "
                  "VALUES (?,?,?,?)", (sid, fid, rule, time.time()))

    def alerts(self, limit=100):
        return self._query("SELECT * FROM alerts ORDER BY alert_id DESC LIMIT ?", (limit,))     