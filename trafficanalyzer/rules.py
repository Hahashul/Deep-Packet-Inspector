import ipaddress
import threading

RULE_TYPES = {"domain", "ip", "app"}


class RuleEngine:
    def __init__(self):
        self.rules = []
        self._lock = threading.Lock()

    def add(self, rtype, value, rule_id=None, action="flag"):
        rtype = rtype.lower()
        if rtype not in RULE_TYPES:
            raise ValueError(f"type must be one of {sorted(RULE_TYPES)}")
        if action not in ("flag", "block"):
            raise ValueError("action must be 'flag' or 'block'")
        value = value.strip().lower().rstrip(".")
        if not value:
            raise ValueError("value is empty")
        if rtype == "ip":
            try:
                value = str(ipaddress.ip_address(value))   # validates, normalises IPv6
            except ValueError:
                raise ValueError(f"'{value}' is not a valid IP address")
        with self._lock:
            if rule_id is None:
                rule_id = max((r["id"] for r in self.rules), default=0) + 1
            rule = {"id": rule_id, "type": rtype, "value": value, "action": action}
            self.rules.append(rule)
        return rule

    def remove(self, rule_id):
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r["id"] != rule_id]
            return len(self.rules) < before

    def list(self):
        with self._lock:
            return list(self.rules)

    def match_all(self, flow):
        """Every rule that matches this flow, as (rule_key, action) pairs."""
        name = (flow.sni or flow.http_host or "").lower()
        hits = []
        for r in self.list():
            v = r["value"]
            if r["type"] == "domain" and name and (name == v or name.endswith("." + v)):
                hits.append((f"domain:{v}", r["action"]))
            elif r["type"] == "app" and flow.app.lower() == v:
                hits.append((f"app:{v}", r["action"]))
            elif r["type"] == "ip" and flow.server_ip.lower() == v:
                hits.append((f"ip:{v}", r["action"]))
        return hits

    def match(self, flow):
        """Rule key to act on. A block rule always wins over a flag rule."""
        hits = self.match_all(flow)
        for key, action in hits:
            if action == "block":
                return key
        return hits[0][0] if hits else ""

    def evaluate(self, flow):
        hit = self.match(flow)
        flow.flagged = bool(hit)
        flow.matched_rule = hit
        return flow.flagged