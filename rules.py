import threading

RULE_TYPES = {"domain", "ip", "app"}


class RuleEngine:
    def __init__(self):
        self.rules = []
        self._lock = threading.Lock()

    def add(self, rtype, value, rule_id=None):
        rtype = rtype.lower()
        if rtype not in RULE_TYPES:
            raise ValueError(f"type must be one of {sorted(RULE_TYPES)}")
        value = value.strip().lower().rstrip(".")
        if not value:
            raise ValueError("value is empty")
        with self._lock:
            if rule_id is None:
                rule_id = max((r["id"] for r in self.rules), default=0) + 1
            rule = {"id": rule_id, "type": rtype, "value": value, "action": "flag"}
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

    def match(self, flow):
        name = (flow.sni or flow.http_host or "").lower()
        for r in self.list():
            v = r["value"]
            if r["type"] == "domain" and name and (name == v or name.endswith("." + v)):
                return f"domain:{v}"
            if r["type"] == "app" and flow.app.lower() == v:
                return f"app:{v}"
            if r["type"] == "ip" and flow.server_ip.lower() == v:
                return f"ip:{v}"
        return ""

    def evaluate(self, flow):
        hit = self.match(flow)
        flow.flagged = bool(hit)
        flow.matched_rule = hit
        return flow.flagged