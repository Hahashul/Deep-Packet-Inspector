import itertools
import threading

RULE_TYPES = {"domain", "ip", "app"}
_ids = itertools.count(1)


class RuleEngine:
    def __init__(self):
        self.rules = []
        self._lock = threading.Lock()

    def add(self, rtype, value):
        rtype = rtype.lower()
        if rtype not in RULE_TYPES:
            raise ValueError(f"type must be one of {sorted(RULE_TYPES)}")
        value = value.strip().lower().rstrip(".")
        if not value:
            raise ValueError("value is empty")
        rule = {"id": next(_ids), "type": rtype, "value": value, "action": "flag"}
        with self._lock:
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
        """Return a description of the first matching rule, or ''."""
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
        """Set flow.flagged / matched_rule. Returns True if flagged."""
        hit = self.match(flow)
        flow.flagged = bool(hit)
        flow.matched_rule = hit
        return flow.flagged