"""Network interface selection for live capture."""
import sys
from scapy.all import conf


def pick_iface(name):
    """Return the Scapy interface whose name or description contains `name` (default interface if empty)."""
    if not name:
        return conf.iface
    for i in conf.ifaces.values():
        text = f"{i.name} {getattr(i, 'description', '')}".lower()
        if name.lower() in text:
            return i
    names = ", ".join(i.name for i in conf.ifaces.values())
    sys.exit(f"No interface matching '{name}'. Available: {names}")
