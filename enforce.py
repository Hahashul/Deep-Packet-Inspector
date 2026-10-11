import subprocess

PREFIX = "TrafficAnalyzer-Block-"


def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        print(f"[enforce] failed ({p.returncode}): {' '.join(cmd[:6])} -> "
              f"{(p.stdout or p.stderr).strip()[:200]}")
    return p.returncode == 0


def block_ip(ip):
    return _run(["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={PREFIX + ip}", "dir=out", "action=block",
                 f"remoteip={ip}", "enable=yes"])


def unblock_ip(ip):
    return _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={PREFIX + ip}"])


def block_udp443(ip):
    """Block only QUIC (UDP/443) to this IP. Browsers then fall back to TCP,
    where domain blocking (RST) applies, so other domains on the IP still work."""
    return _run(["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={PREFIX}udp443-{ip}", "dir=out", "action=block",
                 "protocol=UDP", "remoteport=443", f"remoteip={ip}", "enable=yes"])


def unblock_udp443(ip):
    return _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={PREFIX}udp443-{ip}"])


def cleanup_stale():
    """Remove every firewall rule this app ever created (e.g. left by a crash or an old version)."""
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"Remove-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue"],
                   capture_output=True, text=True)
