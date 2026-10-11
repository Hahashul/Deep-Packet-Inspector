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


def block_udp443_all():
    """QUIC shield: block ALL outbound UDP/443 so every browser falls back to TCP,
    where TLS names are visible and domain/app blocks (RST) can work. This also
    cuts QUIC sessions opened while capture was paused, which we cannot see."""
    return _run(["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={PREFIX}udp443-all", "dir=out", "action=block",
                 "protocol=UDP", "remoteport=443", "enable=yes"])


def unblock_udp443_all():
    return _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={PREFIX}udp443-all"])


def cleanup_stale():
    """Remove every firewall rule this app ever created (e.g. left by a crash or an old version)."""
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"Remove-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue"],
                   capture_output=True, text=True)
