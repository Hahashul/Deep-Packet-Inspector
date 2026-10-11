import subprocess

PREFIX = "TrafficAnalyzer-Block-"


def block_ip(ip):
    name = PREFIX + ip
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={name}", "dir=out", "action=block",
         f"remoteip={ip}", "enable=yes"],
        capture_output=True, text=True
    )


def unblock_ip(ip):
    name = PREFIX + ip
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
        capture_output=True, text=True
    )