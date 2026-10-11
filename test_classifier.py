"""Run with:  python test_classifier.py   (or: pytest test_classifier.py)"""
from classifier import classify

CASES = {
    # (input) -> expected app
    "www.youtube.com": "YouTube",
    "rr1---sn-ci5gup-civd.googlevideo.com": "YouTube",
    "accounts.google.com": "Google",
    "ohttp-relay-safebrowsing-chrome.google.fastly-edge.com": "Google",   # specific beats generic
    "main.vscode-cdn.net": "Microsoft",
    "catalog.gamepass.com": "Microsoft",
    "claude.ai": "Claude/Anthropic",
    "www.claudeusercontent.com": "Claude/Anthropic",
    "auth.grammarly.com": "Grammarly",
    "extension.femetrics.grammarly.io": "Grammarly",
    "something.vercel.app": "Vercel",
    "cloudflare-ech.com": "Cloudflare",
    "pagead2.googlesyndication.com": "Ads & Tracking",
    "192.168.1.4:8008": "Local network",
    "10.0.0.7": "Local network",
    "172.16.5.9:56789": "Local network",
    "8.8.8.8": "Other",                       # public IP literal is not "local"
    "notinthemap.example": "Other",
    "": "Unknown",
    "WWW.YOUTUBE.COM.": "YouTube",            # case and trailing dot
    "evilgithub.com": "Other",                # must not match 'github.com' as a suffix
    "notgoogle.com": "Other",
}


def test_all():
    bad = {k: (classify(k), v) for k, v in CASES.items() if classify(k) != v}
    assert not bad, f"mismatches (got, expected): {bad}"


if __name__ == "__main__":
    test_all()
    print(f"all {len(CASES)} classifier cases passed")
