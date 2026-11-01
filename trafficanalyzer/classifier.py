import ipaddress

APP_MAP = {
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
                "youtu.be", "youtube-nocookie.com"],
    "Google": ["google.com", "gstatic.com", "googleapis.com", "googlezip.net",
               "googleusercontent.com", "gvt1.com", "gvt2.com", "google.co.in", "nel.goog",
               "google.fastly-edge.com"],
    "GitHub": ["github.com", "githubassets.com", "githubusercontent.com",
               "github.io", "githubcopilot.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "Microsoft": ["microsoft.com", "skype.com", "live.com", "office.com",
                  "msftconnecttest.com", "windows.com", "bing.com",
                  "azureedge.net", "vscode-cdn.net", "vsassets.io", "visualstudio.com",
                  "exp-tas.com", "gamepass.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "Facebook/Meta": ["facebook.com", "fbcdn.net", "instagram.com",
                      "whatsapp.net", "whatsapp.com"],
    "Amazon": ["amazon.com", "amazonaws.com", "cloudfront.net"],
    "Spotify": ["spotify.com", "scdn.co"],
    "Wikipedia": ["wikipedia.org", "wikimedia.org"],
    "Reddit": ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com"],
    "Bot protection (PerimeterX)": ["px-cloud.net", "protechts.net"],
    "Claude/Anthropic": ["claude.ai", "claude.com", "anthropic.com",
                         "claudeusercontent.com"],
    "Grammarly": ["grammarly.com", "grammarly.io"],
    "Vercel": ["vercel.app", "vercel.com"],
    "Cloudflare": ["cloudflare.com", "cloudflare-ech.com"],
    "Coda": ["coda.io"],
    "Ollama": ["ollama.com"],
    "Ads & Tracking": ["doubleclick.net", "googlesyndication.com",
                       "adtrafficquality.google", "googleadservices.com",
                       "google-analytics.com", "googletagmanager.com",
                       "demdex.net", "adnxs.com", "trkn.us"],
}

# Flatten to (suffix, app), longest suffix first so the most specific wins
_RULES = sorted(
    ((suffix, app) for app, suffixes in APP_MAP.items() for suffix in suffixes),
    key=lambda r: len(r[0]),
    reverse=True,
)

def _is_private_host(host):
    """True for an IP literal (optionally with :port) on a private/local network."""
    host = host.strip("[]")
    if host.count(":") == 1:                  # IPv4:port
        host = host.split(":")[0]
    elif host.startswith("[") or host.count(":") > 1:
        host = host.split("]")[0].strip("[")  # IPv6 literal, possibly [v6]:port
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def classify(domain):
    """Return an app name. 'Unknown' = no domain, 'Other' = domain not in map,
    'Local network' = a device on the user's own LAN (e.g. a Chromecast)."""
    if not domain:
        return "Unknown"
    domain = domain.lower().rstrip(".")
    if _is_private_host(domain):
        return "Local network"
    for suffix, app in _RULES:
        if domain == suffix or domain.endswith("." + suffix):
            return app
    return "Other"