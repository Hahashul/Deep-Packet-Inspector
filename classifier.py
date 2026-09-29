APP_MAP = {
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
                "youtu.be", "youtube-nocookie.com"],
    "Google": ["google.com", "gstatic.com", "googleapis.com", "googlezip.net",
               "googleusercontent.com", "gvt1.com", "gvt2.com" , "google.co.in"],
    "GitHub": ["github.com", "githubassets.com", "githubusercontent.com",
               "github.io", "githubcopilot.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "Microsoft": ["microsoft.com", "skype.com", "live.com", "office.com",
                  "msftconnecttest.com", "windows.com", "bing.com",
                  "azureedge.net", "vscode-cdn.net", "vsassets.io", "visualstudio.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "Facebook/Meta": ["facebook.com", "fbcdn.net", "instagram.com",
                      "whatsapp.net", "whatsapp.com"],
    "Amazon": ["amazon.com", "amazonaws.com", "cloudfront.net"],
    "Spotify": ["spotify.com", "scdn.co"],
    "Wikipedia": ["wikipedia.org", "wikimedia.org"],
    "Reddit": ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com"],
    "Bot protection (PerimeterX)": ["px-cloud.net", "protechts.net"],
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

def classify(domain):
    """Return an app name. 'Unknown' = no domain, 'Other' = domain not in map."""
    if not domain:
        return "Unknown"
    domain = domain.lower().rstrip(".")
    for suffix, app in _RULES:
        if domain == suffix or domain.endswith("." + suffix):
            return app
    return "Other"