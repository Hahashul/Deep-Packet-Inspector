# Real-Time Network Traffic Analyzer

Identifies which domains and apps a network is using **without decrypting traffic**,
by reading the unencrypted TLS ClientHello (SNI) and HTTP Host headers.
Live dashboard over WebSocket.

## Features
- Live packet capture (Scapy + BPF filter), producer/consumer queue
- Flow tracking by 5-tuple, upload/download counted separately
- SNI extraction with TCP reassembly for split ClientHellos
- Domain-to-app classifier (YouTube, Google, GitHub, ads/trackers, ...)
- Flag rules by domain, IP or app, editable live
- FastAPI REST + WebSocket, single-page dashboard

## Setup (Windows)
1. Install Python 3.11+ and [Wireshark/Npcap](https://www.wireshark.org/)
2. ```
   python -m venv venv
   venv\Scripts\Activate.ps1
   pip install -r requirements.txt
````
3. Run from an **Administrator** terminal:
````
   uvicorn server:app --port 8000
````
   Set `$env:IFACE="Wi-Fi"` first if the wrong interface is picked.
4. Open http://127.0.0.1:8000

Offline demos: `python step5_apps.py your.pcap`

## Known limitations
- QUIC/HTTP3 (UDP) and Encrypted Client Hello are not classified
- Connections that started before capture began cannot be named
- Data is in memory only (no persistence yet)

## Legal
Only capture traffic on networks and machines you own or have explicit
permission to monitor.
````

## 3. Commit locally

````powershell
git init
git add .
git status
````

Check that the `git status` list contains your `.py` files, `static/index.html`, `README.md`, `requirements.txt`, and `.gitignore`, and does **not** contain `venv` or any `.pcap` files. Then:

````powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git commit -m "Traffic analyzer MVP: capture, SNI/DPI, classifier, rules, dashboard"
git branch -M main
````

Use the email tied to your GitHub account. If you don't want your real email public, GitHub has a private `noreply` address under Settings → Emails.

## 4. Create the repo on GitHub

1. Go to github.com/new.
2. Name it `traffic-analyzer`, choose Public or Private, and **leave "Add a README" and "Add .gitignore" unticked**, since you already have both.
3. Click **Create repository**. GitHub shows a URL like `https://github.com/<you>/traffic-analyzer.git`.

## 5. Push

````powershell
git remote add origin https://github.com/<you>/traffic-analyzer.git
git push -u origin main
````

A browser window should open asking you to sign in to GitHub. Approve it, and the push completes. Refresh the repo page and your files should be there.

## Later changes

After any edit, this is the whole routine:

````powershell
git add .
git commit -m "describe what you changed"
git push
````

A note on the code: the files are named `step1_...` to `step9`, which reflects how we built it. That's fine for now. If you want it to look cleaner for a portfolio, we can later group the core modules into a package and keep the steps as `examples/`.

Tell me if `git status` shows anything unexpected, or if the push errors, and paste the message. Then we can pick up the Wireshark validation.