# Real-Time Network Traffic Analyzer

Shows which **domains and apps** a network is using, live, **without decrypting any traffic**.
It reads what is sent in the clear: the TLS ClientHello (SNI), HTTP `Host` headers, the QUIC
Initial packet, and DNS answers. Rules can flag or **block** by domain, app or IP; when rules overlap, block wins.

> Domain extraction matches Wireshark on **192/192 TCP flows and 18/18 QUIC flows**
> (100% precision and recall). See [Validation](#validation).

## Features
- **Live capture** with Scapy and a BPF filter; a producer/consumer queue keeps the sniffer fast
- **Flow tracking** by 5-tuple, with upload and download counted separately and idle/closed flows expired
- **SNI extraction** from TLS, with TCP reassembly for ClientHellos split across packets
- **QUIC/HTTP3 naming**: derives the Initial-packet keys (public, RFC 9001), decrypts the handshake
  only, and reads its ClientHello; CRYPTO frames are reassembled across packets (QUIC v1 and v2)
- **DNS fallback**: IP-to-name learned from plaintext DNS answers, used when no SNI was seen
- **Classifier** that maps domains to apps (YouTube, Google, GitHub, Netflix, ads/trackers, ...)
- **Rules by domain, app or IP**, each with action `flag` or `block`, editable live
- **Domain-aware blocking** (see below)
- **History**: sessions, flows and alerts saved to SQLite
- **FastAPI REST + WebSocket** and a single-page dashboard

## How it works
```
 Npcap/Scapy ──> queue ──> worker ──> flow table ──> rule engine ──> dashboard (WebSocket)
 (BPF filter)              │            │                  │
                           │            │                  ├─ flag  -> alert saved to SQLite
                           │            │                  └─ block -> enforcement
                           ├─ TLS SNI / HTTP Host (TCP, with reassembly)
                           ├─ QUIC Initial -> ClientHello (UDP/443)
                           └─ DNS answers  -> IP-to-name fallback
```

## Domain-aware blocking
Blocking by IP breaks on shared CDN addresses (blocking one site takes down others on the same
IP) and only acts after a connection exists. Instead:

| Rule type | Mechanism |
|---|---|
| `domain`, `app` (TCP) | When the SNI/Host matches, inject a **TCP RST** at the connection's tracked sequence number. Only that connection dies; no IP is blocked. Retries are reset the same way. |
| `domain`, `app` (QUIC) | RST does not exist for UDP, so UDP/443 to that server IP is firewall-blocked. The browser falls back to TCP, where the RST applies. Other domains on the IP are unaffected. |
| `ip` | Windows firewall outbound block on that IP. |

Removing a rule removes its firewall entries; leftover entries from a crashed run are cleaned up
at startup. Packets are injected as raw Ethernet frames through Npcap, because Windows blocks raw
TCP sockets.

## Setup (Windows)
1. Install Python 3.11+ and [Wireshark/Npcap](https://www.wireshark.org/) (Npcap is required)
2. In the project folder:
   ```powershell
   python -m venv venv
   venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. Run from an **Administrator** terminal (needed for capture, packet injection and firewall rules):
   ```powershell
   .\run.ps1          # creates the venv, installs requirements, starts on 127.0.0.1:8000
   ```
   or manually: `uvicorn server:app --host 127.0.0.1 --port 8000`
   If the wrong network interface is picked, set it first: `$env:IFACE="Wi-Fi"`
4. Open http://127.0.0.1:8000

## Usage
1. Browse normally; flows appear with domain, app, bytes up/down and a FLAGGED badge on matches.
2. Add a rule in the dashboard: choose type (`domain` / `app` / `ip`), value (e.g. `reddit.com`,
   `YouTube`), and action `Flag` or `Block`.
3. Reload the site. For `Block`, the connection is reset (QUIC sites fall back to TCP first, so
   expect a short delay).
4. Delete the rule to lift the block.

Fully close and reopen the browser after adding a block rule: connections that were already open
are only reset if they send more data.

## API
| Endpoint | Description |
|---|---|
| `GET /flows`, `GET /stats` | Current flows and totals |
| `WS /ws` | Live stream for the dashboard |
| `GET/POST /rules`, `DELETE /rules/{id}` | Manage rules |
| `GET /blocked` | Active firewall blocks and the rule behind each |
| `GET /resets` | Number of RSTs injected |
| `GET /sessions`, `/sessions/{id}/flows`, `/alerts` | History from SQLite |

## Security
All API endpoints and the WebSocket need a **per-run token**; the dashboard page receives it
automatically. Requests with a foreign `Origin` or a `Host` other than localhost are rejected
(CSRF and DNS-rebinding protection). Rule values are validated, and the server listens on
localhost only. Pin a token for scripts with `API_TOKEN`:
```powershell
$env:API_TOKEN="my-secret"; .\run.ps1
curl.exe -H "X-API-Token: my-secret" http://127.0.0.1:8000/alerts
```
| Variable | Default | Meaning |
|---|---|---|
| `IFACE` | auto | Interface to capture on |
| `QUIC_SHIELD` | `1` | `0` disables the all-UDP/443 block (VPN over UDP/443) |
| `API_TOKEN` | random per run | Fixed token for scripts |
| `AUTH` | `1` | `0` disables authentication (tests only) |
| `ALLOWED_HOSTS` / `ALLOWED_ORIGINS` | none | Extra accepted Host / Origin values |
| `RETENTION_DAYS` | `30` | History older than this is deleted at startup |

## Docker (Linux, monitoring only)
```bash
docker build -t traffic-analyzer .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -e IFACE=eth0 traffic-analyzer
```
Firewall and RST enforcement need Windows; in the container they report as unavailable.

## Validation
Name extraction is cross-checked against Wireshark's tshark, an independent dissector, with
`validate_sni.py`, matching flows by 5-tuple.

| One browsing capture | Flows | Recall | Precision |
|---|---|---|---|
| TCP (TLS SNI / HTTP Host) | 192 | 100.0% | 100.0% |
| QUIC (UDP/443) | 18 | 100.0% | 100.0% |

Byte-weighted agreement on TCP is also 100%, and tshark can name 98.4% of all TCP bytes.
Run it yourself:
```powershell
python validate_sni.py your.pcap --csv report.csv
```

## Tests
```powershell
python run_tests.py         # runs every suite: classifier, QUIC, blocking, capture, security, robustness
```
GitHub Actions runs the same command on every push. `test_dns.py` and `test_expiry.py` take a
pcap: `python test_dns.py your.pcap`. Offline demos of each build stage: `python step5_apps.py your.pcap`.

## Project layout
| File | Role |
|---|---|
| `server.py` | FastAPI app, capture, worker, rule enforcement |
| `analyzer.py` | Per-packet pipeline: flows, SNI, QUIC, DNS fallback |
| `step2_flows.py`, `step3_sni.py`, `step4_reassembly.py` | Flow table, TLS/HTTP parsing, TCP reassembly |
| `quic.py` | QUIC Initial decryption and ClientHello extraction |
| `dns_cache.py`, `classifier.py` | DNS name fallback, domain-to-app map |
| `rules.py`, `enforce.py`, `reset.py` | Rule engine, firewall blocks, TCP RST injection |
| `db.py`, `static/index.html` | SQLite persistence (indexes, retention), dashboard |
| `run.ps1`, `Dockerfile`, `run_tests.py` | Windows launcher, Linux image, one-command test runner |
| `validate_sni.py` | Accuracy check against Wireshark |

## Known limitations
- Throughput is about 3,700 to 5,000 packets/s per core (Scapy dissection); drops are counted in the dashboard
- Encrypted Client Hello (ECH) hides the SNI and cannot be classified
- Connections that started before capture began cannot be named
- RST blocking races the real traffic: the ClientHello has already left, so a connection can
  occasionally slip through; browser retries are reset the same way
- QUIC flows are named from the handshake only, so their byte counts cover Initial packets, not
  the whole stream
- Blocking a QUIC site relies on the browser falling back to TCP
- Windows only for enforcement (`netsh` firewall, Npcap injection); capture and analysis work
  wherever Scapy does

## Legal
Only capture traffic on networks and machines you own or have explicit permission to monitor.