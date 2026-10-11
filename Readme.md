# Real-Time Network Traffic Analyzer

Identifies which domains and apps a network is using **without decrypting traffic**,
by reading the unencrypted TLS ClientHello (SNI) and HTTP Host headers.
Live dashboard over WebSocket.

## Features
- Live packet capture (Scapy + BPF filter), producer/consumer queue
- Flow tracking by 5-tuple, upload/download counted separately
- SNI extraction with TCP reassembly for split ClientHellos
- QUIC/HTTP3 naming: decrypts the client Initial packet (keys are public per RFC 9001) and reads its ClientHello, incl. ClientHellos split across packets
- Domain-to-app classifier (YouTube, Google, GitHub, ads/trackers, ...)
- Flag or block by domain, IP or app, editable live
- Domain-aware blocking: connections whose SNI/Host matches a domain or app block rule are reset with an injected TCP RST (QUIC: UDP/443 to that IP is blocked so browsers fall back to TCP) (no IP blocking, so no collateral damage on shared CDNs). IP rules use the Windows firewall
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

## Validation
Domain extraction is cross-checked against Wireshark/tshark (an independent TLS/HTTP
dissector) with `validate_sni.py`, matching flows by 5-tuple.

| Metric (TCP, 192 flows, one browsing capture) | Result |
|---|---|
| Recall (flows tshark named that we also named) | 100.0% |
| Precision (names that match tshark's) | 100.0% |
| Byte-weighted agreement | 100.0% |
| TCP bytes tshark can name | 98.4% |

| QUIC flows named (18 flows): recall / precision | 100.0% / 100.0% |

QUIC is ~9% of flows in this capture (18 of 210).
Run it yourself: `python validate_sni.py your.pcap --csv report.csv`

## Known limitations
- Encrypted Client Hello is not classified
- QUIC flows are named from the handshake only: their byte counts cover Initial packets, not the whole stream
- Connections that started before capture began cannot be named
- RST blocking races the real traffic and is TCP-only: QUIC is handled indirectly: a matching QUIC flow gets UDP/443 to that IP firewall-blocked, forcing the browser back to TCP where the RST applies
- Firewall rules from a crashed run are not cleaned up on next start

## Legal
Only capture traffic on networks and machines you own or have explicit
permission to monitor.
