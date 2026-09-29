import sys
from scapy.all import rdpcap, TCP
from step2_flows import FlowManager, fmt_bytes

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ")


class Short(Exception):
    """Payload ended before the structure we were parsing did."""


def take(data, pos, n):
    if pos + n > len(data):
        raise Short
    return data[pos:pos + n], pos + n


def parse_client_hello(data):
    """Return (status, sni). status is 'ok', 'partial' or 'no'."""
    # TLS record: type 0x16 (handshake), version 0x03xx; handshake type 0x01 (ClientHello)
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return "no", None
    try:
        # record header (5) + handshake header (4) + client version (2) + random (32)
        pos = 43
        b, pos = take(data, pos, 1)          # session id length
        pos += b[0]
        b, pos = take(data, pos, 2)          # cipher suites length
        pos += int.from_bytes(b, "big")
        b, pos = take(data, pos, 1)          # compression methods length
        pos += b[0]
        b, pos = take(data, pos, 2)          # total extensions length
        ext_end = pos + int.from_bytes(b, "big")

        while pos < ext_end:
            hdr, pos = take(data, pos, 4)    # extension type (2) + length (2)
            etype = int.from_bytes(hdr[:2], "big")
            elen = int.from_bytes(hdr[2:], "big")
            if etype == 0:                   # server_name extension
                body, _ = take(data, pos, elen)
                # list length (2), name type (1), name length (2), name
                if len(body) >= 5 and body[2] == 0:
                    nlen = int.from_bytes(body[3:5], "big")
                    name = body[5:5 + nlen].decode("ascii", "ignore").lower()
                    return "ok", name
                return "ok", None
            pos += elen
        return "ok", None                    # complete hello, no SNI extension
    except Short:
        return "partial", None


def parse_http_host(data):
    if not data.startswith(HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            return line[5:].strip().decode("ascii", "ignore").lower()
    return None


def main(path):
    packets = rdpcap(path)
    fm = FlowManager()
    partial = set()

    for pkt in packets:
        flow = fm.process(pkt)
        if flow is None or TCP not in pkt:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload or flow.sni or flow.http_host:
            continue

        status, sni = parse_client_hello(payload)
        if status == "ok" and sni:
            flow.sni = sni
        elif status == "partial":
            partial.add(id(flow))
        elif status == "no":
            host = parse_http_host(payload)
            if host:
                flow.http_host = host

    flows = sorted(fm.flows.values(), key=lambda f: f.total_bytes, reverse=True)

    print(f"{'PROTO':5} {'SERVER':<26} {'NAME':<38} {'UP':>9} {'DOWN':>9}")
    for f in flows[:25]:
        server = f"{f.server_ip}:{f.server_port}"
        name = f.sni or f.http_host or "-"
        print(f"{f.protocol:5} {server[-26:]:<26} {name[:38]:<38} "
              f"{fmt_bytes(f.bytes_sent):>9} {fmt_bytes(f.bytes_recv):>9}")

    tcp = [f for f in flows if f.protocol == "TCP"]
    named = [f for f in tcp if f.sni or f.http_host]
    still_partial = [f for f in tcp if id(f) in partial and not f.sni]
    print(f"\nTCP flows: {len(tcp)} | named: {len(named)} | "
          f"ClientHello split across packets: {len(still_partial)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")