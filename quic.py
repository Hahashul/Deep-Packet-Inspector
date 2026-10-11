"""Read the SNI from a QUIC client Initial packet (RFC 9001 section 5).

Initial packets are encrypted, but with keys derived from the packet's own
Destination Connection ID, which is public. So anyone on the path can decrypt
the handshake (not the later 1-RTT traffic) and read the TLS ClientHello,
exactly as Wireshark does. Supports QUIC v1 and v2.

A modern ClientHello (post-quantum key share) often spans two Initial packets,
so CRYPTO frames are reassembled by offset across packets.
"""
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from step3_sni import parse_client_hello

V1, V2 = 0x00000001, 0x6B3343CF
SALTS = {
    V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
LABELS = {V1: (b"quic key", b"quic iv", b"quic hp"),
          V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")}
INITIAL_TYPE = {V1: 0, V2: 1}
MAX_CRYPTO = 16384          # sanity cap on reassembled handshake bytes


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]   # length <= 32


def derive_client_keys(dcid, version=V1):
    """(key, iv, hp) for client Initial packets."""
    initial = hmac.new(SALTS[version], dcid, hashlib.sha256).digest()
    client = _expand_label(initial, b"client in", 32)
    k, i, h = LABELS[version]
    return _expand_label(client, k, 16), _expand_label(client, i, 12), _expand_label(client, h, 16)


def _varint(b, pos):
    n = 1 << (b[pos] >> 6)
    if pos + n > len(b):
        raise ValueError("short varint")
    return int.from_bytes(b[pos:pos + n], "big") & ((1 << (8 * n - 2)) - 1), pos + n


def decrypt_initial(dgram):
    """Decrypt the first packet of a UDP datagram if it is a client Initial.
    Returns the plaintext frames, or None."""
    try:
        if len(dgram) < 1200 // 4 or not dgram[0] & 0x80:         # long header only
            return None
        version = int.from_bytes(dgram[1:5], "big")
        if version not in SALTS or (dgram[0] >> 4) & 3 != INITIAL_TYPE[version]:
            return None
        pos = 5
        dlen = dgram[pos]; pos += 1
        dcid = dgram[pos:pos + dlen]; pos += dlen
        slen = dgram[pos]; pos += 1 + slen
        tlen, pos = _varint(dgram, pos); pos += tlen            # token
        length, pos = _varint(dgram, pos)
        pn_off = pos
        end = pn_off + length
        if end > len(dgram) or length < 20:
            return None
        key, iv, hp = derive_client_keys(dcid, version)
        sample = dgram[pn_off + 4:pn_off + 20]
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        first = dgram[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 3) + 1
        pn_bytes = bytes(a ^ b for a, b in zip(dgram[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
        header = bytes([first]) + dgram[1:pn_off] + pn_bytes
        nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pn_bytes, "big")).to_bytes(12, "big")
        return AESGCM(key).decrypt(nonce, dgram[pn_off + pn_len:end], header)
    except Exception:
        return None


def crypto_frames(plain):
    """Yield (offset, data) for every CRYPTO frame in a decrypted Initial payload."""
    pos = 0
    while pos < len(plain):
        t, pos = _varint(plain, pos)
        if t in (0x00, 0x01):                    # PADDING, PING
            continue
        if t == 0x06:                            # CRYPTO
            off, pos = _varint(plain, pos)
            n, pos = _varint(plain, pos)
            yield off, plain[pos:pos + n]
            pos += n
        elif t in (0x02, 0x03):                  # ACK
            for _ in range(4):                   # largest, delay, range count, first range
                v, pos = _varint(plain, pos)
                if _ == 2:
                    count = v
            for _ in range(count * 2):
                _v, pos = _varint(plain, pos)
            if t == 0x03:
                for _ in range(3):
                    _v, pos = _varint(plain, pos)
        else:
            return                               # unknown frame: stop


class QuicSni:
    """Per-flow collector: feed client datagrams until the SNI is known."""
    def __init__(self):
        self.frags = {}          # offset -> bytes
        self.done = False
        self.tries = 0

    def add(self, dgram):
        """Returns (status, sni) like parse_client_hello; ('no', None) if not Initial."""
        self.tries += 1
        plain = decrypt_initial(dgram)
        if plain is None:
            return "no", None
        try:
            for off, data in crypto_frames(plain):
                if data and off + len(data) <= MAX_CRYPTO:
                    self.frags[off] = data
        except ValueError:
            pass
        buf, cursor = b"", 0
        for off in sorted(self.frags):
            if off > cursor:
                break
            d = self.frags[off]
            if off + len(d) > cursor:
                buf += d[cursor - off:]
                cursor = off + len(d)
        if not buf:
            return "partial", None
        return parse_client_hello(b"\x16\x03\x01\x00\x00" + buf)   # fake TLS record header
