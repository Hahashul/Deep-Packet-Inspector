"""QUIC Initial parsing: RFC 9001 key vectors + an encrypt/decrypt round trip."""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import quic


def test_rfc9001_key_vectors():          # RFC 9001 Appendix A.1
    key, iv, hp = quic.derive_client_keys(bytes.fromhex("8394c8f03e515708"))
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def _hello(sni, pad=0):
    name = sni.encode()
    sn = b"\x00" + len(name).to_bytes(2, "big") + name
    sn = len(sn).to_bytes(2, "big") + sn
    ext = b"\x00\x00" + len(sn).to_bytes(2, "big") + sn
    ext += b"\xff\x01" + pad.to_bytes(2, "big") + b"\x00" * pad          # filler extension
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(ext).to_bytes(2, "big") + ext)
    return b"\x01" + len(body).to_bytes(3, "big") + body                 # handshake msg


def _build_initial(frames, dcid, pn, version=quic.V1):
    """Encrypt an Initial the way a client would (test helper)."""
    key, iv, hp = quic.derive_client_keys(dcid, version)
    plain = frames + b"\x00" * max(0, 1200 - len(frames) - 60)
    pn_b = pn.to_bytes(4, "big")
    length = 4 + len(plain) + 16
    ftype = quic.INITIAL_TYPE[version]
    first = 0xC0 | (ftype << 4) | 3
    hdr = (bytes([first]) + version.to_bytes(4, "big") + bytes([len(dcid)]) + dcid
           + b"\x00" + b"\x00" + (0x4000 | length).to_bytes(2, "big"))
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    ct = AESGCM(key).encrypt(nonce, plain, hdr + pn_b)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(ct[0:16] if False else ct[:16]) + enc.finalize()
    prot = bytearray(hdr + pn_b + ct)
    prot[0] ^= mask[0] & 0x0F
    for i in range(4):
        prot[len(hdr) + i] ^= mask[1 + i]
    return bytes(prot)


def _crypto(offset, data):
    return b"\x06" + bytes([offset >> 8 | 0x40, offset & 0xFF]) + (0x4000 | len(data)).to_bytes(2, "big") + data


def test_single_packet_sni():
    dcid = os.urandom(8)
    pkt = _build_initial(_crypto(0, _hello("www.youtube.com")), dcid, 0)
    assert quic.QuicSni().add(pkt) == ("ok", "www.youtube.com")


def test_v2_sni():
    pkt = _build_initial(_crypto(0, _hello("github.com")), os.urandom(8), 1, quic.V2)
    assert quic.QuicSni().add(pkt) == ("ok", "github.com")


def test_hello_split_across_two_packets():
    dcid = os.urandom(8)
    hello = _hello("optimizationguide-pa.googleapis.com", pad=300)
    a, b = hello[:200], hello[200:]
    s = quic.QuicSni()
    assert s.add(_build_initial(_crypto(200, b), dcid, 1))[0] == "partial"   # out of order
    assert s.add(_build_initial(_crypto(0, a), dcid, 0)) == ("ok", "optimizationguide-pa.googleapis.com")


def test_garbage_is_ignored():
    assert quic.QuicSni().add(os.urandom(1200)) == ("no", None)
    assert quic.QuicSni().add(b"") == ("no", None)


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
