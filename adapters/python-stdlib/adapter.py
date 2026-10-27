#!/usr/bin/env python3
"""Independent Python implementation of the lab's ops, using only the standard library.

Key derivation follows Zafe's independent checker
(https://github.com/zafe-cash/zafe/blob/main/scripts/check_zip2005_vectors.py, Apache-2.0),
with the legacy profile added from the protocol spec. Bech32m follows the BIP 350
reference algorithm. It shares no code with the TypeScript reference adapter.
"""

import hashlib
import json
import sys

P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
Q = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001
QK_CONTEXT = "Zcash ZIP 2005 qk-derivation v1"


def prf_expand(key: bytes, t: bytes) -> bytes:
    return hashlib.blake2b(key + t, digest_size=64, person=b"Zcash_ExpandSeed").digest()


def le32(x: int) -> bytes:
    return x.to_bytes(32, "little")


def to_base(b: bytes) -> bytes:
    return le32(int.from_bytes(b, "little") % P)


def to_scalar(b: bytes) -> bytes:
    return le32(int.from_bytes(b, "little") % Q)


# --- Minimal BLAKE3, single chunk (from Zafe's checker) -------------------------------
_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, block_len, flags):
    m = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
    s = cv[:] + _IV[:4] + [0, 0, block_len, flags]
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1]); _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5]); _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9]); _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13]); _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _PERM]
    return [s[i] ^ s[i + 8] for i in range(8)]


def _single_chunk(key_words, data, mode):
    blocks = [data[i:i + 64] for i in range(0, len(data), 64)] or [b""]
    cv = key_words
    for i, block in enumerate(blocks):
        flags = mode | (1 if i == 0 else 0) | ((2 | 8) if i == len(blocks) - 1 else 0)
        cv = _compress(cv, block.ljust(64, b"\0"), len(block), flags)
    return b"".join(w.to_bytes(4, "little") for w in cv)


def blake3_derive_key(context: str, material: bytes) -> bytes:
    ctx = _single_chunk(_IV, context.encode(), 32)
    return _single_chunk([int.from_bytes(ctx[4 * i:4 * i + 4], "little") for i in range(8)], material, 64)


# --- Key derivation ---------------------------------------------------------------------

def derive_fvk(profile: str, sk: bytes, ak: bytes) -> dict:
    nk = to_base(prf_expand(sk, b"\x07"))
    if profile == "legacy":
        rivk = to_scalar(prf_expand(sk, b"\x08"))
        return {"fvk": (ak + nk + rivk).hex(), "nk": nk.hex(), "rivk": rivk.hex()}
    qsk = prf_expand(sk, b"\x0c")[:32]
    qk = blake3_derive_key(QK_CONTEXT, qsk)
    rivk = to_scalar(prf_expand(qk, b"\x0d" + ak + nk))
    return {"fvk": (ak + nk + rivk).hex(), "nk": nk.hex(), "rivk": rivk.hex(), "qsk": qsk.hex(), "qk": qk.hex()}


# --- Bech32m (BIP 350) -------------------------------------------------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32m_encode(hrp, payload):
    data = _convertbits(payload, 8, 5, True)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ BECH32M_CONST
    return hrp + "1" + "".join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def bech32m_decode(s):
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or any(c not in CHARSET for c in s[pos + 1:]):
        return None
    hrp, data = s[:pos], [CHARSET.find(c) for c in s[pos + 1:]]
    if _polymod(_hrp_expand(hrp) + data) != BECH32M_CONST:
        return None
    payload = _convertbits(data[:-6], 5, 8, False)
    return None if payload is None else (hrp, bytes(payload))


# --- zkfrost v1 backups -------------------------------------------------------------------

def backup_encode(b):
    payload = bytes([1, b["id"], b["t"], b["n"]]) + bytes.fromhex(b["share"]) + bytes.fromhex(b["sk"])
    if len(payload) != 68:
        raise ValueError("share and sk must be 32 bytes")
    return bech32m_encode("zkfrost", payload)


def backup_decode(s):
    d = bech32m_decode(s.strip())
    if d is None:
        return {"error": {"code": "not_bech32m"}}
    hrp, p = d
    if hrp != "zkfrost":
        return {"error": {"code": "wrong_hrp"}}
    if len(p) != 68:
        return {"error": {"code": "wrong_length"}}
    if p[0] != 1:
        return {"error": {"code": "unsupported_version"}}
    ident, t, n = p[1], p[2], p[3]
    if n == 0 or ident == 0 or ident > n or t == 0 or t > n:
        return {"error": {"code": "invalid_params"}}
    return {"backup": {"id": ident, "t": t, "n": n, "share": p[4:36].hex(), "sk": p[36:68].hex()}}


def handle(req):
    op = req.get("op")
    if op == "hello":
        return {"name": "python-stdlib", "version": "0.1.0",
                "ops": ["derive_fvk", "backup_encode", "backup_decode"], "profiles": ["legacy", "zip2005-use-qsk"]}
    if op == "derive_fvk":
        if req["profile"] not in ("legacy", "zip2005-use-qsk"):
            return {"error": {"code": "unsupported"}}
        return derive_fvk(req["profile"], bytes.fromhex(req["sk"]), bytes.fromhex(req["ak"]))
    if op == "backup_encode":
        return {"string": backup_encode(req["backup"])}
    if op == "backup_decode":
        return backup_decode(req["string"])
    return {"error": {"code": "unsupported"}}


def main():
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        try:
            res = handle(req)
        except Exception as e:  # report, don't crash the session
            res = {"error": {"code": "invalid_input", "message": str(e)}}
        sys.stdout.write(json.dumps({"id": req.get("id"), **res}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
