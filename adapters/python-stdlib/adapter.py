#!/usr/bin/env python3
"""Independent Python implementation of the lab's ops, using only the standard library.

FROST signing implements FROST(Pallas, BLAKE2b-512) with re-randomization from
RFC 9591 and the hash definitions in ZF's reddsa crate, with affine point
arithmetic written here. Key derivation follows Zafe's independent checker
(https://github.com/zafe-cash/zafe/blob/main/scripts/check_zip2005_vectors.py, Apache-2.0),
with the legacy profile added from the protocol spec. Bech32m follows the BIP 350
reference algorithm. It shares no code with the TypeScript reference adapter.
"""

import hashlib
import json
import secrets
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


# --- Pallas points (affine; None is the identity) and FROST(Pallas, BLAKE2b-512) -------

def _sqrt(a):
    """Tonelli-Shanks mod P, or None if a is not a square."""
    if a == 0:
        return 0
    if pow(a, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = next(z for z in range(2, 100) if pow(z, (P - 1) // 2, P) == P - 1)
    m, c, t, r = s, pow(z, q, P), pow(a, q, P), pow(a, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % P, i + 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    return r


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pt_mul(pt, k):
    if pt is G:
        return _mul_g(k)
    acc = None
    for bit in bin(k % Q)[2:]:
        acc = pt_add(acc, acc)
        if bit == "1":
            acc = pt_add(acc, pt)
    return acc


def pt_encode(pt):
    if pt is None:
        return bytes(32)
    x, y = pt
    b = bytearray(le32(x))
    b[31] |= (y & 1) << 7
    return bytes(b)


def pt_decode(b):
    if len(b) != 32:
        raise ValueError("point must be 32 bytes")
    sign, x = b[31] >> 7, int.from_bytes(b, "little") & ((1 << 255) - 1)
    y = _sqrt((x ** 3 + 5) % P) if x < P else None
    if y is None or (x == 0 and sign == 0):
        raise ValueError("invalid point")
    return (x, y if y & 1 == sign else P - y)


G = pt_decode(bytes.fromhex("63c975b884721a8d0ca1707be30c7f0c5f445f3e7c188d3b06d6f128b32355b7"))
_G_TABLE = [G]  # [2^i]G, so multiplying G needs additions only
for _ in range(254):
    _G_TABLE.append(pt_add(_G_TABLE[-1], _G_TABLE[-1]))


def _mul_g(k):
    acc, k, i = None, k % Q, 0
    while k:
        if k & 1:
            acc = pt_add(acc, _G_TABLE[i])
        k, i = k >> 1, i + 1
    return acc


def _h(person, data):
    return hashlib.blake2b(data, digest_size=64, person=person).digest()


def _hs(person, data):
    return int.from_bytes(_h(person, data), "little") % Q


def scalar(hexstr):
    s = int.from_bytes(bytes.fromhex(hexstr), "little")
    if len(hexstr) != 64 or s >= Q:
        raise ValueError("not a canonical scalar")
    return s


def frost_keygen(t, n):
    coeffs = [secrets.randbelow(Q) for _ in range(t)]
    shares = {i: sum(c * pow(i, k, Q) for k, c in enumerate(coeffs)) % Q for i in range(1, n + 1)}
    if pt_mul(G, coeffs[0])[1] & 1:  # Orchard needs an even-y ak: negate everything
        coeffs[0], shares = Q - coeffs[0], {i: (Q - v) % Q for i, v in shares.items()}
    return {"group_key": pt_encode(pt_mul(G, coeffs[0])).hex(),
            "shares": [{"id": i, "signing_share": le32(v).hex(), "verifying_share": pt_encode(pt_mul(G, v)).hex()}
                       for i, v in shares.items()]}


NONCES = {}


def frost_commit(req):
    share = le32(scalar(req["signing_share"]))
    d = _hs(b"FROST_RedPallasN", secrets.token_bytes(32) + share)
    e = _hs(b"FROST_RedPallasN", secrets.token_bytes(32) + share)
    NONCES[(req["session"], req["participant"])] = (d, e)
    return {"hiding": pt_encode(pt_mul(G, d)).hex(), "binding": pt_encode(pt_mul(G, e)).hex()}


def frost_sign(req):
    d, e = NONCES.pop((req["session"], req["participant"]))
    me, alpha = req["participant"], scalar(req["randomizer"])
    msg = bytes.fromhex(req["message"])
    coms = sorted(req["commitments"], key=lambda c: c["id"])
    rk = pt_add(pt_decode(bytes.fromhex(req["group_key"])), pt_mul(G, alpha))
    enc_list = b"".join(le32(c["id"]) + bytes.fromhex(c["hiding"]) + bytes.fromhex(c["binding"]) for c in coms)
    prefix = pt_encode(rk) + _h(b"FROST_RedPallasM", msg) + _h(b"FROST_RedPallasC", enc_list)
    rho = {c["id"]: _hs(b"FROST_RedPallasR", prefix + le32(c["id"])) for c in coms}
    R = None
    for c in coms:
        R = pt_add(R, pt_add(pt_decode(bytes.fromhex(c["hiding"])), pt_mul(pt_decode(bytes.fromhex(c["binding"])), rho[c["id"]])))
    chal = _hs(b"Zcash_RedPallasH", pt_encode(R) + pt_encode(rk) + msg)
    lam = 1
    for c in coms:
        if c["id"] != me:
            lam = lam * c["id"] * pow(c["id"] - me, -1, Q) % Q
    z = (d + e * rho[me] + lam * (scalar(req["signing_share"]) + alpha) * chal) % Q
    return {"signature_share": le32(z).hex()}


def redpallas_verify(req):
    sig, msg = bytes.fromhex(req["signature"]), bytes.fromhex(req["message"])
    try:
        rk, R = pt_decode(bytes.fromhex(req["rk"])), pt_decode(sig[:32])
    except ValueError:
        return {"valid": False}
    S = int.from_bytes(sig[32:], "little")
    if len(sig) != 64 or S >= Q:
        return {"valid": False}
    chal = _hs(b"Zcash_RedPallasH", sig[:32] + pt_encode(rk) + msg)
    return {"valid": pt_mul(G, S) == pt_add(R, pt_mul(rk, chal))}


def handle(req):
    op = req.get("op")
    if op == "hello":
        return {"name": "python-stdlib", "version": "0.1.0",
                "ops": ["derive_fvk", "backup_encode", "backup_decode", "frost_keygen", "frost_commit", "frost_sign",
                        "redpallas_verify"], "profiles": ["legacy", "zip2005-use-qsk"]}
    if op == "derive_fvk":
        if req["profile"] not in ("legacy", "zip2005-use-qsk"):
            return {"error": {"code": "unsupported"}}
        return derive_fvk(req["profile"], bytes.fromhex(req["sk"]), bytes.fromhex(req["ak"]))
    if op == "backup_encode":
        return {"string": backup_encode(req["backup"])}
    if op == "backup_decode":
        return backup_decode(req["string"])
    if op == "frost_keygen":
        return frost_keygen(req["t"], req["n"])
    if op == "frost_commit":
        return frost_commit(req)
    if op == "frost_sign":
        return frost_sign(req)
    if op == "redpallas_verify":
        return redpallas_verify(req)
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
