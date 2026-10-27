import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { blake2b } from "../src/crypto/blake2b.ts";
import { blake3DeriveKey, blake3Hash } from "../src/crypto/blake3.ts";
import { bech32mDecode, bech32mEncode } from "../src/crypto/bech32m.ts";
import { hex, unhex } from "../src/crypto/hex.ts";
import { isValidAkEncoding } from "../src/crypto/pallas.ts";
import { deriveFvk } from "../src/derive.ts";

const enc = (s: string) => new TextEncoder().encode(s);

// Expected values from Python's hashlib.blake2b.
test("BLAKE2b matches hashlib, with and without personalization", () => {
  assert.equal(hex(blake2b(enc("abc"))),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  const data = Uint8Array.from({ length: 200 }, (_, i) => i);
  assert.equal(hex(blake2b(data, 64, enc("Zcash_ExpandSeed"))),
    "0314113573ef2c3d7aa4ae6c68608509309f744d66af41e78cf4e760456fd3145875e8313eac60d31139147ea1775dd8a9c15e9965685777110006d56eead761");
  assert.equal(hex(blake2b(new Uint8Array(0), 32, enc("ZcashTestPerson!"))),
    "b671e23e6377f8b323b3443db73a5b5df8c5b9093b3fe321b86ed948031e2587");
  assert.equal(hex(blake2b(Uint8Array.from({ length: 128 }, (_, i) => i))),
    "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115");
});

test("BLAKE3 official vectors: empty hash", () => {
  assert.equal(hex(blake3Hash(new Uint8Array(0))), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  assert.equal(blake3DeriveKey("ctx", new Uint8Array(0)).length, 32);
});

test("bech32m: BIP 350 valid strings decode, corrupted ones don't", () => {
  for (const s of ["A1LQFN3A", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"]) {
    assert.ok(!("error" in bech32mDecode(s)), s);
  }
  assert.deepEqual(bech32mDecode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryy"), { error: "bad_checksum" });
  assert.deepEqual(bech32mDecode("A1LqFN3A"), { error: "mixed_case" });
  const bytes = Uint8Array.from({ length: 68 }, (_, i) => i * 3);
  const s = bech32mEncode("zkfrost", bytes);
  const d = bech32mDecode(s);
  assert.ok("bytes" in d && hex(d.bytes) === hex(bytes));
});

test("legacy derivation matches the official Orchard key vectors", () => {
  const suite = JSON.parse(readFileSync(new URL("../vectors/derive_legacy.json", import.meta.url), "utf8"));
  for (const v of suite.vectors) {
    const d = deriveFvk("legacy", unhex(v.sk), unhex(v.ak));
    assert.equal(hex(d.nk), v.nk);
    assert.equal(hex(d.rivk), v.rivk);
    assert.equal(hex(d.fvk), v.fvk);
    assert.ok(isValidAkEncoding(unhex(v.ak)));
  }
});

test("ZIP 2005 use_qsk derivation matches the frost-tools#610 vectors", () => {
  const suite = JSON.parse(readFileSync(new URL("../vectors/derive_zip2005_use_qsk.json", import.meta.url), "utf8"));
  for (const v of suite.vectors) {
    const d = deriveFvk("zip2005-use-qsk", unhex(v.sk), unhex(v.ak));
    assert.equal(hex(d.qsk!), v.qsk);
    assert.equal(hex(d.qk!), v.qk);
    assert.equal(hex(d.rivk), v.rivk);
    assert.equal(hex(d.fvk), v.fvk);
  }
});

test("the two profiles agree on nk but give a different rivk for the same group", () => {
  const sk = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const ak = unhex("262473baab7c8fbf24c39e0b2d2dd4736f7b74d7f3b6d32d1e8c62421368ad0e");
  const a = deriveFvk("legacy", sk, ak);
  const b = deriveFvk("zip2005-use-qsk", sk, ak);
  assert.equal(hex(a.nk), hex(b.nk));
  assert.notEqual(hex(a.rivk), hex(b.rivk));
});
