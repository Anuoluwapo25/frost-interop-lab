import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { AdapterClient, loadManifests } from "../src/adapter.ts";
import { hex, unhex } from "../src/crypto/hex.ts";
import { add, encodePoint, equal, IDENTITY, leToBig, modQ, mul, Q, SPENDAUTH_G } from "../src/crypto/pallas.ts";
import { aggregate, commit, dealerKeygen, scalarBytes, signShare, verifySpendAuth } from "../src/frost.ts";
import { keygen, signRound } from "../src/signing.ts";
import { runSpend } from "../src/spend.ts";

const rand = (n: number) => new Uint8Array(randomBytes(n));
const randomScalar = () => modQ(leToBig(rand(64)));

test("pallas: group law and the SpendAuth basepoint", () => {
  const G = SPENDAUTH_G;
  assert.equal(hex(encodePoint(G)), "63c975b884721a8d0ca1707be30c7f0c5f445f3e7c188d3b06d6f128b32355b7");
  assert.ok(equal(mul(G, 5n), add(mul(G, 2n), mul(G, 3n))));
  assert.ok(equal(mul(G, Q), IDENTITY));
});

test("frost: a 3-of-5 rerandomized signature verifies under rk and only there", () => {
  const k = dealerKeygen(3, 5, rand);
  assert.equal(k.groupKey[31] & 0x80, 0, "group key must have even y");
  const signers = [k.shares[1], k.shares[3], k.shares[4]];
  const alpha = randomScalar(), message = rand(32);
  const nonces = signers.map((s) => commit(s.id, s.share, rand));
  const commitments = nonces.map((n) => n.commitment);
  const shares = signers.map((s, i) => ({
    id: s.id, verifyingShare: k.verifyingShares[s.id - 1].key,
    z: signShare({ id: s.id, share: s.share, nonces: nonces[i], groupKey: k.groupKey, alpha, message, commitments }),
  }));
  const a = aggregate({ groupKey: k.groupKey, alpha, message, commitments, shares });
  assert.deepEqual(a.badSigners, []);
  assert.ok(verifySpendAuth(a.rk, message, a.signature));
  assert.ok(!verifySpendAuth(k.groupKey, message, a.signature), "must not verify under the unrandomized key");

  // A share computed without α is caught and blamed.
  const bad = [...shares];
  bad[1] = { ...bad[1], z: signShare({ id: signers[1].id, share: signers[1].share, nonces: nonces[1], groupKey: k.groupKey, alpha: 0n, message, commitments }) };
  assert.deepEqual(aggregate({ groupKey: k.groupKey, alpha, message, commitments, shares: bad }).badSigners, [signers[1].id]);
});

test("redpallas: the lab verifier matches the orchard crate on every shared vector", () => {
  const { vectors } = JSON.parse(readFileSync(new URL("../vectors/redpallas_spendauth.json", import.meta.url), "utf8"));
  for (const v of vectors) assert.equal(verifySpendAuth(unhex(v.rk), unhex(v.message), unhex(v.signature)), v.valid, v.why);
});

const rustManifest = loadManifests().find((m) => m.name === "orchard-rust");

test("mixed groups: ZF's Rust FROST and the TypeScript signer sign together", async (t) => {
  const rust = new AdapterClient(rustManifest!), ts = new AdapterClient(loadManifests().find((m) => m.name === "reference")!);
  try {
    if ((await rust.request("hello")).error) return t.skip("orchard-rust adapter not built");
    for (const dealer of [rust, ts]) {
      const g = await keygen(dealer, 2, 3);
      assert.ok(!("error" in g));
      const r = await signRound({ group: g, signers: new Map([[1, rust], [3, ts]]), message: rand(32), alpha: scalarBytes(randomScalar()), verifiers: [rust, ts] });
      assert.ok(r.ok, r.problem);
      assert.deepEqual(r.verdicts, { lab: true, "orchard-rust": true, reference: true });
    }
  } finally {
    rust.close();
    ts.close();
  }
});

test("end to end: the group spends an Orchard note; a wrong signature is rejected", async (t) => {
  const rust = new AdapterClient(rustManifest!), ts = new AdapterClient(loadManifests().find((m) => m.name === "reference")!);
  try {
    if ((await rust.request("hello")).error) return t.skip("orchard-rust adapter not built");
    const r = await runSpend({ builder: rust, dealer: ts, signers: [rust, ts], verifiers: [rust, ts] });
    assert.ok(r.ok, JSON.stringify(r.steps.filter((s) => !s.ok)));

    // Negative control: a valid group signature over a different message.
    const g = await keygen(ts, 2, 3);
    assert.ok(!("error" in g));
    const sk = hex(rand(32));
    const prep = await rust.request("orchard_spend_prepare", { session: "neg", profile: "legacy", sk, ak: g.group_key }, 120_000);
    const wrong = await signRound({ group: g, signers: new Map([[1, rust], [2, ts]]), message: rand(32), alpha: unhex(String(prep.randomizer)), verifiers: [] });
    assert.ok(wrong.ok);
    const fin = await rust.request("orchard_spend_finish", { session: "neg", signature: wrong.signature }, 120_000);
    assert.equal(fin.valid, false);
  } finally {
    rust.close();
    ts.close();
  }
});
