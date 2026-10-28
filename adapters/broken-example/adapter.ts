// A deliberately broken implementation, to show what the lab catches.
// It has four realistic bugs:
//   1. ZIP 2005: reduces rivk modulo the base field p instead of the scalar
//      field q (ToBase instead of ToScalar). An easy slip: both are 255-bit
//      Pallas fields and the code reads almost the same. The address changes.
//   2. Backups: forgets to check that the participant id is at most n.
//   3. FROST signing: ignores the randomizer α, so its share is computed for
//      the group key ak instead of the randomized rk an Orchard spend uses.
//   4. RedPallas verification: reduces S mod q instead of rejecting S >= q,
//      accepting a second encoding of every signature (malleability).

import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { decodeBackup, encodeBackup } from "../../src/backup.ts";
import { bech32mDecode } from "../../src/crypto/bech32m.ts";
import { blake3DeriveKey } from "../../src/crypto/blake3.ts";
import { concat, hex, unhex } from "../../src/crypto/hex.ts";
import { bigToLe32, leToBig, Q, toBase } from "../../src/crypto/pallas.ts";
import { deriveFvk, prfExpand, QK_CONTEXT } from "../../src/derive.ts";
import { commit, dealerKeygen, type Nonces, scalarBytes, scalarFrom, signShare, verifySpendAuth } from "../../src/frost.ts";

const rand = (n: number) => new Uint8Array(randomBytes(n));
const nonces = new Map<string, Nonces>();

function zip2005Buggy(sk: Uint8Array, ak: Uint8Array) {
  const nk = toBase(prfExpand(sk, Uint8Array.of(0x07)));
  const qk = blake3DeriveKey(QK_CONTEXT, prfExpand(sk, Uint8Array.of(0x0c)).slice(0, 32));
  const rivk = toBase(prfExpand(qk, concat(Uint8Array.of(0x0d), ak, nk))); // bug 1
  return { fvk: hex(concat(ak, nk, rivk)), nk: hex(nk), rivk: hex(rivk) };
}

function handle(req: any): Record<string, unknown> {
  switch (req.op) {
    case "hello":
      return { name: "broken-example", version: "0.0.1", ops: ["derive_fvk", "backup_encode", "backup_decode", "frost_keygen", "frost_commit", "frost_sign", "redpallas_verify"], profiles: ["legacy", "zip2005-use-qsk"] };
    case "derive_fvk": {
      const sk = unhex(req.sk, 32), ak = unhex(req.ak, 32);
      if (req.profile === "zip2005-use-qsk") return zip2005Buggy(sk, ak);
      const d = deriveFvk("legacy", sk, ak);
      return { fvk: hex(d.fvk), nk: hex(d.nk), rivk: hex(d.rivk) };
    }
    case "backup_encode":
      return { string: encodeBackup(req.backup) };
    case "backup_decode": {
      const r = decodeBackup(req.string);
      if ("error" in r && r.error === "invalid_params") {
        // bug 2: only the threshold and group size are checked
        const d = bech32mDecode(req.string.trim());
        if ("bytes" in d) {
          const [id, t, n] = [d.bytes[1], d.bytes[2], d.bytes[3]];
          if (n > 0 && t > 0 && t <= n) {
            return { backup: { id, t, n, share: hex(d.bytes.slice(4, 36)), sk: hex(d.bytes.slice(36, 68)) } };
          }
        }
      }
      return "error" in r ? { error: { code: r.error } } : { backup: r.backup };
    }
    case "frost_keygen": {
      const k = dealerKeygen(req.t, req.n, rand);
      return {
        group_key: hex(k.groupKey),
        shares: k.shares.map((s, i) => ({ id: s.id, signing_share: hex(scalarBytes(s.share)), verifying_share: hex(k.verifyingShares[i].key) })),
      };
    }
    case "frost_commit": {
      const n = commit(req.participant, scalarFrom(unhex(req.signing_share, 32)), rand);
      nonces.set(`${req.session}/${req.participant}`, n);
      return { hiding: hex(n.commitment.hiding), binding: hex(n.commitment.binding) };
    }
    case "frost_sign": {
      const n = nonces.get(`${req.session}/${req.participant}`)!;
      const z = signShare({
        id: req.participant, share: scalarFrom(unhex(req.signing_share, 32)), nonces: n, groupKey: unhex(req.group_key, 32),
        alpha: 0n, // bug 3: the randomizer is ignored
        message: unhex(req.message),
        commitments: req.commitments.map((c: any) => ({ id: c.id, hiding: unhex(c.hiding, 32), binding: unhex(c.binding, 32) })),
      });
      return { signature_share: hex(scalarBytes(z)) };
    }
    case "redpallas_verify": {
      const sig = unhex(req.signature);
      if (sig.length === 64) sig.set(bigToLe32(leToBig(sig.subarray(32)) % Q), 32); // bug 4: S >= q accepted
      return { valid: verifySpendAuth(unhex(req.rk), unhex(req.message), sig) };
    }
    default:
      return { error: { code: "unsupported" } };
  }
}

createInterface({ input: process.stdin }).on("line", (line) => {
  let req: any;
  try {
    req = JSON.parse(line);
  } catch {
    return;
  }
  let res: Record<string, unknown>;
  try {
    res = handle(req);
  } catch (e) {
    res = { error: { code: "invalid_input", message: (e as Error).message } };
  }
  process.stdout.write(JSON.stringify({ id: req.id, ...res }) + "\n");
});
