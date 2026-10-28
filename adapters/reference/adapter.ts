// The lab's own TypeScript implementation, exposed through the adapter protocol.

import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { decodeBackup, encodeBackup } from "../../src/backup.ts";
import { hex, unhex } from "../../src/crypto/hex.ts";
import { deriveFvk, PROFILES, type Profile } from "../../src/derive.ts";
import { commit, dealerKeygen, type Nonces, scalarBytes, scalarFrom, signShare, verifySpendAuth } from "../../src/frost.ts";

const rand = (n: number) => new Uint8Array(randomBytes(n));
const nonces = new Map<string, Nonces>(); // round-1 nonces by session/id, used once

function handle(req: any): Record<string, unknown> {
  switch (req.op) {
    case "hello":
      return { name: "reference", version: "0.1.0", ops: ["derive_fvk", "backup_encode", "backup_decode", "frost_keygen", "frost_commit", "frost_sign", "redpallas_verify"], profiles: [...PROFILES] };
    case "derive_fvk": {
      if (!PROFILES.includes(req.profile)) return { error: { code: "unsupported" } };
      const d = deriveFvk(req.profile as Profile, unhex(req.sk, 32), unhex(req.ak, 32));
      const out: Record<string, string> = { fvk: hex(d.fvk), nk: hex(d.nk), rivk: hex(d.rivk) };
      if (d.qsk) out.qsk = hex(d.qsk);
      if (d.qk) out.qk = hex(d.qk);
      return out;
    }
    case "backup_encode":
      return { string: encodeBackup(req.backup) };
    case "backup_decode": {
      const r = decodeBackup(req.string);
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
      const key = `${req.session}/${req.participant}`;
      const n = nonces.get(key);
      if (!n) return { error: { code: "invalid_input", message: "no round-1 nonces for this session and id" } };
      nonces.delete(key);
      const z = signShare({
        id: req.participant, share: scalarFrom(unhex(req.signing_share, 32)), nonces: n, groupKey: unhex(req.group_key, 32),
        alpha: scalarFrom(unhex(req.randomizer, 32)), message: unhex(req.message),
        commitments: req.commitments.map((c: any) => ({ id: c.id, hiding: unhex(c.hiding, 32), binding: unhex(c.binding, 32) })),
      });
      return { signature_share: hex(scalarBytes(z)) };
    }
    case "redpallas_verify":
      return { valid: verifySpendAuth(unhex(req.rk), unhex(req.message), unhex(req.signature)) };
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
