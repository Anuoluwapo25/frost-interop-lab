// A deliberately broken implementation, to show what the lab catches.
// It has two realistic bugs:
//   1. ZIP 2005: reduces rivk modulo the base field p instead of the scalar
//      field q (ToBase instead of ToScalar). An easy slip: both are 255-bit
//      Pallas fields and the code reads almost the same. The address changes.
//   2. Backups: forgets to check that the participant id is at most n.

import { createInterface } from "node:readline";
import { decodeBackup, encodeBackup } from "../../src/backup.ts";
import { bech32mDecode } from "../../src/crypto/bech32m.ts";
import { blake3DeriveKey } from "../../src/crypto/blake3.ts";
import { concat, hex, unhex } from "../../src/crypto/hex.ts";
import { toBase } from "../../src/crypto/pallas.ts";
import { deriveFvk, prfExpand, QK_CONTEXT } from "../../src/derive.ts";

function zip2005Buggy(sk: Uint8Array, ak: Uint8Array) {
  const nk = toBase(prfExpand(sk, Uint8Array.of(0x07)));
  const qk = blake3DeriveKey(QK_CONTEXT, prfExpand(sk, Uint8Array.of(0x0c)).slice(0, 32));
  const rivk = toBase(prfExpand(qk, concat(Uint8Array.of(0x0d), ak, nk))); // bug 1
  return { fvk: hex(concat(ak, nk, rivk)), nk: hex(nk), rivk: hex(rivk) };
}

function handle(req: any): Record<string, unknown> {
  switch (req.op) {
    case "hello":
      return { name: "broken-example", version: "0.0.1", ops: ["derive_fvk", "backup_encode", "backup_decode"], profiles: ["legacy", "zip2005-use-qsk"] };
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
