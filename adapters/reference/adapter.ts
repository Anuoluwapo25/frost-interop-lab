// The lab's own TypeScript implementation, exposed through the adapter protocol.

import { createInterface } from "node:readline";
import { decodeBackup, encodeBackup } from "../../src/backup.ts";
import { hex, unhex } from "../../src/crypto/hex.ts";
import { deriveFvk, PROFILES, type Profile } from "../../src/derive.ts";

function handle(req: any): Record<string, unknown> {
  switch (req.op) {
    case "hello":
      return { name: "reference", version: "0.1.0", ops: ["derive_fvk", "backup_encode", "backup_decode"], profiles: [...PROFILES] };
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
