// A narrated run for demos: the derivation split, the lab catching bugs, then
// a FROST group split across implementations spending an Orchard note.

import { loadManifests } from "./adapter.ts";
import { hex, unhex } from "./crypto/hex.ts";
import { deriveFvk } from "./derive.ts";
import { runLab } from "./lab.ts";
import { AREA_LABEL } from "./report.ts";

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const mid = (h: string) => `${h.slice(0, 16)}…${h.slice(-8)}`;

console.log(bold("\n1. One FROST group, two different wallets\n"));
const sk = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const ak = unhex("262473baab7c8fbf24c39e0b2d2dd4736f7b74d7f3b6d32d1e8c62421368ad0e");
const legacy = deriveFvk("legacy", sk, ak);
const zip = deriveFvk("zip2005-use-qsk", sk, ak);
console.log(`   Same group key (ak) and shared sk, two derivations in use today:`);
console.log(`   legacy           rivk ${mid(hex(legacy.rivk))}   ${dim("(ZF zcash-sign generate)")}`);
console.log(`   ZIP 2005 use_qsk rivk ${mid(hex(zip.rivk))}   ${dim("(Zafe, Zkool's newest groups)")}`);
console.log(`   ${red("Different rivk → different viewing key → different address.")}`);
console.log(`   Restore with the wrong one and the wallet shows a zero balance.\n`);

console.log(bold("2. The lab: shared vectors + every pair on random inputs\n"));
const manifests = loadManifests();
const report = await runLab(manifests, { fuzzCases: 100, seed: "demo" });

for (const a of report.adapters) {
  if (!a.available) {
    console.log(`   ${a.name.padEnd(15)} ${dim(`not built: ${a.reason}`)}`);
    continue;
  }
  const cells = Object.entries(a.areas).map(([area, v]) =>
    v!.failed ? red(`✗ ${AREA_LABEL[area as keyof typeof AREA_LABEL]} ${v!.failed}/${v!.passed + v!.failed} failed`)
      : green(`✓ ${AREA_LABEL[area as keyof typeof AREA_LABEL]} ${v!.passed}`));
  console.log(`   ${a.name.padEnd(15)} ${cells.join("   ")}`);
}

console.log(bold("\n3. Who works with whom\n"));
for (const p of report.pairs.filter((p) => p.status !== "untested")) {
  const mark = p.status === "compatible" ? green("compatible  ") : red("INCOMPATIBLE");
  const detail = p.status === "compatible" ? dim(`${p.cases} random cases agree`) : p.why;
  console.log(`   ${mark} ${`${p.a} × ${p.b}`.padEnd(32)} ${AREA_LABEL[p.area].padEnd(34)} ${detail}`);
}

const broken = report.adapters.find((a) => a.name === "broken-example");
const firstBug = broken?.areas["derive:zip2005-use-qsk"]?.failures[0];
if (firstBug) {
  console.log(bold("\n4. What it caught in broken-example\n"));
  console.log(`   ZIP 2005 ${firstBug.field}: expected ${mid(firstBug.expected!)}, got ${mid(firstBug.got!)}`);
  console.log(`   ${dim("Bug: rivk reduced mod p (base field) instead of q (scalar field).")}`);
  const backup = broken!.areas.backup?.failures[0];
  if (backup) console.log(`   Backups: ${backup.case}: ${backup.got?.slice(0, 40)}…`);
  const signing = broken!.areas.signing?.failures ?? [];
  const badShare = signing.find((f) => f.case.startsWith("sign"));
  const malleable = signing.find((f) => f.case.includes("non-canonical"));
  if (badShare) console.log(`   Signing: ${badShare.note}`);
  console.log(`   ${dim("Bug: the signer ignores the randomizer α, so its share is for ak, not the spend's rk.")}`);
  if (malleable) console.log(`   Verifying: accepted a signature with S + q ${dim("(malleable: a second valid encoding)")}`);
}

if (report.spend) {
  console.log(bold("\n5. End to end: one FROST group, shares in different implementations, spends an Orchard note\n"));
  for (const st of report.spend.steps) console.log(`   ${st.ok ? green("✓") : red("✗")} ${st.step.padEnd(19)} ${st.detail}`);
  console.log(report.spend.ok
    ? green(`\n   The orchard crate accepts the transaction: Halo2 proof, the group's spend authorization and the binding signature.`)
    : red(`\n   The spend failed.`));
  console.log(dim(`   The note sits in a local commitment tree, so the bundle is valid but not broadcast.`));
}
console.log(`\n   Full report: ${bold("node src/cli.ts run")} → reports/report.html\n`);
