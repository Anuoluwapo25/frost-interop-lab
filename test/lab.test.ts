import { test } from "node:test";
import assert from "node:assert/strict";
import { loadManifests } from "../src/adapter.ts";
import { runLab } from "../src/lab.ts";
import { decodeBackup, encodeBackup } from "../src/backup.ts";
import { toHtml, toMarkdown } from "../src/report.ts";

test("backup vectors: encode/decode round trip and Zkool's rejection rules", () => {
  const b = { id: 2, t: 2, n: 3, share: "11".repeat(32), sk: "22".repeat(32) };
  const s = encodeBackup(b);
  assert.ok(s.startsWith("zkfrost1"));
  assert.deepEqual(decodeBackup(s), { backup: b });
  assert.deepEqual(decodeBackup(`  ${s.toUpperCase()}\n`), { backup: b });
  assert.deepEqual(decodeBackup(encodeBackup({ ...b, id: 4 })), { error: "invalid_params" });
});

test("lab: independent implementations agree, the broken example is caught", async () => {
  const manifests = loadManifests().filter((m) => ["reference", "python-stdlib", "broken-example", "orchard-rust"].includes(m.name));
  const report = await runLab(manifests, { fuzzCases: 6, seed: "test" });
  const pair = (a: string, b: string, area: string) =>
    report.pairs.find((p) => p.area === area && ((p.a === a && p.b === b) || (p.a === b && p.b === a)))!;

  for (const area of ["derive:legacy", "derive:zip2005-use-qsk", "backup"]) {
    assert.equal(pair("python-stdlib", "reference", area).status, "compatible", area);
  }
  assert.equal(pair("broken-example", "reference", "derive:legacy").status, "compatible");
  assert.equal(pair("broken-example", "reference", "derive:zip2005-use-qsk").status, "incompatible");
  assert.equal(pair("broken-example", "reference", "backup").status, "incompatible");

  const broken = report.adapters.find((a) => a.name === "broken-example")!;
  assert.equal(broken.areas["derive:zip2005-use-qsk"]!.failed, 8);
  assert.ok(broken.areas.backup!.failures.some((f) => f.case === "reject: participant id > n"));
  assert.equal(pair("broken-example", "reference", "signing").status, "incompatible");
  assert.ok(broken.areas.signing!.failures.some((f) => f.case.includes("non-canonical")));
  assert.ok(broken.areas.signing!.failures.some((f) => /invalid signature share from broken-example/.test(f.note ?? "")));
  assert.equal(report.adapters.find((a) => a.name === "reference")!.areas.signing!.failed, 0);

  // An adapter that isn't built is reported, not fatal.
  const rust = report.adapters.find((a) => a.name === "orchard-rust");
  if (rust && !rust.available) assert.match(rust.reason!, /cargo build/);
  if (rust?.available) {
    assert.equal(pair("orchard-rust", "reference", "signing").status, "compatible");
    assert.ok(report.spend?.ok, JSON.stringify(report.spend?.steps));
  }

  assert.match(toMarkdown(report), /Pairwise compatibility/);
  assert.match(toHtml(report), /<table>/);
});
