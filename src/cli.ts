#!/usr/bin/env node
// fil run   [--adapters a,b] [--fuzz N] [--seed S] [--out dir]   run the lab, write reports
// fil spend [--signers a,b] [--dealer d]                        a FROST group spends an Orchard note
// fil list                                                      list adapters
// Exit code: 0 when every tested pair is compatible and the end-to-end spend
// is valid, 1 otherwise (for CI).

import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { AdapterClient, loadManifests } from "./adapter.ts";
import { runLab } from "./lab.ts";
import { runSpend } from "./spend.ts";
import { toHtml, toMarkdown } from "./report.ts";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    adapters: { type: "string" },
    fuzz: { type: "string", default: "50" },
    seed: { type: "string" },
    out: { type: "string", default: "reports" },
    signers: { type: "string", default: "orchard-rust,python-stdlib,reference" },
    dealer: { type: "string", default: "python-stdlib" },
  },
});

const command = positionals[0] ?? "run";
let manifests = loadManifests();

if (command === "list") {
  for (const m of manifests) console.log(`${m.name.padEnd(18)} ${m.kind.padEnd(10)} ${m.description}`);
  process.exit(0);
}

if (command === "spend") {
  const open = (name: string) => {
    const m = manifests.find((x) => x.name === name);
    if (!m) throw new Error(`no adapter named ${name}`);
    return new AdapterClient(m);
  };
  const names = [...new Set(["orchard-rust", values.dealer!, ...values.signers!.split(",")])];
  const clients = new Map(names.map((n) => [n, open(n)]));
  const signers = values.signers!.split(",").map((n) => clients.get(n)!);
  const t = Math.max(2, signers.length);
  console.log(`\nA ${t}-of-${t + 1} FROST group with shares on ${values.signers!.split(",").join(", ")} spends an Orchard note.\n`);
  const r = await runSpend({ builder: clients.get("orchard-rust")!, dealer: clients.get(values.dealer!)!, signers, verifiers: [...clients.values()], t, n: t + 1 });
  for (const st of r.steps) console.log(`${st.ok ? "✓" : "✗"} ${st.step.padEnd(19)} ${st.detail}`);
  console.log(r.ok ? "\nValid: the orchard crate accepts the proof and every signature." : "\nThe spend failed.");
  for (const c of clients.values()) c.close();
  process.exit(r.ok ? 0 : 1);
}

if (command !== "run") {
  console.error("Usage: fil run [--adapters a,b] [--fuzz N] [--seed S] [--out dir] | fil spend [--signers a,b] [--dealer d] | fil list");
  process.exit(2);
}

if (values.adapters) {
  const wanted = values.adapters.split(",");
  manifests = manifests.filter((m) => wanted.includes(m.name));
}
const seed = values.seed ?? new Date().toISOString().slice(0, 10);
const fuzzCases = Number(values.fuzz);

const report = await runLab(manifests, { fuzzCases, seed });
const outDir = resolve(values.out!);
mkdirSync(outDir, { recursive: true });
writeFileSync(resolve(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
writeFileSync(resolve(outDir, "report.md"), toMarkdown(report));
writeFileSync(resolve(outDir, "report.html"), toHtml(report));

process.stdout.write(toMarkdown(report));
console.log(`\nWrote ${outDir}/report.{json,md,html}`);
process.exit(report.pairs.some((p) => p.status === "incompatible") || report.spend?.ok === false ? 1 : 0);
