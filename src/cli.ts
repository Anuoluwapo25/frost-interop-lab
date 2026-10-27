#!/usr/bin/env node
// fil run   [--adapters a,b] [--fuzz N] [--seed S] [--out dir]   run the lab, write reports
// fil list                                                      list adapters
// Exit code: 0 when every tested pair is compatible, 1 otherwise (for CI).

import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadManifests } from "./adapter.ts";
import { runLab } from "./lab.ts";
import { toHtml, toMarkdown } from "./report.ts";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    adapters: { type: "string" },
    fuzz: { type: "string", default: "50" },
    seed: { type: "string" },
    out: { type: "string", default: "reports" },
  },
});

const command = positionals[0] ?? "run";
let manifests = loadManifests();

if (command === "list") {
  for (const m of manifests) console.log(`${m.name.padEnd(18)} ${m.kind.padEnd(10)} ${m.description}`);
  process.exit(0);
}

if (command !== "run") {
  console.error("Usage: fil run [--adapters a,b] [--fuzz N] [--seed S] [--out dir] | fil list");
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
process.exit(report.pairs.some((p) => p.status === "incompatible") ? 1 : 0);
