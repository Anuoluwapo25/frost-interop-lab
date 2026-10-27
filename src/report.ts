// Renders a lab report as Markdown (for PRs and issues) and as a standalone
// HTML compatibility matrix.

import { AREAS, type Area, type PairResult, type Report } from "./lab.ts";

export const AREA_LABEL: Record<Area, string> = {
  "derive:legacy": "Key derivation (legacy)",
  "derive:zip2005-use-qsk": "Key derivation (ZIP 2005 use_qsk)",
  backup: "zkfrost v1 backups",
};

// Long hex values are shortened to their ends; other text is kept whole up to a limit.
const short = (s?: string) => {
  if (!s) return "";
  if (/^[0-9a-f]{25,}$/i.test(s)) return `${s.slice(0, 12)}…${s.slice(-8)}`;
  return s.length > 120 ? `${s.slice(0, 117)}…` : s;
};

function pairFor(r: Report, a: string, b: string, area: Area): PairResult | undefined {
  return r.pairs.find((p) => p.area === area && ((p.a === a && p.b === b) || (p.a === b && p.b === a)));
}

export function toMarkdown(r: Report): string {
  const lines: string[] = [];
  lines.push(`# FROST Interop Lab report`, "");
  lines.push(`${r.generatedAt} · seed \`${r.seed}\` · ${r.fuzzCases} random cases per area`, "");
  lines.push(`## Conformance to the shared vectors`, "");
  lines.push(`| Adapter | Kind | ${AREAS.map((a) => AREA_LABEL[a]).join(" | ")} |`);
  lines.push(`| --- | --- | ${AREAS.map(() => "---").join(" | ")} |`);
  for (const a of r.adapters) {
    const cells = AREAS.map((area) => {
      if (!a.available) return "unavailable";
      const v = a.areas[area];
      if (!v) return "not supported";
      return v.failed ? `**${v.failed} failed** / ${v.passed + v.failed}` : `pass (${v.passed})`;
    });
    lines.push(`| ${a.name} | ${a.kind} | ${cells.join(" | ")} |`);
  }
  const unavailable = r.adapters.filter((a) => !a.available);
  if (unavailable.length) {
    lines.push("", ...unavailable.map((a) => `- ${a.name} unavailable: ${a.reason}`));
  }
  lines.push("", `## Pairwise compatibility`, "");
  lines.push(`| Pair | ${AREAS.map((a) => AREA_LABEL[a]).join(" | ")} |`);
  lines.push(`| --- | ${AREAS.map(() => "---").join(" | ")} |`);
  const names = r.adapters.map((a) => a.name);
  for (let x = 0; x < names.length; x++) {
    for (let y = x + 1; y < names.length; y++) {
      const cells = AREAS.map((area) => {
        const p = pairFor(r, names[x], names[y], area);
        if (!p || p.status === "untested") return "–";
        return p.status === "compatible" ? `compatible (${p.cases})` : `**incompatible**: ${p.why}`;
      });
      lines.push(`| ${names[x]} × ${names[y]} | ${cells.join(" | ")} |`);
    }
  }
  const failures = r.adapters.flatMap((a) =>
    Object.entries(a.areas).flatMap(([area, v]) => v!.failures.slice(0, 3).map((f) => ({ a: a.name, area, f }))));
  if (failures.length) {
    lines.push("", `## First failures`, "");
    for (const { a, area, f } of failures) {
      const detail = f.note ?? `${f.field ? f.field + ": " : ""}expected \`${short(f.expected)}\`, got \`${short(f.got)}\``;
      lines.push(`- **${a}**, ${AREA_LABEL[area as Area]}, ${f.case}: ${detail}`);
    }
  }
  return lines.join("\n") + "\n";
}

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

export function toHtml(r: Report): string {
  const names = r.adapters.map((a) => a.name);
  const cell = (a: string, b: string) => {
    if (a === b) return `<td class="self"></td>`;
    const parts = AREAS.map((area) => {
      const p = pairFor(r, a, b, area);
      const st = p?.status ?? "untested";
      const title = p?.why ?? (st === "compatible" ? `${p?.cases} random cases agree` : "");
      const sym = st === "compatible" ? "✓" : st === "incompatible" ? "✗" : "–";
      return `<span class="m ${st}" title="${esc(AREA_LABEL[area])}: ${esc(title)}">${sym}</span>`;
    });
    return `<td>${parts.join("")}</td>`;
  };
  const conf = r.adapters.map((a) => `<tr><th scope="row">${esc(a.name)}<small>${esc(a.kind)}${a.version ? ` · ${esc(a.version)}` : ""}</small></th>${AREAS.map((area) => {
    if (!a.available) return `<td class="untested">unavailable</td>`;
    const v = a.areas[area];
    if (!v) return `<td class="untested">not supported</td>`;
    return v.failed ? `<td class="incompatible">${v.failed} of ${v.passed + v.failed} failed</td>` : `<td class="compatible">pass · ${v.passed}</td>`;
  }).join("")}</tr>`).join("");
  const failures = r.adapters.flatMap((a) => Object.entries(a.areas).flatMap(([area, v]) =>
    v!.failures.slice(0, 3).map((f) => `<li><strong>${esc(a.name)}</strong> · ${esc(AREA_LABEL[area as Area])} · ${esc(f.case)}: ${
      f.note ? esc(f.note) : `${f.field ? esc(f.field) + " " : ""}expected <code>${esc(short(f.expected))}</code>, got <code>${esc(short(f.got))}</code>`}</li>`)));
  const mismatches = r.pairs.filter((p) => p.status === "incompatible" && p.example).map((p) =>
    `<li><strong>${esc(p.a)} × ${esc(p.b)}</strong> · ${esc(AREA_LABEL[p.area])}: ${esc(p.why)}${p.example?.field ? ` (first: ${esc(p.example.field)})` : ""}</li>`);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FROST Interop Lab report</title>
<style>
:root{--bg:#f7f7f5;--fg:#1c1d1f;--muted:#66696f;--line:#e2e1dc;--card:#fff;--ok:#1f7a4d;--okbg:#e2f2e8;--bad:#b3261e;--badbg:#fbe3e1}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ecebe6;--muted:#9da1a7;--line:#2f3236;--card:#1c1e21;--ok:#6fcf97;--okbg:#1d3326;--bad:#f28b82;--badbg:#3d2120}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 64px}h1{margin:0 0 4px;font-size:24px}h2{font-size:17px;margin:0 0 12px}
.sub{color:var(--muted);margin:0 0 20px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px;overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{padding:8px 10px;border-top:1px solid var(--line);text-align:left;vertical-align:middle}thead th{border-top:0;color:var(--muted);font-size:13px}
th small{display:block;color:var(--muted);font-weight:400;font-size:12px}td.compatible{color:var(--ok)}td.incompatible{color:var(--bad);font-weight:600}td.untested{color:var(--muted)}td.self{background:var(--bg)}
.m{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:6px;margin-right:4px;font-weight:700}.m.compatible{background:var(--okbg);color:var(--ok)}.m.incompatible{background:var(--badbg);color:var(--bad)}.m.untested{color:var(--muted);border:1px solid var(--line)}
.legend{color:var(--muted);font-size:13px;margin-top:10px}code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}ul{margin:0;padding-left:18px}li{margin:4px 0}
</style></head><body><main>
<h1>Which Zcash FROST implementations work together</h1>
<p class="sub">FROST Interop Lab · ${esc(r.generatedAt)} · seed <code>${esc(r.seed)}</code> · ${r.fuzzCases} random cases per area</p>
<div class="card"><h2>Pairwise compatibility</h2>
<table><thead><tr><th></th>${names.map((n) => `<th>${esc(n)}</th>`).join("")}</tr></thead>
<tbody>${names.map((a) => `<tr><th scope="row">${esc(a)}</th>${names.map((b) => cell(a, b)).join("")}</tr>`).join("")}</tbody></table>
<p class="legend">Each cell: ${AREAS.map((a, i) => `${i + 1}. ${esc(AREA_LABEL[a])}`).join(" · ")}. ✓ agree on the shared vectors and on every random case · ✗ disagree · – not tested by both. Hover for details.</p></div>
<div class="card"><h2>Conformance to the shared vectors</h2>
<table><thead><tr><th>Adapter</th>${AREAS.map((a) => `<th>${esc(AREA_LABEL[a])}</th>`).join("")}</tr></thead><tbody>${conf}</tbody></table></div>
${failures.length || mismatches.length ? `<div class="card"><h2>What broke</h2><ul>${[...failures, ...mismatches].join("")}</ul></div>` : ""}
</main></body></html>
`;
}
