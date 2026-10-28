// Runs every suite against every adapter, then compares adapters with each
// other on random inputs (differential testing), and returns one report.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AdapterClient, type Hello, type Manifest, type Response } from "./adapter.ts";
import { hex } from "./crypto/hex.ts";
import { isOnCurveX, leToBig, modQ } from "./crypto/pallas.ts";
import { PROFILES, type Profile } from "./derive.ts";
import { scalarBytes } from "./frost.ts";
import { keygen, signRound } from "./signing.ts";
import { runSpend, type SpendStep } from "./spend.ts";

const VECTORS_DIR = resolve(import.meta.dirname, "../vectors");
const readVectors = (file: string) => JSON.parse(readFileSync(resolve(VECTORS_DIR, file), "utf8"));

export type Area = `derive:${Profile}` | "backup" | "signing";
export const AREAS: Area[] = [...PROFILES.map((p) => `derive:${p}` as const), "backup", "signing"];

export type Failure = { case: string; field?: string; expected?: string; got?: string; note?: string };

export type AdapterResult = {
  name: string;
  kind: Manifest["kind"];
  description: string;
  available: boolean;
  reason?: string;
  version?: string;
  areas: Partial<Record<Area, { passed: number; failed: number; failures: Failure[] }>>;
};

export type PairResult = {
  a: string;
  b: string;
  area: Area;
  status: "compatible" | "incompatible" | "untested";
  cases: number;
  mismatches: number;
  why?: string;
  example?: Failure;
};

export type Report = {
  generatedAt: string;
  seed: string;
  fuzzCases: number;
  adapters: AdapterResult[];
  pairs: PairResult[];
  spend?: { ok: boolean; builder: string; signers: string[]; steps: SpendStep[] };
};

type Live = { manifest: Manifest; client: AdapterClient; hello: Hello; result: AdapterResult };

// Deterministic random bytes from a seed, so a failing run can be replayed.
function rng(seed: string) {
  let counter = 0;
  return (n: number): Uint8Array => {
    const out = new Uint8Array(n);
    for (let off = 0; off < n; off += 32) {
      const block = createHash("sha256").update(`${seed}:${counter++}`).digest();
      out.set(block.subarray(0, Math.min(32, n - off)), off);
    }
    return out;
  };
}

// A random valid `ak`: an on-curve x below 2^254 (so the sign bit is 0, even y).
function randomAk(rand: (n: number) => Uint8Array): Uint8Array {
  for (;;) {
    const b = rand(32);
    b[31] &= 0x3f;
    const x = leToBig(b);
    if (x !== 0n && isOnCurveX(x)) return b;
  }
}

const supports = (h: Hello, op: string, profile?: string) =>
  h.ops.includes(op) && (profile === undefined || h.profiles.includes(profile));

const isUnsupported = (r: Response) => r.error?.code === "unsupported";

const SIGNING_OPS = ["frost_keygen", "frost_commit", "frost_sign"];
const canSign = (h: Hello) => SIGNING_OPS.every((op) => h.ops.includes(op));
const canVerify = (h: Hello) => h.ops.includes("redpallas_verify");

// A random FROST signing session: t-of-n with 2 <= t <= n <= 5, a 32-byte
// message (the size of a sighash) and a random randomizer α.
function randomSession(rand: (n: number) => Uint8Array) {
  const n = 2 + (rand(1)[0] % 4);
  const t = 2 + (rand(1)[0] % (n - 1));
  const ids = Array.from({ length: n }, (_, i) => i + 1).sort(() => rand(1)[0] - 128).slice(0, t).sort((a, b) => a - b);
  return { t, n, ids, message: rand(32), alpha: scalarBytes(modQ(leToBig(rand(64)))) };
}

function compareFields(expected: Record<string, unknown>, got: Response, fields: string[], label: string): Failure[] {
  if (got.error) return [{ case: label, note: `error: ${got.error.code}${got.error.message ? ` (${got.error.message})` : ""}` }];
  const out: Failure[] = [];
  for (const f of fields) {
    if (got[f] === undefined) {
      if (f === "fvk") out.push({ case: label, field: f, note: "missing required field" });
      continue;
    }
    if (expected[f] !== undefined && String(got[f]).toLowerCase() !== String(expected[f]).toLowerCase()) {
      out.push({ case: label, field: f, expected: String(expected[f]), got: String(got[f]) });
    }
  }
  return out;
}

async function vectorSuites(l: Live, rand: (n: number) => Uint8Array) {
  for (const profile of PROFILES) {
    if (!supports(l.hello, "derive_fvk", profile)) continue;
    const suite = readVectors(profile === "legacy" ? "derive_legacy.json" : "derive_zip2005_use_qsk.json");
    const failures: Failure[] = [];
    let passed = 0;
    for (const [i, v] of suite.vectors.entries()) {
      const r = await l.client.request("derive_fvk", { profile, sk: v.sk, ak: v.ak });
      const f = compareFields(v, r, suite.fields, `vector ${i}`);
      f.length ? failures.push(...f) : passed++;
    }
    l.result.areas[`derive:${profile}`] = { passed, failed: suite.vectors.length - passed, failures };
  }

  const canEncode = supports(l.hello, "backup_encode");
  const canDecode = supports(l.hello, "backup_decode");
  if (canEncode || canDecode) {
    const suite = readVectors("backup_zkfrost_v1.json");
    const failures: Failure[] = [];
    let passed = 0, total = 0;
    const check = (ok: boolean, f: Failure) => {
      total++;
      ok ? passed++ : failures.push(f);
    };
    for (const [i, v] of suite.valid.entries()) {
      if (canEncode) {
        const r = await l.client.request("backup_encode", { backup: v.backup });
        check(r.string === v.string, { case: `encode valid ${i}`, expected: v.string, got: String(r.string ?? r.error?.code) });
      }
      if (canDecode) {
        for (const [variant, s] of [["", v.string], [" (uppercase)", v.string.toUpperCase()], [" (whitespace)", `  ${v.string}\n`]]) {
          const r = await l.client.request("backup_decode", { string: s });
          const same = !r.error && JSON.stringify(r.backup) === JSON.stringify(v.backup);
          check(same, { case: `decode valid ${i}${variant}`, expected: JSON.stringify(v.backup), got: JSON.stringify(r.backup ?? r.error) });
        }
      }
    }
    if (canDecode) {
      for (const v of suite.invalid) {
        const r = await l.client.request("backup_decode", { string: v.string });
        check(!!r.error && !isUnsupported(r), {
          case: `reject: ${v.why}`,
          expected: `an error (${v.error})`,
          got: r.error ? r.error.code : `accepted ${JSON.stringify(r.backup)}`,
        });
      }
    }
    l.result.areas.backup = { passed, failed: total - passed, failures };
  }

  // Signing: the shared RedPallas vectors, then groups this adapter deals and
  // signs alone, checked by the lab's verifier and its own.
  if (canVerify(l.hello) || canSign(l.hello)) {
    const failures: Failure[] = [];
    let passed = 0, total = 0;
    if (canVerify(l.hello)) {
      for (const v of readVectors("redpallas_spendauth.json").vectors) {
        total++;
        const r = await l.client.request("redpallas_verify", { rk: v.rk, message: v.message, signature: v.signature });
        r.valid === v.valid ? passed++ : failures.push({
          case: `verify: ${v.why}`, expected: v.valid ? "valid" : "rejected", got: r.error ? `error ${r.error.code}` : r.valid ? "valid" : "rejected",
        });
      }
    }
    if (canSign(l.hello)) {
      for (let i = 0; i < 5; i++) {
        total++;
        const s = randomSession(rand);
        const g = await keygen(l.client, s.t, s.n);
        if ("error" in g) {
          failures.push({ case: `sign alone ${s.t}-of-${s.n}`, note: g.error });
          continue;
        }
        const r = await signRound({ group: g, signers: new Map(s.ids.map((id) => [id, l.client])), message: s.message, alpha: s.alpha,
          verifiers: canVerify(l.hello) ? [l.client] : [] });
        r.ok ? passed++ : failures.push({ case: `sign alone ${s.t}-of-${s.n}, signers ${s.ids.join(",")}`, note: r.problem });
      }
    }
    l.result.areas.signing = { passed, failed: total - passed, failures };
  }
}

function pairKey(a: string, b: string, area: Area) {
  return `${a}|${b}|${area}`;
}

export async function runLab(manifests: Manifest[], opts: { fuzzCases: number; seed: string }): Promise<Report> {
  const live: Live[] = [];
  const results: AdapterResult[] = [];

  for (const m of manifests) {
    const result: AdapterResult = { name: m.name, kind: m.kind, description: m.description, available: false, areas: {} };
    results.push(result);
    const client = new AdapterClient(m);
    const hello = await client.request("hello", {}, 20_000);
    if (hello.error) {
      result.reason = hello.error.message ?? hello.error.code;
      if (m.build) result.reason += ` (build it with: ${m.build})`;
      client.close();
      continue;
    }
    result.available = true;
    result.version = String(hello.version ?? "");
    live.push({ manifest: m, client, hello: hello as unknown as Hello, result });
  }

  // Differential testing: random inputs, every pair of adapters must agree.
  const rand = rng(opts.seed);
  const signingRand = rng(`${opts.seed}:signing`); // separate stream, so derivation inputs don't depend on it
  for (const l of live) await vectorSuites(l, signingRand);
  const tally = new Map<string, { cases: number; mismatches: number; example?: Failure }>();
  const bump = (a: string, b: string, area: Area, mismatch?: Failure) => {
    const k = pairKey(a, b, area);
    const t = tally.get(k) ?? { cases: 0, mismatches: 0 };
    t.cases++;
    if (mismatch) {
      t.mismatches++;
      t.example ??= mismatch;
    }
    tally.set(k, t);
  };

  for (let i = 0; i < opts.fuzzCases; i++) {
    const sk = hex(rand(32));
    const ak = hex(randomAk(rand));
    for (const profile of PROFILES) {
      const area: Area = `derive:${profile}`;
      const takers = live.filter((l) => supports(l.hello, "derive_fvk", profile));
      const answers = await Promise.all(takers.map((l) => l.client.request("derive_fvk", { profile, sk, ak })));
      for (let x = 0; x < takers.length; x++) {
        for (let y = x + 1; y < takers.length; y++) {
          const [ra, rb] = [answers[x], answers[y]];
          let mismatch: Failure | undefined;
          if (ra.error || rb.error) {
            mismatch = { case: `sk=${sk} ak=${ak}`, note: `error: ${ra.error?.code ?? "ok"} vs ${rb.error?.code ?? "ok"}` };
          } else {
            const common = Object.keys(ra).filter((k) => k !== "id" && rb[k] !== undefined);
            const bad = common.find((k) => String(ra[k]).toLowerCase() !== String(rb[k]).toLowerCase());
            if (bad) mismatch = { case: `sk=${sk} ak=${ak}`, field: bad, expected: String(ra[bad]), got: String(rb[bad]) };
          }
          bump(takers[x].manifest.name, takers[y].manifest.name, area, mismatch);
        }
      }
    }

    // Backups: every encoder's string must decode to the same fields in every decoder.
    const n = 1 + (rand(1)[0] % 15);
    const backup = { id: 1 + (rand(1)[0] % n), t: 1 + (rand(1)[0] % n), n, share: hex(rand(32)), sk };
    const encoders = live.filter((l) => supports(l.hello, "backup_encode"));
    const decoders = live.filter((l) => supports(l.hello, "backup_decode"));
    const strings = await Promise.all(encoders.map((l) => l.client.request("backup_encode", { backup })));
    for (const [ei, enc] of encoders.entries()) {
      for (const dec of decoders) {
        if (dec === enc) continue;
        const s = strings[ei].string as string | undefined;
        const r = s ? await dec.client.request("backup_decode", { string: s }) : null;
        const ok = r && !r.error && JSON.stringify(r.backup) === JSON.stringify(backup);
        const [a, b] = [enc.manifest.name, dec.manifest.name].sort();
        bump(a, b, "backup", ok ? undefined : {
          case: `${enc.manifest.name} encoded, ${dec.manifest.name} decoded`,
          expected: JSON.stringify(backup),
          got: r ? JSON.stringify(r.backup ?? r.error) : `encoder error ${strings[ei].error?.code}`,
        });
      }
    }

    // Signing: for every pair, one group whose shares are split between the two
    // implementations (dealer alternating), checked by both verifiers.
    const signingCapable = live.filter((l) => canSign(l.hello) || canVerify(l.hello));
    const rounds: Promise<void>[] = [];
    for (let x = 0; x < signingCapable.length; x++) {
      for (let y = x + 1; y < signingCapable.length; y++) {
        const pair = [signingCapable[x], signingCapable[y]];
        const signers = pair.filter((l) => canSign(l.hello));
        if (!signers.length) continue;
        const s = randomSession(signingRand); // drawn up front, so runs stay reproducible
        const dealer = signers[i % signers.length];
        const label = `${s.t}-of-${s.n}, dealt by ${dealer.manifest.name}`;
        const tally = (f?: Failure) => bump(pair[0].manifest.name, pair[1].manifest.name, "signing", f);
        rounds.push((async () => {
          const g = await keygen(dealer.client, s.t, s.n);
          if ("error" in g) return tally({ case: label, note: g.error });
          const r = await signRound({
            group: g, message: s.message, alpha: s.alpha,
            signers: new Map(s.ids.map((id, k) => [id, signers[(k + i) % signers.length].client])),
            verifiers: pair.filter((l) => canVerify(l.hello)).map((l) => l.client),
          });
          tally(r.ok ? undefined : { case: `${label}; signers ${r.signers.map((v) => `${v.id}:${v.adapter}`).join(", ")}`, note: r.problem });
        })());
      }
    }
    await Promise.all(rounds);
  }

  // Verdicts per pair and area.
  const pairs: PairResult[] = [];
  const names = results.map((r) => r.name);
  for (let x = 0; x < names.length; x++) {
    for (let y = x + 1; y < names.length; y++) {
      const [ra, rb] = [results[x], results[y]];
      for (const area of AREAS) {
        const base = { a: ra.name, b: rb.name, area };
        const va = ra.areas[area], vb = rb.areas[area];
        if (!ra.available || !rb.available || !va || !vb) {
          pairs.push({ ...base, status: "untested", cases: 0, mismatches: 0,
            why: !ra.available || !rb.available ? "adapter unavailable" : "not supported by both" });
          continue;
        }
        const t = tally.get(pairKey(ra.name, rb.name, area)) ?? tally.get(pairKey(rb.name, ra.name, area)) ?? { cases: 0, mismatches: 0 };
        const vectorFail = va.failed ? ra.name : vb.failed ? rb.name : null;
        const status = t.mismatches === 0 && !vectorFail ? "compatible" : "incompatible";
        pairs.push({
          ...base, status, cases: t.cases, mismatches: t.mismatches, example: t.example,
          why: status === "compatible" ? undefined
            : t.mismatches ? `${t.mismatches} of ${t.cases} random cases disagree`
            : `${vectorFail} fails the shared vectors`,
        });
      }
    }
  }

  // End to end: a group split across every signing implementation that passes
  // its vectors spends an Orchard note built and validated by the orchard crate.
  let spend: Report["spend"];
  const builder = live.find((l) => l.hello.ops.includes("orchard_spend_prepare"));
  const goodSigners = live.filter((l) => canSign(l.hello) && l.result.areas.signing?.failed === 0);
  if (builder && goodSigners.length) {
    const others = goodSigners.filter((l) => l !== builder);
    const signers = [...(goodSigners.includes(builder) ? [builder] : []), ...others];
    const r = await runSpend({
      builder: builder.client, dealer: (others[0] ?? builder).client, t: Math.max(2, signers.length), n: Math.max(3, signers.length + 1),
      signers: signers.map((l) => l.client), verifiers: live.filter((l) => canVerify(l.hello) && l.result.areas.signing?.failed === 0).map((l) => l.client),
    });
    spend = { ok: r.ok, builder: builder.manifest.name, signers: signers.map((l) => l.manifest.name), steps: r.steps };
  }

  for (const l of live) l.client.close();
  return { generatedAt: new Date().toISOString(), seed: opts.seed, fuzzCases: opts.fuzzCases, adapters: results, pairs, spend };
}
