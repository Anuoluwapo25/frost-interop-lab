// The lab as FROST coordinator: one adapter deals the key, a mix of adapters
// sign (round 1 commitments, round 2 shares), the lab aggregates and names any
// bad share, and every verifier checks the final RedPallas signature.

import type { AdapterClient } from "./adapter.ts";
import { hex, unhex } from "./crypto/hex.ts";
import { aggregate, type Commitment, scalarFrom, verifySpendAuth } from "./frost.ts";

export type KeyShare = { id: number; signing_share: string; verifying_share: string };
export type Group = { dealer: string; t: number; n: number; group_key: string; shares: KeyShare[] };

export type RoundResult = {
  ok: boolean;
  problem?: string;
  signers: { id: number; adapter: string }[];
  rk?: string;
  signature?: string;
  badSigners: string[];
  verdicts: Record<string, boolean>;
};

let sessions = 0;

export async function keygen(dealer: AdapterClient, t: number, n: number): Promise<Group | { error: string }> {
  const r = await dealer.request("frost_keygen", { t, n });
  if (r.error) return { error: `${dealer.manifest.name} keygen: ${r.error.code}${r.error.message ? ` (${r.error.message})` : ""}` };
  const g = { dealer: dealer.manifest.name, t, n, group_key: String(r.group_key), shares: r.shares as KeyShare[] };
  if (!/^[0-9a-f]{64}$/.test(g.group_key) || g.shares?.length !== n) return { error: `${g.dealer} keygen: malformed response` };
  if (parseInt(g.group_key.slice(62), 16) & 0x80) return { error: `${g.dealer} keygen: group key has odd y, not a valid Orchard ak` };
  return g;
}

// `signers` maps each participating share id to the adapter that holds it.
export async function signRound(p: {
  group: Group; signers: Map<number, AdapterClient>; message: Uint8Array; alpha: Uint8Array; verifiers: AdapterClient[];
}): Promise<RoundResult> {
  const session = `s${++sessions}`;
  const entries = [...p.signers.entries()].sort((a, b) => a[0] - b[0]);
  const base = { signers: entries.map(([id, c]) => ({ id, adapter: c.manifest.name })), badSigners: [] as string[], verdicts: {} };
  const share = (id: number) => p.group.shares.find((s) => s.id === id)!;
  const fail = (problem: string): RoundResult => ({ ...base, ok: false, problem });

  const round1 = await Promise.all(entries.map(([id, c]) =>
    c.request("frost_commit", { session, participant: id, signing_share: share(id).signing_share })));
  const bad1 = round1.findIndex((r) => r.error);
  if (bad1 >= 0) return fail(`${entries[bad1][1].manifest.name} commit: ${round1[bad1].error!.code}`);
  const commitments = entries.map(([id], i) => ({ id, hiding: String(round1[i].hiding), binding: String(round1[i].binding) }));

  const package_ = { group_key: p.group.group_key, message: hex(p.message), randomizer: hex(p.alpha), commitments };
  const round2 = await Promise.all(entries.map(([id, c]) =>
    c.request("frost_sign", { session, participant: id, signing_share: share(id).signing_share, ...package_ })));
  const bad2 = round2.findIndex((r) => r.error);
  if (bad2 >= 0) return fail(`${entries[bad2][1].manifest.name} sign: ${round2[bad2].error!.code}${round2[bad2].error!.message ? ` (${round2[bad2].error!.message})` : ""}`);

  let agg;
  try {
    agg = aggregate({
      groupKey: unhex(p.group.group_key, 32), alpha: scalarFrom(p.alpha), message: p.message,
      commitments: commitments.map((c): Commitment => ({ id: c.id, hiding: unhex(c.hiding, 32), binding: unhex(c.binding, 32) })),
      shares: entries.map(([id], i) => ({ id, z: scalarFrom(unhex(String(round2[i].signature_share), 32)), verifyingShare: unhex(share(id).verifying_share, 32) })),
    });
  } catch (e) {
    return fail(`aggregation: ${(e as Error).message}`);
  }
  const badSigners = agg.badSigners.map((id) => `${p.signers.get(id)!.manifest.name} (share ${id})`);
  const [rk, signature] = [hex(agg.rk), hex(agg.signature)];

  const verdicts: Record<string, boolean> = { lab: verifySpendAuth(agg.rk, p.message, agg.signature) };
  const answers = await Promise.all(p.verifiers.map((v) => v.request("redpallas_verify", { rk, message: hex(p.message), signature })));
  p.verifiers.forEach((v, i) => (verdicts[v.manifest.name] = answers[i].valid === true));

  const rejected = Object.entries(verdicts).filter(([, ok]) => !ok).map(([name]) => name);
  const ok = badSigners.length === 0 && rejected.length === 0;
  const problem = ok ? undefined
    : badSigners.length ? `invalid signature share from ${badSigners.join(", ")}`
    : `signature rejected by ${rejected.join(", ")}`;
  return { ...base, ok, problem, rk, signature, badSigners, verdicts };
}
