// End to end: a FROST group whose shares live in different implementations
// spends a real Orchard note. The orchard-rust adapter builds and proves the
// bundle, the group signs its sighash with the spend's randomizer, and the
// orchard crate validates the finished bundle (Halo2 proof, spend
// authorization and binding signatures).

import { randomBytes } from "node:crypto";
import type { AdapterClient } from "./adapter.ts";
import { hex, unhex } from "./crypto/hex.ts";
import { encodePoint } from "./crypto/pallas.ts";
import type { Profile } from "./derive.ts";
import { randomizedKey, scalarFrom } from "./frost.ts";
import { keygen, signRound, type RoundResult } from "./signing.ts";

export type SpendStep = { step: string; ok: boolean; detail: string };

export async function runSpend(p: {
  builder: AdapterClient; dealer: AdapterClient; signers: AdapterClient[]; verifiers: AdapterClient[];
  t?: number; n?: number; profile?: Profile;
}): Promise<{ ok: boolean; steps: SpendStep[]; round?: RoundResult }> {
  const { t = 2, n = 3, profile = "zip2005-use-qsk" } = p;
  const steps: SpendStep[] = [];
  const done = (step: string, ok: boolean, detail: string) => (steps.push({ step, ok, detail }), ok);
  const session = `spend-${hex(new Uint8Array(randomBytes(4)))}`;

  const group = await keygen(p.dealer, t, n);
  if ("error" in group) return { ok: done("Key generation", false, group.error), steps };
  done("Key generation", true, `${t}-of-${n} group dealt by ${group.dealer}; group key ak ${group.group_key}`);

  const sk = hex(new Uint8Array(randomBytes(32)));
  const keys = await p.builder.request("derive_fvk", { profile, sk, ak: group.group_key });
  if (keys.error) return { ok: done("Group address", false, keys.error.message ?? keys.error.code), steps };
  done("Group address", true, `${profile} UFVK ${String(keys.ufvk_testnet).slice(0, 28)}…`);

  const prep = await p.builder.request("orchard_spend_prepare", { session, profile, sk, ak: group.group_key }, 120_000);
  if (prep.error) return { ok: done("Build and prove", false, prep.error.message ?? prep.error.code), steps };
  done("Build and prove", true,
    `${prep.actions} actions spending a ${Number(prep.value) / 1e8} ZEC note, Halo2 proof created; sighash ${prep.sighash}`);

  const alpha = unhex(String(prep.randomizer), 32);
  const expectedRk = hex(encodePoint(randomizedKey(unhex(group.group_key, 32), scalarFrom(alpha))));
  if (expectedRk !== prep.rk) return { ok: done("Randomized key", false, `spend rk ${prep.rk} is not ak + [α]G = ${expectedRk}`), steps };
  done("Randomized key", true, `the spend's rk equals ak + [α]G for the group key`);

  const ids = Array.from({ length: n }, (_, i) => i + 1).slice(0, t);
  const round = await signRound({
    group, message: unhex(String(prep.sighash), 32), alpha, verifiers: p.verifiers,
    signers: new Map(ids.map((id, k) => [id, p.signers[k % p.signers.length]])),
  });
  const who = round.signers.map((s) => `share ${s.id} on ${s.adapter}`).join(", ");
  if (!round.ok) return { ok: done("FROST signing", false, `${who}: ${round.problem}`), steps, round };
  done("FROST signing", true, `${who}; verified by ${Object.keys(round.verdicts).join(", ")}`);

  const fin = await p.builder.request("orchard_spend_finish", { session, signature: round.signature }, 120_000);
  const valid = !fin.error && fin.valid === true;
  done("Orchard validation", valid, fin.error ? fin.error.message ?? fin.error.code : `${fin.stage}; nullifier ${fin.nullifier}`);
  return { ok: valid, steps, round };
}
