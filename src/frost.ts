// FROST(Pallas, BLAKE2b-512) with re-randomization, as ZF's reddsa crate and
// frost-core implement it (RFC 9591 plus the rerandomized variant Zcash uses
// for Orchard spend authorization), and RedPallas SpendAuth verification.
//
// Re-randomized signing with randomizer α: every signer and the aggregator use
// rk = ak + [α]G as the group key, and each signer adds α to its share. Since
// the Lagrange coefficients sum to 1, the aggregate is a plain RedPallas
// signature under rk, exactly what an Orchard spend carries.

import { blake2b } from "./crypto/blake2b.ts";
import { concat } from "./crypto/hex.ts";
import {
  add, bigToLe32, decodePoint, encodePoint, equal, IDENTITY, invQ, leToBig, mul, modQ, Q, SPENDAUTH_G as G, type Point,
} from "./crypto/pallas.ts";

const enc = new TextEncoder();
const hashToScalar = (personal: string, data: Uint8Array) => modQ(leToBig(blake2b(data, 64, enc.encode(personal))));

const H1 = (m: Uint8Array) => hashToScalar("FROST_RedPallasR", m); // binding factor
const H2 = (m: Uint8Array) => hashToScalar("Zcash_RedPallasH", m); // challenge: RedPallas H*
const H3 = (m: Uint8Array) => hashToScalar("FROST_RedPallasN", m); // nonce
const H4 = (m: Uint8Array) => blake2b(m, 64, enc.encode("FROST_RedPallasM")); // message
const H5 = (m: Uint8Array) => blake2b(m, 64, enc.encode("FROST_RedPallasC")); // commitment list

export const scalarBytes = (s: bigint) => bigToLe32(modQ(s));

export function scalarFrom(b: Uint8Array): bigint {
  const s = leToBig(b);
  if (b.length !== 32 || s >= Q) throw new Error("not a canonical scalar");
  return s;
}

export function pointFrom(b: Uint8Array, what = "point"): Point {
  const p = decodePoint(b);
  if (!p || p.Z === 0n) throw new Error(`invalid ${what}`);
  return p;
}

export type Commitment = { id: number; hiding: Uint8Array; binding: Uint8Array };
export type Nonces = { hiding: bigint; binding: bigint; commitment: Commitment };

// Trusted-dealer key generation: Shamir shares of a random secret, negated if
// needed so the group key has even y (a valid Orchard `ak`).
export function dealerKeygen(t: number, n: number, rand: (n: number) => Uint8Array) {
  const coeffs = Array.from({ length: t }, () => modQ(leToBig(rand(64))));
  let shares = Array.from({ length: n }, (_, i) => {
    const x = BigInt(i + 1);
    return { id: i + 1, share: coeffs.reduceRight((acc, c) => modQ(acc * x + c), 0n) };
  });
  let groupKey = encodePoint(mul(G, coeffs[0]));
  if (groupKey[31] & 0x80) {
    shares = shares.map((s) => ({ id: s.id, share: modQ(-s.share) }));
    groupKey = encodePoint(mul(G, modQ(-coeffs[0])));
  }
  return { groupKey, shares, verifyingShares: shares.map((s) => ({ id: s.id, key: encodePoint(mul(G, s.share)) })) };
}

// Round 1: nonces from fresh randomness mixed with the share (RFC 9591 § 4.1).
export function commit(id: number, share: bigint, rand: (n: number) => Uint8Array): Nonces {
  const hiding = H3(concat(rand(32), scalarBytes(share)));
  const binding = H3(concat(rand(32), scalarBytes(share)));
  return { hiding, binding, commitment: { id, hiding: encodePoint(mul(G, hiding)), binding: encodePoint(mul(G, binding)) } };
}

export const randomizedKey = (groupKey: Uint8Array, alpha: bigint) => add(pointFrom(groupKey, "group key"), mul(G, alpha));

type Session = { message: Uint8Array; commitments: Commitment[]; rk: Point };

function bindingFactors(s: Session): Map<number, bigint> {
  const sorted = [...s.commitments].sort((a, b) => a.id - b.id);
  const list = concat(...sorted.flatMap((c) => [scalarBytes(BigInt(c.id)), c.hiding, c.binding]));
  const prefix = concat(encodePoint(s.rk), H4(s.message), H5(list));
  return new Map(sorted.map((c) => [c.id, H1(concat(prefix, scalarBytes(BigInt(c.id))))]));
}

function groupCommitment(s: Session, rho: Map<number, bigint>): Point {
  return s.commitments.reduce(
    (R, c) => add(R, add(pointFrom(c.hiding, "commitment"), mul(pointFrom(c.binding, "commitment"), rho.get(c.id)!))),
    IDENTITY,
  );
}

function lagrange(id: number, ids: number[]): bigint {
  let num = 1n, den = 1n;
  for (const j of ids) {
    if (j === id) continue;
    num = modQ(num * BigInt(j));
    den = modQ(den * BigInt(j - id));
  }
  return modQ(num * invQ(den));
}

const challenge = (R: Point, rk: Point, message: Uint8Array) => H2(concat(encodePoint(R), encodePoint(rk), message));

// Round 2: z_i = d_i + e_i·ρ_i + λ_i·(s_i + α)·c.
export function signShare(p: {
  id: number; share: bigint; nonces: Nonces; groupKey: Uint8Array; alpha: bigint; message: Uint8Array; commitments: Commitment[];
}): bigint {
  const mine = p.commitments.find((c) => c.id === p.id);
  if (!mine || !equal(pointFrom(mine.hiding), pointFrom(p.nonces.commitment.hiding))
    || !equal(pointFrom(mine.binding), pointFrom(p.nonces.commitment.binding))) {
    throw new Error("own commitment missing from the signing package");
  }
  const s: Session = { message: p.message, commitments: p.commitments, rk: randomizedKey(p.groupKey, p.alpha) };
  const rho = bindingFactors(s);
  const c = challenge(groupCommitment(s, rho), s.rk, s.message);
  const lambda = lagrange(p.id, p.commitments.map((x) => x.id));
  return modQ(p.nonces.hiding + p.nonces.binding * rho.get(p.id)! + lambda * modQ(p.share + p.alpha) * c);
}

// Aggregation. If the signature doesn't verify, each share is checked so the
// bad signer is named (frost-core's cheater detection does the same).
export function aggregate(p: {
  groupKey: Uint8Array; alpha: bigint; message: Uint8Array; commitments: Commitment[];
  shares: { id: number; z: bigint; verifyingShare: Uint8Array }[];
}): { signature: Uint8Array; rk: Uint8Array; badSigners: number[] } {
  const s: Session = { message: p.message, commitments: p.commitments, rk: randomizedKey(p.groupKey, p.alpha) };
  const rho = bindingFactors(s);
  const R = groupCommitment(s, rho);
  const c = challenge(R, s.rk, s.message);
  const ids = p.commitments.map((x) => x.id);
  const z = p.shares.reduce((acc, x) => modQ(acc + x.z), 0n);
  const signature = concat(encodePoint(R), scalarBytes(z));
  if (equal(mul(G, z), add(R, mul(s.rk, c)))) return { signature, rk: encodePoint(s.rk), badSigners: [] };
  const badSigners = p.shares.filter(({ id, z, verifyingShare }) => {
    const com = p.commitments.find((x) => x.id === id)!;
    const Ri = add(pointFrom(com.hiding), mul(pointFrom(com.binding), rho.get(id)!));
    const Yi = add(pointFrom(verifyingShare, "verifying share"), mul(G, p.alpha));
    return !equal(mul(G, z), add(Ri, mul(Yi, modQ(lagrange(id, ids) * c))));
  }).map((x) => x.id);
  return { signature, rk: encodePoint(s.rk), badSigners };
}

// RedPallas SpendAuth verification: [S]G = R + [H*(R ‖ rk ‖ m)]rk.
export function verifySpendAuth(rk: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const R = decodePoint(signature.subarray(0, 32));
  const S = leToBig(signature.subarray(32));
  const vk = decodePoint(rk);
  if (!R || !vk || vk.Z === 0n || S >= Q) return false;
  return equal(mul(G, S), add(R, mul(vk, challenge(R, vk, message))));
}
