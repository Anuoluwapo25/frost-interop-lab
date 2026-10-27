// Reference implementations of the two ways Zcash FROST wallets derive the
// group's Orchard full viewing key from the shared `sk` and the group key `ak`.
//
//   legacy           nk = ToBase(PRF^expand_sk([7])), rivk = ToScalar(PRF^expand_sk([8]))
//                    (the protocol spec's derivation, with only ak swapped)
//   zip2005-use-qsk  ZIP 2005 § 4.2.3: nk as above,
//                    qsk = truncate_32(PRF^expand_sk([0x0C])),
//                    qk = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk),
//                    rivk = ToScalar(PRF^expand_qk([0x0D] || ak || nk))
//
// FVK = ak || nk || rivk (96 bytes). The two profiles share ak and nk and
// differ only in rivk, so the same group gets a different address under each.

import { blake2b } from "./crypto/blake2b.ts";
import { blake3DeriveKey } from "./crypto/blake3.ts";
import { concat } from "./crypto/hex.ts";
import { toBase, toScalar } from "./crypto/pallas.ts";

export const PROFILES = ["legacy", "zip2005-use-qsk"] as const;
export type Profile = (typeof PROFILES)[number];

export const QK_CONTEXT = "Zcash ZIP 2005 qk-derivation v1";
const EXPAND_SEED = new TextEncoder().encode("Zcash_ExpandSeed");

export function prfExpand(key: Uint8Array, t: Uint8Array): Uint8Array {
  return blake2b(concat(key, t), 64, EXPAND_SEED);
}

export type Derived = {
  nk: Uint8Array;
  rivk: Uint8Array;
  fvk: Uint8Array;
  qsk?: Uint8Array;
  qk?: Uint8Array;
};

export function deriveFvk(profile: Profile, sk: Uint8Array, ak: Uint8Array): Derived {
  if (sk.length !== 32 || ak.length !== 32) throw new Error("sk and ak must be 32 bytes");
  const nk = toBase(prfExpand(sk, Uint8Array.of(0x07)));
  if (profile === "legacy") {
    const rivk = toScalar(prfExpand(sk, Uint8Array.of(0x08)));
    return { nk, rivk, fvk: concat(ak, nk, rivk) };
  }
  const qsk = prfExpand(sk, Uint8Array.of(0x0c)).slice(0, 32);
  const qk = blake3DeriveKey(QK_CONTEXT, qsk);
  const rivk = toScalar(prfExpand(qk, concat(Uint8Array.of(0x0d), ak, nk)));
  return { nk, rivk, fvk: concat(ak, nk, rivk), qsk, qk };
}
