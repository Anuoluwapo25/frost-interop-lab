// Pallas field arithmetic needed for Orchard key derivation and for generating
// valid random `ak` values (x-coordinates of curve points with even y).

export const P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n; // base field
export const Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n; // scalar field

export function leToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

export function bigToLe32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// ToBase / ToScalar of a 64-byte PRF output: little-endian integer reduced mod p or q.
export const toBase = (b: Uint8Array) => bigToLe32(leToBig(b) % P);
export const toScalar = (b: Uint8Array) => bigToLe32(leToBig(b) % Q);

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  base %= m;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return r;
}

// Pallas: y^2 = x^3 + 5. An x is a valid point's x-coordinate iff x^3 + 5 is a square.
export function isOnCurveX(x: bigint): boolean {
  if (x >= P) return false;
  const rhs = (modPow(x, 3n, P) + 5n) % P;
  return rhs === 0n || modPow(rhs, (P - 1n) / 2n, P) === 1n;
}

// Encoding of a SpendValidatingKey: x little-endian with the sign bit (top bit) 0,
// i.e. the even-y point. Returns null if the bytes can't be such an encoding.
export function isValidAkEncoding(ak: Uint8Array): boolean {
  if (ak.length !== 32 || (ak[31] & 0x80) !== 0) return false;
  const x = leToBig(ak);
  return x !== 0n && isOnCurveX(x);
}
