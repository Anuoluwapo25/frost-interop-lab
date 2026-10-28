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

// Point arithmetic, for RedPallas and FROST signing. Jacobian coordinates
// (x = X/Z^2, y = Y/Z^3) avoid an inversion per addition; Z = 0 is the identity.

export type Point = { X: bigint; Y: bigint; Z: bigint };

export const IDENTITY: Point = { X: 1n, Y: 1n, Z: 0n };

const mod = (a: bigint, m = P) => ((a % m) + m) % m;
export const modQ = (a: bigint) => mod(a, Q);
export const invQ = (a: bigint) => modPow(modQ(a), Q - 2n, Q);

export function double(p: Point): Point {
  if (p.Z === 0n || p.Y === 0n) return IDENTITY;
  const A = mod(p.X * p.X), B = mod(p.Y * p.Y), C = mod(B * B);
  const D = mod(2n * (mod((p.X + B) * (p.X + B)) - A - C));
  const E = mod(3n * A), F = mod(E * E);
  const X = mod(F - 2n * D);
  return { X, Y: mod(E * (D - X) - 8n * C), Z: mod(2n * p.Y * p.Z) };
}

export function add(p: Point, q: Point): Point {
  if (p.Z === 0n) return q;
  if (q.Z === 0n) return p;
  const Z1Z1 = mod(p.Z * p.Z), Z2Z2 = mod(q.Z * q.Z);
  const U1 = mod(p.X * Z2Z2), U2 = mod(q.X * Z1Z1);
  const S1 = mod(p.Y * q.Z * Z2Z2), S2 = mod(q.Y * p.Z * Z1Z1);
  if (U1 === U2) return S1 === S2 ? double(p) : IDENTITY;
  const H = mod(U2 - U1), I = mod(4n * H * H), J = mod(H * I), r = mod(2n * (S2 - S1)), V = mod(U1 * I);
  const X = mod(r * r - J - 2n * V);
  return { X, Y: mod(r * (V - X) - 2n * S1 * J), Z: mod(((p.Z + q.Z) ** 2n - Z1Z1 - Z2Z2) * H) };
}

export const neg = (p: Point): Point => ({ ...p, Y: mod(-p.Y) });

export function mul(p: Point, k: bigint): Point {
  if (p === SPENDAUTH_G) return mulG(k);
  let r = IDENTITY;
  for (let i = BigInt(modQ(k).toString(2).length) - 1n; i >= 0n; i--) {
    r = double(r);
    if ((modQ(k) >> i) & 1n) r = add(r, p);
  }
  return r;
}

export function equal(p: Point, q: Point): boolean {
  if (p.Z === 0n || q.Z === 0n) return p.Z === q.Z;
  const Z1Z1 = mod(p.Z * p.Z), Z2Z2 = mod(q.Z * q.Z);
  return mod(p.X * Z2Z2) === mod(q.X * Z1Z1) && mod(p.Y * q.Z * Z2Z2) === mod(q.Y * p.Z * Z1Z1);
}

function affine(p: Point): { x: bigint; y: bigint } {
  const zi = modPow(p.Z, P - 2n, P), zi2 = mod(zi * zi);
  return { x: mod(p.X * zi2), y: mod(p.Y * zi2 * zi) };
}

// Square root mod p by Tonelli-Shanks (p - 1 = 2^32 * t).
function sqrt(a: bigint): bigint | null {
  if (a === 0n) return 0n;
  if (modPow(a, (P - 1n) / 2n, P) !== 1n) return null;
  let s = 0n, t = P - 1n;
  while (!(t & 1n)) { t >>= 1n; s++; }
  let z = 2n;
  while (modPow(z, (P - 1n) / 2n, P) === 1n) z++;
  let m = s, c = modPow(z, t, P), x = modPow(a, (t + 1n) / 2n, P), b = modPow(a, t, P);
  while (b !== 1n) {
    let i = 0n, b2 = b;
    while (b2 !== 1n) { b2 = mod(b2 * b2); i++; }
    const f = modPow(c, 1n << (m - i - 1n), P);
    x = mod(x * f); c = mod(f * f); b = mod(b * c); m = i;
  }
  return x;
}

// Pasta encoding: x little-endian, top bit = y mod 2; the identity is all zeros.
export function encodePoint(p: Point): Uint8Array {
  if (p.Z === 0n) return new Uint8Array(32);
  const { x, y } = affine(p);
  const out = bigToLe32(x);
  out[31] |= Number(y & 1n) << 7;
  return out;
}

export function decodePoint(b: Uint8Array): Point | null {
  if (b.length !== 32) return null;
  const sign = BigInt(b[31] >> 7);
  const xb = b.slice();
  xb[31] &= 0x7f;
  const x = leToBig(xb);
  if (x >= P) return null;
  if (x === 0n && sign === 0n) return IDENTITY;
  const y = sqrt((modPow(x, 3n, P) + 5n) % P);
  if (y === null) return null;
  return { X: x, Y: (y & 1n) === sign ? y : mod(-y), Z: 1n };
}

// The Orchard SpendAuthSig basepoint, GroupHash^P("z.cash:Orchard", "G")
// (protocol spec § 5.4.7.1), in its compressed encoding.
export const SPENDAUTH_G = decodePoint(new Uint8Array([
  99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12,
  95, 68, 95, 62, 124, 24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
]))!;

// Fixed-base multiplication by G with a table of [2^i]G: additions only.
let gTable: Point[] | undefined;
function mulG(k: bigint): Point {
  gTable ??= Array.from({ length: 255 }).reduce<Point[]>((t, _, i) => (t.push(i ? double(t[i - 1]) : SPENDAUTH_G), t), []);
  let r = IDENTITY;
  for (let i = 0, e = modQ(k); e > 0n; i++, e >>= 1n) if (e & 1n) r = add(r, gTable[i]);
  return r;
}
