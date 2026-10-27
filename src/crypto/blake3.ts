// BLAKE3 for inputs of at most one chunk (1024 bytes), which is all ZIP 2005's
// H^qk = BLAKE3.derive_key(context, qsk) needs. Covers hash and derive_key modes.

const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START = 1, CHUNK_END = 2, ROOT = 8, DERIVE_KEY_CONTEXT = 32, DERIVE_KEY_MATERIAL = 64;

const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

function compress(cv: number[], block: Uint8Array, blockLen: number, flags: number): number[] {
  let m = Array.from({ length: 16 }, (_, i) =>
    (block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24)) >>> 0);
  const s = [...cv, IV[0], IV[1], IV[2], IV[3], 0, 0, blockLen, flags];
  const g = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    s[a] = (s[a] + s[b] + x) >>> 0;
    s[d] = rotr(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b] + y) >>> 0;
    s[d] = rotr(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = rotr(s[b] ^ s[c], 7);
  };
  for (let r = 0; r < 7; r++) {
    g(0, 4, 8, 12, m[0], m[1]);
    g(1, 5, 9, 13, m[2], m[3]);
    g(2, 6, 10, 14, m[4], m[5]);
    g(3, 7, 11, 15, m[6], m[7]);
    g(0, 5, 10, 15, m[8], m[9]);
    g(1, 6, 11, 12, m[10], m[11]);
    g(2, 7, 8, 13, m[12], m[13]);
    g(3, 4, 9, 14, m[14], m[15]);
    if (r < 6) m = PERM.map((i) => m[i]);
  }
  return Array.from({ length: 8 }, (_, i) => (s[i] ^ s[i + 8]) >>> 0);
}

function singleChunk(key: number[], data: Uint8Array, modeFlags: number): Uint8Array {
  if (data.length > 1024) throw new Error("single-chunk BLAKE3 only");
  const nBlocks = Math.max(1, Math.ceil(data.length / 64));
  let cv = key;
  for (let i = 0; i < nBlocks; i++) {
    const chunk = data.subarray(i * 64, Math.min(data.length, (i + 1) * 64));
    const block = new Uint8Array(64);
    block.set(chunk);
    let flags = modeFlags;
    if (i === 0) flags |= CHUNK_START;
    if (i === nBlocks - 1) flags |= CHUNK_END | ROOT;
    cv = compress(cv, block, chunk.length, flags);
  }
  const out = new Uint8Array(32);
  cv.forEach((w, i) => {
    out[4 * i] = w & 0xff;
    out[4 * i + 1] = (w >>> 8) & 0xff;
    out[4 * i + 2] = (w >>> 16) & 0xff;
    out[4 * i + 3] = (w >>> 24) & 0xff;
  });
  return out;
}

export function blake3Hash(data: Uint8Array): Uint8Array {
  return singleChunk(IV, data, 0);
}

export function blake3DeriveKey(context: string, material: Uint8Array): Uint8Array {
  const ctxKey = singleChunk(IV, new TextEncoder().encode(context), DERIVE_KEY_CONTEXT);
  const words = Array.from({ length: 8 }, (_, i) =>
    (ctxKey[4 * i] | (ctxKey[4 * i + 1] << 8) | (ctxKey[4 * i + 2] << 16) | (ctxKey[4 * i + 3] << 24)) >>> 0);
  return singleChunk(words, material, DERIVE_KEY_MATERIAL);
}
