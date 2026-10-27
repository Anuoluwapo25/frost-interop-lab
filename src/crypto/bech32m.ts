// Bech32m (BIP 350) encode/decode for byte payloads. No 90-character limit:
// Zcash strings such as zkfrost backups are longer than BIP 173 allows.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] | null {
  let acc = 0, bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i];
    if (value < 0 || value >> from) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return out;
}

export function bech32mEncode(hrp: string, bytes: Uint8Array): string {
  const data = convertBits(bytes, 8, 5, true)!;
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ BECH32M_CONST;
  const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map((d) => CHARSET[d]).join("");
}

export type Bech32mError = "mixed_case" | "no_separator" | "bad_char" | "bad_checksum" | "bad_padding";

export function bech32mDecode(s: string): { hrp: string; bytes: Uint8Array } | { error: Bech32mError } {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) return { error: "mixed_case" };
  const str = s.toLowerCase();
  const pos = str.lastIndexOf("1");
  if (pos < 1 || pos + 7 > str.length) return { error: "no_separator" };
  const hrp = str.slice(0, pos);
  for (const c of hrp) {
    const code = c.charCodeAt(0);
    if (code < 33 || code > 126) return { error: "bad_char" };
  }
  const data: number[] = [];
  for (const c of str.slice(pos + 1)) {
    const d = CHARSET.indexOf(c);
    if (d === -1) return { error: "bad_char" };
    data.push(d);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== BECH32M_CONST) return { error: "bad_checksum" };
  const bytes = convertBits(data.slice(0, -6), 5, 8, false);
  if (!bytes) return { error: "bad_padding" };
  return { hrp, bytes: Uint8Array.from(bytes) };
}
