export function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function unhex(s: string, len?: number): Uint8Array {
  if (!/^([0-9a-f]{2})*$/i.test(s)) throw new Error(`not hex: ${s.slice(0, 20)}…`);
  const b = Uint8Array.from(Buffer.from(s, "hex"));
  if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
  return b;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
