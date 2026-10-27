// The `zkfrost` member backup string, format version 1, as implemented by Zkool
// (hhanh00/zkool2 rust/src/frost/backup.rs) and proposed as the common format in
// the interoperable FROST co-signing grant: bech32m, HRP "zkfrost", 68 bytes:
//   version (1) = 1 | participant id (1) | threshold t (1) | group size n (1)
//   | FROST signing share (32) | group sk (32)
// Valid only when n ≥ 1, 1 ≤ id ≤ n and 1 ≤ t ≤ n.

import { bech32mDecode, bech32mEncode } from "./crypto/bech32m.ts";
import { hex, unhex } from "./crypto/hex.ts";

export const BACKUP_HRP = "zkfrost";
export const BACKUP_VERSION = 1;
const PAYLOAD_LEN = 68;

export type Backup = { id: number; t: number; n: number; share: string; sk: string };

export type BackupError =
  | "not_bech32m"
  | "wrong_hrp"
  | "wrong_length"
  | "unsupported_version"
  | "invalid_params";

export function encodeBackup(b: Backup): string {
  const payload = new Uint8Array(PAYLOAD_LEN);
  payload.set([BACKUP_VERSION, b.id, b.t, b.n]);
  payload.set(unhex(b.share, 32), 4);
  payload.set(unhex(b.sk, 32), 36);
  return bech32mEncode(BACKUP_HRP, payload);
}

export function decodeBackup(s: string): { backup: Backup } | { error: BackupError } {
  const d = bech32mDecode(s.trim());
  if ("error" in d) return { error: "not_bech32m" };
  if (d.hrp !== BACKUP_HRP) return { error: "wrong_hrp" };
  if (d.bytes.length !== PAYLOAD_LEN) return { error: "wrong_length" };
  if (d.bytes[0] !== BACKUP_VERSION) return { error: "unsupported_version" };
  const [id, t, n] = [d.bytes[1], d.bytes[2], d.bytes[3]];
  if (n === 0 || id === 0 || id > n || t === 0 || t > n) return { error: "invalid_params" };
  return {
    backup: { id, t, n, share: hex(d.bytes.slice(4, 36)), sk: hex(d.bytes.slice(36, 68)) },
  };
}
