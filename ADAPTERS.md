# Writing an adapter

An adapter lets the lab test your FROST implementation without changing it. It is a small program that reads JSON requests, one per line, on stdin, and writes one JSON response per line on stdout. Anything on stderr is ignored, so log there freely.

Put it in `adapters/<your-name>/` with an `adapter.json` manifest:

```json
{
  "name": "my-wallet",
  "description": "My Wallet 1.4, Rust core",
  "kind": "wallet",
  "command": ["./target/release/my-wallet-adapter"],
  "build": "cargo build --release"
}
```

- `command` runs from the adapter's directory.
- `kind` is `wallet`, `library`, `reference` or `example`.
- `build` is shown to people whose adapter binary is missing.

## Requests and responses

Every request has an `id` and an `op`. Echo the `id` in the response. If you don't support an op or profile, answer `{"id": …, "error": {"code": "unsupported"}}`; the lab marks it as skipped, not failed. All byte strings are lowercase hex.

### `hello`

```json
{"id": 1, "op": "hello"}
{"id": 1, "name": "my-wallet", "version": "1.4.0", "ops": ["derive_fvk", "backup_encode", "backup_decode"], "profiles": ["legacy", "zip2005-use-qsk"]}
```

### `derive_fvk`

Derive the group's Orchard full viewing key from the group's shared `sk` and the FROST group key `ak` (32-byte even-y encoding).

```json
{"id": 2, "op": "derive_fvk", "profile": "zip2005-use-qsk", "sk": "<32 bytes>", "ak": "<32 bytes>"}
{"id": 2, "fvk": "<96 bytes>", "nk": "…", "rivk": "…", "default_address_raw": "<43 bytes>", "ufvk_testnet": "uviewtest1…"}
```

`fvk` is required. The other fields are optional; every field you return is compared against the vectors and against other adapters.

| Profile | Meaning |
| --- | --- |
| `legacy` | `nk` and `rivk` from `sk` as in the protocol spec; only `ak` replaced by the group key. Not quantum recoverable. |
| `zip2005-use-qsk` | ZIP 2005 § 4.2.3 with `use_qsk = true`: `rivk = ToScalar(PRF^expand_qk([0x0D] ‖ ak ‖ nk))`. |

### `backup_encode` and `backup_decode`

The `zkfrost` v1 member backup string (bech32m, HRP `zkfrost`, 68 bytes: version, id, t, n, share, sk).

```json
{"id": 3, "op": "backup_encode", "backup": {"id": 1, "t": 2, "n": 3, "share": "<32 bytes>", "sk": "<32 bytes>"}}
{"id": 3, "string": "zkfrost1…"}

{"id": 4, "op": "backup_decode", "string": "zkfrost1…"}
{"id": 4, "backup": {"id": 1, "t": 2, "n": 3, "share": "…", "sk": "…"}}
```

A string you reject must get an error response, e.g. `{"id": 4, "error": {"code": "invalid_params"}}`. The lab checks *that* you reject it; the code is reported but not required to match.

## Planned ops

These are next, and their shape is open for discussion with wallet teams:

- **`frost_commit` / `frost_sign`:** round 1 and round 2 of RedPallas FROST signing with a given randomizer. The lab mixes signers from different implementations in one group and verifies the aggregate signature on a real PCZT.
- **`group_descriptor`:** export and import of the shared group descriptor, once the spec settles.
