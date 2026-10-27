//! FROST Interop Lab adapter on the official `orchard` and `zcash_keys` crates.
//!
//! The FVK is built the way Zkool does it (hhanh00/zkool2 rust/src/frost/keys.rs):
//! take the protocol-spec FVK of `sk`, swap in the group `ak`, and for ZIP 2005
//! replace `rivk` with the `use_qsk` value. `FullViewingKey::from_bytes` then
//! validates the result, and the crates compute the default address and UFVK,
//! which the TypeScript and Python adapters can't.

use std::io::{self, BufRead, Write};

use ff::{FromUniformBytes, PrimeField};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use pasta_curves::pallas;
use serde_json::{json, Value};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

const QK_CONTEXT: &str = "Zcash ZIP 2005 qk-derivation v1";

fn prf_expand(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();
    state.update(key);
    for p in parts {
        state.update(p);
    }
    *state.finalize().as_array()
}

fn bytes32(v: &Value, field: &str) -> Result<[u8; 32], String> {
    let s = v[field].as_str().ok_or(format!("missing {field}"))?;
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes"))
}

fn derive_fvk(req: &Value) -> Result<Value, String> {
    let profile = req["profile"].as_str().unwrap_or("");
    if profile != "legacy" && profile != "zip2005-use-qsk" {
        return Ok(json!({"error": {"code": "unsupported"}}));
    }
    let sk_bytes = bytes32(req, "sk")?;
    let ak = bytes32(req, "ak")?;
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).ok_or("invalid sk")?;

    let mut fvkb = FullViewingKey::from(&sk).to_bytes();
    fvkb[0..32].copy_from_slice(&ak);
    if profile == "zip2005-use-qsk" {
        let nk: [u8; 32] = fvkb[32..64].try_into().unwrap();
        let qsk: [u8; 32] = prf_expand(&sk_bytes, &[&[0x0c]])[..32].try_into().unwrap();
        let qk = blake3::derive_key(QK_CONTEXT, &qsk);
        let rivk = pallas::Scalar::from_uniform_bytes(&prf_expand(&qk, &[&[0x0d], &ak, &nk])).to_repr();
        fvkb[64..96].copy_from_slice(&rivk);
    }
    let fvk = FullViewingKey::from_bytes(&fvkb).ok_or("FullViewingKey::from_bytes rejected the key")?;
    let address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let ufvk = UnifiedFullViewingKey::new(None, Some(fvk.clone()))
        .map_err(|e| format!("{e:?}"))?
        .encode(&Network::TestNetwork);
    Ok(json!({
        "fvk": hex::encode(fvkb),
        "nk": hex::encode(&fvkb[32..64]),
        "rivk": hex::encode(&fvkb[64..96]),
        "default_address_raw": hex::encode(address),
        "ufvk_testnet": ufvk,
    }))
}

fn handle(req: &Value) -> Value {
    match req["op"].as_str() {
        Some("hello") => json!({
            "name": "orchard-rust",
            "version": env!("CARGO_PKG_VERSION"),
            "ops": ["derive_fvk"],
            "profiles": ["legacy", "zip2005-use-qsk"],
        }),
        Some("derive_fvk") => derive_fvk(req)
            .unwrap_or_else(|e| json!({"error": {"code": "invalid_input", "message": e}})),
        _ => json!({"error": {"code": "unsupported"}}),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let mut res = handle(&req);
        res["id"] = req["id"].clone();
        let _ = writeln!(out, "{res}");
        let _ = out.flush();
    }
}
