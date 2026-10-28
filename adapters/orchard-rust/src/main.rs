//! FROST Interop Lab adapter on the official `orchard` and `zcash_keys` crates.
//!
//! The FVK is built the way Zkool does it (hhanh00/zkool2 rust/src/frost/keys.rs):
//! take the protocol-spec FVK of `sk`, swap in the group `ak`, and for ZIP 2005
//! replace `rivk` with the `use_qsk` value. `FullViewingKey::from_bytes` then
//! validates the result, and the crates compute the default address and UFVK,
//! which the TypeScript and Python adapters can't.
//!
//! FROST signing uses ZF's FROST(Pallas, BLAKE2b-512) ciphersuite from the
//! `reddsa` crate with `frost-rerandomized`, the stack zcash-sign and frost-tools
//! use, and signatures are checked with the `orchard` crate's own RedPallas
//! SpendAuth verifier.

mod spend;

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};

use ff::{FromUniformBytes, PrimeField};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use rand_core::OsRng;
use reddsa::frost::redpallas::{
    self as frost,
    keys::{IdentifierList, KeyPackage, SigningShare, VerifyingShare},
    rerandomized::Randomizer,
    round1::{NonceCommitment, SigningCommitments, SigningNonces},
    Identifier, SigningPackage, VerifyingKey,
};
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
    let fvk = group_fvk(req)?;
    let fvkb = fvk.to_bytes();
    let address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk.clone())
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

/// The group's FVK from `profile`, `sk` and the FROST group key `ak`.
fn group_fvk(req: &Value) -> Result<FullViewingKey, String> {
    let profile = req["profile"].as_str().unwrap_or("");
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
    FullViewingKey::from_bytes(&fvkb).ok_or("FullViewingKey::from_bytes rejected the key".into())
}

fn hex_field(v: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(v[field].as_str().ok_or(format!("missing {field}"))?).map_err(|e| format!("{field}: {e}"))
}

fn identifier(v: &Value, field: &str) -> Result<Identifier, String> {
    let id = v[field].as_u64().filter(|&i| (1..=u16::MAX as u64).contains(&i)).ok_or("id must be 1..65535")?;
    Identifier::try_from(id as u16).map_err(|e| e.to_string())
}

fn frost_keygen(req: &Value) -> Result<Value, String> {
    let t = req["t"].as_u64().ok_or("missing t")? as u16;
    let n = req["n"].as_u64().ok_or("missing n")? as u16;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(n, t, IdentifierList::Default, OsRng)
        .map_err(|e| e.to_string())?;
    let shares: Vec<Value> = shares
        .values()
        .map(|s| {
            let id = s.identifier().serialize();
            let vs = pubkeys.verifying_shares()[s.identifier()].serialize().unwrap();
            json!({"id": u16::from_le_bytes([id[0], id[1]]), "signing_share": hex::encode(s.signing_share().serialize()), "verifying_share": hex::encode(vs)})
        })
        .collect();
    Ok(json!({"group_key": hex::encode(pubkeys.verifying_key().serialize().map_err(|e| e.to_string())?), "shares": shares}))
}

fn frost_commit(req: &Value, nonces: &mut HashMap<String, SigningNonces>) -> Result<Value, String> {
    let share = SigningShare::deserialize(&hex_field(req, "signing_share")?).map_err(|e| e.to_string())?;
    let session = req["session"].as_str().ok_or("missing session")?;
    let (n, c) = frost::round1::commit(&share, &mut OsRng);
    nonces.insert(format!("{session}/{}", req["participant"]), n);
    Ok(json!({
        "hiding": hex::encode(c.hiding().serialize().map_err(|e| e.to_string())?),
        "binding": hex::encode(c.binding().serialize().map_err(|e| e.to_string())?),
    }))
}

fn frost_sign(req: &Value, nonces: &mut HashMap<String, SigningNonces>) -> Result<Value, String> {
    let session = req["session"].as_str().ok_or("missing session")?;
    let my_nonces = nonces.remove(&format!("{session}/{}", req["participant"])).ok_or("no round-1 nonces for this session and id")?;
    let share = SigningShare::deserialize(&hex_field(req, "signing_share")?).map_err(|e| e.to_string())?;
    let group_key = VerifyingKey::deserialize(&hex_field(req, "group_key")?).map_err(|e| e.to_string())?;
    let commitments = req["commitments"].as_array().ok_or("missing commitments")?;
    let mut map = BTreeMap::new();
    for c in commitments {
        let hiding = NonceCommitment::deserialize(&hex_field(c, "hiding")?).map_err(|e| e.to_string())?;
        let binding = NonceCommitment::deserialize(&hex_field(c, "binding")?).map_err(|e| e.to_string())?;
        map.insert(identifier(c, "id")?, SigningCommitments::new(hiding, binding));
    }
    let package = SigningPackage::new(map, &hex_field(req, "message")?);
    let key_package = KeyPackage::new(identifier(req, "participant")?, share, VerifyingShare::from(share), group_key, commitments.len() as u16);
    let randomizer = Randomizer::deserialize(&hex_field(req, "randomizer")?).map_err(|e| e.to_string())?;
    // An Orchard spend's randomizer α is fixed by the transaction builder (it is in
    // the PCZT), so sign with it directly rather than deriving one from a seed.
    #[allow(deprecated)]
    let z = frost_rerandomized::sign(&package, &my_nonces, &key_package, randomizer).map_err(|e| e.to_string())?;
    Ok(json!({"signature_share": hex::encode(z.serialize())}))
}

fn redpallas_verify(req: &Value) -> Result<Value, String> {
    let rk: [u8; 32] = hex_field(req, "rk")?.try_into().map_err(|_| "rk must be 32 bytes")?;
    let sig: [u8; 64] = hex_field(req, "signature")?.try_into().map_err(|_| "signature must be 64 bytes")?;
    let valid = VerificationKey::<SpendAuth>::try_from(rk)
        .map(|vk| vk.verify(&hex_field(req, "message").unwrap_or_default(), &Signature::from(sig)).is_ok())
        .unwrap_or(false);
    Ok(json!({"valid": valid}))
}

#[derive(Default)]
struct State {
    nonces: HashMap<String, SigningNonces>,
    spends: spend::Spends,
}

fn handle(req: &Value, state: &mut State) -> Value {
    let session = req["session"].as_str().unwrap_or("");
    let result = match req["op"].as_str() {
        Some("frost_keygen") => frost_keygen(req),
        Some("frost_commit") => frost_commit(req, &mut state.nonces),
        Some("frost_sign") => frost_sign(req, &mut state.nonces),
        Some("orchard_spend_prepare") => group_fvk(req).and_then(|fvk| state.spends.prepare(session, fvk)),
        Some("orchard_spend_finish") => hex_field(req, "signature")
            .and_then(|s| s.try_into().map_err(|_| "signature must be 64 bytes".to_string()))
            .and_then(|s| state.spends.finish(session, s)),
        Some("redpallas_verify") => redpallas_verify(req),
        _ => return handle_keys(req),
    };
    result.unwrap_or_else(|e| json!({"error": {"code": "invalid_input", "message": e}}))
}

fn handle_keys(req: &Value) -> Value {
    match req["op"].as_str() {
        Some("hello") => json!({
            "name": "orchard-rust",
            "version": env!("CARGO_PKG_VERSION"),
            "ops": ["derive_fvk", "frost_keygen", "frost_commit", "frost_sign", "redpallas_verify", "orchard_spend_prepare", "orchard_spend_finish"],
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
    let mut state = State::default();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let mut res = handle(&req, &mut state);
        res["id"] = req["id"].clone();
        let _ = writeln!(out, "{res}");
        let _ = out.flush();
    }
}
