//! A real Orchard spend authorized by a FROST group, using the orchard crate's
//! PCZT roles (the flow zcash-sign and frost-tools use).
//!
//! `orchard_spend_prepare` builds a bundle that spends a note held by the
//! group's address, creates the Halo2 proof and signs the dummy actions, then
//! hands back the sighash, the spend's randomizer α and rk = ak + [α]G for the
//! FROST group to sign. `orchard_spend_finish` applies the group's signature,
//! adds the binding signature and runs the orchard crate's BatchValidator:
//! proof, every spend authorization signature and the binding signature.
//!
//! The spent note sits alone in a locally built commitment tree, so the bundle
//! is valid against that anchor; it has not been mined, so it can't be
//! broadcast. Everything else is what a wallet would put on chain.

use std::collections::HashMap;

use ff::{Field, PrimeField};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BatchValidator, BundleVersion, Flags, TxVersion},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    primitives::redpallas::Signature,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Note, NOTE_COMMITMENT_TREE_DEPTH,
};
use pasta_curves::pallas;
use rand_core::OsRng;
use serde_json::{json, Value};

const VERSION: BundleVersion = BundleVersion::orchard_v2();
const CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::FixedPostNu6_2;
const NOTE_VALUE: u64 = 100_000; // 0.001 ZEC
const FEE: u64 = 10_000;

pub struct Pending {
    pczt: orchard::pczt::Bundle,
    sighash: [u8; 32],
    action: usize,
}

#[derive(Default)]
pub struct Spends {
    pk: Option<ProvingKey>,
    vk: Option<VerifyingKey>,
    pending: HashMap<String, Pending>,
}

/// A note of NOTE_VALUE to the group's address, alone in a fresh commitment tree.
fn note_in_tree(fvk: &FullViewingKey) -> Result<(Note, MerklePath), String> {
    let recipient = fvk.address_at(0u32, Scope::External);
    let note = loop {
        let rho = Option::<Rho>::from(Rho::from_bytes(&pallas::Base::random(OsRng).to_repr())).ok_or("rho")?;
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(seed, &rho)) else { continue };
        if let Some(note) = Option::<Note>::from(Note::from_parts(recipient, NoteValue::from_raw(NOTE_VALUE), rho, rseed, VERSION.note_version())) {
            break note;
        }
    };
    let auth_path: [MerkleHashOrchard; NOTE_COMMITMENT_TREE_DEPTH] =
        core::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8)));
    Ok((note, MerklePath::from_parts(0, auth_path)))
}

impl Spends {
    pub fn prepare(&mut self, session: &str, fvk: FullViewingKey) -> Result<Value, String> {
        let (note, path) = note_in_tree(&fvk)?;
        let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));
        let change = fvk.address_at(0u32, Scope::Internal);

        let mut builder = Builder::new(BundleType::DEFAULT, VERSION, Flags::ENABLED, anchor).map_err(|e| format!("builder: {e:?}"))?;
        builder.add_spend(fvk.clone(), note, path).map_err(|e| format!("add_spend: {e:?}"))?;
        builder
            .add_output(None, change, NoteValue::from_raw(NOTE_VALUE - FEE), [0u8; 512])
            .map_err(|e| format!("add_output: {e:?}"))?;
        let (mut pczt, _) = builder.build_for_pczt(OsRng).map_err(|e| format!("build: {e:?}"))?;

        let pk = self.pk.get_or_insert_with(|| ProvingKey::build(CIRCUIT));
        pczt.create_proof(pk, OsRng).map_err(|e| format!("proof: {e:?}"))?;

        // The spend authorization signatures sign the bundle's ZIP 244 digest.
        let effects = pczt.extract_effects::<i64>().map_err(|e| format!("effects: {e:?}"))?.ok_or("empty bundle")?;
        let sighash: [u8; 32] = effects.commitment(TxVersion::V5).map_err(|e| format!("digest: {e:?}"))?.0.as_bytes().try_into().unwrap();
        pczt.finalize_io(sighash, OsRng).map_err(|e| format!("finalize_io: {e:?}"))?;

        let action = pczt
            .actions()
            .iter()
            .position(|a| a.spend().value().map(|v| v.inner()) == Some(NOTE_VALUE))
            .ok_or("spend action not found")?;
        let spend = pczt.actions()[action].spend();
        let alpha = spend.alpha().ok_or("missing alpha")?;
        let rk: [u8; 32] = spend.rk().into();
        let actions = pczt.actions().len();
        self.pending.insert(session.to_owned(), Pending { pczt, sighash, action });
        Ok(json!({
            "sighash": hex::encode(sighash),
            "randomizer": hex::encode(alpha.to_repr()),
            "rk": hex::encode(rk),
            "actions": actions,
            "value": NOTE_VALUE,
            "fee": FEE,
        }))
    }

    pub fn finish(&mut self, session: &str, signature: [u8; 64]) -> Result<Value, String> {
        let Pending { mut pczt, sighash, action } = self.pending.remove(session).ok_or("no prepared spend for this session")?;
        if pczt.actions_mut()[action].apply_signature(sighash, Signature::from(signature)).is_err() {
            return Ok(json!({"valid": false, "stage": "spend authorization signature rejected by the orchard crate"}));
        }
        let unbound = pczt.extract::<i64>().map_err(|e| format!("extract: {e:?}"))?.ok_or("empty bundle")?;
        let bundle = unbound.apply_binding_signature(sighash, OsRng).ok_or("binding signature")?;

        let vk = self.vk.get_or_insert_with(|| VerifyingKey::build(CIRCUIT));
        let mut validator = BatchValidator::new(vk);
        validator.add_bundle(&bundle, sighash).map_err(|e| format!("validator: {e:?}"))?;
        let valid = validator.validate(OsRng);
        Ok(json!({
            "valid": valid,
            "stage": if valid { "proof, spend authorization and binding signatures all valid" } else { "BatchValidator rejected the bundle" },
            "actions": bundle.actions().len(),
            "nullifier": hex::encode(bundle.actions()[action].nullifier().to_bytes()),
            "proof_bytes": bundle.authorization().proof().as_ref().len(),
        }))
    }
}
