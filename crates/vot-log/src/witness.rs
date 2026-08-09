//! Witness keys, signing, and threshold verification.

use super::{
    Error, NoteSignature, Signature, SignedCheckpoint, Signer, SigningKey, VerifyingKey,
    note_key_hash, valid_note_name,
};

/// Adds a signature over a checkpoint body. Same call for log operator or
/// witness; the format makes no distinction.
///
/// # Errors
/// Rejects a malformed origin or signer name.
pub fn sign_checkpoint(
    signed: &mut SignedCheckpoint,
    name: &str,
    key: &SigningKey,
) -> Result<(), Error> {
    if !valid_note_name(name) {
        return Err(Error::Malformed);
    }
    let body = signed.checkpoint.body()?;
    let public = key.verifying_key().to_bytes();
    signed.signatures.push(NoteSignature {
        name: name.to_owned(),
        key_hash: note_key_hash(name, &public),
        signature: key.sign(body.as_bytes()).to_bytes().to_vec(),
    });
    Ok(())
}

/// A key a relying party is willing to accept as a witness.
#[derive(Clone, Debug)]
pub struct WitnessKey {
    pub name: String,
    pub key: VerifyingKey,
}

/// Checks a checkpoint against a witness policy. Returns verifying names.
/// Unknown signers are ignored, not rejected.
///
/// # Errors
/// Rejects a malformed checkpoint, or one carrying fewer distinct accepted
/// witnesses than `required`.
pub fn verify_checkpoint(
    signed: &SignedCheckpoint,
    witnesses: &[WitnessKey],
    required: usize,
) -> Result<Vec<String>, Error> {
    let body = signed.checkpoint.body()?;
    // Counted once per name and per key to prevent aliasing.
    let mut accepted: Vec<(String, [u8; 32])> = Vec::new();
    for signature in &signed.signatures {
        let bytes: [u8; 64] = match signature.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        for witness in witnesses {
            if witness.name != signature.name {
                continue;
            }
            // The key hash binds the name to the key, so a signature cannot be
            // moved to a signer whose name a verifier happens to accept.
            if note_key_hash(&witness.name, &witness.key.to_bytes()) != signature.key_hash {
                continue;
            }
            let public = witness.key.to_bytes();
            if witness
                .key
                .verify_strict(body.as_bytes(), &Signature::from_bytes(&bytes))
                .is_ok()
                && !accepted
                    .iter()
                    .any(|(name, seen)| *seen == public || *name == witness.name)
            {
                accepted.push((witness.name.clone(), public));
            }
        }
    }
    if accepted.len() < required {
        return Err(Error::Unwitnessed);
    }
    Ok(accepted.into_iter().map(|(name, _)| name).collect())
}
