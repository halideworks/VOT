//! Token signature preimage and signature operations.

use super::{
    Capability, DOMAIN, Error, FORMAT_ID, Signature, SignedCapability, Signer, SigningKey,
    VerifyingKey, validate_key_id,
};

/// What an issuer signs, and what a verifier checks against. The domain and
/// format identifier are bound in so signatures cannot be repurposed.
///
/// # Errors
/// Rejects a key identifier outside its bounds.
pub fn signing_input(key_id: &[u8], capability: &[u8]) -> Result<Vec<u8>, Error> {
    validate_key_id(key_id)?;
    let key_id_len = u8::try_from(key_id.len()).map_err(|_| Error::InvalidKeyId)?;
    let mut input = Vec::with_capacity(DOMAIN.len() + 3 + key_id.len() + capability.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&FORMAT_ID.to_be_bytes());
    input.push(key_id_len);
    input.extend_from_slice(key_id);
    input.extend_from_slice(capability);
    Ok(input)
}

/// Signs a capability under an issuer key.
///
/// # Errors
/// Rejects a capability the format does not allow and a key identifier outside
/// its bounds.
pub fn sign(
    capability: &Capability,
    key_id: &[u8],
    key: &SigningKey,
) -> Result<SignedCapability, Error> {
    let bytes = capability.canonical_bytes()?;
    let input = signing_input(key_id, &bytes)?;
    Ok(SignedCapability {
        key_id: key_id.to_vec(),
        capability: bytes,
        signature: key.sign(&input).to_bytes(),
    })
}

/// Checks the signature over a capability under one issuer key. Only confirms
/// the bytes came from that key; trust is the verifier's decision.
///
/// # Errors
/// Rejects a key identifier outside its bounds and a signature that does not
/// verify.
pub fn verify_signature(signed: &SignedCapability, key: &VerifyingKey) -> Result<(), Error> {
    let input = signing_input(&signed.key_id, &signed.capability)?;
    // verify_strict rejects low-order/torsion keys so one signature cannot
    // verify under two.
    key.verify_strict(&input, &Signature::from_bytes(&signed.signature))
        .map_err(|_| Error::Signature)
}
