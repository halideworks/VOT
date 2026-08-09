//! Witness statements and their signatures.

use super::{
    AuthScheme, Error, Signature, Signer, SigningKey, VerifyingKey, valid_rfc3339, validate_key_id,
};

/// A witness statement: an independent party recording that it saw a chain head
/// at its own clock time.
///
/// Anchors a chain against issuer rewrites: the witness timestamp is outside
/// the issuer's control, so re-signing observations cannot move it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessStatement {
    /// Envelope digest of the observation being witnessed.
    pub head: [u8; 32],
    /// The witness's own observation time, not the issuer's.
    pub observed_at: String,
    pub key_id: Vec<u8>,
}

/// A witness statement with its signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessSignature {
    pub statement: WitnessStatement,
    pub scheme: AuthScheme,
    pub authentication: Vec<u8>,
}

pub(super) const WITNESS_DOMAIN: &[u8] = b"VOT witness v0\0";

impl WitnessStatement {
    /// # Errors
    /// Rejects an invalid timestamp or key identifier.
    pub fn validate(&self) -> Result<(), Error> {
        validate_key_id(&self.key_id)?;
        if !valid_rfc3339(&self.observed_at) {
            return Err(Error::InvalidTimestamp);
        }
        Ok(())
    }

    /// Deterministic bytes a witness signature covers.
    ///
    /// # Errors
    /// Propagates validation failures.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut output = Vec::with_capacity(WITNESS_DOMAIN.len() + 96);
        output.extend_from_slice(WITNESS_DOMAIN);
        vot_cbor::map(&mut output, 3);
        vot_cbor::uint(&mut output, 0);
        vot_cbor::bytes(&mut output, &self.head);
        vot_cbor::uint(&mut output, 1);
        vot_cbor::text(&mut output, &self.observed_at);
        vot_cbor::uint(&mut output, 2);
        vot_cbor::bytes(&mut output, &self.key_id);
        Ok(output)
    }
}

/// Signs a witness statement.
///
/// # Errors
/// Rejects an invalid statement.
pub fn witness_ed25519(
    statement: WitnessStatement,
    key: &SigningKey,
) -> Result<WitnessSignature, Error> {
    let bytes = statement.canonical_bytes()?;
    let authentication = key.sign(&bytes).to_bytes().to_vec();
    Ok(WitnessSignature {
        statement,
        scheme: AuthScheme::Ed25519,
        authentication,
    })
}

/// Verifies one witness signature over the head it claims.
///
/// # Errors
/// Rejects a statement about a different head, a non-Ed25519 witness, or a
/// signature that does not verify.
pub fn verify_witness(
    signature: &WitnessSignature,
    head: &[u8; 32],
    key: &VerifyingKey,
) -> Result<(), Error> {
    if signature.statement.head != *head {
        return Err(Error::WitnessHeadMismatch);
    }
    if signature.scheme != AuthScheme::Ed25519 {
        // A witness a relying party cannot check without also being able to
        // forge is not a witness.
        return Err(Error::UnexpectedScheme);
    }
    let bytes: [u8; 64] = signature
        .authentication
        .as_slice()
        .try_into()
        .map_err(|_| Error::Authentication)?;
    key.verify_strict(
        &signature.statement.canonical_bytes()?,
        &Signature::from_bytes(&bytes),
    )
    .map_err(|_| Error::Authentication)
}
