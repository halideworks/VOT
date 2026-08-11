//! Authentication schemes and their signature operations.

use super::{
    DOMAIN, Digest, Error, Receipt, Sha256, Signature, Signer, SigningKey, VerifiedBy,
    VerifiedReceipt, VerifyingKey, encode_authenticated,
};
#[cfg(any(feature = "hmac", test))]
use super::{Hmac, KeyInit, Mac};

/// Registered receipt authentication schemes.
///
/// Ed25519 is the default: a receipt is evidence for a third party, and a
/// symmetric MAC is forgeable by anyone who can verify it. HMAC is registered
/// for traffic that never leaves one trust domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthScheme {
    Ed25519 = 1,
    HmacSha256 = 2,
}

impl AuthScheme {
    #[must_use]
    pub const fn authenticator_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::HmacSha256 => 32,
        }
    }

    pub(super) const fn from_registry(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Ed25519),
            2 => Some(Self::HmacSha256),
            _ => None,
        }
    }

    /// Whether a receipt under this scheme can be checked by a party that
    /// cannot also produce one.
    #[must_use]
    pub const fn is_third_party_verifiable(self) -> bool {
        matches!(self, Self::Ed25519)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReceipt {
    pub receipt: Receipt,
    pub scheme: AuthScheme,
    pub key_id: Vec<u8>,
    pub authentication: Vec<u8>,
}

impl AuthenticatedReceipt {
    /// Digest of the encoded envelope, which is what a chain link or a witness
    /// statement commits to.
    ///
    /// # Errors
    /// Propagates an invalid receipt or key identifier.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        let mut hasher = Sha256::new();
        hasher.update(encode_authenticated(self)?);
        Ok(hasher.finalize().into())
    }
}

/// Bytes an authenticator covers: domain, scheme, then the canonical receipt.
///
/// The scheme and key identifier are inside the signed input. Scheme binding
/// prevents replay under another scheme; the key identifier acts as a context
/// label, so a receipt cannot be relabelled without breaking the signature.
/// Length-prefixed so no identifier can be read as the start of the receipt.
pub(super) fn signing_input(
    scheme: AuthScheme,
    key_id: &[u8],
    receipt: &Receipt,
) -> Result<Vec<u8>, Error> {
    validate_key_id(key_id)?;
    let key_id_len = u8::try_from(key_id.len()).map_err(|_| Error::InvalidKeyId)?;
    let canonical = receipt.canonical_bytes()?;
    let mut input = Vec::with_capacity(DOMAIN.len() + 3 + key_id.len() + canonical.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&(scheme as u16).to_be_bytes());
    input.push(key_id_len);
    input.extend_from_slice(key_id);
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub(super) fn validate_key_id(key_id: &[u8]) -> Result<(), Error> {
    if key_id.is_empty() || key_id.len() > 64 {
        Err(Error::InvalidKeyId)
    } else {
        Ok(())
    }
}

/// Signs a receipt so a party holding only the public key can check it.
///
/// # Errors
/// Rejects an invalid receipt or key identifier.
pub fn sign_ed25519(
    receipt: Receipt,
    key_id: &[u8],
    key: &SigningKey,
) -> Result<AuthenticatedReceipt, Error> {
    let input = signing_input(AuthScheme::Ed25519, key_id, &receipt)?;
    let signature = key.sign(&input);
    Ok(AuthenticatedReceipt {
        receipt,
        scheme: AuthScheme::Ed25519,
        key_id: key_id.to_vec(),
        authentication: signature.to_bytes().to_vec(),
    })
}

/// Verifies an Ed25519 receipt against an issuer public key.
///
/// # Errors
/// Rejects a receipt authenticated under another scheme, a malformed
/// signature, or one that does not verify.
pub fn verify_ed25519(
    receipt: &AuthenticatedReceipt,
    key: &VerifyingKey,
) -> Result<VerifiedReceipt, Error> {
    if receipt.scheme != AuthScheme::Ed25519 {
        return Err(Error::UnexpectedScheme);
    }
    let bytes: [u8; 64] = receipt
        .authentication
        .as_slice()
        .try_into()
        .map_err(|_| Error::Authentication)?;
    let input = signing_input(AuthScheme::Ed25519, &receipt.key_id, &receipt.receipt)?;
    // verify_strict rejects signatures under low-order or torsion public keys,
    // so one signature cannot verify under two different keys.
    key.verify_strict(&input, &Signature::from_bytes(&bytes))
        .map_err(|_| Error::Authentication)?;
    Ok(VerifiedReceipt {
        authenticated: receipt.clone(),
        by: VerifiedBy::Ed25519(Box::new(key.to_bytes())),
    })
}

/// Authenticates a receipt with a shared secret.
///
/// Only sound inside one trust domain: a holder of the key can forge as well as
/// check. Cross-boundary receipts use [`sign_ed25519`].
///
/// # Errors
/// Rejects an invalid receipt, key identifier, or short key.
#[cfg(any(feature = "hmac", test))]
pub fn authenticate_hmac_sha256(
    receipt: Receipt,
    key_id: &[u8],
    key: &[u8],
) -> Result<AuthenticatedReceipt, Error> {
    if key.len() < 32 {
        return Err(Error::InvalidKey);
    }
    let input = signing_input(AuthScheme::HmacSha256, key_id, &receipt)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    mac.update(&input);
    let authentication = mac.finalize().into_bytes().to_vec();
    Ok(AuthenticatedReceipt {
        receipt,
        scheme: AuthScheme::HmacSha256,
        key_id: key_id.to_vec(),
        authentication,
    })
}

/// # Errors
/// Rejects a receipt authenticated under another scheme, a short key, or a MAC
/// that does not verify.
#[cfg(any(feature = "hmac", test))]
pub fn verify_hmac_sha256(
    receipt: &AuthenticatedReceipt,
    key: &[u8],
) -> Result<VerifiedReceipt, Error> {
    if receipt.scheme != AuthScheme::HmacSha256 {
        return Err(Error::UnexpectedScheme);
    }
    if key.len() < 32 {
        return Err(Error::InvalidKey);
    }
    let input = signing_input(AuthScheme::HmacSha256, &receipt.key_id, &receipt.receipt)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    mac.update(&input);
    mac.verify_slice(&receipt.authentication)
        .map_err(|_| Error::Authentication)?;
    Ok(VerifiedReceipt {
        authenticated: receipt.clone(),
        by: VerifiedBy::HmacSha256,
    })
}
