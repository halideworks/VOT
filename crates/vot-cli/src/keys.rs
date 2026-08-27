//! Key grammar, key material, and capability issuance.

use crate::{
    AuthenticatedReceipt, Error, File, Path, PathBuf, Read, SigningKey, VerifyingKey,
    authenticate_hmac_sha256, authz, hex_of, io, parse_package_root, sign_ed25519, verify_ed25519,
    verify_hmac_sha256, write_new_synced,
};

/// The certificate and key a server presents.
///
/// The certificate is ephemeral and unverified; assurance comes from the
/// proof chain, not the channel. TLS 1.3 has no anonymous mode, so one is
/// generated per process unless the caller supplies its own.
pub enum Credentials {
    /// Generated for this process, thrown away with it.
    Ephemeral,
    /// PEM files the caller supplied, for a server behind a name someone
    /// does verify.
    Files { certificate: PathBuf, key: PathBuf },
}

/// Mints a capability for one package and writes it.
///
/// ADR-0036. The token says who issued it, which deployment it is for, whose
/// key may spend it, which package, and for how long. Everything a serve
/// checks is in here or in the issuer key it was configured with.
///
/// # Errors
/// Rejects a key source that is not an Ed25519 secret for the issuer or an
/// Ed25519 public key for the holder, a root that is not one, a validity of
/// no length, and a destination that already exists.
pub fn issue_capability(
    issuer_source: &str,
    issuer: &str,
    audience: &str,
    holder_source: &str,
    root: &str,
    seconds: &str,
    out: &Path,
) -> Result<(), Error> {
    let KeyMaterial::Signing(issuer_key) = load_key_spec(issuer_source)? else {
        return Err(Error::InvalidArguments);
    };
    let KeyMaterial::Verifying(holder_key) = load_key_spec(holder_source)? else {
        return Err(Error::InvalidArguments);
    };
    let token = authz::issue(
        issuer,
        audience,
        &issuer_key,
        holder_key.to_bytes(),
        parse_package_root(root)?,
        authz::now_seconds()?,
        seconds.parse().map_err(|_| Error::InvalidArguments)?,
    )?;
    write_new_synced(out, &token)
}

/// Mints a capability for pushing one exact package and writes it.
#[expect(
    clippy::too_many_arguments,
    reason = "the CLI helper takes the command's eight required operands"
)]
pub fn issue_push_capability(
    issuer_source: &str,
    issuer: &str,
    audience: &str,
    holder_source: &str,
    root: &str,
    length: &str,
    seconds: &str,
    out: &Path,
) -> Result<(), Error> {
    let KeyMaterial::Signing(issuer_key) = load_key_spec(issuer_source)? else {
        return Err(Error::InvalidArguments);
    };
    let KeyMaterial::Verifying(holder_key) = load_key_spec(holder_source)? else {
        return Err(Error::InvalidArguments);
    };
    let token = authz::issue_push(
        issuer,
        audience,
        &issuer_key,
        holder_key.to_bytes(),
        parse_package_root(root)?,
        length.parse().map_err(|_| Error::InvalidArguments)?,
        authz::now_seconds()?,
        seconds.parse().map_err(|_| Error::InvalidArguments)?,
    )?;
    write_new_synced(out, &token)
}

/// Loads a capability and the private holder key it names.
pub fn load_capability_holder(
    capability: &Path,
    key_source: &str,
) -> Result<std::sync::Arc<authz::Holder>, Error> {
    let KeyMaterial::Signing(key) = load_key_spec(key_source)? else {
        return Err(Error::InvalidArguments);
    };
    Ok(std::sync::Arc::new(authz::Holder::new(
        std::fs::read(capability)?,
        *key,
    )?))
}

/// A fresh Ed25519 keypair, as the two `KEY_SOURCE` strings it is used as.
///
/// The holder of a capability needs a key before one can be issued to them,
/// and nothing else here makes one.
///
/// # Errors
/// Reports [`Error::Randomness`] when the system will not give 32 bytes.
pub fn generate_keypair() -> Result<(String, String), Error> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::Randomness)?;
    let key = SigningKey::from_bytes(&seed);
    Ok((
        format!("ed25519-secret:{}", hex_of(&key.to_bytes())),
        format!("ed25519-public:{}", hex_of(&key.verifying_key().to_bytes())),
    ))
}

/// What a loaded key can do.
///
/// A shared secret can sign and verify, but only inside one trust domain: a
/// holder can forge as well as check. A signing key produces receipts anyone
/// with the public half can check. A verifying key can only check, which is
/// exactly the auditor's position and the case the product exists for.
#[derive(Clone, Debug)]
pub enum KeyMaterial {
    Signing(Box<SigningKey>),
    Verifying(Box<VerifyingKey>),
    Shared(Vec<u8>),
}

impl KeyMaterial {
    /// Whether a receipt made with this key can be checked by a party that
    /// cannot also produce one.
    #[must_use]
    pub const fn is_third_party_verifiable(&self) -> bool {
        matches!(self, Self::Signing(_) | Self::Verifying(_))
    }

    pub(crate) fn sign(
        &self,
        receipt: vot_receipt::Receipt,
    ) -> Result<AuthenticatedReceipt, Error> {
        match self {
            Self::Signing(key) => Ok(sign_ed25519(receipt, KEY_ID, key)?),
            Self::Shared(secret) => Ok(authenticate_hmac_sha256(receipt, KEY_ID, secret)?),
            // Publishing needs a private key. Failing here beats writing a
            // receipt nobody can check.
            Self::Verifying(_) => Err(Error::InvalidArguments),
        }
    }

    pub(crate) fn verify(&self, authenticated: &AuthenticatedReceipt) -> Result<(), Error> {
        match self {
            Self::Signing(key) => verify_ed25519(authenticated, &key.verifying_key()),
            Self::Verifying(key) => verify_ed25519(authenticated, key),
            Self::Shared(secret) => verify_hmac_sha256(authenticated, secret),
        }
        .map(drop)
        .map_err(|_| Error::InvalidBundle)
    }
}

pub(crate) const KEY_ID: &[u8] = b"vot-cli";
pub(crate) const ED25519_KEY_BYTES: usize = 32;
pub(crate) const SECRET_KEY_PREFIX: &str = "ed25519-secret:";
pub(crate) const PUBLIC_KEY_PREFIX: &str = "ed25519-public:";
pub(crate) const MIN_HMAC_KEY_BYTES: usize = 32;
pub(crate) const MAX_HMAC_KEY_BYTES: usize = 64;
pub(crate) const HEX_KEY_PREFIX: &str = "hex:";
pub(crate) const RAW_KEY_PREFIX: &str = "raw:";
pub(crate) const MAX_KEY_SOURCE_BYTES: usize = SECRET_KEY_PREFIX.len() + 2 * MAX_HMAC_KEY_BYTES + 1;

pub fn decode_key(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) || value.len() > 2 * MAX_HMAC_KEY_BYTES {
        return Err(Error::InvalidArguments);
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex(pair[0]).ok_or(Error::InvalidArguments)?;
        let low = hex(pair[1]).ok_or(Error::InvalidArguments)?;
        output.push(high * 16 + low);
    }
    if !(MIN_HMAC_KEY_BYTES..=MAX_HMAC_KEY_BYTES).contains(&output.len()) {
        return Err(Error::InvalidArguments);
    }
    Ok(output)
}

pub(crate) const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Loads an HMAC key without putting the key bytes in the process argument list.
///
/// The source is one of:
/// - `env:NAME` for an environment variable;
/// - `-` for stdin; or
/// - a filesystem path.
///
/// Both raw keys and hexadecimal text files are accepted. Raw input is
/// preserved byte-for-byte; hexadecimal text must use the explicit hex:
/// prefix, and textual raw keys may use raw:. Keys must contain 32..=64
/// bytes. Source reads are bounded to `MAX_KEY_SOURCE_BYTES` bytes.
pub fn load_key_spec(spec: &str) -> Result<KeyMaterial, Error> {
    let bytes = if let Some(name) = spec.strip_prefix("env:") {
        if name.is_empty() {
            return Err(Error::InvalidArguments);
        }
        let value = std::env::var(name).map_err(|_| Error::InvalidArguments)?;
        validate_key_source_length(value.len())?;
        value.into_bytes()
    } else if spec == "-" {
        read_key_source(io::stdin().lock())?
    } else {
        read_key_source(File::open(spec)?)?
    };
    parse_loaded_key(bytes)
}

pub(crate) fn validate_key_source_length(length: usize) -> Result<(), Error> {
    if length > MAX_KEY_SOURCE_BYTES {
        Err(Error::InvalidArguments)
    } else {
        Ok(())
    }
}

pub(crate) fn read_key_source(reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_KEY_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    validate_key_source_length(bytes.len())?;
    Ok(bytes)
}

pub(crate) fn parse_loaded_key(bytes: Vec<u8>) -> Result<KeyMaterial, Error> {
    if let Ok(text) = std::str::from_utf8(&bytes) {
        // An Ed25519 key is labelled, because 32 bytes of secret and 32 bytes
        // of public key are indistinguishable and using one as the other would
        // either leak a secret or produce receipts nobody can check.
        if let Some(encoded) = text.strip_prefix(SECRET_KEY_PREFIX) {
            let seed = decode_fixed_key(encoded.trim())?;
            return Ok(KeyMaterial::Signing(Box::new(SigningKey::from_bytes(
                &seed,
            ))));
        }
        if let Some(encoded) = text.strip_prefix(PUBLIC_KEY_PREFIX) {
            let public = decode_fixed_key(encoded.trim())?;
            let key = VerifyingKey::from_bytes(&public).map_err(|_| Error::InvalidArguments)?;
            return Ok(KeyMaterial::Verifying(Box::new(key)));
        }
        if let Some(encoded) = text.strip_prefix(HEX_KEY_PREFIX) {
            return Ok(KeyMaterial::Shared(decode_key(encoded.trim())?));
        }
        if let Some(raw) = text.strip_prefix(RAW_KEY_PREFIX) {
            return Ok(KeyMaterial::Shared(validate_loaded_key(
                raw.as_bytes().to_vec(),
            )?));
        }
    }
    Ok(KeyMaterial::Shared(validate_loaded_key(bytes)?))
}

/// Decodes exactly one Ed25519 key's worth of hex.
pub(crate) fn decode_fixed_key(value: &str) -> Result<[u8; ED25519_KEY_BYTES], Error> {
    if value.len() != 2 * ED25519_KEY_BYTES {
        return Err(Error::InvalidArguments);
    }
    let mut output = [0_u8; ED25519_KEY_BYTES];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex(pair[0]).ok_or(Error::InvalidArguments)?;
        let low = hex(pair[1]).ok_or(Error::InvalidArguments)?;
        *slot = high * 16 + low;
    }
    Ok(output)
}

pub(crate) fn validate_loaded_key(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if !(MIN_HMAC_KEY_BYTES..=MAX_HMAC_KEY_BYTES).contains(&bytes.len()) {
        return Err(Error::InvalidArguments);
    }
    Ok(bytes)
}
