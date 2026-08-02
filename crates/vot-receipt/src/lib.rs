//! Canonical authenticated VOT assurance receipts.

#![allow(clippy::missing_errors_doc)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"VOT receipt v0\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AssuranceLevel {
    Admitted = 1,
    TransitVerified = 2,
    Durable = 3,
    AtRestVerified = 4,
    Published = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommitProfile {
    Fast = 1,
    Balanced = 2,
    Strict = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SubjectKind {
    Object = 0,
    Package = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub subject_kind: SubjectKind,
    pub suite_id: u16,
    pub subject_digest: [u8; 32],
    pub subject_length: u64,
    pub assurance: AssuranceLevel,
    pub profile: CommitProfile,
    pub actual_predecessor: AssuranceLevel,
    pub provider: u16,
    pub provider_version: [u16; 3],
    pub session_id: [u8; 16],
    pub incarnation_id: [u8; 16],
    pub sequence: u64,
    pub observed_at: String,
    pub clock_source: u8,
    pub flags: u8,
    /// Envelope digest of the previous observation for this subject.
    ///
    /// `None` only for the first observation in a chain. Every later one links
    /// to its predecessor, so the record cannot be rewritten one entry at a
    /// time: changing any observation changes every digest after it.
    pub previous: Option<[u8; 32]>,
}

/// Registered receipt authentication schemes.
///
/// Ed25519 is the default because a receipt is evidence for a third party. A
/// symmetric MAC cannot serve that: anyone able to verify it is equally able to
/// forge it, so the auditor a receipt is meant for either cannot check it or
/// becomes capable of manufacturing it. HMAC remains registered for traffic
/// that never leaves one trust domain.
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

    const fn from_registry(value: u64) -> Option<Self> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKey,
    InvalidKeyId,
    InvalidTimestamp,
    InvalidFlags,
    InvalidClockSource,
    InvalidSuite,
    InvalidProvider,
    InvalidSubjectLength,
    InvalidSequence,
    Authentication,
    /// The envelope names a scheme other than the one the verifier requires.
    UnexpectedScheme,
    /// A witness signed a different head than the one presented.
    WitnessHeadMismatch,
    /// An entry does not link to its predecessor, or the first one links.
    ChainBroken,
    /// An entry in the chain is about a different subject.
    ChainSubjectMismatch,
    /// A chain with no observations proves nothing.
    EmptyChain,
    InvalidEncoding,
    TooLarge,
    NonCanonical,
}

impl Receipt {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=2).contains(&self.suite_id) {
            return Err(Error::InvalidSuite);
        }
        if !(1..=4).contains(&self.provider) {
            return Err(Error::InvalidProvider);
        }
        if self.subject_length > i64::MAX as u64 {
            return Err(Error::InvalidSubjectLength);
        }
        if self.sequence == 0 {
            return Err(Error::InvalidSequence);
        }
        if !valid_rfc3339(&self.observed_at) {
            return Err(Error::InvalidTimestamp);
        }
        if self.clock_source > 2 {
            return Err(Error::InvalidClockSource);
        }
        if self.flags > 15 {
            return Err(Error::InvalidFlags);
        }
        Ok(())
    }

    /// Encodes the receipt as RFC 8949 deterministic CBOR.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut output = Vec::with_capacity(160);
        // Key 17 is optional, so the map length depends on whether this
        // observation links to a predecessor.
        encode_map(if self.previous.is_some() { 15 } else { 14 }, &mut output);
        encode_uint(0, &mut output);
        encode_uint(0, &mut output);
        encode_uint(1, &mut output);
        encode_array(4, &mut output);
        encode_uint(self.subject_kind as u64, &mut output);
        encode_uint(u64::from(self.suite_id), &mut output);
        encode_bytes(&self.subject_digest, &mut output);
        encode_uint(self.subject_length, &mut output);
        encode_uint(2, &mut output);
        encode_uint(self.assurance as u64, &mut output);
        encode_uint(3, &mut output);
        encode_uint(self.profile as u64, &mut output);
        encode_uint(4, &mut output);
        encode_uint(self.actual_predecessor as u64, &mut output);
        encode_uint(5, &mut output);
        encode_uint(u64::from(self.provider), &mut output);
        encode_uint(6, &mut output);
        encode_array(3, &mut output);
        for component in self.provider_version {
            encode_uint(u64::from(component), &mut output);
        }
        encode_uint(7, &mut output);
        encode_bytes(&self.session_id, &mut output);
        encode_uint(8, &mut output);
        encode_bytes(&self.incarnation_id, &mut output);
        encode_uint(9, &mut output);
        encode_uint(self.sequence, &mut output);
        encode_uint(10, &mut output);
        encode_text(&self.observed_at, &mut output);
        encode_uint(11, &mut output);
        encode_uint(u64::from(self.clock_source), &mut output);
        encode_uint(12, &mut output);
        encode_uint(u64::from(self.suite_id), &mut output);
        encode_uint(13, &mut output);
        encode_uint(u64::from(self.flags), &mut output);
        if let Some(previous) = &self.previous {
            encode_uint(17, &mut output);
            encode_bytes(previous, &mut output);
        }
        Ok(output)
    }
}

fn valid_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 35
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let Some(year) = decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = decimal(&bytes[17..19]) else {
        return false;
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }

    let mut offset = 19;
    if bytes.get(offset) == Some(&b'.') {
        let fraction_start = offset + 1;
        let digits = bytes[fraction_start..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return false;
        }
        offset = fraction_start + digits;
    }
    match bytes.get(offset) {
        Some(b'Z' | b'z') => offset + 1 == bytes.len(),
        Some(b'+' | b'-') => {
            bytes.len() == offset + 6
                && bytes.get(offset + 3) == Some(&b':')
                && decimal(&bytes[offset + 1..offset + 3]).is_some_and(|hours| hours <= 23)
                && decimal(&bytes[offset + 4..offset + 6]).is_some_and(|minutes| minutes <= 59)
        }
        _ => false,
    }
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn encode_head(major: u8, value: u64, output: &mut Vec<u8>) {
    match value {
        0..=23 => output.push(head_byte(major, u8::try_from(value).unwrap())),
        24..=0xff => {
            output.push(head_byte(major, 24));
            output.push(u8::try_from(value).unwrap());
        }
        0x100..=0xffff => {
            output.push(head_byte(major, 25));
            output.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(head_byte(major, 26));
            output.extend_from_slice(&u32::try_from(value).unwrap().to_be_bytes());
        }
        _ => {
            output.push(head_byte(major, 27));
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

const fn head_byte(major: u8, additional: u8) -> u8 {
    major * 32 + additional
}

fn encode_uint(value: u64, output: &mut Vec<u8>) {
    encode_head(0, value, output);
}

fn encode_bytes(value: &[u8], output: &mut Vec<u8>) {
    encode_head(2, value.len() as u64, output);
    output.extend_from_slice(value);
}

fn encode_text(value: &str, output: &mut Vec<u8>) {
    encode_head(3, value.len() as u64, output);
    output.extend_from_slice(value.as_bytes());
}

fn encode_array(length: u64, output: &mut Vec<u8>) {
    encode_head(4, length, output);
}

fn encode_map(length: u64, output: &mut Vec<u8>) {
    encode_head(5, length, output);
}

/// A witness statement: an independent party recording that it saw a chain head
/// at its own clock time.
///
/// This is what anchors a chain. An issuer signing its own observations can
/// rewrite and re-sign all of them, and `observed_at` is whatever the issuer
/// says. A witness signature over the head, timestamped by the witness, means a
/// later rewrite has to also produce witness signatures the issuer cannot make.
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

const WITNESS_DOMAIN: &[u8] = b"VOT witness v0\0";

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
        encode_map(3, &mut output);
        encode_uint(0, &mut output);
        encode_bytes(&self.head, &mut output);
        encode_uint(1, &mut output);
        encode_text(&self.observed_at, &mut output);
        encode_uint(2, &mut output);
        encode_bytes(&self.key_id, &mut output);
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

/// The tuple that identifies what a receipt is about.
fn subject_identity(receipt: &Receipt) -> (SubjectKind, u16, [u8; 32], u64) {
    (
        receipt.subject_kind,
        receipt.suite_id,
        receipt.subject_digest,
        receipt.subject_length,
    )
}

/// Checks that a sequence of observations forms one unbroken chain.
///
/// Each entry must link to its predecessor's envelope digest, carry the same
/// subject, and advance the issuer sequence. The first entry must not link.
///
/// # Errors
/// Reports the first structural break.
pub fn verify_chain(chain: &[AuthenticatedReceipt]) -> Result<(), Error> {
    let Some(first) = chain.first() else {
        return Err(Error::EmptyChain);
    };
    if first.receipt.previous.is_some() {
        return Err(Error::ChainBroken);
    }
    // Object identity is the suite, the root, and the length. Identical digest
    // bytes under different suites are different objects, so leaving the suite
    // out would let a chain mix two of them.
    let subject = subject_identity(&first.receipt);
    let mut previous_digest = first.digest()?;
    let mut previous_sequence = first.receipt.sequence;
    for entry in chain.iter().skip(1) {
        if entry.receipt.previous != Some(previous_digest) {
            return Err(Error::ChainBroken);
        }
        if subject_identity(&entry.receipt) != subject {
            return Err(Error::ChainSubjectMismatch);
        }
        if entry.receipt.sequence <= previous_sequence {
            return Err(Error::InvalidSequence);
        }
        previous_digest = entry.digest()?;
        previous_sequence = entry.receipt.sequence;
    }
    Ok(())
}

/// Bytes an authenticator covers: domain, scheme, then the canonical receipt.
///
/// The scheme is inside the signed input so an authenticator produced under one
/// scheme can never be replayed as another.
/// Bytes an authenticator covers.
///
/// The key identifier is inside them. It names which key the issuer claimed to
/// be using, and a verifier that treats it as a context label needs it to be
/// authentic: otherwise a receipt signed by the same issuer for another context
/// can be relabelled without disturbing the signature. It is length prefixed so
/// no identifier can be read as the start of the canonical receipt.
fn signing_input(scheme: AuthScheme, key_id: &[u8], receipt: &Receipt) -> Result<Vec<u8>, Error> {
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

fn validate_key_id(key_id: &[u8]) -> Result<(), Error> {
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
pub fn verify_ed25519(receipt: &AuthenticatedReceipt, key: &VerifyingKey) -> Result<(), Error> {
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
        .map_err(|_| Error::Authentication)
}

/// Authenticates a receipt with a shared secret.
///
/// Only sound inside one trust domain: a holder of the key can forge as well as
/// check. Cross-boundary receipts use [`sign_ed25519`].
///
/// # Errors
/// Rejects an invalid receipt, key identifier, or short key.
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
pub fn verify_hmac_sha256(receipt: &AuthenticatedReceipt, key: &[u8]) -> Result<(), Error> {
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
        .map_err(|_| Error::Authentication)
}

pub fn encode_authenticated(receipt: &AuthenticatedReceipt) -> Result<Vec<u8>, Error> {
    validate_key_id(&receipt.key_id)?;
    if receipt.authentication.len() != receipt.scheme.authenticator_len() {
        return Err(Error::Authentication);
    }
    let canonical = receipt.receipt.canonical_bytes()?;
    let mut output = Vec::with_capacity(canonical.len() + receipt.key_id.len() + 48);
    encode_map(4, &mut output);
    encode_uint(0, &mut output);
    output.extend_from_slice(&canonical);
    encode_uint(1, &mut output);
    encode_uint(receipt.scheme as u64, &mut output);
    encode_uint(2, &mut output);
    encode_bytes(&receipt.key_id, &mut output);
    encode_uint(3, &mut output);
    encode_bytes(&receipt.authentication, &mut output);
    Ok(output)
}

/// Decodes one bounded, deterministic authenticated receipt envelope.
pub fn decode_authenticated(input: &[u8]) -> Result<AuthenticatedReceipt, Error> {
    if input.len() > 65_536 {
        return Err(Error::TooLarge);
    }
    let mut decoder = Decoder::new(input);
    decoder.exact_map(4)?;
    decoder.exact_key(0)?;
    let receipt = decode_receipt(&mut decoder)?;
    decoder.exact_key(1)?;
    let scheme = AuthScheme::from_registry(decoder.uint()?).ok_or(Error::InvalidEncoding)?;
    decoder.exact_key(2)?;
    let key_id = decoder.bytes(64)?;
    if key_id.is_empty() {
        return Err(Error::InvalidKeyId);
    }
    decoder.exact_key(3)?;
    let authentication = decoder.bytes(scheme.authenticator_len())?;
    if authentication.len() != scheme.authenticator_len() {
        return Err(Error::InvalidEncoding);
    }
    decoder.finish()?;
    let authenticated = AuthenticatedReceipt {
        receipt,
        scheme,
        key_id,
        authentication,
    };
    if encode_authenticated(&authenticated)? != input {
        return Err(Error::NonCanonical);
    }
    Ok(authenticated)
}

fn decode_receipt(decoder: &mut Decoder<'_>) -> Result<Receipt, Error> {
    // Fourteen keys, or fifteen when the observation links to a predecessor.
    let entries = decoder.head(5)?;
    if entries != 14 && entries != 15 {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(0)?;
    if decoder.uint()? != 0 {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(1)?;
    decoder.exact_array(4)?;
    let subject_kind = match decoder.uint()? {
        0 => SubjectKind::Object,
        1 => SubjectKind::Package,
        _ => return Err(Error::InvalidEncoding),
    };
    let suite_id = decoder.u16()?;
    let subject_digest = decoder.fixed_bytes()?;
    let subject_length = decoder.uint()?;
    decoder.exact_key(2)?;
    let assurance = decode_assurance(decoder.uint()?)?;
    decoder.exact_key(3)?;
    let profile = match decoder.uint()? {
        1 => CommitProfile::Fast,
        2 => CommitProfile::Balanced,
        3 => CommitProfile::Strict,
        _ => return Err(Error::InvalidEncoding),
    };
    decoder.exact_key(4)?;
    let actual_predecessor = decode_assurance(decoder.uint()?)?;
    decoder.exact_key(5)?;
    let provider = decoder.u16()?;
    decoder.exact_key(6)?;
    decoder.exact_array(3)?;
    let provider_version = [decoder.u16()?, decoder.u16()?, decoder.u16()?];
    decoder.exact_key(7)?;
    let session_id = decoder.fixed_bytes()?;
    decoder.exact_key(8)?;
    let incarnation_id = decoder.fixed_bytes()?;
    decoder.exact_key(9)?;
    let sequence = decoder.uint()?;
    decoder.exact_key(10)?;
    let observed_at = decoder.text(35)?;
    decoder.exact_key(11)?;
    let clock_source = decoder.u8()?;
    decoder.exact_key(12)?;
    if decoder.u16()? != suite_id {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(13)?;
    let flags = decoder.u8()?;
    let previous = if entries == 15 {
        decoder.exact_key(17)?;
        Some(decoder.fixed_bytes::<32>()?)
    } else {
        None
    };
    let receipt = Receipt {
        subject_kind,
        suite_id,
        subject_digest,
        subject_length,
        assurance,
        profile,
        actual_predecessor,
        provider,
        provider_version,
        session_id,
        incarnation_id,
        sequence,
        observed_at,
        clock_source,
        flags,
        previous,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn decode_assurance(value: u64) -> Result<AssuranceLevel, Error> {
    match value {
        1 => Ok(AssuranceLevel::Admitted),
        2 => Ok(AssuranceLevel::TransitVerified),
        3 => Ok(AssuranceLevel::Durable),
        4 => Ok(AssuranceLevel::AtRestVerified),
        5 => Ok(AssuranceLevel::Published),
        _ => Err(Error::InvalidEncoding),
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if self.remaining.len() < length {
            return Err(Error::InvalidEncoding);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, Error> {
        let first = *self.take(1)?.first().ok_or(Error::InvalidEncoding)?;
        if first >> 5 != expected_major {
            return Err(Error::InvalidEncoding);
        }
        match first & 0x1f {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                (value >= 24).then_some(value).ok_or(Error::NonCanonical)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| Error::InvalidEncoding)?,
                ));
                (value > 0xff).then_some(value).ok_or(Error::NonCanonical)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| Error::InvalidEncoding)?,
                ));
                (value > 0xffff).then_some(value).ok_or(Error::NonCanonical)
            }
            27 => {
                let value = u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| Error::InvalidEncoding)?,
                );
                (value > 0xffff_ffff)
                    .then_some(value)
                    .ok_or(Error::NonCanonical)
            }
            _ => Err(Error::InvalidEncoding),
        }
    }

    fn uint(&mut self) -> Result<u64, Error> {
        self.head(0)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        u16::try_from(self.uint()?).map_err(|_| Error::InvalidEncoding)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        u8::try_from(self.uint()?).map_err(|_| Error::InvalidEncoding)
    }

    fn exact_key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn exact_map(&mut self, expected: u64) -> Result<(), Error> {
        if self.head(5)? == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn exact_array(&mut self, expected: u64) -> Result<(), Error> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let length = usize::try_from(self.head(2)?).map_err(|_| Error::TooLarge)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)
    }

    fn text(&mut self, maximum: usize) -> Result<String, Error> {
        let length = usize::try_from(self.head(3)?).map_err(|_| Error::TooLarge)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| Error::InvalidEncoding)
    }

    fn finish(self) -> Result<(), Error> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> Receipt {
        Receipt {
            subject_kind: SubjectKind::Object,
            suite_id: 1,
            subject_digest: [7; 32],
            subject_length: 4096,
            assurance: AssuranceLevel::Published,
            profile: CommitProfile::Strict,
            actual_predecessor: AssuranceLevel::AtRestVerified,
            provider: 1,
            provider_version: [0, 3, 0],
            session_id: [2; 16],
            incarnation_id: [3; 16],
            sequence: 5,
            observed_at: "2026-07-31T16:00:00Z".to_owned(),
            clock_source: 1,
            flags: 0,
            previous: None,
        }
    }

    /// Pulls one hex string out of the conformance vector without a JSON
    /// dependency. The file is flat and machine-generated, so a field lookup is
    /// enough, and `tools/validate_receipt_vectors.py` parses it properly.
    fn vector_field(name: &str) -> Vec<u8> {
        vector_field_after("{", name)
    }

    /// `authenticator_hex` and the key fields appear once per scheme, so a
    /// lookup says which scheme it means rather than relying on file order.
    fn vector_field_after(marker: &str, name: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/receipt/signing-transcript.json"
        ))
        .expect("conformance vector is missing");
        let from = text
            .find(marker)
            .unwrap_or_else(|| panic!("no marker {marker}"));
        let text = &text[from..];
        let key = format!("\"{name}\": \"");
        let start = text.find(&key).unwrap_or_else(|| panic!("no field {name}")) + key.len();
        let value = &text[start..start + text[start..].find('"').expect("unterminated field")];
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().chunks_exact(2) {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("{name} is not hexadecimal"),
            };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        bytes
    }

    #[test]
    fn the_published_conformance_vector_is_what_this_produces() {
        // ADR-0007 requires vectors for a wire-visible change, and the point of
        // publishing one is that somebody else's implementation can check
        // itself against it. This asserts ours still produces those exact
        // bytes; tools/validate_receipt_vectors.py rebuilds the same transcript
        // independently in Python and recomputes the MAC, so the two agreeing
        // is what makes the file trustworthy rather than merely recorded.
        let key_id = vector_field("key_id_hex");
        let canonical = vector_field("canonical_receipt_hex");
        let seed: [u8; 32] = vector_field("secret_key_seed_hex").try_into().unwrap();
        let signing = SigningKey::from_bytes(&seed);

        let receipt = Receipt {
            subject_kind: SubjectKind::Package,
            suite_id: 1,
            subject_digest: [0x11; 32],
            subject_length: 1_048_576,
            assurance: AssuranceLevel::Published,
            profile: CommitProfile::Fast,
            actual_predecessor: AssuranceLevel::AtRestVerified,
            provider: 1,
            provider_version: [0, 4, 0],
            session_id: [0x22; 16],
            incarnation_id: [0x33; 16],
            sequence: 7,
            observed_at: "2026-08-02T00:00:00Z".to_owned(),
            clock_source: 1,
            flags: 0,
            previous: None,
        };
        assert_eq!(
            receipt.canonical_bytes().unwrap(),
            canonical,
            "the canonical receipt encoding drifted from the published vector"
        );

        let signed = sign_ed25519(receipt.clone(), &key_id, &signing).unwrap();
        assert_eq!(
            signed.authentication,
            vector_field_after("\"name\": \"ED25519\"", "authenticator_hex"),
            "the Ed25519 authenticator drifted from the published vector"
        );
        assert_eq!(
            signing.verifying_key().to_bytes().to_vec(),
            vector_field("public_key_hex")
        );
        verify_ed25519(&signed, &signing.verifying_key()).unwrap();
        assert_eq!(
            encode_authenticated(&signed).unwrap(),
            vector_field("authenticated_envelope_ed25519_hex")
        );

        let mac_key = vector_field_after("\"name\": \"HMAC_SHA256\"", "secret_key_hex");
        let maced = authenticate_hmac_sha256(receipt, &key_id, &mac_key).unwrap();
        assert_eq!(
            maced.authentication,
            vector_field_after("\"name\": \"HMAC_SHA256\"", "authenticator_hex"),
            "the HMAC authenticator drifted from the published vector"
        );
        verify_hmac_sha256(&maced, &mac_key).unwrap();
    }

    #[test]
    fn the_authenticated_bytes_match_the_registry() {
        // spec/registries.md defines this input normatively: domain separator,
        // two-byte scheme, key identifier behind a one-byte length, canonical
        // receipt. An independent implementation follows that text, not this
        // crate, so the two agreeing is the whole of interoperability. Pinned
        // as bytes rather than described, because a test that rebuilt the input
        // the same way the code does would agree with any format at all.
        let input = signing_input(AuthScheme::Ed25519, b"receiver-1", &receipt()).unwrap();
        let canonical = receipt().canonical_bytes().unwrap();

        assert_eq!(&input[..DOMAIN.len()], b"VOT receipt v0\0");
        let rest = &input[DOMAIN.len()..];
        assert_eq!(&rest[..2], &[0x00, 0x01], "ED25519 is scheme 0x0001");
        assert_eq!(rest[2], 10, "the key identifier is length prefixed");
        assert_eq!(&rest[3..13], b"receiver-1");
        assert_eq!(&rest[13..], canonical.as_slice());
        assert_eq!(input.len(), DOMAIN.len() + 3 + 10 + canonical.len());

        // The MAC scheme differs only in the two scheme bytes.
        let maced = signing_input(AuthScheme::HmacSha256, b"receiver-1", &receipt()).unwrap();
        assert_eq!(&maced[DOMAIN.len()..DOMAIN.len() + 2], &[0x00, 0x02]);
        assert_eq!(&maced[DOMAIN.len() + 2..], &input[DOMAIN.len() + 2..]);

        // A one-byte prefix covers the identifier bounds receipt.cddl sets.
        assert_eq!(
            signing_input(AuthScheme::Ed25519, &[b'k'; 64], &receipt()).unwrap()[DOMAIN.len() + 2],
            64
        );
        assert_eq!(
            signing_input(AuthScheme::Ed25519, &[b'k'; 65], &receipt()),
            Err(Error::InvalidKeyId)
        );
        assert_eq!(
            signing_input(AuthScheme::Ed25519, b"", &receipt()),
            Err(Error::InvalidKeyId)
        );
    }

    #[test]
    fn authentication_binds_every_receipt_field() {
        let key = [9; 32];
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &key).unwrap();
        verify_hmac_sha256(&authenticated, &key).unwrap();
        let mut changed = authenticated;
        changed.receipt.sequence += 1;
        assert_eq!(
            verify_hmac_sha256(&changed, &key),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn timestamps_require_rfc3339_syntax_and_ranges() {
        let mut receipt = receipt();
        for valid in [
            "2024-02-29T23:59:60Z",
            "2000-02-29T00:00:00Z",
            "2026-07-31T16:00:00.123456789-04:00",
            "2026-07-31T20:00:00+00:00",
            "2026-07-31t20:00:00z",
            "2026-07-31t20:00:00Z",
            "2026-07-31T20:00:00z",
        ] {
            receipt.observed_at = valid.to_owned();
            assert_eq!(receipt.validate(), Ok(()), "{valid}");
        }
        for invalid in [
            "xxxxxxxxxxxxxxxxxxxx",
            "2026-01-01T00:00:0Z",
            "2026-01-01T00:00:00.1234567890123456Z",
            "2026/07-31T16:00:00Z",
            "2026-07/31T16:00:00Z",
            "2026-07-31 16:00:00Z",
            "2026-07-31T16.00:00Z",
            "2026-07-31T16:00.00Z",
            "2026-00-31T16:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-07-00T00:00:00Z",
            "2026-07-31T24:00:00Z",
            "2026-07-31T16:60:00Z",
            "2026-07-31T16:00:61Z",
            "2026-07-31T16:00:00.Z",
            "2026-07-31T16:00:00+24:00",
            "2026-07-31T16:00:00+00:60",
        ] {
            receipt.observed_at = invalid.to_owned();
            assert_eq!(
                receipt.validate(),
                Err(Error::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    #[test]
    fn receipt_numeric_bounds_are_exact() {
        let mut receipt = receipt();
        receipt.subject_length = i64::MAX as u64;
        receipt.clock_source = 2;
        receipt.flags = 15;
        assert_eq!(receipt.validate(), Ok(()));

        receipt.subject_length = i64::MAX as u64 + 1;
        assert_eq!(receipt.validate(), Err(Error::InvalidSubjectLength));
        receipt.subject_length = 0;
        receipt.clock_source = 3;
        assert_eq!(receipt.validate(), Err(Error::InvalidClockSource));
        receipt.clock_source = 0;
        receipt.flags = 16;
        assert_eq!(receipt.validate(), Err(Error::InvalidFlags));
    }

    #[test]
    fn weak_keys_and_unidentified_keys_are_rejected() {
        assert_eq!(
            authenticate_hmac_sha256(receipt(), b"", &[1; 32]),
            Err(Error::InvalidKeyId)
        );
        assert_eq!(
            authenticate_hmac_sha256(receipt(), b"key", &[1; 16]),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn authenticated_envelope_is_deterministic_cbor() {
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        let first = encode_authenticated(&authenticated).unwrap();
        let second = encode_authenticated(&authenticated).unwrap();
        assert_eq!(first, second);
        assert_eq!(decode_authenticated(&first).unwrap(), authenticated);
        assert_eq!(first[0], 0xa4);
        let canonical = authenticated.receipt.canonical_bytes().unwrap();
        assert_eq!(canonical[0], 0xae);
        let mut actual = String::new();
        for byte in canonical {
            use std::fmt::Write as _;
            write!(&mut actual, "{byte:02x}").unwrap();
        }
        assert_eq!(
            actual,
            "ae000001840001582007070707070707070707070707070707070707070707070707070707070707071910000205030304040501068300030007500202020202020202020202020202020208500303030303030303030303030303030309050a74323032362d30372d33315431363a30303a30305a0b010c010d00"
        );
    }

    #[test]
    fn authenticated_round_trip_covers_every_receipt_enum_value() {
        for subject_kind in [SubjectKind::Object, SubjectKind::Package] {
            for assurance in [
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
                AssuranceLevel::AtRestVerified,
                AssuranceLevel::Published,
            ] {
                for profile in [
                    CommitProfile::Fast,
                    CommitProfile::Balanced,
                    CommitProfile::Strict,
                ] {
                    let mut value = receipt();
                    value.subject_kind = subject_kind;
                    value.assurance = assurance;
                    value.actual_predecessor = assurance;
                    value.profile = profile;
                    let authenticated =
                        authenticate_hmac_sha256(value, b"receiver-1", &[9; 32]).unwrap();
                    let encoded = encode_authenticated(&authenticated).unwrap();
                    assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
                }
            }
        }
    }

    #[test]
    fn deterministic_cbor_integer_widths_and_decoder_edges_are_exact() {
        for major in 0..=5 {
            for additional in [0, 23, 24, 25, 26, 27] {
                assert_eq!(head_byte(major, additional), major * 32 + additional);
            }
        }
        for value in [
            23,
            24,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
        ] {
            let mut receipt = receipt();
            receipt.subject_length = value;
            let authenticated = authenticate_hmac_sha256(receipt, b"receiver-1", &[9; 32]).unwrap();
            let encoded = encode_authenticated(&authenticated).unwrap();
            assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
        }

        for (input, expected) in [
            (&[0x18, 0x17][..], Err(Error::NonCanonical)),
            (&[0x18, 0x18][..], Ok(24)),
            (&[0x19, 0x00, 0xff][..], Err(Error::NonCanonical)),
            (&[0x19, 0x01, 0x00][..], Ok(0x100)),
            (
                &[0x1a, 0x00, 0x00, 0xff, 0xff][..],
                Err(Error::NonCanonical),
            ),
            (&[0x1a, 0x00, 0x01, 0x00, 0x00][..], Ok(0x1_0000)),
            (
                &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff][..],
                Err(Error::NonCanonical),
            ),
            (
                &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00][..],
                Ok(0x1_0000_0000),
            ),
        ] {
            assert_eq!(Decoder::new(input).uint(), expected);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    /// Builds a signed chain: each observation links to the previous envelope.
    fn chain(key: &SigningKey, levels: &[AssuranceLevel]) -> Vec<AuthenticatedReceipt> {
        let mut chain: Vec<AuthenticatedReceipt> = Vec::new();
        for (index, level) in levels.iter().enumerate() {
            let mut entry = receipt();
            entry.assurance = *level;
            entry.sequence = index as u64 + 1;
            entry.previous = chain.last().map(|last| last.digest().unwrap());
            chain.push(sign_ed25519(entry, b"issuer-1", key).unwrap());
        }
        chain
    }

    #[test]
    fn a_chain_links_every_observation_to_its_predecessor() {
        let key = signing_key();
        let signed = chain(
            &key,
            &[
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
                AssuranceLevel::AtRestVerified,
                AssuranceLevel::Published,
            ],
        );
        verify_chain(&signed).unwrap();
        for entry in &signed {
            verify_ed25519(entry, &key.verifying_key()).unwrap();
        }
        assert!(signed[0].receipt.previous.is_none());
        assert_eq!(
            signed[4].receipt.previous,
            Some(signed[3].digest().unwrap())
        );
    }

    #[test]
    fn rewriting_one_observation_breaks_every_link_after_it() {
        // This is what the chain buys: a middle entry cannot be replaced
        // without also reissuing everything downstream.
        let key = signing_key();
        let mut signed = chain(
            &key,
            &[
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
            ],
        );
        let mut rewritten = signed[1].receipt.clone();
        rewritten.observed_at = "2031-01-01T00:00:00Z".to_owned();
        signed[1] = sign_ed25519(rewritten, b"issuer-1", &key).unwrap();
        // Re-signed and individually valid, but the chain no longer joins.
        verify_ed25519(&signed[1], &key.verifying_key()).unwrap();
        assert_eq!(verify_chain(&signed), Err(Error::ChainBroken));
    }

    #[test]
    fn a_chain_rejects_every_structural_break() {
        let key = signing_key();
        assert_eq!(verify_chain(&[]), Err(Error::EmptyChain));

        // A first entry that claims a predecessor.
        let mut genesis = receipt();
        genesis.previous = Some([9; 32]);
        let orphan = sign_ed25519(genesis, b"issuer-1", &key).unwrap();
        assert_eq!(verify_chain(&[orphan]), Err(Error::ChainBroken));

        let signed = chain(&key, &[AssuranceLevel::Admitted, AssuranceLevel::Durable]);
        verify_chain(&signed).unwrap();

        // An entry about a different subject. Identity is the suite, the root
        // and the length, so each of them has to break the chain.
        for divergent in [
            Receipt {
                subject_digest: [0xfe; 32],
                ..signed[1].receipt.clone()
            },
            Receipt {
                subject_length: signed[1].receipt.subject_length + 1,
                ..signed[1].receipt.clone()
            },
            Receipt {
                // Same digest bytes under another suite is another object.
                suite_id: 2,
                ..signed[1].receipt.clone()
            },
            Receipt {
                subject_kind: SubjectKind::Package,
                ..signed[1].receipt.clone()
            },
        ] {
            let foreign = sign_ed25519(divergent, b"issuer-1", &key).unwrap();
            assert_eq!(
                verify_chain(&[signed[0].clone(), foreign]),
                Err(Error::ChainSubjectMismatch)
            );
        }

        // A sequence that does not advance.
        let mut stalled = signed[1].receipt.clone();
        stalled.sequence = signed[0].receipt.sequence;
        let stalled = sign_ed25519(stalled, b"issuer-1", &key).unwrap();
        assert_eq!(
            verify_chain(&[signed[0].clone(), stalled]),
            Err(Error::InvalidSequence)
        );
    }

    #[test]
    fn witness_bytes_are_pinned_and_cover_every_field() {
        // Signing and verifying with the same function proves nothing about
        // what is signed, so the encoding is pinned directly.
        let statement = WitnessStatement {
            head: [0xab; 32],
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        let bytes = statement.canonical_bytes().unwrap();
        assert_eq!(
            hex(&bytes),
            "564f54207769746e65737320763000a3005820abababababababababababababababababababababababababababababababab0174323032362d30382d30325430343a30303a30305a02497769746e6573732d61"
        );

        // Every field is inside those bytes.
        for changed in [
            WitnessStatement {
                head: [0xac; 32],
                ..statement.clone()
            },
            WitnessStatement {
                observed_at: "2026-08-02T04:00:01Z".to_owned(),
                ..statement.clone()
            },
            WitnessStatement {
                key_id: b"witness-b".to_vec(),
                ..statement.clone()
            },
        ] {
            assert_ne!(changed.canonical_bytes().unwrap(), bytes);
        }
    }

    #[test]
    fn a_witness_anchors_the_head_at_its_own_time() {
        let issuer = signing_key();
        let witness = SigningKey::from_bytes(&[11; 32]);
        let signed = chain(
            &issuer,
            &[AssuranceLevel::Admitted, AssuranceLevel::Durable],
        );
        let head = signed.last().unwrap().digest().unwrap();

        let statement = WitnessStatement {
            head,
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        let attested = witness_ed25519(statement, &witness).unwrap();
        verify_witness(&attested, &head, &witness.verifying_key()).unwrap();

        // A witness signature does not carry over to another head.
        let other = signed[0].digest().unwrap();
        assert_eq!(
            verify_witness(&attested, &other, &witness.verifying_key()),
            Err(Error::WitnessHeadMismatch)
        );

        // Nor to another witness key.
        let impostor = SigningKey::from_bytes(&[12; 32]);
        assert_eq!(
            verify_witness(&attested, &head, &impostor.verifying_key()),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn a_witness_statement_is_rejected_when_malformed_or_symmetric() {
        let witness = SigningKey::from_bytes(&[11; 32]);
        let head = [3; 32];
        let good = WitnessStatement {
            head,
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        assert!(good.canonical_bytes().is_ok());

        for broken in [
            WitnessStatement {
                key_id: Vec::new(),
                ..good.clone()
            },
            WitnessStatement {
                key_id: vec![1; 65],
                ..good.clone()
            },
            WitnessStatement {
                observed_at: "not a time".to_owned(),
                ..good.clone()
            },
        ] {
            assert!(broken.validate().is_err());
        }

        // A symmetric witness would be checkable only by someone able to forge
        // it, which defeats the point of a witness.
        let mut symmetric = witness_ed25519(good, &witness).unwrap();
        symmetric.scheme = AuthScheme::HmacSha256;
        assert_eq!(
            verify_witness(&symmetric, &head, &witness.verifying_key()),
            Err(Error::UnexpectedScheme)
        );
    }

    #[test]
    fn the_chain_link_survives_the_envelope_round_trip() {
        let key = signing_key();
        let signed = chain(&key, &[AssuranceLevel::Admitted, AssuranceLevel::Durable]);
        for entry in &signed {
            let decoded = decode_authenticated(&encode_authenticated(entry).unwrap()).unwrap();
            assert_eq!(&decoded, entry);
        }
        // The linked form encodes one more map entry than the genesis form.
        let genesis = encode_authenticated(&signed[0]).unwrap();
        let linked = encode_authenticated(&signed[1]).unwrap();
        assert!(linked.len() > genesis.len());
        verify_chain(&[
            decode_authenticated(&genesis).unwrap(),
            decode_authenticated(&linked).unwrap(),
        ])
        .unwrap();
    }

    #[test]
    fn an_ed25519_receipt_verifies_with_only_the_public_key() {
        // The whole point: the party checking the receipt cannot produce one.
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        assert_eq!(signed.scheme, AuthScheme::Ed25519);
        assert_eq!(signed.authentication.len(), 64);
        assert!(signed.scheme.is_third_party_verifiable());
        verify_ed25519(&signed, &key.verifying_key()).unwrap();

        // A different issuer key does not verify.
        let other = SigningKey::from_bytes(&[8; 32]);
        assert_eq!(
            verify_ed25519(&signed, &other.verifying_key()),
            Err(Error::Authentication)
        );

        // Relabelling the key identifier breaks the signature. A verifier that
        // uses it to separate contexts, as the CLI does for its publication
        // receipts, would otherwise accept a receipt the same issuer signed for
        // something else entirely.
        let mut relabelled = signed.clone();
        relabelled.key_id = b"issuer-2".to_vec();
        assert_eq!(
            verify_ed25519(&relabelled, &key.verifying_key()),
            Err(Error::Authentication)
        );

        // An identifier outside the registry bound is refused before any
        // signature check, on the way in and on the way out.
        let mut unbounded = signed.clone();
        unbounded.key_id = Vec::new();
        assert_eq!(
            verify_ed25519(&unbounded, &key.verifying_key()),
            Err(Error::InvalidKeyId)
        );
        unbounded.key_id = vec![b'k'; 65];
        assert_eq!(
            verify_ed25519(&unbounded, &key.verifying_key()),
            Err(Error::InvalidKeyId)
        );
    }

    #[test]
    fn a_changed_receipt_or_signature_fails() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();

        let mut altered = signed.clone();
        altered.receipt.sequence += 1;
        assert_eq!(
            verify_ed25519(&altered, &key.verifying_key()),
            Err(Error::Authentication)
        );

        let mut flipped = signed.clone();
        flipped.authentication[0] ^= 1;
        assert_eq!(
            verify_ed25519(&flipped, &key.verifying_key()),
            Err(Error::Authentication)
        );

        let mut truncated = signed;
        truncated.authentication.pop();
        assert_eq!(
            verify_ed25519(&truncated, &key.verifying_key()),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn an_authenticator_cannot_be_replayed_under_another_scheme() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        let maced = authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap();

        // A verifier that requires one scheme refuses the other outright,
        // rather than reporting a signature failure it might retry.
        assert_eq!(
            verify_hmac_sha256(&signed, &[9; 32]),
            Err(Error::UnexpectedScheme)
        );
        assert_eq!(
            verify_ed25519(&maced, &key.verifying_key()),
            Err(Error::UnexpectedScheme)
        );

        // The scheme is inside the signed bytes, so the two cover different
        // input even for an identical receipt.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"issuer-1", &receipt()).unwrap(),
            signing_input(AuthScheme::HmacSha256, b"issuer-1", &receipt()).unwrap()
        );
        // So is the key identifier, so a receipt cannot be relabelled as
        // belonging to another context without breaking its authenticator.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"issuer-1", &receipt()).unwrap(),
            signing_input(AuthScheme::Ed25519, b"issuer-2", &receipt()).unwrap()
        );
        // Length prefixed, so a longer identifier cannot absorb the byte that
        // follows it and leave the same input.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"ab", &receipt()).unwrap(),
            signing_input(AuthScheme::Ed25519, b"a", &receipt()).unwrap()
        );
        assert!(!AuthScheme::HmacSha256.is_third_party_verifiable());
    }

    #[test]
    fn the_envelope_round_trips_both_schemes() {
        let key = signing_key();
        for authenticated in [
            sign_ed25519(receipt(), b"issuer-1", &key).unwrap(),
            authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap(),
        ] {
            let encoded = encode_authenticated(&authenticated).unwrap();
            let decoded = decode_authenticated(&encoded).unwrap();
            assert_eq!(decoded, authenticated);
            assert_eq!(
                decoded.authentication.len(),
                decoded.scheme.authenticator_len()
            );
        }
    }

    #[test]
    fn the_envelope_rejects_a_scheme_length_mismatch() {
        let mut wrong = authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap();
        wrong.scheme = AuthScheme::Ed25519;
        assert_eq!(encode_authenticated(&wrong), Err(Error::Authentication));

        let key = signing_key();
        let mut short = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        short.authentication.truncate(32);
        assert_eq!(encode_authenticated(&short), Err(Error::Authentication));
    }

    #[test]
    fn an_unregistered_scheme_is_refused_on_decode() {
        assert_eq!(AuthScheme::from_registry(1), Some(AuthScheme::Ed25519));
        assert_eq!(AuthScheme::from_registry(2), Some(AuthScheme::HmacSha256));
        for unknown in [0, 3, 255] {
            assert_eq!(AuthScheme::from_registry(unknown), None);
        }
        let key = signing_key();
        let encoded = encode_authenticated(&sign_ed25519(receipt(), b"i", &key).unwrap()).unwrap();
        // Byte-patch the scheme field to an unregistered value.
        let position = encoded
            .windows(2)
            .position(|pair| pair == [0x01, 0x01])
            .unwrap();
        let mut tampered = encoded;
        tampered[position + 1] = 0x03;
        assert_eq!(decode_authenticated(&tampered), Err(Error::InvalidEncoding));
    }

    #[test]
    fn the_envelope_digest_is_what_a_chain_or_witness_commits_to() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        let digest = signed.digest().unwrap();
        assert_eq!(digest, signed.digest().unwrap());

        let mut later = signed.clone();
        later.receipt.sequence += 1;
        let later = sign_ed25519(later.receipt, b"issuer-1", &key).unwrap();
        assert_ne!(later.digest().unwrap(), digest);

        // It covers the envelope, so the key identifier is inside it too.
        let other_id = sign_ed25519(receipt(), b"issuer-2", &key).unwrap();
        assert_ne!(other_id.digest().unwrap(), digest);
    }

    #[test]
    fn authenticator_lengths_match_the_registry() {
        assert_eq!(AuthScheme::Ed25519.authenticator_len(), 64);
        assert_eq!(AuthScheme::HmacSha256.authenticator_len(), 32);
    }

    #[test]
    fn authentication_and_envelope_bounds_are_exact() {
        let mut key_id_64 = AuthenticatedReceipt {
            receipt: receipt(),
            scheme: AuthScheme::HmacSha256,
            key_id: vec![1; 64],
            authentication: vec![2; 32],
        };
        assert!(encode_authenticated(&key_id_64).is_ok());
        key_id_64.key_id.push(1);
        assert_eq!(encode_authenticated(&key_id_64), Err(Error::InvalidKeyId));
        key_id_64.key_id.clear();
        assert_eq!(encode_authenticated(&key_id_64), Err(Error::InvalidKeyId));

        assert!(authenticate_hmac_sha256(receipt(), &[1; 64], &[9; 32]).is_ok());
        assert_eq!(
            authenticate_hmac_sha256(receipt(), &[1; 65], &[9; 32]),
            Err(Error::InvalidKeyId)
        );
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        assert_eq!(
            verify_hmac_sha256(&authenticated, &[9; 31]),
            Err(Error::InvalidKey)
        );

        assert_eq!(
            decode_authenticated(&vec![0; 65_536]),
            Err(Error::InvalidEncoding)
        );
        let mut max_timestamp = receipt();
        max_timestamp.observed_at = "2026-07-31T16:00:00.123456789+23:59".to_owned();
        assert_eq!(max_timestamp.observed_at.len(), 35);
        let authenticated =
            authenticate_hmac_sha256(max_timestamp, b"receiver-1", &[9; 32]).unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(decode_authenticated(&trailing), Err(Error::InvalidEncoding));
    }

    #[test]
    fn authenticated_decoder_rejects_truncation_noncanonical_and_bounds() {
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        for length in 0..encoded.len() {
            assert!(decode_authenticated(&encoded[..length]).is_err());
        }
        let mut noncanonical = vec![0xb8, 0x04];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            decode_authenticated(&noncanonical),
            Err(Error::NonCanonical)
        );
        assert_eq!(decode_authenticated(&vec![0; 65_537]), Err(Error::TooLarge));
        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        let decoded = decode_authenticated(&changed).unwrap();
        assert_eq!(
            verify_hmac_sha256(&decoded, &[9; 32]),
            Err(Error::Authentication)
        );
    }
}
