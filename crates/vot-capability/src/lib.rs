//! `ed25519-cbor-v1` capability format (`spec/registries.md` section 11).
//!
//! Reads, writes, and checks signatures over capabilities. Signature covers the
//! canonical bytes exactly as signed (not a re-encoding). Times are epoch seconds.

#![forbid(unsafe_code)]

pub mod verify;

/// What a capability can authorize, re-exported so a caller need not depend
/// on `vot-codec` to name one.
pub use vot_codec::Operation;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The format identifier `spec/registries.md` section 11 gives this format.
pub const FORMAT_ID: u16 = 0x0001;

/// What the signature covers, before the key identifier and the capability.
///
/// Distinct from the receipt and witness domains in `vot-receipt`, so a signature
/// over one statement is not valid input for another.
const DOMAIN: &[u8] = b"VOT capability v0\0";

/// The one delegation constraint this format defines. Any other value is refused.
pub const NO_FURTHER_DELEGATION: u64 = 0;

/// Bounds every field the format fixes. `spec/capability.cddl` is normative and
/// these are the same numbers.
pub mod bounds {
    /// A key identifier names a key rather than being one.
    pub const KEY_ID: (usize, usize) = (1, 64);
    /// Issuer and audience are deployment identities.
    pub const IDENTITY: (usize, usize) = (1, 128);
    /// Operations a capability may allow, from `spec/registries.md` section 12.
    pub const OPERATIONS: (usize, usize) = (1, 16);
    /// Resource limits, from `spec/registries.md` section 13.
    pub const LIMITS: usize = 16;
    /// Byte ranges a scope may name. Empty means the whole object.
    pub const RANGES: usize = 64;
    /// A signed capability, which `spec/session.cddl` bounds again at 48 KiB when
    /// it travels in `SESSION_OPEN`.
    pub const SIGNED: usize = 49_152;
    /// A scope, which `spec/session.cddl` bounds again at 4 KiB when it travels
    /// as a requested or granted scope.
    pub const SCOPE: usize = 4_096;
}

/// Why a capability could not be read, written, or checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Not deterministic CBOR at all.
    Encoding(vot_cbor::Error),
    /// A version this format does not define.
    UnsupportedVersion(u64),
    /// An identity that is empty, too long, or carries a control character.
    InvalidIdentity,
    /// A key identifier outside its length bounds.
    InvalidKeyId,
    /// An operation set that is empty, unordered, repeats, or names the reserved
    /// zero.
    InvalidOperations,
    /// A resource limit map that is unordered, repeats, or names the reserved
    /// zero.
    InvalidLimits,
    /// A verification suite this revision does not define.
    InvalidSuite(u64),
    /// A range that is empty, out of order, overlapping, or past the object.
    InvalidRange,
    /// An expiry that does not follow its not-before.
    InvalidValidity,
    /// A delegation constraint other than [`NO_FURTHER_DELEGATION`].
    UnsupportedDelegation(u64),
    /// A nonce or proof outside the size `spec/session.cddl` fixes for it.
    InvalidLength,
    /// The signature does not verify under the key it names.
    Signature,
    /// A structure too large to encode within the bounds the format fixes.
    TooLarge,
}

impl From<vot_cbor::Error> for Error {
    fn from(error: vot_cbor::Error) -> Self {
        Self::Encoding(error)
    }
}

/// A half-open byte range of an object, as `(offset, length)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub offset: u64,
    pub length: u64,
}

impl Range {
    /// The first byte past this range, or `None` when it does not fit `u64`.
    #[must_use]
    pub const fn end(self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }
}

/// What object, and what part of it, a capability is about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    /// A verification suite from `spec/registries.md` section 5.
    pub suite: u16,
    /// The object root under that suite.
    pub root: [u8; 32],
    /// The exact length, when the issuer knew it.
    pub length: Option<u64>,
    /// Allowed ranges, ascending and strictly separated. Empty means the whole
    /// object.
    pub ranges: Vec<Range>,
}

/// A ceiling the holder may not exceed, by the identifier
/// `spec/registries.md` section 13 gives it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limit {
    pub id: u16,
    pub value: u64,
}

/// The claims `spec/security.md` section 5 requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Who issued it. Checked against the anchor entry that names the key.
    pub issuer: String,
    /// Which deployment it is for.
    pub audience: String,
    /// The holder key a proof of possession is made under.
    pub holder_key: [u8; 32],
    /// What it allows, from `spec/registries.md` section 12. Ascending, no
    /// repeats, at least one: a capability that allows nothing is not one.
    pub operations: Vec<u64>,
    /// What object it is about.
    pub scope: Scope,
    /// Ceilings, ascending by identifier. An absent limit is not a grant of
    /// unlimited use; the verifier's own bounds still apply.
    pub limits: Vec<Limit>,
    /// Seconds since the epoch, inclusive.
    pub not_before: u64,
    /// Seconds since the epoch, exclusive, and strictly after `not_before`.
    pub expiry: u64,
    /// The unique identifier a deny list names.
    pub token_id: [u8; 16],
    /// [`NO_FURTHER_DELEGATION`] in this format.
    pub delegation: u64,
}

/// A capability with the issuer signature over it. Holds the exact signed
/// bytes so verification is independent of this crate's encoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCapability {
    /// Which key the issuer claimed to use. Bound into the signature.
    pub key_id: Vec<u8>,
    /// The canonical capability, exactly as signed.
    pub capability: Vec<u8>,
    pub signature: [u8; 64],
}

impl Range {
    fn validate(self) -> Result<(), Error> {
        if self.length == 0 || self.end().is_none() {
            return Err(Error::InvalidRange);
        }
        Ok(())
    }
}

impl Scope {
    /// # Errors
    /// Rejects an unknown suite, and ranges that are empty, unordered,
    /// overlapping, or past a known length.
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=2).contains(&self.suite) {
            return Err(Error::InvalidSuite(u64::from(self.suite)));
        }
        if self.ranges.len() > bounds::RANGES {
            return Err(Error::TooLarge);
        }
        let mut previous_end = None;
        for range in &self.ranges {
            range.validate()?;
            // Strictly separated, not just disjoint: adjacent ranges are one
            // range written twice.
            if previous_end.is_some_and(|end| range.offset <= end) {
                return Err(Error::InvalidRange);
            }
            let end = range.end().ok_or(Error::InvalidRange)?;
            if let Some(length) = self.length
                && end > length
            {
                return Err(Error::InvalidRange);
            }
            previous_end = Some(end);
        }
        Ok(())
    }

    /// Whether `range` is inside what this scope allows.
    ///
    /// An empty range list is the whole object, bounded by a known length.
    #[must_use]
    pub fn allows(&self, range: Range) -> bool {
        let Some(end) = range.end() else {
            return false;
        };
        if range.length == 0 {
            return false;
        }
        if self.ranges.is_empty() {
            return self.length.is_none_or(|length| end <= length);
        }
        self.ranges
            .iter()
            .any(|allowed| range.offset >= allowed.offset && Some(end) <= allowed.end())
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        vot_cbor::map(out, 4);
        vot_cbor::uint(out, 0);
        vot_cbor::uint(out, u64::from(self.suite));
        vot_cbor::uint(out, 1);
        vot_cbor::bytes(out, &self.root);
        vot_cbor::uint(out, 2);
        match self.length {
            Some(length) => vot_cbor::uint(out, length),
            None => vot_cbor::null(out),
        }
        vot_cbor::uint(out, 3);
        vot_cbor::array(out, self.ranges.len() as u64);
        for range in &self.ranges {
            vot_cbor::array(out, 2);
            vot_cbor::uint(out, range.offset);
            vot_cbor::uint(out, range.length);
        }
        Ok(())
    }

    fn decode(reader: &mut vot_cbor::Reader<'_>) -> Result<Self, Error> {
        reader.map(4)?;
        reader.key(0)?;
        let value = reader.uint()?;
        let suite = u16::try_from(value).map_err(|_| Error::InvalidSuite(value))?;
        reader.key(1)?;
        let root = reader.fixed_bytes::<32>()?;
        reader.key(2)?;
        let length = if reader.peek_null() {
            reader.null()?;
            None
        } else {
            Some(reader.uint()?)
        };
        reader.key(3)?;
        let count = reader.array_len(bounds::RANGES as u64)?;
        let mut ranges = Vec::with_capacity(usize::try_from(count).map_err(|_| Error::TooLarge)?);
        for _ in 0..count {
            reader.array(2)?;
            ranges.push(Range {
                offset: reader.uint()?,
                length: reader.uint()?,
            });
        }
        let scope = Self {
            suite,
            root,
            length,
            ranges,
        };
        scope.validate()?;
        Ok(scope)
    }
}

/// Encodes a scope on its own, which is how a requested or granted scope travels.
///
/// # Errors
/// Rejects a scope the format does not allow, and one past the 4 KiB
/// `spec/session.cddl` gives the field.
pub fn encode_scope(scope: &Scope) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    scope.encode(&mut out)?;
    Ok(out)
}

/// Decodes a scope on its own.
///
/// # Errors
/// Rejects bytes that are not one canonical scope, and trailing bytes.
pub fn decode_scope(input: &[u8]) -> Result<Scope, Error> {
    if input.len() > bounds::SCOPE {
        return Err(Error::TooLarge);
    }
    let mut reader = vot_cbor::Reader::new(input);
    let scope = Scope::decode(&mut reader)?;
    reader.finish()?;
    Ok(scope)
}

fn validate_identity(value: &str) -> Result<(), Error> {
    let (low, high) = bounds::IDENTITY;
    if !(low..=high).contains(&value.len()) {
        return Err(Error::InvalidIdentity);
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidIdentity);
    }
    Ok(())
}

fn validate_key_id(key_id: &[u8]) -> Result<(), Error> {
    let (low, high) = bounds::KEY_ID;
    if (low..=high).contains(&key_id.len()) {
        Ok(())
    } else {
        Err(Error::InvalidKeyId)
    }
}

impl Capability {
    /// Checks every rule the format fixes, whatever the issuer intended.
    ///
    /// # Errors
    /// Rejects an identity, operation set, limit map, scope, validity window, or
    /// delegation constraint the format does not allow.
    pub fn validate(&self) -> Result<(), Error> {
        validate_identity(&self.issuer)?;
        validate_identity(&self.audience)?;

        let (low, high) = bounds::OPERATIONS;
        if !(low..=high).contains(&self.operations.len()) {
            return Err(Error::InvalidOperations);
        }
        if self.operations[0] == 0
            || !self.operations.windows(2).all(|pair| pair[0] < pair[1])
            || self.operations.iter().any(|value| *value > 0xffff)
        {
            return Err(Error::InvalidOperations);
        }

        if self.limits.len() > bounds::LIMITS {
            return Err(Error::TooLarge);
        }
        if self.limits.first().is_some_and(|limit| limit.id == 0)
            || !self.limits.windows(2).all(|pair| pair[0].id < pair[1].id)
        {
            return Err(Error::InvalidLimits);
        }

        self.scope.validate()?;

        if self.expiry <= self.not_before {
            return Err(Error::InvalidValidity);
        }
        if self.delegation != NO_FURTHER_DELEGATION {
            return Err(Error::UnsupportedDelegation(self.delegation));
        }
        Ok(())
    }

    /// Whether the window is open at `now`. Inclusive of `not_before`, exclusive
    /// of `expiry`.
    #[must_use]
    pub const fn is_current(&self, now: u64) -> bool {
        now >= self.not_before && now < self.expiry
    }

    /// Whether this capability allows `operation`.
    ///
    /// Takes a [`vot_codec::Operation`] rather than an identifier, because
    /// this is where a grant is decided and `spec/registries.md` section 12
    /// says an unknown identifier grants nothing. A closed argument is how
    /// that is true rather than merely intended: there is no unregistered
    /// value to ask about.
    ///
    /// ```compile_fail,E0308
    /// # use vot_capability::Capability;
    /// # fn check(capability: &Capability) -> bool {
    /// capability.allows(0x0004)
    /// # }
    /// ```
    #[must_use]
    pub fn allows(&self, operation: vot_codec::Operation) -> bool {
        self.operations.contains(&operation.identifier())
    }

    /// Whether the capability's operation set names `identifier`, registered
    /// or not.
    ///
    /// For round-tripping and diagnostics. This answers what the token says,
    /// not what it authorizes, and deliberately reads as neither: a grant
    /// goes through [`Capability::allows`].
    #[must_use]
    pub fn carries(&self, identifier: u64) -> bool {
        self.operations.contains(&identifier)
    }

    /// The ceiling this capability puts on `limit`, when it states one.
    #[must_use]
    pub fn limit(&self, id: u16) -> Option<u64> {
        self.limits
            .iter()
            .find(|limit| limit.id == id)
            .map(|limit| limit.value)
    }

    /// The canonical encoding, which is what an issuer signs.
    ///
    /// # Errors
    /// Rejects a capability [`validate`](Self::validate) refuses.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        vot_cbor::map(&mut out, 11);
        vot_cbor::uint(&mut out, 0);
        vot_cbor::uint(&mut out, 0);
        vot_cbor::uint(&mut out, 1);
        vot_cbor::text(&mut out, &self.issuer);
        vot_cbor::uint(&mut out, 2);
        vot_cbor::text(&mut out, &self.audience);
        vot_cbor::uint(&mut out, 3);
        vot_cbor::bytes(&mut out, &self.holder_key);
        vot_cbor::uint(&mut out, 4);
        vot_cbor::array(&mut out, self.operations.len() as u64);
        for operation in &self.operations {
            vot_cbor::uint(&mut out, *operation);
        }
        vot_cbor::uint(&mut out, 5);
        self.scope.encode(&mut out)?;
        vot_cbor::uint(&mut out, 6);
        vot_cbor::map(&mut out, self.limits.len() as u64);
        for limit in &self.limits {
            vot_cbor::uint(&mut out, u64::from(limit.id));
            vot_cbor::uint(&mut out, limit.value);
        }
        vot_cbor::uint(&mut out, 7);
        vot_cbor::uint(&mut out, self.not_before);
        vot_cbor::uint(&mut out, 8);
        vot_cbor::uint(&mut out, self.expiry);
        vot_cbor::uint(&mut out, 9);
        vot_cbor::bytes(&mut out, &self.token_id);
        vot_cbor::uint(&mut out, 10);
        vot_cbor::uint(&mut out, self.delegation);
        Ok(out)
    }

    /// Reads a capability from the bytes a signature covered.
    ///
    /// # Errors
    /// Rejects bytes that are not one canonical capability, and every rule
    /// [`validate`](Self::validate) checks.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, Error> {
        let mut reader = vot_cbor::Reader::new(input);
        reader.map(11)?;
        reader.key(0)?;
        let version = reader.uint()?;
        if version != 0 {
            return Err(Error::UnsupportedVersion(version));
        }
        reader.key(1)?;
        let issuer = reader.text(bounds::IDENTITY.1)?.to_owned();
        reader.key(2)?;
        let audience = reader.text(bounds::IDENTITY.1)?.to_owned();
        reader.key(3)?;
        let holder_key = reader.fixed_bytes::<32>()?;
        reader.key(4)?;
        let count = reader.array_len(bounds::OPERATIONS.1 as u64)?;
        let mut operations =
            Vec::with_capacity(usize::try_from(count).map_err(|_| Error::TooLarge)?);
        for _ in 0..count {
            operations.push(reader.uint()?);
        }
        reader.key(5)?;
        let scope = Scope::decode(&mut reader)?;
        reader.key(6)?;
        let count = reader.map_len(bounds::LIMITS as u64)?;
        let mut limits = Vec::with_capacity(usize::try_from(count).map_err(|_| Error::TooLarge)?);
        for _ in 0..count {
            let id = u16::try_from(reader.uint()?).map_err(|_| Error::InvalidLimits)?;
            limits.push(Limit {
                id,
                value: reader.uint()?,
            });
        }
        reader.key(7)?;
        let not_before = reader.uint()?;
        reader.key(8)?;
        let expiry = reader.uint()?;
        reader.key(9)?;
        let token_id = reader.fixed_bytes::<16>()?;
        reader.key(10)?;
        let delegation = reader.uint()?;
        reader.finish()?;

        let capability = Self {
            issuer,
            audience,
            holder_key,
            operations,
            scope,
            limits,
            not_before,
            expiry,
            token_id,
            delegation,
        };
        capability.validate()?;
        Ok(capability)
    }
}

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

/// Encodes a signed capability, which is what `SESSION_OPEN` carries.
///
/// # Errors
/// Rejects a key identifier outside its bounds.
pub fn encode(signed: &SignedCapability) -> Result<Vec<u8>, Error> {
    validate_key_id(&signed.key_id)?;
    let mut out = Vec::new();
    vot_cbor::map(&mut out, 4);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 1);
    vot_cbor::bytes(&mut out, &signed.key_id);
    vot_cbor::uint(&mut out, 2);
    vot_cbor::bytes(&mut out, &signed.capability);
    vot_cbor::uint(&mut out, 3);
    vot_cbor::bytes(&mut out, &signed.signature);
    Ok(out)
}

/// Reads a signed capability without checking the signature or claims.
///
/// # Errors
/// Rejects bytes that are not one canonical envelope, a key identifier outside
/// its bounds, and an envelope past the size the format fixes.
pub fn decode(input: &[u8]) -> Result<SignedCapability, Error> {
    if input.len() > bounds::SIGNED {
        return Err(Error::TooLarge);
    }
    let mut reader = vot_cbor::Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let version = reader.uint()?;
    if version != 0 {
        return Err(Error::UnsupportedVersion(version));
    }
    reader.key(1)?;
    let key_id = reader.bytes(bounds::KEY_ID.1)?.to_vec();
    validate_key_id(&key_id)?;
    reader.key(2)?;
    let capability = reader.bytes(bounds::SIGNED)?.to_vec();
    reader.key(3)?;
    let signature = reader.fixed_bytes::<64>()?;
    reader.finish()?;
    Ok(SignedCapability {
        key_id,
        capability,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn holder_key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn capability() -> Capability {
        Capability {
            issuer: "issuer.example".to_owned(),
            audience: "receiver.example".to_owned(),
            holder_key: holder_key().verifying_key().to_bytes(),
            operations: vec![1, 3],
            scope: Scope {
                suite: 1,
                root: [7; 32],
                length: Some(1 << 20),
                ranges: vec![
                    Range {
                        offset: 0,
                        length: 65_536,
                    },
                    Range {
                        offset: 131_072,
                        length: 65_536,
                    },
                ],
            },
            limits: vec![
                Limit { id: 1, value: 4 },
                Limit {
                    id: 2,
                    value: 1 << 30,
                },
            ],
            not_before: 1_700_000_000,
            expiry: 1_700_003_600,
            token_id: [0xc1; 16],
            delegation: NO_FURTHER_DELEGATION,
        }
    }

    #[test]
    fn a_capability_round_trips_through_its_canonical_bytes() {
        let value = capability();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(Capability::from_canonical_bytes(&bytes), Ok(value.clone()));

        let signed = sign(&value, b"issuer-1", &issuer_key()).unwrap();
        assert_eq!(
            signed.capability, bytes,
            "the signature covers what it sends"
        );
        let encoded = encode(&signed).unwrap();
        assert_eq!(decode(&encoded), Ok(signed.clone()));
        assert_eq!(
            verify_signature(&signed, &issuer_key().verifying_key()),
            Ok(())
        );
    }

    #[test]
    fn the_signature_is_over_the_bytes_that_arrived() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        let decoded = decode(&encode(&signed).unwrap()).unwrap();
        assert_eq!(decoded.capability, signed.capability);
        assert_eq!(
            verify_signature(&decoded, &issuer_key().verifying_key()),
            Ok(())
        );
    }

    #[test]
    fn a_signature_is_bound_to_its_key_identifier_and_its_format() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();

        let mut relabelled = signed.clone();
        relabelled.key_id = b"issuer-2".to_vec();
        assert_eq!(
            verify_signature(&relabelled, &issuer_key().verifying_key()),
            Err(Error::Signature)
        );

        let mut other_format = signing_input(b"issuer-1", &signed.capability).unwrap();
        let position = DOMAIN.len();
        other_format[position..position + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(
            issuer_key()
                .verifying_key()
                .verify_strict(&other_format, &Signature::from_bytes(&signed.signature))
                .is_err()
        );

        let other = SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            verify_signature(&signed, &other.verifying_key()),
            Err(Error::Signature)
        );
    }

    #[test]
    fn one_altered_byte_of_the_capability_fails_the_signature() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        for index in 0..signed.capability.len() {
            let mut altered = signed.clone();
            altered.capability[index] ^= 1;
            assert_eq!(
                verify_signature(&altered, &issuer_key().verifying_key()),
                Err(Error::Signature),
                "byte {index}"
            );
        }
        for index in 0..signed.signature.len() {
            let mut altered = signed.clone();
            altered.signature[index] ^= 1;
            assert_eq!(
                verify_signature(&altered, &issuer_key().verifying_key()),
                Err(Error::Signature),
                "signature byte {index}"
            );
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one row per rule reads as a table")]
    fn every_rule_the_format_fixes_is_refused_on_its_own() {
        let cases: Vec<(&str, Capability, Error)> = vec![
            (
                "an empty issuer",
                Capability {
                    issuer: String::new(),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "a control character in an audience",
                Capability {
                    audience: "receiver\n.example".to_owned(),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "an identity one byte past its bound",
                Capability {
                    issuer: "i".repeat(bounds::IDENTITY.1 + 1),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "no operations at all",
                Capability {
                    operations: Vec::new(),
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "the reserved operation zero",
                Capability {
                    operations: vec![0, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "operations out of order",
                Capability {
                    operations: vec![3, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "a repeated operation",
                Capability {
                    operations: vec![1, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "an operation past the registry's width",
                Capability {
                    operations: vec![0x1_0000],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "the reserved limit zero",
                Capability {
                    limits: vec![Limit { id: 0, value: 1 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "limits out of order",
                Capability {
                    limits: vec![Limit { id: 2, value: 1 }, Limit { id: 1, value: 1 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "a repeated limit",
                Capability {
                    limits: vec![Limit { id: 1, value: 1 }, Limit { id: 1, value: 2 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "an unknown suite",
                Capability {
                    scope: Scope {
                        suite: 3,
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidSuite(3),
            ),
            (
                "an empty range",
                Capability {
                    scope: Scope {
                        ranges: vec![Range {
                            offset: 0,
                            length: 0,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "ranges out of order",
                Capability {
                    scope: Scope {
                        ranges: vec![
                            Range {
                                offset: 128,
                                length: 8,
                            },
                            Range {
                                offset: 0,
                                length: 8,
                            },
                        ],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "overlapping ranges",
                Capability {
                    scope: Scope {
                        ranges: vec![
                            Range {
                                offset: 0,
                                length: 16,
                            },
                            Range {
                                offset: 8,
                                length: 16,
                            },
                        ],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "a range past a known length",
                Capability {
                    scope: Scope {
                        length: Some(64),
                        ranges: vec![Range {
                            offset: 0,
                            length: 65,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "a range that overflows",
                Capability {
                    scope: Scope {
                        length: None,
                        ranges: vec![Range {
                            offset: u64::MAX,
                            length: 2,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "an expiry at its not-before",
                Capability {
                    expiry: capability().not_before,
                    ..capability()
                },
                Error::InvalidValidity,
            ),
            (
                "an expiry before its not-before",
                Capability {
                    expiry: capability().not_before - 1,
                    ..capability()
                },
                Error::InvalidValidity,
            ),
            (
                "a delegation this format does not define",
                Capability {
                    delegation: 1,
                    ..capability()
                },
                Error::UnsupportedDelegation(1),
            ),
        ];
        for (name, value, expected) in cases {
            assert_eq!(value.validate(), Err(expected), "{name}");
            assert_eq!(value.canonical_bytes(), Err(expected), "{name} encoded");
        }
    }

    #[test]
    fn a_bound_admits_its_own_maximum() {
        let mut value = capability();
        value.issuer = "i".repeat(bounds::IDENTITY.1);
        value.audience = "a".repeat(bounds::IDENTITY.1);
        value.operations = (1..=bounds::OPERATIONS.1 as u64).collect();
        value.limits = (1..=u16::try_from(bounds::LIMITS).unwrap())
            .map(|id| Limit {
                id,
                value: u64::MAX,
            })
            .collect();
        value.scope.length = None;
        value.scope.ranges = (0..bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * 2,
                length: 1,
            })
            .collect();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(Capability::from_canonical_bytes(&bytes), Ok(value.clone()));

        let signed = sign(&value, &[0xab; 64], &issuer_key()).unwrap();
        assert_eq!(decode(&encode(&signed).unwrap()), Ok(signed));

        let mut wide = capability();
        wide.operations = (1..=bounds::OPERATIONS.1 as u64 + 1).collect();
        assert_eq!(wide.validate(), Err(Error::InvalidOperations));
        let mut many = capability();
        many.limits = (1..=u16::try_from(bounds::LIMITS).unwrap() + 1)
            .map(|id| Limit { id, value: 1 })
            .collect();
        assert_eq!(many.validate(), Err(Error::TooLarge));
        let mut ranged = capability();
        ranged.scope.length = None;
        ranged.scope.ranges = (0..=bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * 2,
                length: 1,
            })
            .collect();
        assert_eq!(ranged.validate(), Err(Error::TooLarge));
    }

    #[test]
    fn a_key_identifier_outside_its_bounds_never_reaches_a_signature() {
        for key_id in [vec![], vec![0; bounds::KEY_ID.1 + 1]] {
            assert_eq!(
                signing_input(&key_id, b"bytes"),
                Err(Error::InvalidKeyId),
                "{} bytes",
                key_id.len()
            );
            assert_eq!(
                sign(&capability(), &key_id, &issuer_key()),
                Err(Error::InvalidKeyId)
            );
            let signed = SignedCapability {
                key_id,
                capability: capability().canonical_bytes().unwrap(),
                signature: [0; 64],
            };
            assert_eq!(encode(&signed), Err(Error::InvalidKeyId));
            assert_eq!(
                verify_signature(&signed, &issuer_key().verifying_key()),
                Err(Error::InvalidKeyId)
            );
        }
    }

    #[test]
    fn an_envelope_that_is_not_one_canonical_item_is_refused() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        let encoded = encode(&signed).unwrap();

        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length]).is_err(), "truncated at {length}");
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode(&trailing),
            Err(Error::Encoding(vot_cbor::Error::Trailing))
        );

        let mut noncanonical = vec![0xb8, 0x04];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            decode(&noncanonical),
            Err(Error::Encoding(vot_cbor::Error::NonCanonical))
        );

        let mut future = SignedCapability { ..signed };
        future.capability = {
            let mut bytes = capability().canonical_bytes().unwrap();
            bytes[2] = 1;
            bytes
        };
        assert_eq!(
            Capability::from_canonical_bytes(&future.capability),
            Err(Error::UnsupportedVersion(1))
        );
    }

    #[test]
    fn a_scope_decides_what_it_allows() {
        let scope = capability().scope;
        assert!(scope.allows(Range {
            offset: 0,
            length: 65_536
        }));
        assert!(scope.allows(Range {
            offset: 65_535,
            length: 1
        }));
        assert!(scope.allows(Range {
            offset: 131_072,
            length: 1
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 65_537
        }));
        assert!(!scope.allows(Range {
            offset: 65_536,
            length: 1
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 196_608
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 0
        }));
        assert!(!scope.allows(Range {
            offset: u64::MAX,
            length: 1
        }));

        let whole = Scope {
            ranges: Vec::new(),
            length: Some(1024),
            ..scope.clone()
        };
        assert!(whole.allows(Range {
            offset: 0,
            length: 1024
        }));
        assert!(!whole.allows(Range {
            offset: 0,
            length: 1025
        }));

        let unbounded = Scope {
            ranges: Vec::new(),
            length: None,
            ..scope
        };
        assert!(unbounded.allows(Range {
            offset: 0,
            length: u64::MAX
        }));
    }

    #[test]
    fn a_scope_travels_on_its_own_and_round_trips() {
        let scope = capability().scope;
        let encoded = encode_scope(&scope).unwrap();
        assert!(encoded.len() <= bounds::SCOPE);
        assert_eq!(decode_scope(&encoded), Ok(scope));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_scope(&trailing),
            Err(Error::Encoding(vot_cbor::Error::Trailing))
        );
        assert_eq!(decode_scope(&[0; bounds::SCOPE + 1]), Err(Error::TooLarge));
    }

    #[test]
    fn every_bound_is_tested_at_its_own_edge() {
        let adjacent = Scope {
            ranges: vec![
                Range {
                    offset: 0,
                    length: 8,
                },
                Range {
                    offset: 8,
                    length: 8,
                },
            ],
            ..capability().scope
        };
        assert_eq!(adjacent.validate(), Err(Error::InvalidRange));
        let separated = Scope {
            ranges: vec![
                Range {
                    offset: 0,
                    length: 8,
                },
                Range {
                    offset: 9,
                    length: 8,
                },
            ],
            ..capability().scope
        };
        assert_eq!(separated.validate(), Ok(()));

        let exact = Scope {
            length: Some(64),
            ranges: vec![Range {
                offset: 32,
                length: 32,
            }],
            ..capability().scope
        };
        assert_eq!(exact.validate(), Ok(()));
        let past = Scope {
            length: Some(64),
            ranges: vec![Range {
                offset: 32,
                length: 33,
            }],
            ..capability().scope
        };
        assert_eq!(past.validate(), Err(Error::InvalidRange));

        let mut widest = capability();
        widest.operations = vec![0xffff];
        assert_eq!(widest.validate(), Ok(()));
        widest.operations = vec![0x1_0000];
        assert_eq!(widest.validate(), Err(Error::InvalidOperations));

        assert_eq!(
            decode_scope(&[0; bounds::SCOPE]),
            Err(Error::Encoding(vot_cbor::Error::WrongType))
        );
        assert_eq!(decode_scope(&[0; bounds::SCOPE + 1]), Err(Error::TooLarge));
        assert_eq!(
            decode(&vec![0; bounds::SIGNED]),
            Err(Error::Encoding(vot_cbor::Error::WrongType))
        );
        assert_eq!(decode(&vec![0; bounds::SIGNED + 1]), Err(Error::TooLarge));

        let mut value = capability();
        value.scope.length = None;
        value.scope.ranges = Vec::new();
        let signed = sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let envelope = encode(&signed).unwrap();
        assert!(envelope.len() < bounds::SIGNED);
        assert_eq!(decode(&envelope), Ok(signed));
    }

    #[test]
    fn the_validity_window_is_inclusive_then_exclusive() {
        let value = capability();
        assert!(!value.is_current(value.not_before - 1));
        assert!(value.is_current(value.not_before));
        assert!(value.is_current(value.expiry - 1));
        assert!(!value.is_current(value.expiry));
    }

    #[test]
    fn what_a_capability_allows_and_limits_is_read_by_identifier() {
        let value = capability();
        assert!(value.allows(vot_codec::Operation::Publish));
        assert!(value.allows(vot_codec::Operation::ReadRanges));
        assert!(
            !value.allows(vot_codec::Operation::ReadManifest),
            "an operation it does not name"
        );
        // The raw view answers about the set, not about a grant, so it sees
        // what a later revision issued and `allows` cannot be asked.
        assert!(value.carries(1));
        assert!(!value.carries(0x0004));
        assert_eq!(value.limit(1), Some(4));
        assert_eq!(value.limit(2), Some(1 << 30));
        assert_eq!(value.limit(3), None, "a limit it does not state");
    }

    #[test]
    fn the_widest_capability_fits_the_field_that_carries_it() {
        let mut value = capability();
        value.issuer = "i".repeat(bounds::IDENTITY.1);
        value.audience = "a".repeat(bounds::IDENTITY.1);
        value.operations = (1..=bounds::OPERATIONS.1 as u64).collect();
        value.limits = (1..=u16::try_from(bounds::LIMITS).unwrap())
            .map(|id| Limit {
                id,
                value: u64::MAX,
            })
            .collect();
        value.scope.length = None;
        value.scope.ranges = (0..bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * (1 << 49),
                length: 1 << 48,
            })
            .collect();

        let scope = encode_scope(&value.scope).unwrap();
        assert_eq!(scope.len(), 1_251, "the widest scope");
        assert!(scope.len() <= bounds::SCOPE, "and it fits its field");

        let signed = sign(&value, &[0xab; 64], &issuer_key()).unwrap();
        let envelope = encode(&signed).unwrap();
        assert_eq!(envelope.len(), 1_905, "the widest signed capability");
        assert!(envelope.len() <= bounds::SIGNED, "and it fits its field");
        assert_eq!(decode(&envelope), Ok(signed));

        assert_eq!(decode(&vec![0; bounds::SIGNED + 1]), Err(Error::TooLarge));
    }
}
