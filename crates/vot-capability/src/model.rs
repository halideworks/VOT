//! Capability, scope, and limit data with the rules the format fixes.

use super::{Error, NO_FURTHER_DELEGATION, bounds};

/// A half-open byte range of an object, as `(offset, length)`.
///
/// Length is nonzero and the end fits in `u64`.
///
/// ```compile_fail,E0451
/// use vot_capability::Range;
/// let _ = Range {
///     offset: 0,
///     length: 0,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    offset: u64,
    length: u64,
}

impl Range {
    /// # Errors
    /// Rejects a zero length and an end that does not fit `u64`.
    pub const fn new(offset: u64, length: u64) -> Result<Self, Error> {
        if length == 0 || offset.checked_add(length).is_none() {
            return Err(Error::InvalidRange);
        }
        Ok(Self { offset, length })
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// The first byte past this range. [`Self::new`] already checked the add.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.offset + self.length
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

impl Scope {
    /// # Errors
    /// Rejects an unknown suite, and ranges that are unordered, overlapping,
    /// or past a known length.
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=2).contains(&self.suite) {
            return Err(Error::InvalidSuite(u64::from(self.suite)));
        }
        if self.ranges.len() > bounds::RANGES {
            return Err(Error::TooLarge);
        }
        let mut previous_end = None;
        for range in &self.ranges {
            // Strictly separated, not just disjoint: adjacent ranges are one
            // range written twice.
            if previous_end.is_some_and(|end| range.offset() <= end) {
                return Err(Error::InvalidRange);
            }
            let end = range.end();
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
        let end = range.end();
        if self.ranges.is_empty() {
            return self.length.is_none_or(|length| end <= length);
        }
        self.ranges
            .iter()
            .any(|allowed| range.offset() >= allowed.offset() && end <= allowed.end())
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
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
            vot_cbor::uint(out, range.offset());
            vot_cbor::uint(out, range.length());
        }
        Ok(())
    }

    pub(super) fn decode(reader: &mut vot_cbor::Reader<'_>) -> Result<Self, Error> {
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
            ranges.push(Range::new(reader.uint()?, reader.uint()?)?);
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

pub(super) fn validate_identity(value: &str) -> Result<(), Error> {
    let (low, high) = bounds::IDENTITY;
    if !(low..=high).contains(&value.len()) {
        return Err(Error::InvalidIdentity);
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidIdentity);
    }
    Ok(())
}

pub(super) fn validate_key_id(key_id: &[u8]) -> Result<(), Error> {
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
}
