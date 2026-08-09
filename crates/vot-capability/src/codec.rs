//! Canonical encode and decode.

use super::{Capability, Error, Limit, Scope, SignedCapability, bounds, validate_key_id};

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

impl Capability {
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
