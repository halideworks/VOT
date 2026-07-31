//! Canonical authenticated VOT assurance receipts.

#![allow(clippy::missing_errors_doc)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReceipt {
    pub receipt: Receipt,
    pub key_id: Vec<u8>,
    pub authentication: [u8; 32],
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
        if !(20..=35).contains(&self.observed_at.len()) || !self.observed_at.is_ascii() {
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
        encode_map(14, &mut output);
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
        Ok(output)
    }
}

fn encode_head(major: u8, value: u64, output: &mut Vec<u8>) {
    match value {
        0..=23 => output.push((major << 5) | u8::try_from(value).unwrap()),
        24..=0xff => {
            output.push((major << 5) | 24);
            output.push(u8::try_from(value).unwrap());
        }
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&u32::try_from(value).unwrap().to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
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

pub fn authenticate_hmac_sha256(
    receipt: Receipt,
    key_id: &[u8],
    key: &[u8],
) -> Result<AuthenticatedReceipt, Error> {
    if key_id.is_empty() || key_id.len() > 64 {
        return Err(Error::InvalidKeyId);
    }
    if key.len() < 32 {
        return Err(Error::InvalidKey);
    }
    let bytes = receipt.canonical_bytes()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    mac.update(DOMAIN);
    mac.update(&bytes);
    let authentication = mac.finalize().into_bytes().into();
    Ok(AuthenticatedReceipt {
        receipt,
        key_id: key_id.to_vec(),
        authentication,
    })
}

pub fn verify_hmac_sha256(receipt: &AuthenticatedReceipt, key: &[u8]) -> Result<(), Error> {
    if key.len() < 32 {
        return Err(Error::InvalidKey);
    }
    let bytes = receipt.receipt.canonical_bytes()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    mac.update(DOMAIN);
    mac.update(&bytes);
    mac.verify_slice(&receipt.authentication)
        .map_err(|_| Error::Authentication)
}

pub fn encode_authenticated(receipt: &AuthenticatedReceipt) -> Result<Vec<u8>, Error> {
    if receipt.key_id.is_empty() || receipt.key_id.len() > 64 {
        return Err(Error::InvalidKeyId);
    }
    let canonical = receipt.receipt.canonical_bytes()?;
    let mut output = Vec::with_capacity(canonical.len() + receipt.key_id.len() + 48);
    encode_map(4, &mut output);
    encode_uint(0, &mut output);
    output.extend_from_slice(&canonical);
    encode_uint(1, &mut output);
    encode_uint(2, &mut output);
    encode_uint(2, &mut output);
    encode_bytes(&receipt.key_id, &mut output);
    encode_uint(3, &mut output);
    encode_bytes(&receipt.authentication, &mut output);
    Ok(output)
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
        }
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
}
