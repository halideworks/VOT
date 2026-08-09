//! Receipt data, assurance and profile mappings, and validation.

use super::{Error, valid_rfc3339};

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
        vot_cbor::map(&mut output, if self.previous.is_some() { 15 } else { 14 });
        vot_cbor::uint(&mut output, 0);
        vot_cbor::uint(&mut output, 0);
        vot_cbor::uint(&mut output, 1);
        vot_cbor::array(&mut output, 4);
        vot_cbor::uint(&mut output, self.subject_kind as u64);
        vot_cbor::uint(&mut output, u64::from(self.suite_id));
        vot_cbor::bytes(&mut output, &self.subject_digest);
        vot_cbor::uint(&mut output, self.subject_length);
        vot_cbor::uint(&mut output, 2);
        vot_cbor::uint(&mut output, self.assurance as u64);
        vot_cbor::uint(&mut output, 3);
        vot_cbor::uint(&mut output, self.profile as u64);
        vot_cbor::uint(&mut output, 4);
        vot_cbor::uint(&mut output, self.actual_predecessor as u64);
        vot_cbor::uint(&mut output, 5);
        vot_cbor::uint(&mut output, u64::from(self.provider));
        vot_cbor::uint(&mut output, 6);
        vot_cbor::array(&mut output, 3);
        for component in self.provider_version {
            vot_cbor::uint(&mut output, u64::from(component));
        }
        vot_cbor::uint(&mut output, 7);
        vot_cbor::bytes(&mut output, &self.session_id);
        vot_cbor::uint(&mut output, 8);
        vot_cbor::bytes(&mut output, &self.incarnation_id);
        vot_cbor::uint(&mut output, 9);
        vot_cbor::uint(&mut output, self.sequence);
        vot_cbor::uint(&mut output, 10);
        vot_cbor::text(&mut output, &self.observed_at);
        vot_cbor::uint(&mut output, 11);
        vot_cbor::uint(&mut output, u64::from(self.clock_source));
        vot_cbor::uint(&mut output, 12);
        vot_cbor::uint(&mut output, u64::from(self.suite_id));
        vot_cbor::uint(&mut output, 13);
        vot_cbor::uint(&mut output, u64::from(self.flags));
        if let Some(previous) = &self.previous {
            vot_cbor::uint(&mut output, 17);
            vot_cbor::bytes(&mut output, previous);
        }
        Ok(output)
    }
}

/// The assurance a publication under `profile` must have performed, in the
/// receipt's own vocabulary.
///
/// The table lives in `vot_commit_model`, which is where the machine reads
/// it. This is the one place the two vocabularies meet, so it is the one
/// place the translation belongs: a second copy anywhere else can be edited
/// into disagreeing with what the verifier will accept, without a compile
/// error to say so.
#[must_use]
pub const fn required_predecessor(profile: CommitProfile) -> AssuranceLevel {
    receipt_assurance(model_profile(profile).required_predecessor())
}

pub(super) const fn receipt_assurance(level: vot_commit_model::Assurance) -> AssuranceLevel {
    match level {
        vot_commit_model::Assurance::Admitted => AssuranceLevel::Admitted,
        vot_commit_model::Assurance::TransitVerified => AssuranceLevel::TransitVerified,
        vot_commit_model::Assurance::Durable => AssuranceLevel::Durable,
        vot_commit_model::Assurance::AtRestVerified => AssuranceLevel::AtRestVerified,
        vot_commit_model::Assurance::Published => AssuranceLevel::Published,
    }
}

pub(super) const fn model_assurance(level: AssuranceLevel) -> vot_commit_model::Assurance {
    match level {
        AssuranceLevel::Admitted => vot_commit_model::Assurance::Admitted,
        AssuranceLevel::TransitVerified => vot_commit_model::Assurance::TransitVerified,
        AssuranceLevel::Durable => vot_commit_model::Assurance::Durable,
        AssuranceLevel::AtRestVerified => vot_commit_model::Assurance::AtRestVerified,
        AssuranceLevel::Published => vot_commit_model::Assurance::Published,
    }
}

pub(super) const fn model_profile(profile: CommitProfile) -> vot_commit_model::Profile {
    match profile {
        CommitProfile::Fast => vot_commit_model::Profile::Fast,
        CommitProfile::Balanced => vot_commit_model::Profile::Balanced,
        CommitProfile::Strict => vot_commit_model::Profile::Strict,
    }
}
