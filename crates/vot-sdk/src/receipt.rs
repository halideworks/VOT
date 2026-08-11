//! Verification-only receipt evidence.

use ed25519_dalek::VerifyingKey;

use crate::error;
use crate::object::ObjectId;
use crate::{Error, ErrorCode};

/// Receipt subject category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKind {
    Object,
    Package,
}

/// Evidence level asserted by a verified receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceLevel {
    Admitted,
    TransitVerified,
    Durable,
    AtRestVerified,
    Published,
}

/// Publication profile asserted by a verified receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitProfile {
    Fast,
    Balanced,
    Strict,
}

/// Receipt whose Ed25519 signature has been checked.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    inner: vot_receipt::VerifiedReceipt,
}

impl VerifiedReceipt {
    #[must_use]
    pub fn subject_kind(&self) -> SubjectKind {
        match self.inner.receipt().subject_kind {
            vot_receipt::SubjectKind::Object => SubjectKind::Object,
            vot_receipt::SubjectKind::Package => SubjectKind::Package,
        }
    }

    #[must_use]
    pub fn subject_id(&self) -> ObjectId {
        let receipt = self.inner.receipt();
        ObjectId {
            suite: receipt.suite_id,
            root: receipt.subject_digest,
            length: receipt.subject_length,
        }
    }

    #[must_use]
    pub fn assurance(&self) -> AssuranceLevel {
        map_assurance(self.inner.receipt().assurance)
    }

    #[must_use]
    pub fn profile(&self) -> CommitProfile {
        match self.inner.receipt().profile {
            vot_receipt::CommitProfile::Fast => CommitProfile::Fast,
            vot_receipt::CommitProfile::Balanced => CommitProfile::Balanced,
            vot_receipt::CommitProfile::Strict => CommitProfile::Strict,
        }
    }

    #[must_use]
    pub fn actual_predecessor(&self) -> AssuranceLevel {
        map_assurance(self.inner.receipt().actual_predecessor)
    }

    #[must_use]
    pub fn provider(&self) -> u16 {
        self.inner.receipt().provider
    }

    #[must_use]
    pub fn provider_version(&self) -> [u16; 3] {
        self.inner.receipt().provider_version
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.inner.receipt().sequence
    }

    #[must_use]
    pub fn observed_at(&self) -> &str {
        &self.inner.receipt().observed_at
    }

    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.inner.authenticated().key_id
    }

    #[must_use]
    pub fn previous_digest(&self) -> Option<[u8; 32]> {
        self.inner.receipt().previous
    }

    pub fn envelope_digest(&self) -> Result<[u8; 32], Error> {
        self.inner.authenticated().digest().map_err(error::receipt)
    }
}

pub fn verify_ed25519(
    encoded_receipt: &[u8],
    public_key: &[u8; 32],
) -> Result<VerifiedReceipt, Error> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| Error::new(ErrorCode::AuthenticationFailed))?;
    let receipt = vot_receipt::decode_authenticated(encoded_receipt).map_err(error::receipt)?;
    vot_receipt::verify_ed25519(&receipt, &key)
        .map(|inner| VerifiedReceipt { inner })
        .map_err(error::receipt)
}

/// Verifies one issuer chain after checking its explicit allocation bound.
pub fn verify_chain(chain: &[VerifiedReceipt], max_receipts: usize) -> Result<(), Error> {
    if chain.len() > max_receipts {
        return Err(Error::new(ErrorCode::LimitExceeded));
    }
    let mut inner = Vec::new();
    inner
        .try_reserve_exact(chain.len())
        .map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
    inner.extend(chain.iter().map(|receipt| receipt.inner.clone()));
    vot_receipt::verify_chain(&inner).map_err(error::receipt)
}

const fn map_assurance(value: vot_receipt::AssuranceLevel) -> AssuranceLevel {
    match value {
        vot_receipt::AssuranceLevel::Admitted => AssuranceLevel::Admitted,
        vot_receipt::AssuranceLevel::TransitVerified => AssuranceLevel::TransitVerified,
        vot_receipt::AssuranceLevel::Durable => AssuranceLevel::Durable,
        vot_receipt::AssuranceLevel::AtRestVerified => AssuranceLevel::AtRestVerified,
        vot_receipt::AssuranceLevel::Published => AssuranceLevel::Published,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn lower_receipt(
        assurance: vot_receipt::AssuranceLevel,
        sequence: u64,
        previous: Option<[u8; 32]>,
    ) -> vot_receipt::Receipt {
        vot_receipt::Receipt {
            subject_kind: vot_receipt::SubjectKind::Object,
            suite_id: 2,
            subject_digest: [9; 32],
            subject_length: 17,
            assurance,
            profile: vot_receipt::CommitProfile::Balanced,
            actual_predecessor: vot_receipt::AssuranceLevel::Durable,
            provider: 3,
            provider_version: [2, 3, 4],
            session_id: [5; 16],
            incarnation_id: [6; 16],
            sequence,
            observed_at: "2026-08-11T12:00:00Z".to_owned(),
            clock_source: 2,
            flags: 3,
            previous,
        }
    }

    fn signed(receipt: vot_receipt::Receipt, key: &SigningKey) -> (VerifiedReceipt, [u8; 32]) {
        let authenticated = vot_receipt::sign_ed25519(receipt, b"issuer", key).unwrap();
        let digest = authenticated.digest().unwrap();
        let encoded = vot_receipt::encode_authenticated(&authenticated).unwrap();
        (
            verify_ed25519(&encoded, &key.verifying_key().to_bytes()).unwrap(),
            digest,
        )
    }

    #[test]
    fn verified_receipt_accessors_and_chain_are_evidence_bound() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let (first, first_digest) = signed(
            lower_receipt(vot_receipt::AssuranceLevel::Admitted, 1, None),
            &key,
        );
        let (second, second_digest) = signed(
            lower_receipt(
                vot_receipt::AssuranceLevel::TransitVerified,
                2,
                Some(first_digest),
            ),
            &key,
        );

        assert_eq!(first.subject_kind(), SubjectKind::Object);
        assert_eq!(
            first.subject_id(),
            ObjectId {
                suite: 2,
                root: [9; 32],
                length: 17,
            }
        );
        assert_eq!(first.profile(), CommitProfile::Balanced);
        assert_eq!(first.actual_predecessor(), AssuranceLevel::Durable);
        assert_eq!(first.provider(), 3);
        assert_eq!(first.provider_version(), [2, 3, 4]);
        assert_eq!(second.sequence(), 2);
        assert_eq!(second.observed_at(), "2026-08-11T12:00:00Z");
        assert_eq!(second.key_id(), b"issuer");
        assert_eq!(first.previous_digest(), None);
        assert_eq!(second.previous_digest(), Some(first_digest));
        assert_eq!(second.envelope_digest().unwrap(), second_digest);
        assert_ne!(second_digest, [0; 32]);
        assert_ne!(second_digest, [1; 32]);

        let chain = [first.clone(), second.clone()];
        verify_chain(&chain, 2).unwrap();
        assert_eq!(
            verify_chain(&chain, 1).unwrap_err().code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            verify_chain(&[second, first], 2).unwrap_err().code(),
            ErrorCode::VerificationFailed
        );
    }

    #[test]
    fn every_assurance_level_maps_to_the_sdk_vocabulary() {
        let key = SigningKey::from_bytes(&[43; 32]);
        let cases = [
            (
                vot_receipt::AssuranceLevel::Admitted,
                AssuranceLevel::Admitted,
            ),
            (
                vot_receipt::AssuranceLevel::TransitVerified,
                AssuranceLevel::TransitVerified,
            ),
            (
                vot_receipt::AssuranceLevel::Durable,
                AssuranceLevel::Durable,
            ),
            (
                vot_receipt::AssuranceLevel::AtRestVerified,
                AssuranceLevel::AtRestVerified,
            ),
            (
                vot_receipt::AssuranceLevel::Published,
                AssuranceLevel::Published,
            ),
        ];
        for (lower, expected) in cases {
            let (verified, _) = signed(lower_receipt(lower, 1, None), &key);
            assert_eq!(verified.assurance(), expected);
        }
    }
}
