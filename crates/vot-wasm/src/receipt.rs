use vot_sdk::receipt as sdk_receipt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ErrorCode, ObjectId, VotError};

/// Receipt subject category.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKind {
    Object,
    Package,
}

/// Evidence level asserted by a verified receipt.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceLevel {
    Admitted,
    TransitVerified,
    Durable,
    AtRestVerified,
    Published,
}

/// Publication profile asserted by a verified receipt.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitProfile {
    Fast,
    Balanced,
    Strict,
}

/// Receipt whose Ed25519 signature has been checked.
#[wasm_bindgen]
#[derive(Clone)]
pub struct VerifiedReceipt {
    inner: sdk_receipt::VerifiedReceipt,
}

#[wasm_bindgen]
impl VerifiedReceipt {
    #[wasm_bindgen(getter, js_name = subjectKind)]
    #[must_use]
    pub fn subject_kind(&self) -> SubjectKind {
        match self.inner.subject_kind() {
            sdk_receipt::SubjectKind::Object => SubjectKind::Object,
            sdk_receipt::SubjectKind::Package => SubjectKind::Package,
        }
    }

    #[wasm_bindgen(getter, js_name = subjectId)]
    #[must_use]
    pub fn subject_id(&self) -> ObjectId {
        ObjectId::from_sdk(self.inner.subject_id())
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn assurance(&self) -> AssuranceLevel {
        map_assurance(self.inner.assurance())
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn profile(&self) -> CommitProfile {
        match self.inner.profile() {
            sdk_receipt::CommitProfile::Fast => CommitProfile::Fast,
            sdk_receipt::CommitProfile::Balanced => CommitProfile::Balanced,
            sdk_receipt::CommitProfile::Strict => CommitProfile::Strict,
        }
    }

    #[wasm_bindgen(getter, js_name = actualPredecessor)]
    #[must_use]
    pub fn actual_predecessor(&self) -> AssuranceLevel {
        map_assurance(self.inner.actual_predecessor())
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn provider(&self) -> u16 {
        self.inner.provider()
    }

    #[wasm_bindgen(getter, js_name = providerVersion)]
    #[must_use]
    pub fn provider_version(&self) -> Vec<u16> {
        self.inner.provider_version().to_vec()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.inner.sequence()
    }

    #[wasm_bindgen(getter, js_name = observedAt)]
    #[must_use]
    pub fn observed_at(&self) -> String {
        self.inner.observed_at().to_owned()
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    #[must_use]
    pub fn key_id(&self) -> Vec<u8> {
        self.inner.key_id().to_vec()
    }

    #[wasm_bindgen(getter, js_name = previousDigest)]
    #[must_use]
    pub fn previous_digest(&self) -> Option<Vec<u8>> {
        self.inner.previous_digest().map(|digest| digest.to_vec())
    }

    #[wasm_bindgen(getter, js_name = envelopeDigest)]
    pub fn envelope_digest(&self) -> Result<Vec<u8>, VotError> {
        Ok(self.inner.envelope_digest()?.to_vec())
    }
}

/// Verifies a receipt without exposing signing or private-key operations.
#[wasm_bindgen(js_name = verifyReceiptEd25519)]
pub fn verify_receipt_ed25519(
    encoded_receipt: &[u8],
    public_key: &[u8],
) -> Result<VerifiedReceipt, VotError> {
    let public_key: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| VotError::new(ErrorCode::InvalidInput))?;
    Ok(VerifiedReceipt {
        inner: sdk_receipt::verify_ed25519(encoded_receipt, public_key)?,
    })
}

/// Bounded collection for verifying one issuer receipt chain.
#[wasm_bindgen]
pub struct ReceiptChain {
    receipts: Vec<sdk_receipt::VerifiedReceipt>,
    maximum: usize,
}

#[wasm_bindgen]
impl ReceiptChain {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            receipts: Vec::new(),
            maximum,
        }
    }

    pub fn push(&mut self, receipt: &VerifiedReceipt) -> Result<(), VotError> {
        if self.receipts.len() >= self.maximum {
            return Err(VotError::new(ErrorCode::LimitExceeded));
        }
        self.receipts
            .try_reserve(1)
            .map_err(|_| VotError::new(ErrorCode::ResourceExhausted))?;
        self.receipts.push(receipt.inner.clone());
        Ok(())
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn length(&self) -> usize {
        self.receipts.len()
    }

    pub fn verify(&self) -> Result<(), VotError> {
        sdk_receipt::verify_chain(&self.receipts, self.maximum).map_err(Into::into)
    }
}

const fn map_assurance(value: sdk_receipt::AssuranceLevel) -> AssuranceLevel {
    match value {
        sdk_receipt::AssuranceLevel::Admitted => AssuranceLevel::Admitted,
        sdk_receipt::AssuranceLevel::TransitVerified => AssuranceLevel::TransitVerified,
        sdk_receipt::AssuranceLevel::Durable => AssuranceLevel::Durable,
        sdk_receipt::AssuranceLevel::AtRestVerified => AssuranceLevel::AtRestVerified,
        sdk_receipt::AssuranceLevel::Published => AssuranceLevel::Published,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn receipt(
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
            verify_receipt_ed25519(&encoded, &key.verifying_key().to_bytes()).unwrap(),
            digest,
        )
    }

    #[test]
    fn receipt_metadata_and_chain_bounds_remain_authenticated() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let (first, first_digest) = signed(
            receipt(vot_receipt::AssuranceLevel::Admitted, 1, None),
            &key,
        );
        let (second, second_digest) = signed(
            receipt(
                vot_receipt::AssuranceLevel::TransitVerified,
                2,
                Some(first_digest),
            ),
            &key,
        );
        assert_eq!(second.assurance(), AssuranceLevel::TransitVerified);
        assert_eq!(second.provider(), 3);
        assert_eq!(second.provider_version(), [2, 3, 4]);
        assert_eq!(second.sequence(), 2);
        assert_eq!(second.observed_at(), "2026-08-11T12:00:00Z");
        assert_eq!(second.key_id(), b"issuer");
        assert_eq!(second.previous_digest(), Some(first_digest.to_vec()));
        assert_eq!(second.envelope_digest().unwrap(), second_digest);

        let mut chain = ReceiptChain::new(2);
        chain.push(&first).unwrap();
        chain.push(&second).unwrap();
        assert_eq!(chain.length(), 2);
        chain.verify().unwrap();
        assert_eq!(
            ReceiptChain::new(2).verify().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            ReceiptChain::new(0).push(&first).unwrap_err().code(),
            ErrorCode::LimitExceeded
        );
    }
}
