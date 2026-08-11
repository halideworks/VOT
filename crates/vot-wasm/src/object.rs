use vot_sdk::coverage as sdk_coverage;
use vot_sdk::object as sdk_object;
use vot_sdk::verify as sdk_verify;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ErrorCode, VotError};

/// Supported VOT object suite.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    Blake3Bao64,
    Sha256Bep52,
}

impl Suite {
    const fn sdk(self) -> sdk_object::Suite {
        match self {
            Self::Blake3Bao64 => sdk_object::Suite::Blake3Bao64,
            Self::Sha256Bep52 => sdk_object::Suite::Sha256Bep52,
        }
    }
}

/// Exact VOT object identity. Storage location is deliberately absent.
#[wasm_bindgen]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub(crate) inner: sdk_object::ObjectId,
}

#[wasm_bindgen]
impl ObjectId {
    #[wasm_bindgen(constructor)]
    pub fn new(suite: Suite, root: &[u8], length: u64) -> Result<Self, VotError> {
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| VotError::new(ErrorCode::InvalidInput))?;
        Ok(Self {
            inner: sdk_object::ObjectId {
                suite: suite.sdk().identifier(),
                root,
                length,
            },
        })
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn suite(&self) -> Suite {
        match self.inner.suite {
            1 => Suite::Blake3Bao64,
            2 => Suite::Sha256Bep52,
            _ => unreachable!("SDK object identities have a supported suite"),
        }
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn root(&self) -> Vec<u8> {
        self.inner.root.to_vec()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn length(&self) -> u64 {
        self.inner.length
    }
}

impl ObjectId {
    pub(crate) const fn from_sdk(inner: sdk_object::ObjectId) -> Self {
        Self { inner }
    }
}

/// Incremental object preparation with an explicit retained-memory bound.
#[wasm_bindgen]
pub struct ObjectBuilder {
    inner: sdk_object::InMemoryObjectBuilder,
}

#[wasm_bindgen]
impl ObjectBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        suite: Suite,
        expected_length: Option<u64>,
        max_object_length: u64,
    ) -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_object::InMemoryObjectBuilder::new(
                suite.sdk(),
                expected_length,
                max_object_length,
            )?,
        })
    }

    /// Copies one caller-bounded chunk into the streaming verifier.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), VotError> {
        self.inner.update(bytes).map_err(Into::into)
    }

    pub fn finish(self) -> Result<PreparedObject, VotError> {
        Ok(PreparedObject {
            inner: self.inner.finish()?,
        })
    }
}

/// Object identity bound to retained proof material.
#[wasm_bindgen]
pub struct PreparedObject {
    pub(crate) inner: sdk_object::InMemoryPreparedObject,
}

#[wasm_bindgen]
impl PreparedObject {
    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_sdk(self.inner.object_id().clone())
    }

    pub fn prove(&self, offset: u64, length: u64) -> Result<RangeProof, VotError> {
        Ok(RangeProof {
            inner: self.inner.prove(offset, length)?,
        })
    }

    #[wasm_bindgen(js_name = encodeCatalog)]
    pub fn encode_catalog(&self, max_catalog_bytes: u64) -> Result<Vec<u8>, VotError> {
        vot_sdk::proof::encode_in_memory(&self.inner, max_catalog_bytes).map_err(Into::into)
    }
}

/// Canonical proof and its exact covered range.
#[wasm_bindgen]
pub struct RangeProof {
    inner: sdk_object::RangeProof,
}

#[wasm_bindgen]
impl RangeProof {
    #[wasm_bindgen(getter, js_name = coveredOffset)]
    #[must_use]
    pub fn covered_offset(&self) -> u64 {
        self.inner.covered_offset()
    }

    #[wasm_bindgen(getter, js_name = coveredLength)]
    #[must_use]
    pub fn covered_length(&self) -> u64 {
        self.inner.covered_length()
    }

    /// Copies the bounded proof bytes to JavaScript.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.proof().to_vec()
    }
}

/// Owned bytes authenticated against one exact VOT object identity.
#[wasm_bindgen]
#[derive(Debug)]
pub struct VerifiedRange {
    object: ObjectId,
    covered_offset: u64,
    data: Vec<u8>,
}

#[wasm_bindgen]
impl VerifiedRange {
    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.object.clone()
    }

    #[wasm_bindgen(getter, js_name = coveredOffset)]
    #[must_use]
    pub fn covered_offset(&self) -> u64 {
        self.covered_offset
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn length(&self) -> usize {
        self.data.len()
    }

    /// Copies only already authenticated bytes to JavaScript.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl VerifiedRange {
    pub(crate) fn from_verified(verified: &sdk_verify::VerifiedSlice<'_>) -> Self {
        Self {
            object: ObjectId::from_sdk(verified.object_id()),
            covered_offset: verified.covered_offset(),
            data: verified.data().to_vec(),
        }
    }
}

#[wasm_bindgen(js_name = verifyRange)]
pub fn verify_range(
    object: &ObjectId,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<VerifiedRange, VotError> {
    let verified = sdk_verify::verify_range(&object.inner, covered_offset, data, proof)?;
    Ok(VerifiedRange::from_verified(&verified))
}

/// Result of accepting an authenticated range.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageUpdate {
    Accepted,
    Replay,
}

/// One authenticated range and the coverage transition it produced.
#[wasm_bindgen]
pub struct CoverageAcceptance {
    range: VerifiedRange,
    update: CoverageUpdate,
}

#[wasm_bindgen]
impl CoverageAcceptance {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn update(&self) -> CoverageUpdate {
        self.update
    }

    #[wasm_bindgen(js_name = intoVerifiedRange)]
    #[must_use]
    pub fn into_verified_range(self) -> VerifiedRange {
        self.range
    }
}

/// Identity-bound authenticated coverage without a host-owned sink.
#[wasm_bindgen]
pub struct ObjectCoverage {
    object: ObjectId,
    inner: sdk_coverage::ObjectCoverage,
}

#[wasm_bindgen]
impl ObjectCoverage {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(object: &ObjectId) -> Self {
        Self {
            object: object.clone(),
            inner: sdk_coverage::ObjectCoverage::new(&object.inner),
        }
    }

    /// Verifies once, then advances coverage only with the borrowed witness.
    #[wasm_bindgen(js_name = verifyAndAccept)]
    pub fn verify_and_accept(
        &mut self,
        covered_offset: u64,
        data: &[u8],
        proof: &[u8],
    ) -> Result<CoverageAcceptance, VotError> {
        let verified = sdk_verify::verify_range(&self.object.inner, covered_offset, data, proof)?;
        let update = match self.inner.accept(&verified)? {
            sdk_coverage::CoverageUpdate::Accepted => CoverageUpdate::Accepted,
            sdk_coverage::CoverageUpdate::Replay => CoverageUpdate::Replay,
        };
        Ok(CoverageAcceptance {
            range: VerifiedRange::from_verified(&verified),
            update,
        })
    }

    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.object.clone()
    }

    #[wasm_bindgen(getter, js_name = coveredBytes)]
    #[must_use]
    pub fn covered_bytes(&self) -> u64 {
        self.inner.covered_bytes()
    }

    #[wasm_bindgen(getter, js_name = fragmentCount)]
    #[must_use]
    pub fn fragment_count(&self) -> usize {
        self.inner.fragment_count()
    }

    #[wasm_bindgen(getter, js_name = complete)]
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_root_length_is_a_stable_input_error() {
        assert_eq!(
            ObjectId::new(Suite::Sha256Bep52, &[0; 31], 0)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn suite_geometry_catalog_and_fragment_accessors_report_the_sdk_state() {
        let blake = ObjectId::new(Suite::Blake3Bao64, &[3; 32], 7).unwrap();
        let sha = ObjectId::new(Suite::Sha256Bep52, &[4; 32], 9).unwrap();
        assert_eq!(blake.suite(), Suite::Blake3Bao64);
        assert_eq!(sha.suite(), Suite::Sha256Bep52);

        let mut data = vec![3; 131_073];
        data[65_536..131_072].fill(5);
        data[131_072] = 7;
        let mut builder = ObjectBuilder::new(
            Suite::Sha256Bep52,
            Some(data.len() as u64),
            data.len() as u64,
        )
        .unwrap();
        builder.update(&data).unwrap();
        let prepared = builder.finish().unwrap();
        let middle = prepared.prove(65_537, 1).unwrap();
        assert_eq!(middle.covered_offset(), 65_536);
        assert_eq!(middle.covered_length(), 65_536);
        assert!(!middle.bytes().is_empty());
        let verified = verify_range(
            &prepared.object_id(),
            middle.covered_offset(),
            &data[65_536..131_072],
            &middle.bytes(),
        )
        .unwrap();
        assert_eq!(verified.covered_offset(), 65_536);
        assert_eq!(verified.length(), 65_536);
        assert_eq!(verified.bytes(), data[65_536..131_072]);
        let catalog = prepared.encode_catalog(u64::MAX).unwrap();
        assert!(catalog.len() > 1);

        let first = prepared.prove(0, 1).unwrap();
        let tail = prepared.prove(131_072, 1).unwrap();
        let mut coverage = ObjectCoverage::new(&prepared.object_id());
        coverage
            .verify_and_accept(0, &data[..65_536], &first.bytes())
            .unwrap();
        coverage
            .verify_and_accept(131_072, &data[131_072..], &tail.bytes())
            .unwrap();
        assert_eq!(coverage.fragment_count(), 2);
        assert!(!coverage.is_complete());
    }
}
