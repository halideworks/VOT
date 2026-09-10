//! Borrowed witnesses for authenticated range bytes.

use crate::Error;
use crate::error;
use crate::object::ObjectId;

/// Borrowed bytes authenticated against one exact object identity.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedSlice<'data> {
    inner: vot_verified_range::VerifiedSlice<'data>,
}

impl<'data> From<vot_verified_range::VerifiedSlice<'data>> for VerifiedSlice<'data> {
    fn from(inner: vot_verified_range::VerifiedSlice<'data>) -> Self {
        Self { inner }
    }
}

impl VerifiedSlice<'_> {
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        let object = self.inner.object();
        ObjectId {
            suite: object.suite,
            root: object.root,
            length: object.length,
        }
    }

    #[must_use]
    pub const fn covered_offset(&self) -> u64 {
        self.inner.covered_offset()
    }

    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.inner.data()
    }
}

pub fn verify_range<'data>(
    object: &ObjectId,
    covered_offset: u64,
    data: &'data [u8],
    proof: &[u8],
) -> Result<VerifiedSlice<'data>, Error> {
    let object = vot_codec::frames::ObjectId {
        suite: object.suite,
        root: object.root,
        length: object.length,
    };
    vot_verified_range::verify_range(object, covered_offset, data, proof)
        .map(|inner| VerifiedSlice { inner })
        .map_err(error::verify)
}

pub(crate) const fn from_inner(inner: vot_verified_range::VerifiedSlice<'_>) -> VerifiedSlice<'_> {
    VerifiedSlice { inner }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{InMemoryObjectBuilder, Suite};

    #[test]
    fn transport_witness_conversion_preserves_identity_offset_and_borrow() {
        let bytes = vec![42; 131_072];
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut builder = InMemoryObjectBuilder::new(suite, Some(131_072), 131_072).unwrap();
            builder.update(&bytes).unwrap();
            let object = builder.finish().unwrap();
            let proof = object.prove(65_536, 65_536).unwrap();
            let id = object.object_id();
            let inner = vot_verified_range::verify_range(
                vot_codec::frames::ObjectId {
                    suite: id.suite,
                    root: id.root,
                    length: id.length,
                },
                65_536,
                &bytes[65_536..],
                proof.proof(),
            )
            .unwrap();
            let converted = VerifiedSlice::from(inner);
            assert_eq!(converted.object_id(), *id);
            assert_eq!(converted.covered_offset(), 65_536);
            assert!(std::ptr::eq(converted.data(), inner.data()));
        }
    }
}
