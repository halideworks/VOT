//! Borrowed witnesses for authenticated range bytes.

use crate::Error;
use crate::error;
use crate::object::ObjectId;

/// Borrowed bytes authenticated against one exact object identity.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedSlice<'data> {
    inner: vot_verified_range::VerifiedSlice<'data>,
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
