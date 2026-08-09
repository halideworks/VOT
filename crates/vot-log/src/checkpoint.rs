//! Checkpoint model and body.

use super::{Error, Hash, MAX_NAME_BYTES, base64};

/// A published tree head. Serialized as a signed note (Go/Sigstore compatible).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Names the log, so a signature over one log's head is not valid for
    /// another's.
    pub origin: String,
    pub size: usize,
    pub root: Hash,
}

impl Checkpoint {
    /// The signed body: origin, size, base64 root, each on its own line.
    ///
    /// # Errors
    /// Rejects an origin that is empty, oversized, or contains a newline, since
    /// either would let one checkpoint be read as another.
    pub fn body(&self) -> Result<String, Error> {
        if self.origin.is_empty() || self.origin.len() > MAX_NAME_BYTES {
            return Err(Error::Malformed);
        }
        if self.origin.contains('\n') {
            return Err(Error::Malformed);
        }
        Ok(format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            base64(&self.root)
        ))
    }
}
