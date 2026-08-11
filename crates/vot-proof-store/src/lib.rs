//! Host-pluggable storage for retained proof nodes.

#![forbid(unsafe_code)]

use std::panic::{RefUnwindSafe, UnwindSafe};

/// One retained suite proof node.
pub type ProofNode = [u8; 32];

/// A retained proof-node storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// A length, ordinal, or allocation cannot be represented.
    Capacity,
    /// A named node is absent or its stored representation is invalid.
    Corrupt,
    /// The backing store cannot currently perform the requested operation.
    Unavailable,
}

/// Sequential storage used while retaining proof nodes.
///
/// A caller starts construction only with a store whose exact length is zero.
/// A successful [`Self::append`] adds exactly one node at the prior length.
/// An append error may have partially changed a backing implementation, so the
/// caller must poison that construction and must not append or read it again.
///
/// [`Self::read`] returns the node at the named ordinal or an error. It never
/// substitutes a zero or another node for missing or corrupt state.
///
/// Storage availability is temporary computation state. Success does not
/// establish durability, at-rest verification, publication, or assurance.
pub trait ProofNodeStorage: Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Returns the exact number of nodes currently stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Capacity`] when the length cannot be represented,
    /// or a backend-specific availability or corruption error.
    fn len(&self) -> Result<u64, StoreError>;

    /// Reports whether the store contains no nodes.
    ///
    /// # Errors
    ///
    /// Propagates the same capacity, availability, or corruption error as
    /// [`Self::len`].
    fn is_empty(&self) -> Result<bool, StoreError> {
        self.len().map(|length| length == 0)
    }

    /// Appends one node at the current length.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Capacity`] when one more node cannot be retained,
    /// or a backend-specific availability or corruption error. Callers must
    /// poison the construction after any error.
    fn append(&mut self, node: ProofNode) -> Result<(), StoreError>;

    /// Reads exactly one previously appended node by ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] for an ordinal outside the stored range,
    /// or a backend-specific capacity, availability, or corruption error.
    fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError>;
}

/// In-memory sequential proof-node storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryNodeStorage {
    nodes: Vec<ProofNode>,
}

impl MemoryNodeStorage {
    /// Creates an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self { nodes: Vec::new() }
    }
}

impl ProofNodeStorage for MemoryNodeStorage {
    fn len(&self) -> Result<u64, StoreError> {
        u64::try_from(self.nodes.len()).map_err(|_| StoreError::Capacity)
    }

    fn append(&mut self, node: ProofNode) -> Result<(), StoreError> {
        self.nodes
            .try_reserve(1)
            .map_err(|_| StoreError::Capacity)?;
        self.nodes.push(node);
        Ok(())
    }

    fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError> {
        if ordinal >= self.len()? {
            return Err(StoreError::Corrupt);
        }
        let index = usize::try_from(ordinal).map_err(|_| StoreError::Capacity)?;
        self.nodes.get(index).copied().ok_or(StoreError::Corrupt)
    }
}

#[cfg(test)]
mod tests;
