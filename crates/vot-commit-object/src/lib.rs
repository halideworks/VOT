//! Commit-state mapping for S3-compatible multipart object stores.

#![allow(clippy::missing_errors_doc)]

use vot_commit_model::{Assurance, Event, Machine, Profile, State};
use vot_object_store::{CompletedObject, Error as StoreError, PartReceipt, S3Compatible};

#[derive(Debug)]
pub enum Error {
    Store(StoreError),
    Model(vot_commit_model::Error),
    ChecksumMismatch,
    MissingObservation,
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<vot_commit_model::Error> for Error {
    fn from(error: vot_commit_model::Error) -> Self {
        Self::Model(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub assurance: Assurance,
    pub sequence: u64,
    pub key: String,
    pub checksum_crc32c: u32,
}

pub struct ObjectCommit<S> {
    store: S,
    machine: Machine,
    upload_id: String,
    key: String,
    parts: Vec<PartReceipt>,
}

impl<S: S3Compatible> ObjectCommit<S> {
    pub fn create(mut store: S, key: &str, now: u64) -> Result<Self, Error> {
        let upload_id = store.create_multipart(key, now)?;
        let mut machine = Machine::new(Profile::Strict);
        machine.apply(Event::Admit)?;
        Ok(Self {
            store,
            machine,
            upload_id,
            key: key.to_owned(),
            parts: Vec::new(),
        })
    }

    pub fn upload_verified_part(&mut self, number: u32, bytes: &[u8]) -> Result<(), Error> {
        let checksum = vot_journal::crc32c(bytes);
        let receipt = self
            .store
            .upload_part(&self.upload_id, number, bytes, checksum)?;
        self.parts.push(receipt);
        Ok(())
    }

    pub fn complete(mut self) -> Result<(S, CompletedObject, Receipt), Error> {
        self.machine.apply(Event::TransitVerified)?;
        self.machine.apply(Event::DataFlushSucceeded)?;
        self.machine.apply(Event::JournalFlushSucceeded)?;
        let object = match self.store.complete_multipart(&self.upload_id, &self.parts) {
            Ok(object) => object,
            Err(error) => {
                self.machine.apply(Event::AtRestVerificationFailed)?;
                return Err(Error::Store(error));
            }
        };
        if self.store.head(&self.key) != Some((object.bytes.len() as u64, object.checksum_crc32c)) {
            self.machine.apply(Event::AtRestVerificationFailed)?;
            return Err(Error::ChecksumMismatch);
        }
        self.machine.apply(Event::AtRestVerified)?;
        self.machine.apply(Event::NamespaceLinked)?;
        let observation = self
            .machine
            .apply(Event::NamespaceDurable)?
            .ok_or(Error::MissingObservation)?;
        let receipt = Receipt {
            assurance: observation.level,
            sequence: observation.sequence,
            key: self.key,
            checksum_crc32c: object.checksum_crc32c,
        };
        Ok((self.store, object, receipt))
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.machine.state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_object_store::MockStore;

    #[test]
    fn backend_checksum_precedes_strict_publication() {
        let mut commit = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        commit.upload_verified_part(1, b"one").unwrap();
        commit.upload_verified_part(2, b"two").unwrap();
        let (store, object, receipt) = commit.complete().unwrap();
        assert_eq!(receipt.assurance, Assurance::Published);
        assert_eq!(store.head("object"), Some((6, object.checksum_crc32c)));
    }
}
