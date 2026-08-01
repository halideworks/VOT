//! Commit-state mapping for S3-compatible multipart object stores.

#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

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
    parts: BTreeMap<u32, PartReceipt>,
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
            parts: BTreeMap::new(),
        })
    }

    pub fn upload_verified_part(&mut self, number: u32, bytes: &[u8]) -> Result<(), Error> {
        let checksum = vot_journal::crc32c(bytes);
        let receipt = self
            .store
            .upload_part(&self.upload_id, number, bytes, checksum)?;
        self.parts.insert(number, receipt);
        Ok(())
    }

    pub fn complete(&mut self) -> Result<(CompletedObject, Receipt), Error> {
        match self.machine.state() {
            State::Admitted => {
                self.machine.apply(Event::TransitVerified)?;
                self.machine.apply(Event::DataFlushSucceeded)?;
                self.machine.apply(Event::JournalFlushSucceeded)?;
            }
            State::RecoveryRequired => {
                self.machine.apply(Event::Recover)?;
            }
            _ => return Err(Error::Model(vot_commit_model::Error::InvalidTransition)),
        }
        let parts: Vec<_> = self.parts.values().cloned().collect();
        let object = match self.store.complete_multipart(&self.upload_id, &parts) {
            Ok(object) => object,
            Err(StoreError::CompletionAmbiguous) => {
                self.machine.apply(Event::NamespaceLinkAmbiguous)?;
                return Err(Error::Store(StoreError::CompletionAmbiguous));
            }
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
            key: self.key.clone(),
            checksum_crc32c: object.checksum_crc32c,
        };
        Ok((object, receipt))
    }

    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.machine.state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_object_store::{Error as StoreError, MockStore, S3Compatible};

    #[derive(Default)]
    struct AmbiguousOnce {
        inner: MockStore,
        completed: Option<CompletedObject>,
    }

    impl S3Compatible for AmbiguousOnce {
        fn create_multipart(&mut self, key: &str, now: u64) -> Result<String, StoreError> {
            self.inner.create_multipart(key, now)
        }

        fn upload_part(
            &mut self,
            upload_id: &str,
            number: u32,
            bytes: &[u8],
            checksum_crc32c: u32,
        ) -> Result<PartReceipt, StoreError> {
            self.inner
                .upload_part(upload_id, number, bytes, checksum_crc32c)
        }

        fn complete_multipart(
            &mut self,
            upload_id: &str,
            parts: &[PartReceipt],
        ) -> Result<CompletedObject, StoreError> {
            if let Some(completed) = &self.completed {
                return Ok(completed.clone());
            }
            let completed = self.inner.complete_multipart(upload_id, parts)?;
            self.completed = Some(completed);
            Err(StoreError::CompletionAmbiguous)
        }

        fn head(&self, key: &str) -> Option<(u64, u32)> {
            self.inner.head(key)
        }
    }

    #[test]
    fn backend_checksum_precedes_strict_publication() {
        let mut commit = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        commit.upload_verified_part(1, b"one").unwrap();
        commit.upload_verified_part(2, b"two").unwrap();
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(receipt.assurance, Assurance::Published);
        assert_eq!(
            commit.store().head("object"),
            Some((6, object.checksum_crc32c))
        );
    }

    #[test]
    fn out_of_order_and_replaced_parts_complete_in_number_order() {
        let mut commit = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        commit.upload_verified_part(2, b"old").unwrap();
        commit.upload_verified_part(1, b"one").unwrap();
        commit.upload_verified_part(2, b"two").unwrap();
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(object.bytes, b"onetwo");
        assert_eq!(receipt.assurance, Assurance::Published);
    }

    #[test]
    fn ambiguous_completion_preserves_state_and_reconciles_on_retry() {
        let mut commit = ObjectCommit::create(AmbiguousOnce::default(), "object", 0).unwrap();
        commit.upload_verified_part(1, b"bytes").unwrap();
        assert!(matches!(
            commit.complete(),
            Err(Error::Store(StoreError::CompletionAmbiguous))
        ));
        assert_eq!(commit.state(), State::RecoveryRequired);
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(object.bytes, b"bytes");
        assert_eq!(receipt.assurance, Assurance::Published);
    }
}
