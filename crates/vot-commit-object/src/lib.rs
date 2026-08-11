//! Commit-state mapping for S3-compatible multipart object stores.

#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use vot_commit_model::{Assurance, Event, Machine, Profile, State};
use vot_object_store::{
    CompletedObject, Error as StoreError, MultipartCompleted, MultipartObjectStore,
    ObjectExpectation, PartReceipt, ReadbackVerified,
};

/// Maximum number of external multipart receipts accepted in one object.
pub const MAX_EXTERNAL_PARTS: usize = 10_000;
/// Maximum external object-key length, in bytes.
pub const MAX_EXTERNAL_KEY_BYTES: usize = 1_024;

#[derive(Debug)]
pub enum Error {
    Store(StoreError),
    Model(vot_commit_model::Error),
    ChecksumMismatch,
    MissingObservation,
}

#[derive(Debug)]
pub enum ExternalError {
    Commit(Error),
    TooManyParts,
    KeyTooLong,
}

impl From<Error> for ExternalError {
    fn from(error: Error) -> Self {
        Self::Commit(error)
    }
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

/// A Strict object commit driven only by evidence from an external mover.
///
/// The part payloads, store credentials, and provider operations remain owned
/// by the host. This value retains only their bounded aggregate expectation.
/// The caller must authenticate evidence provenance and reject stale or
/// cross-instance replay before calling `accept_completion` or
/// `accept_verification`. The machine enforces ordering and replay only within
/// one `ExternalObjectCommit` value.
pub struct ExternalObjectCommit {
    machine: Machine,
    expectation: ObjectExpectation,
}

impl ExternalObjectCommit {
    /// Validates canonical external part receipts without retaining their list.
    pub fn from_parts(key: &str, parts: &[PartReceipt]) -> Result<Self, ExternalError> {
        if key.len() > MAX_EXTERNAL_KEY_BYTES {
            return Err(ExternalError::KeyTooLong);
        }
        if parts.len() > MAX_EXTERNAL_PARTS {
            return Err(ExternalError::TooManyParts);
        }
        let expectation = ObjectExpectation::from_parts(key, parts).map_err(Error::from)?;
        Ok(Self {
            machine: admitted_strict_machine()?,
            expectation,
        })
    }

    #[must_use]
    pub const fn expectation(&self) -> &ObjectExpectation {
        &self.expectation
    }

    /// Accepts matching completion evidence and stops at Durable.
    pub fn accept_completion(
        &mut self,
        completed: &MultipartCompleted,
    ) -> Result<Assurance, ExternalError> {
        if self.machine.state() != State::Admitted {
            return Err(Error::Model(vot_commit_model::Error::InvalidTransition).into());
        }
        let assurance = advance_to_durable(&mut self.machine)?;
        if let Err(error) = validate_completion(completed, &self.expectation) {
            poison_at_rest(&mut self.machine)?;
            return Err(Error::Store(error).into());
        }
        Ok(assurance)
    }

    /// Accepts matching full-readback evidence and publishes the Strict receipt.
    pub fn accept_verification(
        &mut self,
        verified: ReadbackVerified,
    ) -> Result<(CompletedObject, Receipt), ExternalError> {
        if self.machine.state() != State::Durable {
            return Err(Error::Model(vot_commit_model::Error::InvalidTransition).into());
        }
        let object = match validate_readback(verified, &self.expectation) {
            Ok(object) => object,
            Err(error) => {
                poison_at_rest(&mut self.machine)?;
                return Err(Error::Store(error).into());
            }
        };
        publish_verified(&mut self.machine, self.expectation.key(), object).map_err(Into::into)
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.machine.state()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionState {
    Pending,
    Ambiguous,
    Confirmed,
}

pub struct ObjectCommit<S> {
    store: S,
    machine: Machine,
    upload_id: String,
    key: String,
    parts: BTreeMap<u32, PartReceipt>,
    expectation: Option<ObjectExpectation>,
    completion: CompletionState,
}

impl<S: MultipartObjectStore> ObjectCommit<S> {
    pub fn create(mut store: S, key: &str, now: u64) -> Result<Self, Error> {
        let upload_id = store.create_multipart(key, now)?;
        Ok(Self {
            store,
            machine: admitted_strict_machine()?,
            upload_id,
            key: key.to_owned(),
            parts: BTreeMap::new(),
            expectation: None,
            completion: CompletionState::Pending,
        })
    }

    pub fn upload_verified_part(&mut self, number: u32, bytes: &[u8]) -> Result<(), Error> {
        if self.machine.state() != State::Admitted {
            return Err(Error::Model(vot_commit_model::Error::InvalidTransition));
        }
        let checksum = vot_journal::crc32c(bytes);
        let receipt = self
            .store
            .upload_part(&self.upload_id, number, bytes, checksum)?;
        if receipt.number != number
            || receipt.length != bytes.len() as u64
            || receipt.checksum_crc32c != checksum
        {
            return Err(Error::ChecksumMismatch);
        }
        self.parts.insert(number, receipt);
        Ok(())
    }

    pub fn complete(&mut self) -> Result<(CompletedObject, Receipt), Error> {
        let parts: Vec<_> = self.parts.values().cloned().collect();
        if self.expectation.is_none() {
            self.expectation = Some(ObjectExpectation::from_parts(&self.key, &parts)?);
        }
        let expected = self
            .expectation
            .clone()
            .ok_or(Error::Store(StoreError::CompletionMismatch))?;
        match self.machine.state() {
            State::Admitted => {
                advance_to_durable(&mut self.machine)?;
            }
            State::RecoveryRequired => {
                self.machine.apply(Event::Recover)?;
            }
            _ => return Err(Error::Model(vot_commit_model::Error::InvalidTransition)),
        }

        if self.completion == CompletionState::Ambiguous {
            match self.validated_readback(&expected) {
                Ok(object) => return self.publish(object),
                Err(StoreError::ObjectNotFound) => {}
                Err(StoreError::Backend) => return self.require_recovery(),
                Err(error) => return self.fail_at_rest(error),
            }
        }

        if self.completion != CompletionState::Confirmed {
            match self.store.complete_multipart(&self.upload_id, &parts) {
                Ok(completed) if validate_completion(&completed, &expected).is_ok() => {
                    self.completion = CompletionState::Confirmed;
                }
                Ok(_) => {
                    self.completion = CompletionState::Ambiguous;
                    return self.fail_at_rest(StoreError::CompletionMismatch);
                }
                Err(StoreError::CompletionAmbiguous) => {
                    self.completion = CompletionState::Ambiguous;
                    return self.require_recovery();
                }
                Err(error) => return self.fail_at_rest(error),
            }
        }

        let object = match self.validated_readback(&expected) {
            Ok(object) => object,
            Err(StoreError::ObjectNotFound | StoreError::Backend) => {
                return self.require_recovery();
            }
            Err(error) => return self.fail_at_rest(error),
        };
        self.publish(object)
    }

    fn validated_readback(
        &self,
        expected: &ObjectExpectation,
    ) -> Result<CompletedObject, StoreError> {
        validate_readback(self.store.verify_by_readback(expected)?, expected)
    }

    fn require_recovery<T>(&mut self) -> Result<T, Error> {
        self.machine.apply(Event::NamespaceLinkAmbiguous)?;
        Err(Error::Store(StoreError::CompletionAmbiguous))
    }

    fn fail_at_rest<T>(&mut self, error: StoreError) -> Result<T, Error> {
        poison_at_rest(&mut self.machine)?;
        self.store.release_multipart(&self.upload_id);
        Err(Error::Store(error))
    }

    fn publish(&mut self, object: CompletedObject) -> Result<(CompletedObject, Receipt), Error> {
        let published = publish_verified(&mut self.machine, &self.key, object)?;
        self.store.release_multipart(&self.upload_id);
        Ok(published)
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

fn admitted_strict_machine() -> Result<Machine, Error> {
    let mut machine = Machine::new(Profile::Strict);
    machine.apply(Event::Admit)?;
    Ok(machine)
}

fn advance_to_durable(machine: &mut Machine) -> Result<Assurance, Error> {
    machine.apply(Event::TransitVerified)?;
    machine.apply(Event::DataFlushSucceeded)?;
    let observation = machine
        .apply(Event::JournalFlushSucceeded)?
        .ok_or(Error::MissingObservation)?;
    Ok(observation.level)
}

fn validate_completion(
    completed: &MultipartCompleted,
    expected: &ObjectExpectation,
) -> Result<(), StoreError> {
    let actual = completed.expectation();
    if actual.key() == expected.key()
        && actual.length() == expected.length()
        && actual.checksum_crc32c() == expected.checksum_crc32c()
    {
        Ok(())
    } else {
        Err(StoreError::CompletionMismatch)
    }
}

fn validate_readback(
    verified: ReadbackVerified,
    expected: &ObjectExpectation,
) -> Result<CompletedObject, StoreError> {
    let object = verified.into_object();
    if object_matches(&object, expected) {
        Ok(object)
    } else {
        Err(StoreError::ChecksumMismatch)
    }
}

fn poison_at_rest(machine: &mut Machine) -> Result<(), Error> {
    machine.apply(Event::AtRestVerificationFailed)?;
    Ok(())
}

fn publish_verified(
    machine: &mut Machine,
    key: &str,
    object: CompletedObject,
) -> Result<(CompletedObject, Receipt), Error> {
    machine.apply(Event::AtRestVerified)?;
    machine.apply(Event::NamespaceLinked)?;
    let observation = machine
        .apply(Event::NamespaceDurable)?
        .ok_or(Error::MissingObservation)?;
    let receipt = Receipt {
        assurance: observation.level,
        sequence: observation.sequence,
        key: key.to_owned(),
        checksum_crc32c: object.checksum_crc32c,
    };
    Ok((object, receipt))
}

fn object_matches(actual: &CompletedObject, expected: &ObjectExpectation) -> bool {
    actual.key == expected.key()
        && actual.length == expected.length()
        && actual.checksum_crc32c == expected.checksum_crc32c()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use vot_object_store::{
        Error as StoreError, MockStore, MultipartCompleted, MultipartObjectStore, ObjectMetadata,
        ReadbackVerified,
    };

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum EvidenceFault {
        #[default]
        None,
        Key,
        Length,
        Checksum,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum PartReceiptFault {
        #[default]
        None,
        Number,
        Length,
        Checksum,
    }

    #[derive(Default)]
    struct ScriptedStore {
        inner: MockStore,
        upload_calls: usize,
        upload_fault: PartReceiptFault,
        complete_calls: usize,
        release_calls: usize,
        readback_calls: Cell<usize>,
        transient_readbacks: Cell<usize>,
        first_completion_ambiguous: bool,
        apply_before_ambiguity: bool,
        completed: Option<MultipartCompleted>,
        completion_fault: EvidenceFault,
        readback_fault: EvidenceFault,
    }

    impl MultipartObjectStore for ScriptedStore {
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
            self.upload_calls += 1;
            let mut receipt = self
                .inner
                .upload_part(upload_id, number, bytes, checksum_crc32c)?;
            match self.upload_fault {
                PartReceiptFault::None => {}
                PartReceiptFault::Number => receipt.number = receipt.number.saturating_add(1),
                PartReceiptFault::Length => receipt.length = receipt.length.saturating_add(1),
                PartReceiptFault::Checksum => receipt.checksum_crc32c ^= 1,
            }
            Ok(receipt)
        }

        fn complete_multipart(
            &mut self,
            upload_id: &str,
            parts: &[PartReceipt],
        ) -> Result<MultipartCompleted, StoreError> {
            self.complete_calls += 1;
            if self.complete_calls == 1 && self.first_completion_ambiguous {
                if self.apply_before_ambiguity {
                    self.completed = Some(self.inner.complete_multipart(upload_id, parts)?);
                }
                return Err(StoreError::CompletionAmbiguous);
            }
            let completed = if let Some(completed) = &self.completed {
                completed.clone()
            } else {
                self.inner.complete_multipart(upload_id, parts)?
            };
            Ok(faulty_completion(&completed, self.completion_fault))
        }

        fn stat_object(&self, key: &str) -> Result<Option<ObjectMetadata>, StoreError> {
            self.inner.stat_object(key)
        }

        fn verify_by_readback(
            &self,
            expected: &ObjectExpectation,
        ) -> Result<ReadbackVerified, StoreError> {
            self.readback_calls.set(self.readback_calls.get() + 1);
            if self.transient_readbacks.get() > 0 {
                self.transient_readbacks
                    .set(self.transient_readbacks.get() - 1);
                return Err(StoreError::Backend);
            }
            let object = self.inner.verify_by_readback(expected)?.into_object();
            Ok(ReadbackVerified::new(faulty_object(
                object,
                self.readback_fault,
            )))
        }

        fn release_multipart(&mut self, upload_id: &str) {
            self.release_calls += 1;
            self.inner.release_multipart(upload_id);
        }
    }

    fn faulty_completion(
        completed: &MultipartCompleted,
        fault: EvidenceFault,
    ) -> MultipartCompleted {
        let expected = completed.expectation();
        let mut part = PartReceipt {
            number: 1,
            checksum_crc32c: expected.checksum_crc32c(),
            length: expected.length(),
        };
        let key = if fault == EvidenceFault::Key {
            "other"
        } else {
            expected.key()
        };
        if fault == EvidenceFault::Length {
            part.length = part.length.saturating_add(1);
        }
        if fault == EvidenceFault::Checksum {
            part.checksum_crc32c ^= 1;
        }
        MultipartCompleted::new(ObjectExpectation::from_parts(key, &[part]).unwrap())
    }

    fn faulty_object(mut object: CompletedObject, fault: EvidenceFault) -> CompletedObject {
        match fault {
            EvidenceFault::None => {}
            EvidenceFault::Key => object.key = "other".to_owned(),
            EvidenceFault::Length => object.length = object.length.saturating_add(1),
            EvidenceFault::Checksum => object.checksum_crc32c ^= 1,
        }
        object
    }

    fn external_parts() -> [PartReceipt; 2] {
        [
            PartReceipt {
                number: 1,
                checksum_crc32c: vot_journal::crc32c(b"one"),
                length: 3,
            },
            PartReceipt {
                number: 2,
                checksum_crc32c: vot_journal::crc32c(b"two"),
                length: 3,
            },
        ]
    }

    fn external_evidence(
        key: &str,
        parts: &[PartReceipt],
    ) -> (MultipartCompleted, ReadbackVerified) {
        let expectation = ObjectExpectation::from_parts(key, parts).unwrap();
        let object = CompletedObject {
            key: key.to_owned(),
            length: expectation.length(),
            checksum_crc32c: expectation.checksum_crc32c(),
        };
        (
            MultipartCompleted::new(expectation),
            ReadbackVerified::new(object),
        )
    }

    #[test]
    fn backend_checksum_precedes_strict_publication() {
        let mut commit = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        commit.upload_verified_part(1, b"one").unwrap();
        commit.upload_verified_part(2, b"two").unwrap();
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(receipt.assurance, Assurance::Published);
        assert_eq!(
            commit.store().stat_object("object"),
            Ok(Some(vot_object_store::ObjectMetadata::new(object.length)))
        );
    }

    #[test]
    fn external_evidence_matches_the_direct_strict_receipt() {
        let mut direct = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        direct.upload_verified_part(1, b"one").unwrap();
        direct.upload_verified_part(2, b"two").unwrap();
        let direct_result = direct.complete().unwrap();

        let parts = external_parts();
        let (completed, verified) = external_evidence("object", &parts);
        let mut external = ExternalObjectCommit::from_parts("object", &parts).unwrap();
        assert!(matches!(
            external.accept_completion(&completed),
            Ok(Assurance::Durable)
        ));
        let external_result = external.accept_verification(verified).unwrap();
        assert_eq!(external_result, direct_result);
        assert_eq!(external.state(), State::Published);
    }

    #[test]
    fn completion_without_readback_stops_at_durable() {
        let parts = external_parts();
        let (completed, _) = external_evidence("object", &parts);
        let mut external = ExternalObjectCommit::from_parts("object", &parts).unwrap();
        assert!(matches!(
            external.accept_completion(&completed),
            Ok(Assurance::Durable)
        ));
        assert_eq!(external.state(), State::Durable);
        assert!(matches!(
            external.accept_completion(&completed),
            Err(ExternalError::Commit(Error::Model(
                vot_commit_model::Error::InvalidTransition
            )))
        ));
        assert_eq!(external.state(), State::Durable);
    }

    #[test]
    fn external_machine_enforces_order_and_same_instance_replay() {
        let parts = external_parts();
        let (completed, verified) = external_evidence("object", &parts);
        let mut external = ExternalObjectCommit::from_parts("object", &parts).unwrap();
        assert!(matches!(
            external.accept_verification(verified.clone()),
            Err(ExternalError::Commit(Error::Model(
                vot_commit_model::Error::InvalidTransition
            )))
        ));
        assert_eq!(external.state(), State::Admitted);
        external.accept_completion(&completed).unwrap();
        external.accept_verification(verified.clone()).unwrap();
        assert!(matches!(
            external.accept_verification(verified),
            Err(ExternalError::Commit(Error::Model(
                vot_commit_model::Error::InvalidTransition
            )))
        ));
        assert_eq!(external.state(), State::Published);
    }

    #[test]
    fn external_part_evidence_is_canonical_and_bounded() {
        let receipt = |number, length| PartReceipt {
            number,
            checksum_crc32c: vot_journal::CRC32C_EMPTY,
            length,
        };
        for invalid in [
            vec![],
            vec![receipt(2, 0)],
            vec![receipt(1, 0), receipt(3, 0)],
            vec![receipt(1, 0), receipt(1, 0)],
            vec![receipt(2, 0), receipt(1, 0)],
            vec![receipt(1, u64::MAX), receipt(2, 1)],
        ] {
            assert!(matches!(
                ExternalObjectCommit::from_parts("object", &invalid),
                Err(ExternalError::Commit(Error::Store(
                    StoreError::CompletionMismatch
                )))
            ));
        }

        let maximum: Vec<_> = (1..=MAX_EXTERNAL_PARTS)
            .map(|number| receipt(u32::try_from(number).unwrap(), 0))
            .collect();
        assert!(ExternalObjectCommit::from_parts("object", &maximum).is_ok());

        let too_many = vec![receipt(0, 0); MAX_EXTERNAL_PARTS + 1];
        assert!(matches!(
            ExternalObjectCommit::from_parts("object", &too_many),
            Err(ExternalError::TooManyParts)
        ));
    }

    #[test]
    fn external_key_bound_precedes_validation_and_cloning() {
        let receipt = PartReceipt {
            number: 1,
            checksum_crc32c: vot_journal::CRC32C_EMPTY,
            length: 0,
        };
        let maximum = "k".repeat(MAX_EXTERNAL_KEY_BYTES);
        assert!(ExternalObjectCommit::from_parts(&maximum, std::slice::from_ref(&receipt)).is_ok());

        let too_long = "k".repeat(MAX_EXTERNAL_KEY_BYTES + 1);
        assert!(matches!(
            ExternalObjectCommit::from_parts(&too_long, &[]),
            Err(ExternalError::KeyTooLong)
        ));
    }

    #[test]
    fn external_completion_is_validated_field_by_field() {
        let parts = external_parts();
        let (completed, _) = external_evidence("object", &parts);
        for fault in [
            EvidenceFault::Key,
            EvidenceFault::Length,
            EvidenceFault::Checksum,
        ] {
            let mut external = ExternalObjectCommit::from_parts("object", &parts).unwrap();
            assert!(matches!(
                external.accept_completion(&faulty_completion(&completed, fault)),
                Err(ExternalError::Commit(Error::Store(
                    StoreError::CompletionMismatch
                )))
            ));
            assert_eq!(external.state(), State::Poisoned, "{fault:?}");
            assert!(external.accept_completion(&completed).is_err(), "{fault:?}");
            assert_eq!(external.state(), State::Poisoned, "{fault:?}");
        }
    }

    #[test]
    fn external_readback_is_validated_field_by_field() {
        let parts = external_parts();
        let (completed, verified) = external_evidence("object", &parts);
        for fault in [
            EvidenceFault::Key,
            EvidenceFault::Length,
            EvidenceFault::Checksum,
        ] {
            let mut external = ExternalObjectCommit::from_parts("object", &parts).unwrap();
            external.accept_completion(&completed).unwrap();
            let faulty = ReadbackVerified::new(faulty_object(verified.object().clone(), fault));
            assert!(matches!(
                external.accept_verification(faulty),
                Err(ExternalError::Commit(Error::Store(
                    StoreError::ChecksumMismatch
                )))
            ));
            assert_eq!(external.state(), State::Poisoned, "{fault:?}");
            assert!(
                external.accept_verification(verified.clone()).is_err(),
                "{fault:?}"
            );
            assert_eq!(external.state(), State::Poisoned, "{fault:?}");
        }
    }

    #[test]
    fn upload_receipt_is_validated_field_by_field() {
        for fault in [
            PartReceiptFault::Number,
            PartReceiptFault::Length,
            PartReceiptFault::Checksum,
        ] {
            let store = ScriptedStore {
                upload_fault: fault,
                ..ScriptedStore::default()
            };
            let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
            assert!(matches!(
                commit.upload_verified_part(1, b"bytes"),
                Err(Error::ChecksumMismatch)
            ));
            assert_eq!(commit.store().upload_calls, 1, "{fault:?}");
            assert_eq!(commit.state(), State::Admitted, "{fault:?}");
        }
    }

    #[test]
    fn out_of_order_and_replaced_parts_complete_in_number_order() {
        let mut commit = ObjectCommit::create(MockStore::default(), "object", 0).unwrap();
        commit.upload_verified_part(2, b"old").unwrap();
        commit.upload_verified_part(1, b"one").unwrap();
        commit.upload_verified_part(2, b"two").unwrap();
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(
            (object.length, object.checksum_crc32c),
            (b"onetwo".len() as u64, vot_journal::crc32c(b"onetwo"))
        );
        assert_eq!(receipt.assurance, Assurance::Published);
    }

    #[test]
    fn confirmed_completion_is_not_repeated_after_transient_readback() {
        let store = ScriptedStore {
            transient_readbacks: Cell::new(2),
            ..ScriptedStore::default()
        };
        let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
        commit.upload_verified_part(1, b"bytes").unwrap();
        assert!(matches!(
            commit.complete(),
            Err(Error::Store(StoreError::CompletionAmbiguous))
        ));
        assert_eq!(commit.state(), State::RecoveryRequired);
        assert_eq!(commit.store().complete_calls, 1);
        assert_eq!(commit.store().readback_calls.get(), 1);
        assert!(matches!(
            commit.complete(),
            Err(Error::Store(StoreError::CompletionAmbiguous))
        ));
        assert_eq!(commit.state(), State::RecoveryRequired);
        assert_eq!(commit.store().complete_calls, 1);
        assert_eq!(commit.store().readback_calls.get(), 2);
        let (object, receipt) = commit.complete().unwrap();
        assert_eq!(
            (object.length, object.checksum_crc32c),
            (b"bytes".len() as u64, vot_journal::crc32c(b"bytes"))
        );
        assert_eq!(receipt.assurance, Assurance::Published);
        assert_eq!(commit.state(), State::Published);
        assert_eq!(commit.store().complete_calls, 1);
        assert_eq!(commit.store().readback_calls.get(), 3);
        assert_eq!(commit.store().release_calls, 1);
    }

    #[test]
    fn no_such_upload_after_applied_completion_reconciles_without_looping() {
        let store = ScriptedStore {
            first_completion_ambiguous: true,
            apply_before_ambiguity: true,
            ..ScriptedStore::default()
        };
        let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
        commit.upload_verified_part(1, b"bytes").unwrap();
        assert!(matches!(
            commit.complete(),
            Err(Error::Store(StoreError::CompletionAmbiguous))
        ));
        assert_eq!(commit.store().complete_calls, 1);
        assert_eq!(commit.store().readback_calls.get(), 0);
        assert!(commit.complete().is_ok());
        assert_eq!(commit.store().complete_calls, 1);
        assert_eq!(commit.store().readback_calls.get(), 1);
        assert_eq!(commit.store().release_calls, 1);
    }

    #[test]
    fn absent_ambiguous_completion_is_retried_once() {
        let store = ScriptedStore {
            first_completion_ambiguous: true,
            ..ScriptedStore::default()
        };
        let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
        commit.upload_verified_part(1, b"bytes").unwrap();
        assert!(commit.complete().is_err());
        assert!(commit.complete().is_ok());
        assert_eq!(commit.store().complete_calls, 2);
        assert_eq!(commit.store().readback_calls.get(), 2);
    }

    #[test]
    fn typed_backend_evidence_is_validated_field_by_field() {
        for fault in [
            EvidenceFault::Key,
            EvidenceFault::Length,
            EvidenceFault::Checksum,
        ] {
            let store = ScriptedStore {
                completion_fault: fault,
                ..ScriptedStore::default()
            };
            let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
            commit.upload_verified_part(1, b"bytes").unwrap();
            assert!(matches!(
                commit.complete(),
                Err(Error::Store(StoreError::CompletionMismatch))
            ));
            assert_eq!(commit.state(), State::Poisoned, "completion {fault:?}");
            assert_eq!(commit.store().readback_calls.get(), 0);
            assert_eq!(commit.store().release_calls, 1);
        }

        for fault in [
            EvidenceFault::Key,
            EvidenceFault::Length,
            EvidenceFault::Checksum,
        ] {
            let store = ScriptedStore {
                readback_fault: fault,
                ..ScriptedStore::default()
            };
            let mut commit = ObjectCommit::create(store, "object", 0).unwrap();
            commit.upload_verified_part(1, b"bytes").unwrap();
            assert!(matches!(
                commit.complete(),
                Err(Error::Store(StoreError::ChecksumMismatch))
            ));
            assert_eq!(commit.state(), State::Poisoned, "readback {fault:?}");
            assert_eq!(commit.store().release_calls, 1);
        }
    }
}
