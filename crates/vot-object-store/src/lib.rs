//! Object-store abstraction, S3-compatible adapter, leases, and orphan collection.

#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "s3-live")]
pub mod aws;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartReceipt {
    pub number: u32,
    pub checksum_crc32c: u32,
    pub length: u64,
}

/// The object a multipart upload is expected to create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectExpectation {
    key: String,
    length: u64,
    checksum_crc32c: u32,
}

impl ObjectExpectation {
    /// Derives the expected object from consecutive multipart receipts.
    pub fn from_parts(key: &str, parts: &[PartReceipt]) -> Result<Self, Error> {
        let Some(first) = parts.first() else {
            return Err(Error::CompletionMismatch);
        };
        if first.number != 1 {
            return Err(Error::CompletionMismatch);
        }
        if parts
            .windows(2)
            .any(|pair| pair[0].number.checked_add(1) != Some(pair[1].number))
        {
            return Err(Error::CompletionMismatch);
        }
        let mut length = 0_u64;
        let mut checksum_crc32c = vot_journal::CRC32C_EMPTY;
        for part in parts {
            length = length
                .checked_add(part.length)
                .ok_or(Error::CompletionMismatch)?;
            checksum_crc32c =
                vot_journal::crc32c_combine(checksum_crc32c, part.checksum_crc32c, part.length);
        }
        Ok(Self {
            key: key.to_owned(),
            length,
            checksum_crc32c,
        })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn checksum_crc32c(&self) -> u32 {
        self.checksum_crc32c
    }
}

/// Evidence that the multipart completion operation returned successfully.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipartCompleted {
    expectation: ObjectExpectation,
}

impl MultipartCompleted {
    #[must_use]
    pub const fn new(expectation: ObjectExpectation) -> Self {
        Self { expectation }
    }

    #[must_use]
    pub const fn expectation(&self) -> &ObjectExpectation {
        &self.expectation
    }

    #[must_use]
    pub fn into_expectation(self) -> ObjectExpectation {
        self.expectation
    }
}

/// Cheap object metadata observed without reading the object body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    length: u64,
}

impl ObjectMetadata {
    #[must_use]
    pub const fn new(length: u64) -> Self {
        Self { length }
    }

    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// What a completed multipart upload turned out to be.
///
/// Its length and checksum rather than its bytes: a completion that handed
/// back the object would put a ceiling on object size at the size of memory,
/// and every caller here is checking what landed rather than reading it.
pub struct CompletedObject {
    pub key: String,
    pub length: u64,
    pub checksum_crc32c: u32,
}

/// An object whose complete body matched its expected length and checksum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadbackVerified {
    object: CompletedObject,
}

impl ReadbackVerified {
    #[must_use]
    pub const fn new(object: CompletedObject) -> Self {
        Self { object }
    }

    #[must_use]
    pub const fn object(&self) -> &CompletedObject {
        &self.object
    }

    #[must_use]
    pub fn into_object(self) -> CompletedObject {
        self.object
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownUpload,
    InvalidPart,
    ChecksumMismatch,
    CompletionMismatch,
    AlreadyExists,
    AlreadyCompleted,
    CompletionAmbiguous,
    ObjectNotFound,
    Backend,
}

pub trait MultipartObjectStore {
    fn create_multipart(&mut self, key: &str, now: u64) -> Result<String, Error>;
    fn upload_part(
        &mut self,
        upload_id: &str,
        number: u32,
        bytes: &[u8],
        checksum_crc32c: u32,
    ) -> Result<PartReceipt, Error>;
    fn complete_multipart(
        &mut self,
        upload_id: &str,
        parts: &[PartReceipt],
    ) -> Result<MultipartCompleted, Error>;
    fn stat_object(&self, key: &str) -> Result<Option<ObjectMetadata>, Error>;
    fn verify_by_readback(&self, expected: &ObjectExpectation) -> Result<ReadbackVerified, Error>;
    /// Releases local state retained only for multipart completion recovery.
    ///
    /// This does not abort a remote multipart upload.
    fn release_multipart(&mut self, upload_id: &str);
}

#[derive(Clone, Debug)]
struct Upload {
    key: String,
    created: u64,
    parts: BTreeMap<u32, (Vec<u8>, u32)>,
    completed: bool,
}

struct StoredObject {
    object: CompletedObject,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub struct MockStore {
    next_upload: u64,
    uploads: BTreeMap<String, Upload>,
    objects: BTreeMap<String, StoredObject>,
    leases: BTreeMap<String, u64>,
    tombstones: BTreeSet<String>,
}

impl MockStore {
    pub fn lease(&mut self, upload_id: &str, expires_at: u64) -> Result<(), Error> {
        if !self.uploads.contains_key(upload_id) {
            return Err(Error::UnknownUpload);
        }
        self.leases.insert(upload_id.to_owned(), expires_at);
        Ok(())
    }

    pub fn collect_orphans(&mut self, now: u64, grace: u64) -> Vec<String> {
        let candidates: Vec<_> = self
            .uploads
            .iter()
            .filter(|(id, upload)| {
                !upload.completed
                    && upload.created.saturating_add(grace) <= now
                    && self.leases.get(*id).is_none_or(|expiry| *expiry <= now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut collected = Vec::new();
        for id in candidates {
            if self.tombstones.insert(id.clone()) {
                self.uploads.remove(&id);
                self.leases.remove(&id);
                collected.push(id);
            }
        }
        collected.sort();
        collected
    }

    #[must_use]
    pub fn object(&self, key: &str) -> Option<&CompletedObject> {
        self.objects.get(key).map(|stored| &stored.object)
    }
}

impl MultipartObjectStore for MockStore {
    fn create_multipart(&mut self, key: &str, now: u64) -> Result<String, Error> {
        let id = format!("upload-{}", self.next_upload);
        self.next_upload += 1;
        self.uploads.insert(
            id.clone(),
            Upload {
                key: key.to_owned(),
                created: now,
                parts: BTreeMap::new(),
                completed: false,
            },
        );
        Ok(id)
    }

    fn upload_part(
        &mut self,
        upload_id: &str,
        number: u32,
        bytes: &[u8],
        checksum_crc32c: u32,
    ) -> Result<PartReceipt, Error> {
        if number == 0 {
            return Err(Error::InvalidPart);
        }
        if vot_journal::crc32c(bytes) != checksum_crc32c {
            return Err(Error::ChecksumMismatch);
        }
        let upload = self
            .uploads
            .get_mut(upload_id)
            .ok_or(Error::UnknownUpload)?;
        if upload.completed {
            return Err(Error::AlreadyCompleted);
        }
        upload
            .parts
            .insert(number, (bytes.to_vec(), checksum_crc32c));
        Ok(PartReceipt {
            number,
            checksum_crc32c,
            length: bytes.len() as u64,
        })
    }

    fn complete_multipart(
        &mut self,
        upload_id: &str,
        parts: &[PartReceipt],
    ) -> Result<MultipartCompleted, Error> {
        let upload = self
            .uploads
            .get_mut(upload_id)
            .ok_or(Error::UnknownUpload)?;
        if upload.completed {
            return Err(Error::AlreadyCompleted);
        }
        if self.objects.contains_key(&upload.key) {
            return Err(Error::AlreadyExists);
        }
        if parts.len() != upload.parts.len() {
            return Err(Error::CompletionMismatch);
        }
        let expectation = ObjectExpectation::from_parts(&upload.key, parts)?;
        let mut bytes = Vec::new();
        for receipt in parts {
            let (part, checksum) = upload
                .parts
                .get(&receipt.number)
                .ok_or(Error::CompletionMismatch)?;
            if *checksum != receipt.checksum_crc32c || part.len() as u64 != receipt.length {
                return Err(Error::CompletionMismatch);
            }
            bytes.extend_from_slice(part);
        }
        let object = CompletedObject {
            key: upload.key.clone(),
            length: bytes.len() as u64,
            checksum_crc32c: vot_journal::crc32c(&bytes),
        };
        upload.completed = true;
        self.objects
            .insert(object.key.clone(), StoredObject { object, bytes });
        Ok(MultipartCompleted::new(expectation))
    }

    fn stat_object(&self, key: &str) -> Result<Option<ObjectMetadata>, Error> {
        Ok(self
            .objects
            .get(key)
            .map(|stored| ObjectMetadata::new(stored.object.length)))
    }

    fn verify_by_readback(&self, expected: &ObjectExpectation) -> Result<ReadbackVerified, Error> {
        let stored = self
            .objects
            .get(expected.key())
            .ok_or(Error::ObjectNotFound)?;
        let actual = CompletedObject {
            key: expected.key().to_owned(),
            length: stored.bytes.len() as u64,
            checksum_crc32c: vot_journal::crc32c(&stored.bytes),
        };
        if actual.length != expected.length()
            || actual.checksum_crc32c != expected.checksum_crc32c()
        {
            return Err(Error::ChecksumMismatch);
        }
        Ok(ReadbackVerified::new(actual))
    }

    fn release_multipart(&mut self, upload_id: &str) {
        self.uploads.remove(upload_id);
        self.leases.remove(upload_id);
    }
}

pub struct MultipartStoreAdapter<B> {
    backend: B,
}

impl<B> MultipartStoreAdapter<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub const fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

impl<B: MultipartObjectStore> MultipartObjectStore for MultipartStoreAdapter<B> {
    fn create_multipart(&mut self, key: &str, now: u64) -> Result<String, Error> {
        self.backend.create_multipart(key, now)
    }

    fn upload_part(
        &mut self,
        id: &str,
        number: u32,
        bytes: &[u8],
        checksum: u32,
    ) -> Result<PartReceipt, Error> {
        self.backend.upload_part(id, number, bytes, checksum)
    }

    fn complete_multipart(
        &mut self,
        id: &str,
        parts: &[PartReceipt],
    ) -> Result<MultipartCompleted, Error> {
        self.backend.complete_multipart(id, parts)
    }

    fn stat_object(&self, key: &str) -> Result<Option<ObjectMetadata>, Error> {
        self.backend.stat_object(key)
    }

    fn verify_by_readback(&self, expected: &ObjectExpectation) -> Result<ReadbackVerified, Error> {
        self.backend.verify_by_readback(expected)
    }

    fn release_multipart(&mut self, upload_id: &str) {
        self.backend.release_multipart(upload_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_checksums_and_conditional_completion() {
        let mut store = MultipartStoreAdapter::new(MockStore::default());
        let id = store.create_multipart("object", 0).unwrap();
        let one = store
            .upload_part(&id, 1, b"one", vot_journal::crc32c(b"one"))
            .unwrap();
        let two = store
            .upload_part(&id, 2, b"two", vot_journal::crc32c(b"two"))
            .unwrap();
        let completed = store.complete_multipart(&id, &[one, two]).unwrap();
        let object = store
            .verify_by_readback(completed.expectation())
            .unwrap()
            .into_object();
        assert_eq!(
            (object.length, object.checksum_crc32c),
            (b"onetwo".len() as u64, vot_journal::crc32c(b"onetwo"))
        );
        assert_eq!(
            store.stat_object("object"),
            Ok(Some(ObjectMetadata::new(6)))
        );
        assert_eq!(store.stat_object("object").unwrap().unwrap().length(), 6);
        store.release_multipart(&id);
        assert_eq!(
            store.complete_multipart(&id, &[]),
            Err(Error::UnknownUpload)
        );
    }

    #[test]
    fn expectation_requires_a_canonical_part_sequence() {
        let one = PartReceipt {
            number: 1,
            checksum_crc32c: vot_journal::crc32c(b"one"),
            length: 3,
        };
        let two = PartReceipt {
            number: 2,
            checksum_crc32c: vot_journal::crc32c(b"two"),
            length: 3,
        };
        assert!(ObjectExpectation::from_parts("object", &[]).is_err());
        assert!(ObjectExpectation::from_parts("object", std::slice::from_ref(&two)).is_err());
        assert!(
            ObjectExpectation::from_parts(
                "object",
                &[
                    one.clone(),
                    PartReceipt {
                        number: 3,
                        ..two.clone()
                    },
                ],
            )
            .is_err()
        );
        let expected = ObjectExpectation::from_parts("object", &[one, two]).unwrap();
        assert_eq!(expected.length(), 6);
        assert_eq!(expected.checksum_crc32c(), vot_journal::crc32c(b"onetwo"));
    }

    #[test]
    fn mismatch_and_failed_completion_publish_nothing() {
        let mut store = MockStore::default();
        let id = store.create_multipart("object", 0).unwrap();
        assert_eq!(
            store.upload_part(&id, 1, b"data", 0),
            Err(Error::ChecksumMismatch)
        );
        assert_eq!(
            store.complete_multipart(&id, &[]),
            Err(Error::CompletionMismatch)
        );
        assert_eq!(store.stat_object("object"), Ok(None));
    }

    #[test]
    fn active_lease_prevents_collection_and_cleanup_is_idempotent() {
        let mut store = MockStore::default();
        let leased = store.create_multipart("leased", 0).unwrap();
        let orphan = store.create_multipart("orphan", 0).unwrap();
        store.lease(&leased, 100).unwrap();
        assert_eq!(store.collect_orphans(50, 10), vec![orphan]);
        assert!(store.collect_orphans(50, 10).is_empty());
        assert_eq!(store.collect_orphans(100, 10), vec![leased]);
        assert!(store.collect_orphans(100, 10).is_empty());
    }

    #[test]
    fn a_receipt_is_checked_against_the_part_it_names_field_by_field() {
        // A receipt names a length and a checksum, and both are compared. Either
        // one taken for the other lets a caller publish an object of bytes it
        // never uploaded.
        let mut store = MockStore::default();
        let id = store.create_multipart("object", 0).unwrap();
        let one = store
            .upload_part(&id, 1, b"one", vot_journal::crc32c(b"one"))
            .unwrap();

        for (name, receipt) in [
            (
                "a checksum that is not the part's",
                PartReceipt {
                    checksum_crc32c: one.checksum_crc32c ^ 1,
                    ..one.clone()
                },
            ),
            (
                "a length that is not the part's",
                PartReceipt {
                    length: one.length + 1,
                    ..one.clone()
                },
            ),
        ] {
            assert_eq!(
                store.complete_multipart(&id, std::slice::from_ref(&receipt)),
                Err(Error::CompletionMismatch),
                "{name}"
            );
            assert!(store.object("object").is_none(), "{name} published nothing");
        }

        // The receipt that does match publishes the object, and the store hands
        // back what it holds rather than nothing.
        let completed = store.complete_multipart(&id, &[one]).unwrap();
        let object = store
            .verify_by_readback(completed.expectation())
            .unwrap()
            .into_object();
        assert_eq!(store.object("object"), Some(&object));
        assert_eq!(
            (object.length, object.checksum_crc32c),
            (b"one".len() as u64, vot_journal::crc32c(b"one"))
        );
        assert!(store.object("absent").is_none());
    }

    #[test]
    fn completion_requires_the_exact_consecutive_uploaded_part_set() {
        let mut store = MockStore::default();
        let id = store.create_multipart("object", 0).unwrap();
        let one = store
            .upload_part(&id, 1, b"one", vot_journal::crc32c(b"one"))
            .unwrap();
        store
            .upload_part(&id, 2, b"two", vot_journal::crc32c(b"two"))
            .unwrap();
        assert_eq!(
            store.complete_multipart(&id, &[one]),
            Err(Error::CompletionMismatch)
        );
        assert_eq!(store.stat_object("object"), Ok(None));
    }

    #[test]
    fn metadata_and_readback_are_distinct_observations() {
        let mut store = MockStore::default();
        let id = store.create_multipart("object", 0).unwrap();
        let part = store
            .upload_part(&id, 1, b"data", vot_journal::crc32c(b"data"))
            .unwrap();
        let completed = store.complete_multipart(&id, &[part]).unwrap();

        assert_eq!(
            store.stat_object("object"),
            Ok(Some(ObjectMetadata::new(4)))
        );
        assert_eq!(store.stat_object("absent"), Ok(None));
        assert_eq!(
            store.verify_by_readback(&ObjectExpectation {
                key: "object".to_owned(),
                length: 5,
                checksum_crc32c: completed.expectation().checksum_crc32c(),
            }),
            Err(Error::ChecksumMismatch)
        );
        assert_eq!(
            store.verify_by_readback(&ObjectExpectation {
                key: "object".to_owned(),
                length: completed.expectation().length(),
                checksum_crc32c: completed.expectation().checksum_crc32c() ^ 1,
            }),
            Err(Error::ChecksumMismatch)
        );
        assert_eq!(
            store.verify_by_readback(&ObjectExpectation {
                key: "absent".to_owned(),
                length: 4,
                checksum_crc32c: vot_journal::crc32c(b"data"),
            }),
            Err(Error::ObjectNotFound)
        );
    }
}
