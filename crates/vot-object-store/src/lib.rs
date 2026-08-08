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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownUpload,
    InvalidPart,
    ChecksumMismatch,
    CompletionMismatch,
    AlreadyExists,
    AlreadyCompleted,
    CompletionAmbiguous,
    Backend,
}

pub trait S3Compatible {
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
    ) -> Result<CompletedObject, Error>;
    fn head(&self, key: &str) -> Option<(u64, u32)>;
}

#[derive(Clone, Debug)]
struct Upload {
    key: String,
    created: u64,
    parts: BTreeMap<u32, (Vec<u8>, u32)>,
    completed: bool,
}

#[derive(Default)]
pub struct MockStore {
    next_upload: u64,
    uploads: BTreeMap<String, Upload>,
    objects: BTreeMap<String, CompletedObject>,
    /// What a real backend holds and this double has to stand in for.
    stored: BTreeMap<String, Vec<u8>>,
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
        self.objects.get(key)
    }
}

impl S3Compatible for MockStore {
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
    ) -> Result<CompletedObject, Error> {
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
        if parts.len() != upload.parts.len()
            || parts.first().is_none_or(|part| part.number != 1)
            || parts
                .windows(2)
                .any(|pair| pair[0].number.checked_add(1) != Some(pair[1].number))
        {
            return Err(Error::CompletionMismatch);
        }
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
        // The double keeps the bytes a real backend would not, because tests
        // read objects back and a real backend is asked to.
        self.stored.insert(object.key.clone(), bytes);
        self.objects.insert(object.key.clone(), object.clone());
        Ok(object)
    }

    fn head(&self, key: &str) -> Option<(u64, u32)> {
        self.objects
            .get(key)
            .map(|object| (object.length, object.checksum_crc32c))
    }
}

pub struct S3Adapter<B> {
    backend: B,
}

impl<B> S3Adapter<B> {
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

impl<B: S3Compatible> S3Compatible for S3Adapter<B> {
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
    ) -> Result<CompletedObject, Error> {
        self.backend.complete_multipart(id, parts)
    }

    fn head(&self, key: &str) -> Option<(u64, u32)> {
        self.backend.head(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_checksums_and_conditional_completion() {
        let mut store = S3Adapter::new(MockStore::default());
        let id = store.create_multipart("object", 0).unwrap();
        let one = store
            .upload_part(&id, 1, b"one", vot_journal::crc32c(b"one"))
            .unwrap();
        let two = store
            .upload_part(&id, 2, b"two", vot_journal::crc32c(b"two"))
            .unwrap();
        let object = store.complete_multipart(&id, &[one, two]).unwrap();
        assert_eq!(
            (object.length, object.checksum_crc32c),
            (b"onetwo".len() as u64, vot_journal::crc32c(b"onetwo"))
        );
        assert_eq!(
            store.head("object"),
            Some((6, vot_journal::crc32c(b"onetwo")))
        );
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
        assert!(store.head("object").is_none());
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
        let object = store.complete_multipart(&id, &[one]).unwrap();
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
        assert!(store.head("object").is_none());
    }
}
