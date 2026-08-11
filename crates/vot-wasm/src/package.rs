use std::cell::Cell;
use std::rc::Rc;

use vot_sdk::package as sdk_package;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ErrorCode, ObjectId, VotError};

const MAX_PATH_COMPONENTS: usize = 256;
const MAX_PATH_COMPONENT_BYTES: usize = 255;

/// Incrementally assembled portable package path.
#[wasm_bindgen]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackagePath {
    components: Vec<String>,
}

#[wasm_bindgen]
impl PackagePath {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, component: String) -> Result<(), VotError> {
        if self.components.len() >= MAX_PATH_COMPONENTS
            || component.len() > MAX_PATH_COMPONENT_BYTES
        {
            return Err(VotError::new(ErrorCode::LimitExceeded));
        }
        self.components
            .try_reserve(1)
            .map_err(|_| VotError::new(ErrorCode::ResourceExhausted))?;
        self.components.push(component);
        Ok(())
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn length(&self) -> usize {
        self.components.len()
    }
}

/// Storage representation of one package entry.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageKind {
    Direct,
    Pack,
}

/// Validated portable package entry.
#[wasm_bindgen]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEntry {
    inner: sdk_package::PackageEntry,
}

#[wasm_bindgen]
impl PackageEntry {
    pub fn direct(path: PackagePath, object: &ObjectId) -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_package::PackageEntry::direct(path.components, &object.inner)?,
        })
    }

    pub fn packed(
        path: PackagePath,
        logical: &ObjectId,
        pack: &ObjectId,
        offset: u64,
    ) -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_package::PackageEntry::packed(
                path.components,
                &logical.inner,
                &pack.inner,
                offset,
            )?,
        })
    }

    #[wasm_bindgen(getter, js_name = pathLength)]
    #[must_use]
    pub fn path_length(&self) -> usize {
        self.inner.path().len()
    }

    #[wasm_bindgen(js_name = pathComponent)]
    pub fn path_component(&self, index: usize) -> Result<String, VotError> {
        self.inner
            .path()
            .nth(index)
            .map(str::to_owned)
            .ok_or_else(|| VotError::new(ErrorCode::InvalidInput))
    }

    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_sdk(self.inner.object_id())
    }

    #[wasm_bindgen(getter, js_name = storageKind)]
    #[must_use]
    pub fn storage_kind(&self) -> StorageKind {
        match self.inner.storage() {
            sdk_package::EntryStorage::Direct => StorageKind::Direct,
            sdk_package::EntryStorage::Pack { .. } => StorageKind::Pack,
        }
    }

    #[wasm_bindgen(getter, js_name = packObjectId)]
    #[must_use]
    pub fn pack_object_id(&self) -> Option<ObjectId> {
        match self.inner.storage() {
            sdk_package::EntryStorage::Direct => None,
            sdk_package::EntryStorage::Pack { object, .. } => Some(ObjectId::from_sdk(object)),
        }
    }

    #[wasm_bindgen(getter, js_name = packOffset)]
    #[must_use]
    pub fn pack_offset(&self) -> Option<u64> {
        match self.inner.storage() {
            sdk_package::EntryStorage::Direct => None,
            sdk_package::EntryStorage::Pack { offset, .. } => Some(offset),
        }
    }
}

/// Incremental canonical package builder.
#[wasm_bindgen]
pub struct PackageBuilder {
    inner: sdk_package::PackageBuilder,
}

#[wasm_bindgen]
impl PackageBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_package::PackageBuilder::new()?,
        })
    }

    pub fn push(&mut self, entry: &PackageEntry) -> Result<Option<PageDraft>, VotError> {
        Ok(self
            .inner
            .push(&entry.inner)?
            .map(|inner| PageDraft { inner }))
    }

    pub fn finish(self) -> Result<PackageAssembly, VotError> {
        let (summary, final_page, finalizer) = self.inner.finish()?.into_parts();
        Ok(PackageAssembly {
            summary: PackageSummary { inner: summary },
            final_page: Some(PageDraft { inner: final_page }),
            finalizer: Some(ManifestFinalizer { inner: finalizer }),
        })
    }
}

/// Canonical package identity and aggregate logical sizes.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSummary {
    inner: sdk_package::PackageSummary,
}

#[wasm_bindgen]
impl PackageSummary {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn root(&self) -> Vec<u8> {
        self.inner.root().to_vec()
    }

    #[wasm_bindgen(getter, js_name = logicalLength)]
    #[must_use]
    pub fn logical_length(&self) -> u64 {
        self.inner.logical_length()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.inner.entries()
    }

    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_sdk(self.inner.object_id())
    }
}

/// Completed package identity and host-spoolable finalization state.
#[wasm_bindgen]
pub struct PackageAssembly {
    summary: PackageSummary,
    final_page: Option<PageDraft>,
    finalizer: Option<ManifestFinalizer>,
}

#[wasm_bindgen]
impl PackageAssembly {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn summary(&self) -> PackageSummary {
        self.summary
    }

    #[wasm_bindgen(js_name = takeFinalPage)]
    pub fn take_final_page(&mut self) -> Result<PageDraft, VotError> {
        self.final_page
            .take()
            .ok_or_else(|| VotError::new(ErrorCode::StateConflict))
    }

    #[wasm_bindgen(js_name = takeFinalizer)]
    pub fn take_finalizer(&mut self) -> Result<ManifestFinalizer, VotError> {
        self.finalizer
            .take()
            .ok_or_else(|| VotError::new(ErrorCode::StateConflict))
    }
}

/// Host-spoolable page awaiting final package identity.
#[wasm_bindgen]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageDraft {
    inner: sdk_package::PageDraft,
}

#[wasm_bindgen]
impl PageDraft {
    pub fn decode(bytes: &[u8]) -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_package::PageDraft::decode(bytes)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, VotError> {
        self.inner.encode().map_err(Into::into)
    }
}

/// Converts ordered page drafts into canonical pages and a seal.
#[wasm_bindgen]
pub struct ManifestFinalizer {
    inner: sdk_package::ManifestFinalizer,
}

#[wasm_bindgen]
impl ManifestFinalizer {
    pub fn push(&mut self, draft: PageDraft) -> Result<EncodedManifestPage, VotError> {
        Ok(EncodedManifestPage {
            bytes: self.inner.push(draft.inner)?.into_bytes(),
        })
    }

    pub fn finish(self) -> Result<EncodedSeal, VotError> {
        Ok(EncodedSeal {
            bytes: self.inner.finish()?.into_bytes(),
        })
    }
}

/// Canonical manifest page bytes.
#[wasm_bindgen]
pub struct EncodedManifestPage {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl EncodedManifestPage {
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Canonical manifest seal bytes.
#[wasm_bindgen]
pub struct EncodedSeal {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl EncodedSeal {
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Incremental manifest verification bound to one expected package identity.
#[wasm_bindgen]
pub struct PackageIngest {
    inner: sdk_package::PackageIngest,
    authenticated: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl PackageIngest {
    #[wasm_bindgen(constructor)]
    pub fn new(encoded_seal: &[u8], expected: &ObjectId) -> Result<Self, VotError> {
        Ok(Self {
            inner: sdk_package::PackageIngest::new_expected(encoded_seal, &expected.inner)?,
            authenticated: Rc::new(Cell::new(false)),
        })
    }

    #[wasm_bindgen(getter, js_name = pageCount)]
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.inner.page_count()
    }

    pub fn push(&mut self, encoded_page: &[u8]) -> Result<ManifestPage, VotError> {
        let page = self.inner.push_page(encoded_page)?;
        Ok(ManifestPage {
            entries: page
                .into_entries()
                .into_iter()
                .map(|inner| PackageEntry { inner })
                .collect(),
            authenticated: Rc::clone(&self.authenticated),
        })
    }

    pub fn finish(self) -> Result<PackageSummary, VotError> {
        let summary = self.inner.finish()?;
        self.authenticated.set(true);
        Ok(PackageSummary { inner: summary })
    }
}

/// Structurally valid page whose entries unlock only after ingest finishes.
#[wasm_bindgen]
pub struct ManifestPage {
    entries: Vec<PackageEntry>,
    authenticated: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl ManifestPage {
    #[wasm_bindgen(getter, js_name = entryCount)]
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn entry(&self, index: usize) -> Result<PackageEntry, VotError> {
        if !self.authenticated.get() {
            return Err(VotError::new(ErrorCode::StateConflict));
        }
        self.entries
            .get(index)
            .cloned()
            .ok_or_else(|| VotError::new(ErrorCode::InvalidInput))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Suite;

    fn object(root: u8, length: u64) -> ObjectId {
        ObjectId::new(Suite::Sha256Bep52, &[root; 32], length).unwrap()
    }

    fn entry(index: usize, object: &ObjectId) -> PackageEntry {
        let mut path = PackagePath::new();
        path.push(format!("{index:08}-{}", "x".repeat(200)))
            .unwrap();
        PackageEntry::direct(path, object).unwrap()
    }

    #[test]
    fn packed_storage_accessors_preserve_identity_and_nonzero_offset() {
        let logical = object(3, 5);
        let pack = object(4, 17);
        let mut path = PackagePath::new();
        path.push("packed.bin".to_owned()).unwrap();
        let entry = PackageEntry::packed(path, &logical, &pack, 7).unwrap();
        assert_eq!(entry.storage_kind(), StorageKind::Pack);
        assert_eq!(entry.pack_object_id(), Some(pack));
        assert_eq!(entry.pack_offset(), Some(7));
    }

    #[test]
    fn path_push_enforces_component_byte_bound_without_mutation() {
        let mut path = PackagePath::new();
        path.push("a".repeat(MAX_PATH_COMPONENT_BYTES)).unwrap();
        assert_eq!(path.length(), 1);

        let error = path
            .push("a".repeat(MAX_PATH_COMPONENT_BYTES + 1))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(path.length(), 1);

        let error = path.push("é".repeat(128)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(path.length(), 1);

        path.push("tail".to_owned()).unwrap();
        assert_eq!(path.length(), 2);
    }

    #[test]
    fn path_push_enforces_component_count_bound_without_mutation() {
        let mut path = PackagePath::new();
        for _ in 0..MAX_PATH_COMPONENTS {
            path.push("a".to_owned()).unwrap();
        }
        assert_eq!(path.length(), MAX_PATH_COMPONENTS);

        let error = path.push("overflow".to_owned()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(path.length(), MAX_PATH_COMPONENTS);
    }

    #[test]
    fn multi_page_package_accessors_and_authentication_are_exact() {
        let object = object(6, 3);
        let mut builder = PackageBuilder::new().unwrap();
        let mut pushed = 0usize;
        let completed = loop {
            let entry = entry(pushed, &object);
            pushed += 1;
            if let Some(page) = builder.push(&entry).unwrap() {
                break page;
            }
            assert!(pushed < 10_000, "fixture must cross one page bound");
        };
        let mut assembly = builder.finish().unwrap();
        let summary = assembly.summary();
        assert_eq!(summary.entries(), pushed as u64);
        assert_eq!(summary.logical_length(), (pushed as u64) * 3);
        assert_eq!(summary.root().len(), 32);
        assert_ne!(summary.root(), vec![1]);
        assert_eq!(summary.object_id().root(), summary.root());
        assert_eq!(summary.object_id().length(), summary.logical_length());

        let final_page = assembly.take_final_page().unwrap();
        let mut finalizer = assembly.take_finalizer().unwrap();
        let first = finalizer.push(completed).unwrap().bytes();
        let second = finalizer.push(final_page).unwrap().bytes();
        let seal = finalizer.finish().unwrap().bytes();
        let mut ingest = PackageIngest::new(&seal, &summary.object_id()).unwrap();
        assert_eq!(ingest.page_count(), 2);
        let first = ingest.push(&first).unwrap();
        assert!(first.entry_count() > 1);
        let second = ingest.push(&second).unwrap();
        assert!(second.entry_count() >= 1);
        assert_eq!(ingest.finish().unwrap(), summary);
        assert_eq!(first.entry(0).unwrap().object_id(), object);
    }
}
