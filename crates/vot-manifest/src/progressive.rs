//! Progressive manifest ingest state.

use super::{
    EntryKind, Error, ManifestPage, PathProfile, Seal, encode_page, is_path_prefix, valid_object,
    validate_entries,
};

#[derive(Clone, Debug)]
pub struct ProgressiveIngest {
    manifest_id: [u8; 16],
    profile: PathProfile,
    digests: Vec<[u8; 32]>,
    last_path: Option<Vec<u8>>,
    last_file: bool,
    poisoned: bool,
}

impl ProgressiveIngest {
    #[must_use]
    pub const fn new(manifest_id: [u8; 16], profile: PathProfile) -> Self {
        Self {
            manifest_id,
            profile,
            digests: Vec::new(),
            last_path: None,
            last_file: false,
            poisoned: false,
        }
    }

    pub fn accept(&mut self, page: &ManifestPage) -> Result<[u8; 32], Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let result = self.accept_inner(page);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn accept_inner(&mut self, page: &ManifestPage) -> Result<[u8; 32], Error> {
        if page.manifest_id != self.manifest_id || page.profile != self.profile {
            return Err(Error::WrongManifest);
        }
        if page.total.is_some() {
            return Err(Error::SealedPageInProgressiveStream);
        }
        if page.index != self.digests.len() as u64 {
            return Err(Error::WrongPageIndex);
        }
        let expected_previous = self.digests.last().copied().unwrap_or([0; 32]);
        if page.previous_digest != expected_previous {
            return Err(Error::BrokenPageChain);
        }
        let keys = validate_entries(&page.entries, page.profile)?;
        if let (Some(previous), Some(first)) = (&self.last_path, keys.first()) {
            if first <= previous {
                return Err(Error::EntriesUnsorted);
            }
            if self.last_file && is_path_prefix(previous, first) {
                return Err(Error::PathCollision);
            }
        }
        let encoded = encode_page(page)?;
        let digest = *blake3::hash(&encoded).as_bytes();
        if let Some(last) = page.entries.last() {
            self.last_file = last.kind == EntryKind::File;
        }
        self.last_path = keys.last().cloned().or_else(|| self.last_path.take());
        self.digests.push(digest);
        Ok(digest)
    }

    pub fn verify_seal(&self, seal: &Seal) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let Some(last_digest) = self.digests.last() else {
            return Err(Error::Poisoned);
        };
        if seal.manifest_id != self.manifest_id
            || seal.final_page_count != self.digests.len() as u64
            || seal.final_page_digest != *last_digest
            || seal.pages.len() != self.digests.len()
            || !valid_object(&seal.package)
        {
            return Err(Error::InvalidSeal);
        }
        for (index, (commitment, digest)) in seal.pages.iter().zip(&self.digests).enumerate() {
            if commitment.index != index as u64 || commitment.digest != *digest {
                return Err(Error::InvalidSeal);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}
