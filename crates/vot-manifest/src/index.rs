//! Page and index navigation.

use super::{Error, PackagePath, PathProfile, canonical_path_key};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    pub fingerprint: [u8; 16],
    pub page: u32,
    pub entry: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ManifestIndex {
    pub(super) entries: Vec<IndexEntry>,
}

impl ManifestIndex {
    #[must_use]
    pub fn with_capacity(entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(entries),
        }
    }

    pub fn push(
        &mut self,
        path: &PackagePath,
        profile: PathProfile,
        page: u32,
        entry: u32,
    ) -> Result<(), Error> {
        let key = canonical_path_key(path, profile)?;
        let digest = blake3::hash(&key);
        let mut fingerprint = [0; 16];
        fingerprint.copy_from_slice(&digest.as_bytes()[..16]);
        self.entries.push(IndexEntry {
            fingerprint,
            page,
            entry,
        });
        Ok(())
    }

    pub fn finish(&mut self) {
        self.entries.sort_unstable_by_key(|entry| entry.fingerprint);
    }

    #[must_use]
    pub fn candidates(&self, path: &PackagePath, profile: PathProfile) -> Vec<(u32, u32)> {
        let Ok(key) = canonical_path_key(path, profile) else {
            return Vec::new();
        };
        let digest = blake3::hash(&key);
        let mut fingerprint = [0; 16];
        fingerprint.copy_from_slice(&digest.as_bytes()[..16]);
        let range = self
            .entries
            .partition_point(|entry| entry.fingerprint < fingerprint)
            ..self
                .entries
                .partition_point(|entry| entry.fingerprint <= fingerprint);
        self.entries[range]
            .iter()
            .map(|entry| (entry.page, entry.entry))
            .collect()
    }

    #[must_use]
    pub const fn bytes_per_entry() -> usize {
        std::mem::size_of::<IndexEntry>()
    }
}
