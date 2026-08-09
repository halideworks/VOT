#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

//! Deterministic VOT small-file pack construction and checked extraction.

use vot_manifest::{PackagePath, PathProfile, canonical_path_key};
use vot_verifier::Suite;

pub const CANDIDATE_MAX: usize = 262_144;
/// Every entry starts on an 8-byte boundary; the gap is zero-filled.
const ENTRY_ALIGNMENT: usize = 8;
pub const TARGET_SIZE: usize = 67_108_864;
pub const HARD_MAX: usize = 134_217_728;
pub const MAX_ENTRIES_PER_PACK: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalFile {
    pub path: PackagePath,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedEntry {
    pub path: PackagePath,
    pub offset: u64,
    pub length: u64,
    pub logical_root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pack {
    pub bytes: Vec<u8>,
    pub entries: Vec<PackedEntry>,
    pub root: [u8; 32],
    pub suite: Suite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPath,
    FileTooLarge,
    DuplicatePath,
    PackTooLarge,
    EntriesUnsorted,
    Bounds,
    HashMismatch,
}

pub fn build(files: Vec<LogicalFile>, profile: PathProfile) -> Result<Vec<Pack>, Error> {
    build_with_suite(files, profile, Suite::Sha256Bep52)
}

pub fn build_with_suite(
    files: Vec<LogicalFile>,
    profile: PathProfile,
    suite: Suite,
) -> Result<Vec<Pack>, Error> {
    build_with_target_and_suite(files, profile, TARGET_SIZE, suite)
}

/// Bounded pack construction for a canonical-path-ordered input stream.
pub struct StreamingPacker {
    profile: PathProfile,
    suite: Suite,
    target_size: usize,
    last_key: Option<Vec<u8>>,
    bytes: Vec<u8>,
    entries: Vec<PackedEntry>,
}

impl StreamingPacker {
    #[must_use]
    pub fn new(profile: PathProfile) -> Self {
        Self::new_with_suite(profile, Suite::Sha256Bep52)
    }

    #[must_use]
    pub fn new_with_suite(profile: PathProfile, suite: Suite) -> Self {
        Self {
            profile,
            suite,
            target_size: TARGET_SIZE,
            last_key: None,
            bytes: Vec::new(),
            entries: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_target(profile: PathProfile, target_size: usize) -> Result<Self, Error> {
        Self::with_target_and_suite(profile, target_size, Suite::Sha256Bep52)
    }

    fn with_target_and_suite(
        profile: PathProfile,
        target_size: usize,
        suite: Suite,
    ) -> Result<Self, Error> {
        if target_size == 0 || target_size > HARD_MAX {
            return Err(Error::PackTooLarge);
        }
        Ok(Self {
            profile,
            suite,
            target_size,
            last_key: None,
            bytes: Vec::new(),
            entries: Vec::new(),
        })
    }

    /// Adds one small file and returns a completed preceding pack when needed.
    pub fn push(&mut self, file: LogicalFile) -> Result<Option<Pack>, Error> {
        if file.bytes.len() > CANDIDATE_MAX {
            return Err(Error::FileTooLarge);
        }
        let key = canonical_path_key(&file.path, self.profile).map_err(|_| Error::InvalidPath)?;
        if self
            .last_key
            .as_ref()
            .is_some_and(|last| key.as_slice() <= last.as_slice())
        {
            return Err(Error::EntriesUnsorted);
        }
        self.last_key = Some(key);

        let needed = padding_to_alignment(self.bytes.len())
            .checked_add(file.bytes.len())
            .ok_or(Error::PackTooLarge)?;
        let must_flush = !self.entries.is_empty()
            && (self.entries.len() == MAX_ENTRIES_PER_PACK
                || self.bytes.len().saturating_add(needed) > self.target_size);
        let completed = must_flush.then(|| {
            finish_pack(
                std::mem::take(&mut self.bytes),
                std::mem::take(&mut self.entries),
                self.suite,
            )
        });

        let offset = append_aligned(&mut self.bytes, &file.bytes);
        self.entries.push(PackedEntry {
            path: file.path,
            offset: offset as u64,
            length: file.bytes.len() as u64,
            logical_root: vot_verifier::root(self.suite, &file.bytes)
                .map_err(|_| Error::PackTooLarge)?,
        });
        Ok(completed)
    }

    #[must_use]
    pub fn flush(&mut self) -> Option<Pack> {
        (!self.entries.is_empty()).then(|| {
            finish_pack(
                std::mem::take(&mut self.bytes),
                std::mem::take(&mut self.entries),
                self.suite,
            )
        })
    }

    #[must_use]
    pub fn finish(mut self) -> Option<Pack> {
        self.flush()
    }
}

#[cfg(test)]
fn build_with_target(
    files: Vec<LogicalFile>,
    profile: PathProfile,
    target_size: usize,
) -> Result<Vec<Pack>, Error> {
    build_with_target_and_suite(files, profile, target_size, Suite::Sha256Bep52)
}

fn build_with_target_and_suite(
    mut files: Vec<LogicalFile>,
    profile: PathProfile,
    target_size: usize,
    suite: Suite,
) -> Result<Vec<Pack>, Error> {
    let mut keyed = Vec::with_capacity(files.len());
    for file in files.drain(..) {
        if file.bytes.len() > CANDIDATE_MAX {
            return Err(Error::FileTooLarge);
        }
        let key = canonical_path_key(&file.path, profile).map_err(|_| Error::InvalidPath)?;
        keyed.push((key, file));
    }
    keyed.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::DuplicatePath);
    }

    let mut packer = StreamingPacker::with_target_and_suite(profile, target_size, suite)?;
    let mut packs = Vec::new();
    for (_, file) in keyed {
        if let Some(pack) = packer.push(file)? {
            packs.push(pack);
        }
    }
    if let Some(pack) = packer.finish() {
        packs.push(pack);
    }
    Ok(packs)
}

/// Zero bytes needed to reach the next entry boundary from `length`.
const fn padding_to_alignment(length: usize) -> usize {
    (ENTRY_ALIGNMENT - length % ENTRY_ALIGNMENT) % ENTRY_ALIGNMENT
}

/// Pads to the entry boundary, appends, and returns the entry's offset.
fn append_aligned(bytes: &mut Vec<u8>, entry: &[u8]) -> usize {
    bytes.resize(bytes.len() + padding_to_alignment(bytes.len()), 0);
    let offset = bytes.len();
    bytes.extend_from_slice(entry);
    offset
}

fn finish_pack(bytes: Vec<u8>, entries: Vec<PackedEntry>, suite: Suite) -> Pack {
    let root =
        vot_verifier::root(suite, &bytes).expect("a bounded pack is a valid verifier stream");
    Pack {
        bytes,
        entries,
        root,
        suite,
    }
}

pub fn extract<'a>(pack: &'a Pack, entry: &PackedEntry) -> Result<&'a [u8], Error> {
    let start = usize::try_from(entry.offset).map_err(|_| Error::Bounds)?;
    let length = usize::try_from(entry.length).map_err(|_| Error::Bounds)?;
    let end = start.checked_add(length).ok_or(Error::Bounds)?;
    let bytes = pack.bytes.get(start..end).ok_or(Error::Bounds)?;
    if vot_verifier::root(pack.suite, bytes).map_err(|_| Error::Bounds)? == entry.logical_root {
        Ok(bytes)
    } else {
        Err(Error::HashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_manifest::Component;

    fn file(path: &str, bytes: &[u8]) -> LogicalFile {
        LogicalFile {
            path: vec![Component::Text(path.to_owned())],
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn deterministic_order_alignment_and_extraction() {
        let files = vec![file("z", b"last"), file("a", b"one"), file("m", b"middle")];
        let packs = build(files, PathProfile::Portable).unwrap();
        assert_eq!(packs.len(), 1);
        let pack = &packs[0];
        assert_eq!(pack.entries[0].path, file("a", b"").path);
        for entry in &pack.entries {
            assert_eq!(entry.offset % 8, 0);
            extract(pack, entry).unwrap();
        }
        assert!(pack.bytes.len() <= HARD_MAX);
    }

    #[test]
    fn files_never_straddle_small_test_packs() {
        let packs = build_with_target(
            vec![
                file("a", &[1; 10]),
                file("b", &[2; 10]),
                file("c", &[3; 10]),
            ],
            PathProfile::Portable,
            20,
        )
        .unwrap();
        assert_eq!(packs.len(), 3);
        for pack in &packs {
            assert_eq!(pack.entries.len(), 1);
            extract(pack, &pack.entries[0]).unwrap();
        }
    }

    #[test]
    fn streaming_packer_flushes_at_the_entry_bound() {
        let mut packer = StreamingPacker::new(PathProfile::Portable);
        for index in 0..=MAX_ENTRIES_PER_PACK {
            let completed = packer.push(file(&format!("{index:05}"), b"")).unwrap();
            if index < MAX_ENTRIES_PER_PACK {
                assert!(completed.is_none());
            } else {
                assert_eq!(completed.unwrap().entries.len(), MAX_ENTRIES_PER_PACK);
            }
        }
        assert_eq!(packer.finish().unwrap().entries.len(), 1);
    }

    #[test]
    fn streaming_packer_rejects_noncanonical_input_order() {
        let mut packer = StreamingPacker::new(PathProfile::Portable);
        packer.push(file("b", b"one")).unwrap();
        assert_eq!(packer.push(file("a", b"two")), Err(Error::EntriesUnsorted));
    }

    #[test]
    fn streaming_packer_size_and_padding_edges_are_exact() {
        assert!(StreamingPacker::with_target(PathProfile::Portable, 0).is_err());
        assert!(StreamingPacker::with_target(PathProfile::Portable, HARD_MAX).is_ok());
        assert!(StreamingPacker::with_target(PathProfile::Portable, HARD_MAX + 1).is_err());

        let mut packer = StreamingPacker::with_target(PathProfile::Portable, 16).unwrap();
        assert!(packer.push(file("a", &[1; 8])).unwrap().is_none());
        assert!(packer.push(file("b", &[2; 8])).unwrap().is_none());
        let completed = packer.push(file("c", &[3])).unwrap().unwrap();
        assert_eq!(completed.bytes.len(), 16);
        assert_eq!(
            completed
                .entries
                .iter()
                .map(|entry| entry.offset)
                .collect::<Vec<_>>(),
            vec![0, 8]
        );
        assert_eq!(packer.finish().unwrap().entries[0].offset, 0);

        let mut alignment = StreamingPacker::with_target(PathProfile::Portable, 32).unwrap();
        alignment.push(file("a", &[1; 3])).unwrap();
        alignment.push(file("b", &[2])).unwrap();
        let aligned = alignment.finish().unwrap();
        assert_eq!(aligned.entries[1].offset, 8);
        assert_eq!(&aligned.bytes[3..8], &[0; 5]);

        let mut padding_flush = StreamingPacker::with_target(PathProfile::Portable, 8).unwrap();
        padding_flush.push(file("a", &[1; 3])).unwrap();
        let completed = padding_flush.push(file("b", &[2])).unwrap().unwrap();
        assert_eq!(completed.bytes.len(), 3);
        assert_eq!(padding_flush.finish().unwrap().bytes.len(), 1);

        let exact = file("exact", &vec![0; CANDIDATE_MAX]);
        assert!(build(vec![exact], PathProfile::Portable).is_ok());
        let mut direct = StreamingPacker::new(PathProfile::Portable);
        assert!(direct.push(file("exact", &vec![0; CANDIDATE_MAX])).is_ok());
        assert_eq!(
            direct.push(file("over", &vec![0; CANDIDATE_MAX + 1])),
            Err(Error::FileTooLarge)
        );
    }

    #[test]
    fn mutation_and_oversize_are_rejected() {
        let mut pack = build(vec![file("a", b"data")], PathProfile::Portable)
            .unwrap()
            .remove(0);
        let entry = pack.entries[0].clone();
        pack.bytes[0] ^= 1;
        assert_eq!(extract(&pack, &entry), Err(Error::HashMismatch));
        assert_eq!(
            build(
                vec![file("a", &vec![0; CANDIDATE_MAX + 1])],
                PathProfile::Portable
            ),
            Err(Error::FileTooLarge)
        );
    }
}
