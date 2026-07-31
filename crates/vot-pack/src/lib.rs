#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

//! Deterministic VOT small-file pack construction and checked extraction.

use vot_manifest::{PackagePath, PathProfile, canonical_path_key};

pub const CANDIDATE_MAX: usize = 262_144;
pub const TARGET_SIZE: usize = 67_108_864;
pub const HARD_MAX: usize = 134_217_728;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPath,
    FileTooLarge,
    DuplicatePath,
    PackTooLarge,
    Bounds,
    HashMismatch,
}

pub fn build(files: Vec<LogicalFile>, profile: PathProfile) -> Result<Vec<Pack>, Error> {
    build_with_target(files, profile, TARGET_SIZE)
}

fn build_with_target(
    mut files: Vec<LogicalFile>,
    profile: PathProfile,
    target_size: usize,
) -> Result<Vec<Pack>, Error> {
    if target_size == 0 || target_size > HARD_MAX {
        return Err(Error::PackTooLarge);
    }
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

    let mut packs = Vec::new();
    let mut bytes = Vec::new();
    let mut entries = Vec::new();
    for (_, file) in keyed {
        let padding = (8 - bytes.len() % 8) % 8;
        let needed = padding
            .checked_add(file.bytes.len())
            .ok_or(Error::PackTooLarge)?;
        if !bytes.is_empty() && bytes.len() + needed > target_size {
            packs.push(finish_pack(bytes, entries));
            bytes = Vec::new();
            entries = Vec::new();
        }
        let padding = (8 - bytes.len() % 8) % 8;
        bytes.resize(bytes.len() + padding, 0);
        let offset = bytes.len();
        bytes.extend_from_slice(&file.bytes);
        if bytes.len() > HARD_MAX {
            return Err(Error::PackTooLarge);
        }
        entries.push(PackedEntry {
            path: file.path,
            offset: offset as u64,
            length: file.bytes.len() as u64,
            logical_root: vot_proof_sha256::root(&file.bytes),
        });
    }
    if !bytes.is_empty() || !entries.is_empty() {
        packs.push(finish_pack(bytes, entries));
    }
    Ok(packs)
}

fn finish_pack(bytes: Vec<u8>, entries: Vec<PackedEntry>) -> Pack {
    let root = vot_proof_sha256::root(&bytes);
    Pack {
        bytes,
        entries,
        root,
    }
}

pub fn extract<'a>(pack: &'a Pack, entry: &PackedEntry) -> Result<&'a [u8], Error> {
    let start = usize::try_from(entry.offset).map_err(|_| Error::Bounds)?;
    let length = usize::try_from(entry.length).map_err(|_| Error::Bounds)?;
    let end = start.checked_add(length).ok_or(Error::Bounds)?;
    let bytes = pack.bytes.get(start..end).ok_or(Error::Bounds)?;
    if vot_proof_sha256::root(bytes) == entry.logical_root {
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
