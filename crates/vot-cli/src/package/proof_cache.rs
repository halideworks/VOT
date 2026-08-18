//! The leaf hashes a serve prepares from, kept beside the object.
//!
//! A serve reads every byte of every object at start to rebuild what its
//! range proofs are read from, which is about 1.4 seconds a gigabyte: a
//! 100 GB bundle answered nothing for over two minutes. `send` already holds
//! those leaves when it writes the object, so it writes them here too.
//!
//! **This file is a cache, never an authority.** What it holds is checked
//! against the root the manifest already names before a proof is read from
//! it, and anything unreadable, stale, or describing another object is
//! ignored in favour of reading the object.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{Error, Suite, object_name};

/// Names the file and the shape of what follows it.
const MAGIC: &[u8; 8] = b"VOTLEAF\x01";
const HASH_BYTES: usize = 32;
/// Header: magic, suite, object length, leaf count.
const HEADER_BYTES: usize = MAGIC.len() + 1 + 8 + 8;

/// Where an object's leaves sit, beside the object itself.
pub(crate) fn path(objects: &Path, root: &[u8; 32]) -> PathBuf {
    objects.join(format!("{}.leaves", object_name(root)))
}

const fn suite_byte(suite: Suite) -> u8 {
    match suite {
        Suite::Blake3Bao64 => 1,
        Suite::Sha256Bep52 => 2,
    }
}

/// Writes the leaves beside the object, replacing whatever was there.
///
/// # Errors
/// Surfaces the write; a caller that cannot keep the cache still has a
/// bundle that serves, so it may discard this.
pub(crate) fn write(
    objects: &Path,
    root: &[u8; 32],
    suite: Suite,
    length: u64,
    leaves: &[[u8; 32]],
) -> Result<(), Error> {
    let destination = path(objects, root);
    let mut bytes = Vec::with_capacity(HEADER_BYTES + leaves.len() * HASH_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.push(suite_byte(suite));
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        bytes.extend_from_slice(leaf);
    }
    let mut file = fs::File::create(&destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Reads the leaves for an object, or `None` for anything this end will not
/// prepare from: no cache, a header that names another suite or length, a
/// count that cannot describe the object, or trailing bytes.
///
/// Never an error: every one of those means reading the object instead.
pub(crate) fn read(
    objects: &Path,
    root: &[u8; 32],
    suite: Suite,
    length: u64,
) -> Option<Vec<[u8; 32]>> {
    let bytes = fs::read(path(objects, root)).ok()?;
    if bytes.len() < HEADER_BYTES || &bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let mut cursor = MAGIC.len();
    if bytes[cursor] != suite_byte(suite) {
        return None;
    }
    cursor += 1;
    let stored_length = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
    cursor += 8;
    let count = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
    cursor += 8;
    if stored_length != length {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    if bytes.len() != cursor + count * HASH_BYTES {
        return None;
    }
    let mut leaves = Vec::with_capacity(count);
    for index in 0..count {
        let at = cursor + index * HASH_BYTES;
        leaves.push(bytes[at..at + HASH_BYTES].try_into().ok()?);
    }
    Some(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|index| {
                let mut leaf = [0_u8; 32];
                leaf[0] = u8::try_from(index % 251).expect("bounded by the modulus");
                leaf
            })
            .collect()
    }

    #[test]
    fn a_cache_round_trips_and_is_exactly_its_header_and_hashes() {
        let directory = crate::tests::temporary("leafcache-roundtrip");
        std::fs::create_dir_all(&directory).unwrap();
        let root = [9_u8; 32];
        let kept = leaves(5);
        write(&directory, &root, Suite::Sha256Bep52, 5 * 65_536, &kept).unwrap();
        assert_eq!(
            std::fs::metadata(path(&directory, &root)).unwrap().len(),
            (HEADER_BYTES + kept.len() * HASH_BYTES) as u64,
            "the file is its header and its hashes, nothing else"
        );
        assert_eq!(
            read(&directory, &root, Suite::Sha256Bep52, 5 * 65_536),
            Some(kept.clone())
        );

        // The other suite's cache is not this suite's, whatever it holds.
        assert_eq!(
            read(&directory, &root, Suite::Blake3Bao64, 5 * 65_536),
            None
        );
        write(&directory, &root, Suite::Blake3Bao64, 5 * 65_536, &kept).unwrap();
        assert_eq!(
            read(&directory, &root, Suite::Sha256Bep52, 5 * 65_536),
            None
        );
        assert_eq!(
            read(&directory, &root, Suite::Blake3Bao64, 5 * 65_536),
            Some(kept)
        );
        crate::harness::discard(&[&directory]);
    }

    #[test]
    fn a_cache_that_does_not_fit_what_it_claims_is_not_read() {
        let directory = crate::tests::temporary("leafcache-misfit");
        std::fs::create_dir_all(&directory).unwrap();
        let root = [4_u8; 32];
        let kept = leaves(4);
        let length = 4 * 65_536;
        write(&directory, &root, Suite::Sha256Bep52, length, &kept).unwrap();
        let file = path(&directory, &root);
        let bytes = std::fs::read(&file).unwrap();

        // Another object's length.
        assert_eq!(
            read(&directory, &root, Suite::Sha256Bep52, length + 1),
            None
        );
        // A hash short, a byte short, and a byte over.
        for wrong in [
            bytes[..bytes.len() - HASH_BYTES].to_vec(),
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.clone(), vec![0]].concat(),
            bytes[..HEADER_BYTES - 1].to_vec(),
            Vec::new(),
        ] {
            std::fs::write(&file, wrong).unwrap();
            assert_eq!(read(&directory, &root, Suite::Sha256Bep52, length), None);
        }
        // Its own magic is what names it.
        let mut alien = bytes.clone();
        alien[0] ^= 0xff;
        std::fs::write(&file, alien).unwrap();
        assert_eq!(read(&directory, &root, Suite::Sha256Bep52, length), None);
        crate::harness::discard(&[&directory]);
    }
}
