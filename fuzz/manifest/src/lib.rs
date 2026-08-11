//! Bounded canonical-manifest exercise shared by the standalone driver and the
//! libFuzzer target.

#![forbid(unsafe_code)]

use vot_manifest::{
    Component, EntryKind, MAX_PAGE_BYTES, ManifestEntry, ManifestPage, ObjectId, PageCommitment,
    PathProfile, Seal, StorageRef, decode_page, encode_page, encode_seal,
};
use vot_package::{
    EntryRecord, Error as PackageError, PackageIngest, PackageRootBuilder, PackageSummary, Storage,
};
use vot_verifier::Suite;

/// Largest input the drivers accept: one byte past the page ceiling, so the
/// over-limit rejection path is reachable.
pub const MAX_INPUT: usize = MAX_PAGE_BYTES + 1;

/// Allocation ceiling enforced by the drivers.
pub const ALLOCATION_LIMIT: usize = 256 * 1024 * 1024;

/// Decodes a page and, when decoding succeeds, requires the encoding to be
/// canonical: re-encoding must reproduce the exact input bytes.
pub fn exercise(input: &[u8]) {
    if let Ok(page) = decode_page(input) {
        assert_eq!(encode_page(&page).ok().as_deref(), Some(input));
    }
    exercise_package_ingest(input);
}

struct IngestFixture {
    expected: ObjectId,
    summary: PackageSummary,
    seal: Seal,
    pages: Vec<ManifestPage>,
}

fn control(input: &[u8], salt: usize) -> u8 {
    if input.is_empty() {
        return u8::try_from(salt % 251).expect("bounded salt");
    }
    input[salt % input.len()]
}

fn record(input: &[u8], ordinal: usize) -> EntryRecord {
    let marker = control(input, ordinal.saturating_mul(5).saturating_add(1));
    let mut root = [0_u8; 32];
    for (index, byte) in root.iter_mut().enumerate() {
        *byte = control(input, ordinal.saturating_add(index).saturating_add(11));
    }
    EntryRecord {
        path: vec![Component::Text(format!("file-{ordinal:06}"))],
        suite: if marker & 1 == 0 {
            Suite::Blake3Bao64
        } else {
            Suite::Sha256Bep52
        },
        logical_root: root,
        logical_length: u64::from(marker),
        storage: Storage::Direct,
    }
}

fn rechain(pages: &mut [ManifestPage], package: ObjectId) -> Seal {
    let mut previous_digest = [0; 32];
    let mut commitments = Vec::with_capacity(pages.len());
    for (index, page) in pages.iter_mut().enumerate() {
        page.index = u64::try_from(index).expect("bounded page index");
        page.previous_digest = previous_digest;
        let encoded = encode_page(page).expect("generated page is canonical");
        previous_digest = *blake3::hash(&encoded).as_bytes();
        commitments.push(PageCommitment {
            index: page.index,
            digest: previous_digest,
        });
    }
    Seal {
        manifest_id: [0x49; 16],
        final_page_count: u64::try_from(pages.len()).expect("bounded page count"),
        final_page_digest: previous_digest,
        package,
        pages: commitments,
    }
}

fn fixture(input: &[u8]) -> IngestFixture {
    let page_count = 2 + usize::from(control(input, 1) % 2);
    let mut package = PackageRootBuilder::new().expect("package transcript initialization");
    let mut pages = Vec::with_capacity(page_count);
    let mut ordinal = 0;
    for page_index in 0..page_count {
        let entry_count = 1 + usize::from(control(input, page_index + 2) % 3);
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let record = record(input, ordinal);
            package.push(&record).expect("generated transcript entry");
            entries.push(record.manifest_entry().expect("generated manifest entry"));
            ordinal += 1;
        }
        pages.push(ManifestPage {
            manifest_id: [0x49; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries,
        });
    }
    let summary = package.finish().expect("generated package summary");
    let expected = ObjectId {
        suite: Suite::Blake3Bao64.identifier(),
        root: summary.root,
        length: summary.logical_length,
    };
    let seal = rechain(&mut pages, expected.clone());
    IngestFixture {
        expected,
        summary,
        seal,
        pages,
    }
}

fn encoded_page(page: &ManifestPage) -> Vec<u8> {
    encode_page(page).expect("generated page encoding")
}

fn open(fixture: &IngestFixture) -> PackageIngest {
    PackageIngest::new_expected(
        &encode_seal(&fixture.seal).expect("generated seal encoding"),
        &fixture.expected,
    )
    .expect("generated expected identity")
}

fn push_all(ingest: &mut PackageIngest, pages: &[ManifestPage]) -> u64 {
    pages
        .iter()
        .map(|page| {
            let validated = ingest
                .push_page(&encoded_page(page))
                .expect("generated page ingest");
            u64::try_from(validated.entries().len()).expect("bounded entry count")
        })
        .sum()
}

fn recommit_page(fixture: &mut IngestFixture, index: usize) {
    let digest = *blake3::hash(&encoded_page(&fixture.pages[index])).as_bytes();
    fixture.seal.pages[index].digest = digest;
    if index + 1 == fixture.pages.len() {
        fixture.seal.final_page_digest = digest;
    }
}

fn exercise_package_ingest(input: &[u8]) {
    let mut fixture = fixture(input);
    let _ = PackageIngest::new(input);
    let _ = PackageIngest::new_expected(input, &fixture.expected);
    match control(input, 0) % 10 {
        0 => {
            let mut ingest = open(&fixture);
            let entries = push_all(&mut ingest, &fixture.pages);
            let summary = ingest.finish().expect("complete generated ingest");
            assert_eq!(summary, fixture.summary);
            assert_eq!(summary.entries, entries);
        }
        1 => {
            let mut ingest = open(&fixture);
            let final_index = fixture.pages.len() - 1;
            push_all(&mut ingest, &fixture.pages[..final_index]);
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        2 => {
            let mut ingest = open(&fixture);
            push_all(&mut ingest, &fixture.pages);
            let extra = encoded_page(&fixture.pages[0]);
            assert_eq!(ingest.push_page(&extra), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.push_page(&extra), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        3 => {
            let second = encoded_page(&fixture.pages[1]);
            let mut ingest = open(&fixture);
            assert_eq!(ingest.push_page(&second), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.push_page(&second), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        4 => {
            let mut wrong = fixture.expected.clone();
            match control(input, 3) % 3 {
                0 => wrong.suite = Suite::Sha256Bep52.identifier(),
                1 => wrong.root[0] ^= 1,
                _ => wrong.length = wrong.length.saturating_add(1),
            }
            let seal = encode_seal(&fixture.seal).expect("generated seal encoding");
            assert!(matches!(
                PackageIngest::new_expected(&seal, &wrong),
                Err(PackageError::RootMismatch)
            ));
        }
        5 => {
            let StorageRef::Direct(object) = fixture.pages[0].entries[0]
                .storage
                .as_mut()
                .expect("generated direct storage")
            else {
                panic!("generated records use direct storage");
            };
            object.root[0] ^= 1;
            fixture.seal = rechain(&mut fixture.pages, fixture.expected.clone());
            let mut ingest = open(&fixture);
            assert!(push_all(&mut ingest, &fixture.pages) > 0);
            assert_eq!(ingest.finish(), Err(PackageError::RootMismatch));
        }
        6 => {
            fixture.pages[0].entries.push(ManifestEntry {
                path: vec![Component::Text("zz-invalid-directory".to_owned())],
                kind: EntryKind::Directory,
                length: None,
                storage: None,
                metadata: None,
            });
            fixture.seal = rechain(&mut fixture.pages, fixture.expected.clone());
            let page = encoded_page(&fixture.pages[0]);
            let mut ingest = open(&fixture);
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        7 => {
            fixture.pages[0].previous_digest[0] ^= 1;
            recommit_page(&mut fixture, 0);
            let page = encoded_page(&fixture.pages[0]);
            let mut ingest = open(&fixture);
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        8 => {
            fixture.seal.pages[0].digest[0] ^= 1;
            let page = encoded_page(&fixture.pages[0]);
            let mut ingest = open(&fixture);
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.push_page(&page), Err(PackageError::InvalidBundle));
            assert_eq!(ingest.finish(), Err(PackageError::InvalidBundle));
        }
        _ => {
            let valid_page = encoded_page(&fixture.pages[0]);
            let mut ingest = open(&fixture);
            if let Err(error) = ingest.push_page(input) {
                assert_eq!(ingest.push_page(&valid_page), Err(error));
                assert_eq!(ingest.finish(), Err(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::exercise;

    #[test]
    fn degenerate_inputs_decode_without_panicking() {
        exercise(&[]);
        exercise(&[0xff; 64]);
        exercise(&vec![0x80; 1024]);
    }
}
