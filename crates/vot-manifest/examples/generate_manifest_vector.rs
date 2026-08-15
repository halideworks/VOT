#![allow(clippy::cast_possible_truncation, clippy::format_collect)]

use vot_manifest::{
    EntryKind, ManifestEntry, ManifestPage, ObjectId, PackagePath, PathProfile, StorageRef,
    encode_page,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let object = ObjectId {
        suite: 2,
        root: [2; 32],
        length: 3,
    };
    let page = ManifestPage {
        manifest_id: [1; 16],
        index: 0,
        total: Some(1),
        previous_digest: [0; 32],
        profile: PathProfile::Portable,
        entries: vec![
            ManifestEntry {
                path: PackagePath::portable(["a.txt"]).unwrap(),
                kind: EntryKind::File,
                length: Some(3),
                storage: Some(StorageRef::Direct(object)),
                metadata: None,
            },
            ManifestEntry {
                path: PackagePath::portable(["shots"]).unwrap(),
                kind: EntryKind::Directory,
                length: None,
                storage: None,
                metadata: None,
            },
        ],
    };
    let encoded = encode_page(&page).unwrap();
    println!("encoded={}", hex(&encoded));
    println!("digest={}", blake3::hash(&encoded));
}
