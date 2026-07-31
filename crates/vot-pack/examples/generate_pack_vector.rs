#![allow(clippy::cast_possible_truncation, clippy::format_collect)]

use vot_manifest::{Component, PathProfile};
use vot_pack::{LogicalFile, build};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn file(path: &str, bytes: &[u8]) -> LogicalFile {
    LogicalFile {
        path: vec![Component::Text(path.to_owned())],
        bytes: bytes.to_vec(),
    }
}

fn main() {
    let pack = build(
        vec![file("z", b"last"), file("a", b"one"), file("m", b"middle")],
        PathProfile::Portable,
    )
    .unwrap()
    .remove(0);
    println!("bytes={}", hex(&pack.bytes));
    println!("root={}", hex(&pack.root));
    for entry in pack.entries {
        let Component::Text(path) = &entry.path[0] else {
            unreachable!()
        };
        println!(
            "{path},{},{},{}",
            entry.offset,
            entry.length,
            hex(&entry.logical_root)
        );
    }
}
