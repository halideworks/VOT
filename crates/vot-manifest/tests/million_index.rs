use std::alloc::System;

use cap::Cap;
use vot_manifest::{Component, ManifestIndex, PathProfile};

const LIMIT: usize = 512 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, LIMIT);

#[test]
fn million_file_index_peak_allocation_is_bounded() {
    let mut index = ManifestIndex::with_capacity(1_000_000);
    for value in 0_u64..1_000_000 {
        let mut first = vec![b'a'; 240];
        first[..16].copy_from_slice(format!("{value:016x}").as_bytes());
        let path = vec![Component::Bytes(first), Component::Bytes(vec![b'b'; 240])];
        index
            .push(
                &path,
                PathProfile::RawPosix,
                u32::try_from(value / 1_000).unwrap(),
                u32::try_from(value % 1_000).unwrap(),
            )
            .unwrap();
    }
    index.finish();
    assert!(ALLOCATOR.allocated() < LIMIT);
    assert_eq!(
        index.candidates(&vec![Component::Bytes(vec![b'x'])], PathProfile::RawPosix),
        vec![]
    );
}
