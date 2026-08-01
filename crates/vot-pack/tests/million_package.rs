use vot_manifest::{Component, PathProfile};
use vot_pack::{LogicalFile, MAX_ENTRIES_PER_PACK, StreamingPacker};

#[test]
#[ignore = "explicit Wave 4 million-file gate"]
fn one_million_small_files_stream_through_bounded_packs() {
    let mut packer = StreamingPacker::new(PathProfile::Portable);
    let mut packs = 0_usize;
    let mut files = 0_usize;
    let mut largest_pack = 0_usize;
    for index in 0..1_000_000_u32 {
        if let Some(pack) = packer
            .push(LogicalFile {
                path: vec![Component::Text(format!("{index:07}"))],
                bytes: Vec::new(),
            })
            .unwrap()
        {
            packs += 1;
            files += pack.entries.len();
            largest_pack = largest_pack.max(pack.entries.len());
        }
    }
    if let Some(pack) = packer.finish() {
        packs += 1;
        files += pack.entries.len();
        largest_pack = largest_pack.max(pack.entries.len());
    }
    assert_eq!(files, 1_000_000);
    assert_eq!(packs, 1_000_000_usize.div_ceil(MAX_ENTRIES_PER_PACK));
    assert_eq!(largest_pack, MAX_ENTRIES_PER_PACK);
}
