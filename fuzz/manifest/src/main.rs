//! Standalone stdin harness for bounded canonical manifest decoding.

#![forbid(unsafe_code)]

use cap::Cap;
use std::alloc::System;
use std::io::{self, Read};
use vot_manifest::{MAX_PAGE_BYTES, decode_page, encode_page};

const MAX_INPUT: u64 = (MAX_PAGE_BYTES as u64) + 1;
const ALLOCATION_LIMIT: usize = 256 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().take(MAX_INPUT).read_to_end(&mut input)?;
    if let Ok(page) = decode_page(&input) {
        assert_eq!(encode_page(&page).ok().as_deref(), Some(input.as_slice()));
    }
    Ok(())
}
