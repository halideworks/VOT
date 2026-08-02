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

fn exercise(input: &[u8]) {
    if let Ok(page) = decode_page(input) {
        assert_eq!(encode_page(&page).ok().as_deref(), Some(input));
    }
}

fn iterations() -> usize {
    std::env::args()
        .skip_while(|argument| argument != "--iterations")
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
        .max(1)
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().take(MAX_INPUT).read_to_end(&mut input)?;
    let mut state = 0x9e37_79b9_u64;
    for iteration in 0..iterations() {
        let mut candidate = input.clone();
        if iteration != 0 && !candidate.is_empty() {
            state ^= state << 7;
            state ^= state >> 9;
            let index = (state as usize) % candidate.len();
            candidate[index] ^= (state >> 17) as u8 | 1;
        }
        exercise(&candidate);
    }
    Ok(())
}
