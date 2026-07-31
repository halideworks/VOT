//! Standalone stdin harness for coverage-guided or mutation fuzzers.

#![forbid(unsafe_code)]

use std::io::{self, Read};
use vot_codec::{DecodeLimits, HARD_MAX_FRAME_PAYLOAD, decode_all};

const MAX_INPUT: u64 = (HARD_MAX_FRAME_PAYLOAD as u64) + 64 * 1024;

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().take(MAX_INPUT).read_to_end(&mut input)?;
    let limits = DecodeLimits {
        max_unknown_payload: HARD_MAX_FRAME_PAYLOAD,
        max_frames: 4096,
    };
    let _ = decode_all(&input, limits);
    Ok(())
}
