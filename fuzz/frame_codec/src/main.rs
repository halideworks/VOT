//! Standalone stdin harness for coverage-guided or mutation fuzzers.

#![forbid(unsafe_code)]

use cap::Cap;
use std::alloc::System;
use std::io::{self, Read};
use vot_codec::{
    DecodeLimits, DecodedFrame, EndpointRole, HARD_MAX_FRAME_PAYLOAD, decode_hello, decode_one,
    decode_settings,
};

const MAX_INPUT: u64 = (HARD_MAX_FRAME_PAYLOAD as u64) + 64 * 1024;
const ALLOCATION_LIMIT: usize = 256 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

fn exercise(input: &[u8]) {
    let limits = DecodeLimits {
        max_unknown_payload: HARD_MAX_FRAME_PAYLOAD,
        max_frames: 4096,
    };
    let mut offset = 0;
    for _ in 0..limits.max_frames {
        if offset == input.len() {
            break;
        }
        let Ok((frame, consumed)) = decode_one(&input[offset..], limits) else {
            break;
        };
        if let DecodedFrame::Known {
            frame_type,
            payload,
        } = frame
        {
            match frame_type {
                vot_codec::frame_type::HELLO => {
                    let _ = decode_hello(payload, EndpointRole::Client);
                    let _ = decode_hello(payload, EndpointRole::Server);
                }
                vot_codec::frame_type::SETTINGS => {
                    let _ = decode_settings(payload);
                }
                vot_codec::frame_type::PACKAGE_DESCRIPTOR
                | vot_codec::frame_type::MANIFEST_REQUEST
                | vot_codec::frame_type::MANIFEST_PAGE
                | vot_codec::frame_type::SEAL
                | vot_codec::frame_type::HAVE
                | vot_codec::frame_type::RANGE_REQUEST
                | vot_codec::frame_type::PROOF_BUNDLE
                | vot_codec::frame_type::DATA_RECORD
                | vot_codec::frame_type::CAPACITY
                | vot_codec::frame_type::TRANSIT_VERIFIED
                | vot_codec::frame_type::CHUNK_DURABLE
                | vot_codec::frame_type::CHUNK_AT_REST_VERIFIED
                | vot_codec::frame_type::PUBLISH_RECEIPT => {
                    let _ = vot_codec::frames::decode(&input[offset..], limits);
                }
                _ => {}
            }
        }
        let Some(next) = offset.checked_add(consumed) else {
            break;
        };
        offset = next;
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
