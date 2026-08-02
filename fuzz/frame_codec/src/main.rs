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

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(input).ok()?.trim();
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    let mut decoded = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push(high * 16 + low);
    }
    Some(decoded)
}

fn normalize_seed(input: Vec<u8>) -> Vec<u8> {
    decode_hex_seed(&input).unwrap_or(input)
}

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
    let input = normalize_seed(input);
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

#[cfg(test)]
mod tests {
    use super::normalize_seed;

    #[test]
    fn hex_seed_is_decoded_before_fuzzing() {
        assert_eq!(normalize_seed(b"0100\n".to_vec()), [1, 0]);
    }

    #[test]
    fn binary_seed_is_preserved() {
        assert_eq!(normalize_seed(vec![0x31, 0x04, 0xde, 0xad]), [0x31, 0x04, 0xde, 0xad]);
    }
}
