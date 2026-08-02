//! Bounded canonical-manifest exercise shared by the standalone driver and the
//! libFuzzer target.

#![forbid(unsafe_code)]

use vot_manifest::{MAX_PAGE_BYTES, decode_page, encode_page};

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
