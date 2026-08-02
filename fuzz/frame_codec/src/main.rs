//! Standalone stdin harness for the pinned-stable bounded fuzz gate.
//!
//! Coverage-guided runs use the libFuzzer target in `fuzz/cargo-fuzz`. This
//! driver has no instrumentation available, so it drives the accumulating
//! mutation engine in `vot-fuzz-mutator` instead of resampling one seed.

#![forbid(unsafe_code)]

use cap::Cap;
use std::alloc::System;
use std::io::{self, Read};
use std::path::PathBuf;

use vot_frame_fuzz_driver::{ALLOCATION_LIMIT, MAX_INPUT, exercise, normalize_seed};
use vot_fuzz_mutator::{Corpus, read_seed_directory};

const MAX_POPULATION: usize = 64;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

fn argument(name: &str) -> Option<String> {
    std::env::args()
        .skip_while(|argument| argument != name)
        .nth(1)
}

fn iterations() -> usize {
    argument("--iterations")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
        .max(1)
}

fn mutation_seed() -> u64 {
    argument("--seed")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x5652_4f54_4630_3031)
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_INPUT as u64)
        .read_to_end(&mut input)?;
    let seed = normalize_seed(input);
    let mut seeds = vec![seed.clone()];
    if let Some(directory) = argument("--corpus") {
        // Extra seeds give the engine material to splice against, which is how
        // a run reaches a valid envelope wrapping a hostile payload. Corpus
        // files are raw frame bytes and are not hex normalized, so the libFuzzer
        // target reading the same directory sees the same seeds.
        seeds.extend(read_seed_directory(&PathBuf::from(directory))?);
    }

    let mut corpus = Corpus::new(seeds, MAX_POPULATION, MAX_INPUT, mutation_seed());
    // The unmutated seed runs first so a committed regression input is always
    // exercised exactly as recorded.
    exercise(&seed);
    for _ in 1..iterations() {
        exercise(&corpus.next_candidate());
    }
    Ok(())
}
