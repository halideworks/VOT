//! Accumulating mutation engine shared by the standalone VOT fuzz drivers.
//!
//! The drivers are also built as libFuzzer targets, where coverage feedback
//! drives corpus selection. This engine covers the pinned-stable CI gate, which
//! has no instrumentation available. It is deliberately not random search over
//! one seed: mutants are fed back into a bounded population so edits compound,
//! inputs change length, and crossover splices two population members. That is
//! what lets a run reach a shape like a valid envelope wrapping a hostile
//! varint, which single-byte flips of one fixed seed never construct.
//!
//! Everything here is deterministic. The same seeds and the same numeric seed
//! produce the same candidate sequence, so a crash found in CI reproduces.

#![forbid(unsafe_code)]

/// Byte values that sit on decoder boundaries: varint continuation and
/// terminator bits, CBOR head bytes, and the signed and unsigned extremes.
const INTERESTING_BYTES: [u8; 12] = [
    0x00, 0x01, 0x7f, 0x80, 0x81, 0xbf, 0xc0, 0xf7, 0xf8, 0xfe, 0xff, 0x1a,
];

/// Integers that sit on varint width boundaries or overflow a narrower type.
const INTERESTING_INTEGERS: [u64; 10] = [
    0,
    1,
    127,
    128,
    16_383,
    16_384,
    4_294_967_295,
    4_294_967_296,
    u64::MAX - 1,
    u64::MAX,
];

/// Deterministic xorshift generator. Reproducibility matters more than quality.
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        // A zero state is absorbing for xorshift.
        Self(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Returns a value in `0..bound`, or `0` when `bound` is zero.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
        }
    }

    fn pick<'a, T>(&mut self, values: &'a [T]) -> &'a T {
        &values[self.below(values.len())]
    }
}

/// A bounded, self-feeding population of inputs.
pub struct Corpus {
    entries: Vec<Vec<u8>>,
    max_entries: usize,
    max_bytes: usize,
    retain_period: u64,
    produced: u64,
    rng: Rng,
}

impl Corpus {
    /// Builds a population from the committed seeds.
    ///
    /// Empty seeds are kept: a decoder must survive them, and insertion
    /// mutations grow them into longer inputs.
    #[must_use]
    pub fn new(seeds: Vec<Vec<u8>>, max_entries: usize, max_bytes: usize, seed: u64) -> Self {
        let mut entries = seeds;
        if entries.is_empty() {
            entries.push(Vec::new());
        }
        entries.truncate(max_entries.max(1));
        Self {
            entries,
            max_entries: max_entries.max(1),
            max_bytes,
            retain_period: 8,
            produced: 0,
            rng: Rng::new(seed),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Produces the next candidate and periodically folds it back into the
    /// population so later candidates build on earlier edits.
    pub fn next_candidate(&mut self) -> Vec<u8> {
        let parent = self.rng.below(self.entries.len());
        let mut candidate = self.entries[parent].clone();
        let edits = 1 + self.rng.below(4);
        for _ in 0..edits {
            self.mutate(&mut candidate);
        }
        candidate.truncate(self.max_bytes);
        self.produced = self.produced.wrapping_add(1);
        if self.produced % self.retain_period == 0 {
            self.retain(candidate.clone());
        }
        candidate
    }

    /// Adds an input to the population, evicting the oldest non-seed entry once
    /// the population is full so memory stays bounded.
    pub fn retain(&mut self, candidate: Vec<u8>) {
        if candidate.len() > self.max_bytes {
            return;
        }
        if self.entries.len() >= self.max_entries {
            // Index 0 is a committed seed and is never evicted, so the
            // population cannot drift away from the shapes we care about. A
            // population of one is therefore all seed and nothing to evict.
            if self.entries.len() > 1 {
                let victim = 1 + self.rng.below(self.entries.len() - 1);
                self.entries[victim] = candidate;
            }
        } else {
            self.entries.push(candidate);
        }
    }

    fn mutate(&mut self, candidate: &mut Vec<u8>) {
        match self.rng.below(7) {
            0 => self.flip_bit(candidate),
            1 => self.set_interesting_byte(candidate),
            2 => self.insert_run(candidate),
            3 => self.delete_run(candidate),
            4 => self.duplicate_block(candidate),
            5 => self.splice(candidate),
            _ => self.append_varint(candidate),
        }
    }

    fn flip_bit(&mut self, candidate: &mut [u8]) {
        if candidate.is_empty() {
            return;
        }
        let index = self.rng.below(candidate.len());
        candidate[index] ^= 1 << self.rng.below(8);
    }

    fn set_interesting_byte(&mut self, candidate: &mut [u8]) {
        if candidate.is_empty() {
            return;
        }
        let index = self.rng.below(candidate.len());
        candidate[index] = *self.rng.pick(&INTERESTING_BYTES);
    }

    fn insert_run(&mut self, candidate: &mut Vec<u8>) {
        if candidate.len() >= self.max_bytes {
            return;
        }
        let headroom = self.max_bytes - candidate.len();
        let length = 1 + self.rng.below(headroom.min(64));
        let at = self.rng.below(candidate.len() + 1);
        let byte = *self.rng.pick(&INTERESTING_BYTES);
        candidate.splice(at..at, std::iter::repeat_n(byte, length));
    }

    fn delete_run(&mut self, candidate: &mut Vec<u8>) {
        if candidate.is_empty() {
            return;
        }
        let at = self.rng.below(candidate.len());
        let length = 1 + self.rng.below((candidate.len() - at).min(64));
        candidate.drain(at..at + length);
    }

    fn duplicate_block(&mut self, candidate: &mut Vec<u8>) {
        if candidate.is_empty() || candidate.len() >= self.max_bytes {
            return;
        }
        let at = self.rng.below(candidate.len());
        let headroom = self.max_bytes - candidate.len();
        let length = 1 + self.rng.below((candidate.len() - at).min(64).min(headroom));
        let block = candidate[at..at + length].to_vec();
        let target = self.rng.below(candidate.len() + 1);
        candidate.splice(target..target, block);
    }

    /// Joins a prefix of the candidate to a suffix of another population entry.
    fn splice(&mut self, candidate: &mut Vec<u8>) {
        let donor = self.entries[self.rng.below(self.entries.len())].clone();
        if donor.is_empty() {
            return;
        }
        let cut = self.rng.below(candidate.len() + 1);
        let take = self.rng.below(donor.len());
        candidate.truncate(cut);
        candidate.extend_from_slice(&donor[take..]);
        candidate.truncate(self.max_bytes);
    }

    /// Appends an unsigned varint holding a boundary integer. Frame payloads
    /// are varint-framed, so this reaches states byte edits rarely do.
    fn append_varint(&mut self, candidate: &mut Vec<u8>) {
        let mut value = *self.rng.pick(&INTERESTING_INTEGERS);
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                candidate.push(byte);
                break;
            }
            candidate.push(byte | 0x80);
        }
        candidate.truncate(self.max_bytes);
    }
}

/// Reads every regular file in a directory as a seed, sorted by name so a run
/// is reproducible regardless of directory order.
///
/// # Errors
/// Propagates directory and file read failures.
pub fn read_seed_directory(path: &std::path::Path) -> std::io::Result<Vec<Vec<u8>>> {
    let mut paths: Vec<_> = std::fs::read_dir(path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    paths.into_iter().map(std::fs::read).collect()
}

#[cfg(test)]
mod tests {
    use super::{Corpus, Rng};

    #[test]
    fn the_same_seed_replays_the_same_candidates() {
        let seeds = vec![b"\x31\x04hello".to_vec(), b"\x00".to_vec()];
        let mut first = Corpus::new(seeds.clone(), 16, 4096, 7);
        let mut second = Corpus::new(seeds, 16, 4096, 7);
        for _ in 0..256 {
            assert_eq!(first.next_candidate(), second.next_candidate());
        }
    }

    #[test]
    fn mutation_changes_length_in_both_directions() {
        let mut corpus = Corpus::new(vec![vec![0x41; 64]], 16, 4096, 11);
        let mut shorter = false;
        let mut longer = false;
        for _ in 0..2048 {
            let length = corpus.next_candidate().len();
            shorter |= length < 64;
            longer |= length > 64;
        }
        assert!(shorter, "no candidate ever shrank");
        assert!(longer, "no candidate ever grew");
    }

    #[test]
    fn mutations_accumulate_into_the_population() {
        let mut corpus = Corpus::new(vec![vec![0x41; 8]], 16, 4096, 13);
        assert_eq!(corpus.len(), 1);
        for _ in 0..64 {
            corpus.next_candidate();
        }
        assert!(corpus.len() > 1, "population never grew past its seed");
    }

    #[test]
    fn the_population_stays_bounded_and_keeps_its_first_seed() {
        let seed = b"seed".to_vec();
        let mut corpus = Corpus::new(vec![seed.clone()], 4, 4096, 17);
        for _ in 0..4096 {
            corpus.next_candidate();
        }
        assert_eq!(corpus.len(), 4);
        assert_eq!(corpus.entries[0], seed);
    }

    #[test]
    fn a_population_of_one_has_nothing_to_evict() {
        let mut corpus = Corpus::new(vec![b"seed".to_vec()], 1, 256, 29);
        for _ in 0..64 {
            corpus.next_candidate();
        }
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.entries[0], b"seed");
    }

    #[test]
    fn candidates_never_exceed_the_byte_ceiling() {
        let mut corpus = Corpus::new(vec![vec![0x41; 32]], 8, 48, 19);
        for _ in 0..4096 {
            assert!(corpus.next_candidate().len() <= 48);
        }
    }

    #[test]
    fn an_empty_seed_still_produces_input() {
        let mut corpus = Corpus::new(Vec::new(), 8, 256, 23);
        assert_eq!(corpus.len(), 1);
        let grew = (0..512).any(|_| !corpus.next_candidate().is_empty());
        assert!(grew, "an empty seed never grew into an input");
    }

    #[test]
    fn a_zero_seed_does_not_freeze_the_generator() {
        let mut rng = Rng::new(0);
        assert_ne!(rng.next_u64(), 0);
        assert_eq!(rng.below(0), 0);
        assert!(rng.below(4) < 4);
    }
}
