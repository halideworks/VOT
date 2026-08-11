//! Bounded retained proof-storage exercise shared by standalone and
//! coverage-guided fuzz drivers.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use vot_object::{Error as ObjectError, ObjectBuilder, PreparedObject, Suite};
use vot_proof_catalog::encode;
use vot_proof_store::{MemoryNodeStorage, ProofNode, ProofNodeStorage, StoreError};

/// Largest candidate accepted by either driver.
pub const MAX_INPUT: usize = 256 * 1024;

/// Allocation ceiling enforced by both drivers.
pub const ALLOCATION_LIMIT: usize = 128 * 1024 * 1024;

const GROUP_SIZE: usize = 65_536;
const READ_NORMAL: u8 = 0;
const READ_UNAVAILABLE: u8 = 1;
const READ_CORRUPT: u8 = 2;
const READ_MISSING: u8 = 3;

struct FaultStore {
    nodes: Vec<ProofNode>,
    length_failure: bool,
    append_failure_at: Option<u64>,
    read_mode: Arc<AtomicU8>,
}

impl FaultStore {
    fn new(read_mode: Arc<AtomicU8>) -> Self {
        Self {
            nodes: Vec::new(),
            length_failure: false,
            append_failure_at: None,
            read_mode,
        }
    }
}

impl ProofNodeStorage for FaultStore {
    fn len(&self) -> Result<u64, StoreError> {
        if self.length_failure {
            return Err(StoreError::Unavailable);
        }
        u64::try_from(self.nodes.len()).map_err(|_| StoreError::Capacity)
    }

    fn append(&mut self, node: ProofNode) -> Result<(), StoreError> {
        let ordinal = self.len()?;
        if self.append_failure_at == Some(ordinal) {
            // A backend may have written part or all of a record before it can
            // report failure. The object builder must poison this construction.
            self.nodes.push(node);
            return Err(StoreError::Unavailable);
        }
        self.nodes.push(node);
        Ok(())
    }

    fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError> {
        match self.read_mode.load(Ordering::Relaxed) {
            READ_UNAVAILABLE => Err(StoreError::Unavailable),
            READ_CORRUPT => Err(StoreError::Corrupt),
            READ_MISSING => Err(StoreError::Corrupt),
            _ => {
                let index = usize::try_from(ordinal).map_err(|_| StoreError::Capacity)?;
                self.nodes.get(index).copied().ok_or(StoreError::Corrupt)
            }
        }
    }
}

fn selector(input: &[u8], salt: usize) -> u64 {
    if input.is_empty() {
        return salt as u64;
    }
    (0..8).fold(0_u64, |value, offset| {
        let index = salt.wrapping_add(offset) % input.len();
        (value << 8) | u64::from(input[index])
    })
}

fn feed(builder: &mut ObjectBuilder, bytes: &[u8], control: &[u8]) -> Result<(), ObjectError> {
    if bytes.is_empty() {
        return builder.update(&[]);
    }
    let mut offset = 0;
    let mut turn = 0;
    while offset < bytes.len() {
        let width = 1 + usize::try_from(selector(control, turn) % (GROUP_SIZE as u64 + 257))
            .map_err(|_| ObjectError::LengthOverflow)?;
        let end = offset.saturating_add(width).min(bytes.len());
        builder.update(&bytes[offset..end])?;
        offset = end;
        turn += 1;
    }
    Ok(())
}

fn prepare_default(suite: Suite, bytes: &[u8], control: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).expect("default builder");
    feed(&mut builder, bytes, control).expect("default update");
    builder.finish().expect("default finish")
}

fn prepare_stored(suite: Suite, bytes: &[u8], control: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::with_proof_storage(
        suite,
        Some(bytes.len() as u64),
        Box::new(MemoryNodeStorage::new()),
    )
    .expect("stored builder");
    feed(&mut builder, bytes, control).expect("stored update");
    builder.finish().expect("stored finish")
}

fn range_cases(length: u64, input: &[u8]) -> [(u64, u64); 4] {
    let offset = selector(input, 3) % length;
    let remaining = length - offset;
    let selected = 1 + selector(input, 11) % remaining;
    [(0, 1), (length - 1, 1), (offset, selected), (0, length)]
}

fn exercise_equivalence(suite: Suite, input: &[u8]) {
    let payload = input.get(1..).unwrap_or_default();
    let default = prepare_default(suite, payload, input);
    let stored = prepare_stored(suite, payload, input);
    assert_eq!(default.object_id(), stored.object_id());

    if payload.is_empty() {
        assert_eq!(default.holds(0, &[]), stored.holds(0, &[]));
    } else {
        for (index, group) in payload.chunks(GROUP_SIZE).enumerate() {
            let offset = u64::try_from(index)
                .expect("bounded index")
                .checked_mul(GROUP_SIZE as u64)
                .expect("bounded offset");
            assert_eq!(default.holds(offset, group), stored.holds(offset, group));
        }
        let mut changed = payload[..payload.len().min(GROUP_SIZE)].to_vec();
        changed[0] ^= 1;
        assert_eq!(default.holds(0, &changed), stored.holds(0, &changed));

        for (offset, length) in range_cases(payload.len() as u64, input) {
            assert_eq!(default.prove(offset, length), stored.prove(offset, length));
        }
    }

    assert_eq!(encode(&default), encode(&stored));
}

fn assert_len_failure(suite: Suite) {
    let read_mode = Arc::new(AtomicU8::new(READ_NORMAL));
    let mut storage = FaultStore::new(read_mode);
    storage.length_failure = true;
    assert!(matches!(
        ObjectBuilder::with_proof_storage(suite, Some(0), Box::new(storage)),
        Err(ObjectError::Storage(StoreError::Unavailable))
    ));
}

fn assert_partial_append_poison(suite: Suite, input: &[u8]) {
    let group_count = 2 + selector(input, 17) % 7;
    let leaf_failure = selector(input, 29) % group_count;
    let read_mode = Arc::new(AtomicU8::new(READ_NORMAL));
    let mut storage = FaultStore::new(read_mode);
    storage.append_failure_at = Some(leaf_failure);
    let expected_length = group_count * GROUP_SIZE as u64;
    let mut builder =
        ObjectBuilder::with_proof_storage(suite, Some(expected_length), Box::new(storage))
            .expect("leaf-fault builder");
    let byte = input.first().copied().unwrap_or(0x5a);
    let group = vec![byte; GROUP_SIZE];
    for ordinal in 0..=leaf_failure {
        let result = builder.update(&group);
        if ordinal == leaf_failure {
            assert_eq!(result, Err(ObjectError::Storage(StoreError::Unavailable)));
        } else {
            result.expect("leaf before selected failure");
        }
    }
    assert_eq!(
        builder.update(&[]),
        Err(ObjectError::Storage(StoreError::Unavailable))
    );
    assert!(matches!(
        builder.finish(),
        Err(ObjectError::Storage(StoreError::Unavailable))
    ));

    let parent_failure = group_count + selector(input, 43) % (group_count / 2);
    let read_mode = Arc::new(AtomicU8::new(READ_NORMAL));
    let mut storage = FaultStore::new(read_mode);
    storage.append_failure_at = Some(parent_failure);
    let mut builder =
        ObjectBuilder::with_proof_storage(suite, Some(expected_length), Box::new(storage))
            .expect("parent-fault builder");
    for _ in 0..group_count {
        builder.update(&group).expect("leaf append");
    }
    assert!(matches!(
        builder.finish(),
        Err(ObjectError::Storage(StoreError::Unavailable))
    ));
}

fn fault_payload(input: &[u8]) -> Vec<u8> {
    let salt = input.first().copied().unwrap_or(0x6d);
    (0..3 * GROUP_SIZE + 17)
        .map(|index| salt.wrapping_add((index % 251) as u8))
        .collect()
}

fn assert_read_failure(suite: Suite, input: &[u8], mode: u8, expected: StoreError) {
    let read_mode = Arc::new(AtomicU8::new(READ_NORMAL));
    let storage = FaultStore::new(Arc::clone(&read_mode));
    let payload = fault_payload(input);
    let mut builder =
        ObjectBuilder::with_proof_storage(suite, Some(payload.len() as u64), Box::new(storage))
            .expect("read-fault builder");
    feed(&mut builder, &payload, input).expect("read-fault update");
    let prepared = builder.finish().expect("read-fault finish");

    read_mode.store(mode, Ordering::Relaxed);
    assert!(matches!(
        prepared.prove(0, 1),
        Err(ObjectError::Storage(error)) if error == expected
    ));
    assert!(!prepared.holds(0, &payload[..GROUP_SIZE]));
}

fn exercise_fault(suite: Suite, input: &[u8]) {
    match input.first().copied().unwrap_or(0) % 5 {
        0 => assert_len_failure(suite),
        1 => assert_partial_append_poison(suite, input),
        2 => assert_read_failure(suite, input, READ_UNAVAILABLE, StoreError::Unavailable),
        3 => assert_read_failure(suite, input, READ_CORRUPT, StoreError::Corrupt),
        _ => assert_read_failure(suite, input, READ_MISSING, StoreError::Corrupt),
    }
}

/// Exercises exact memory/stored equivalence and one input-selected host fault
/// for both verification suites.
pub fn exercise(input: &[u8]) {
    let suites = if input.first().copied().unwrap_or(0) & 0x80 == 0 {
        [Suite::Blake3Bao64, Suite::Sha256Bep52]
    } else {
        [Suite::Sha256Bep52, Suite::Blake3Bao64]
    };
    for suite in suites {
        exercise_equivalence(suite, input);
        exercise_fault(suite, input);
    }
}

#[cfg(test)]
mod tests {
    use super::exercise;

    #[test]
    fn degenerate_inputs_do_not_panic() {
        exercise(&[]);
        exercise(&[0]);
        exercise(&[0xff; 257]);
    }

    #[test]
    fn deterministic_fault_seeds_do_not_panic() {
        for seed in [
            include_bytes!("../corpus/len-failure.bin").as_slice(),
            include_bytes!("../corpus/append-partial.bin").as_slice(),
            include_bytes!("../corpus/read-unavailable.bin").as_slice(),
            include_bytes!("../corpus/read-corrupt.bin").as_slice(),
            include_bytes!("../corpus/read-missing.bin").as_slice(),
        ] {
            exercise(seed);
        }
    }
}
