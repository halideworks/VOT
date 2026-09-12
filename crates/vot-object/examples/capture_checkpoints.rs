//! Capture representation experiment. This owns its input; it is not a file watcher.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use vot_object::{ObjectBuilder, PreparedObject, Suite, proof_leaves_at};
use vot_verifier::GROUP_SIZE as GROUP;

const DESCRIPTION_DOMAIN: &[u8] = b"capture-composition-experiment\0";

#[derive(Clone, Copy, Debug)]
enum Representation {
    Full,
    Leaves,
    Composition,
}

struct Draft {
    suite: Suite,
    representation: Representation,
    bytes: Vec<u8>,
    leaves: Vec<[u8; 32]>,
    dirty: BTreeSet<usize>,
}

struct Checkpoint {
    prepared: PreparedObject,
    description: Option<Vec<u8>>,
}

#[derive(Default)]
struct Work {
    payload_bytes: u64,
    metadata_bytes: u64,
    elapsed: Duration,
}

fn prepare(suite: Suite, bytes: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).unwrap();
    builder.update(bytes).unwrap();
    builder.finish().unwrap()
}

impl Draft {
    fn new(suite: Suite, representation: Representation) -> Self {
        Self {
            suite,
            representation,
            bytes: Vec::new(),
            leaves: Vec::new(),
            dirty: BTreeSet::new(),
        }
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) {
        assert!(
            offset <= self.bytes.len(),
            "the experiment does not create holes"
        );
        if bytes.is_empty() {
            return;
        }
        let end = offset.checked_add(bytes.len()).unwrap();
        self.bytes.resize(end.max(self.bytes.len()), 0);
        self.bytes[offset..end].copy_from_slice(bytes);
        self.dirty.extend(offset / GROUP..end.div_ceil(GROUP));
    }

    fn truncate(&mut self, length: usize) {
        assert!(length <= self.bytes.len());
        if length == self.bytes.len() {
            return;
        }
        self.bytes.truncate(length);
        let groups = length.div_ceil(GROUP);
        self.leaves.truncate(groups);
        self.dirty.retain(|index| *index < groups);
        if !length.is_multiple_of(GROUP) {
            self.dirty.insert(length / GROUP);
        }
    }

    fn checkpoint(&mut self) -> (Checkpoint, Work) {
        let start = Instant::now();
        let mut work = Work::default();
        let mut description = None;
        let prepared = match self.representation {
            Representation::Full => {
                work.payload_bytes = self.bytes.len() as u64;
                work.metadata_bytes = self.bytes.len().div_ceil(GROUP) as u64 * 32;
                prepare(self.suite, &self.bytes)
            }
            Representation::Leaves if self.bytes.len() <= GROUP => {
                work.payload_bytes = self.bytes.len() as u64;
                let object = prepare(self.suite, &self.bytes);
                self.leaves = object.proof_leaves().unwrap();
                work.metadata_bytes = self.leaves.len() as u64 * 32;
                object
            }
            Representation::Leaves | Representation::Composition => {
                self.leaves
                    .resize(self.bytes.len().div_ceil(GROUP), [0; 32]);
                for &index in &self.dirty {
                    let offset = index * GROUP;
                    let bytes = &self.bytes[offset..(offset + GROUP).min(self.bytes.len())];
                    self.leaves[index] = match self.representation {
                        Representation::Leaves => proof_leaves_at(
                            self.suite,
                            offset as u64,
                            bytes,
                            self.bytes.len() as u64,
                        )
                        .unwrap()[0],
                        Representation::Composition => prepare(self.suite, bytes).object_id().root,
                        Representation::Full => unreachable!(),
                    };
                    work.payload_bytes += bytes.len() as u64;
                }
                // ponytail: full tree/description rebuild per checkpoint; measure before adding incremental trees.
                match self.representation {
                    Representation::Leaves => {
                        work.metadata_bytes = self.leaves.len() as u64 * 32;
                        PreparedObject::from_proof_leaves(
                            self.suite,
                            self.bytes.len() as u64,
                            self.leaves.clone(),
                        )
                        .unwrap()
                    }
                    Representation::Composition => {
                        let encoded = self.description();
                        work.metadata_bytes = encoded.len() as u64;
                        let object = prepare(self.suite, &encoded);
                        description = Some(encoded);
                        object
                    }
                    Representation::Full => unreachable!(),
                }
            }
        };
        self.dirty.clear();
        work.elapsed = start.elapsed();
        (
            Checkpoint {
                prepared,
                description,
            },
            work,
        )
    }

    fn description(&self) -> Vec<u8> {
        let mut encoded = DESCRIPTION_DOMAIN.to_vec();
        encoded.extend_from_slice(&self.suite.identifier().to_le_bytes());
        encoded.extend_from_slice(&(self.bytes.len() as u64).to_le_bytes());
        for (index, root) in self.leaves.iter().enumerate() {
            let offset = index * GROUP;
            let length = GROUP.min(self.bytes.len() - offset);
            encoded.extend_from_slice(&(offset as u64).to_le_bytes());
            encoded.extend_from_slice(&(length as u64).to_le_bytes());
            encoded.extend_from_slice(root);
        }
        encoded
    }
}

fn main() {
    println!("suite,workload,representation,checkpoints,payload_bytes,metadata_bytes,prepare_ms");
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for workload in ["append", "rewrite", "truncate-regrow"] {
            for representation in [
                Representation::Full,
                Representation::Leaves,
                Representation::Composition,
            ] {
                let mut draft = Draft::new(suite, representation);
                if workload != "append" {
                    draft.write(0, &vec![3; 64 * GROUP]);
                    std::hint::black_box(draft.checkpoint());
                }
                let mut total = Work::default();
                for step in 0..1024 {
                    if workload == "append" {
                        draft.write(draft.bytes.len(), &[7; GROUP / 16]);
                    } else if workload == "rewrite" {
                        draft.write(0, &[u8::try_from(step % 251).unwrap()]);
                    } else if step % 2 == 0 {
                        draft.truncate(63 * GROUP + 17);
                    } else {
                        draft.write(draft.bytes.len(), &vec![9; GROUP - 17]);
                    }
                    let (checkpoint, work) = draft.checkpoint();
                    std::hint::black_box(checkpoint.prepared.object_id());
                    std::hint::black_box(&checkpoint.description);
                    total.payload_bytes += work.payload_bytes;
                    total.metadata_bytes += work.metadata_bytes;
                    total.elapsed += work.elapsed;
                }
                println!(
                    "{suite:?},{workload},{representation:?},1024,{},{},{:.3}",
                    total.payload_bytes,
                    total.metadata_bytes,
                    total.elapsed.as_secs_f64() * 1000.0
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_object::ObjectId;

    fn verify(object: &PreparedObject, offset: u64, bytes: &[u8]) -> bool {
        let cover = object.prove(offset, bytes.len() as u64).unwrap();
        verify_proof(object.object_id(), offset, bytes, cover.proof())
    }

    fn verify_proof(id: &ObjectId, offset: u64, bytes: &[u8], proof: &[u8]) -> bool {
        match id.suite {
            1 => vot_proof_blake3::verify(&id.root, id.length, offset, bytes, proof).is_ok(),
            2 => vot_proof_sha256::verify(&id.root, id.length, offset, bytes, proof).is_ok(),
            _ => unreachable!(),
        }
    }

    fn check(draft: &mut Draft) -> Work {
        let (checkpoint, work) = draft.checkpoint();
        if let Some(description) = checkpoint.description {
            let mut expected = DESCRIPTION_DOMAIN.to_vec();
            expected.extend_from_slice(&draft.suite.identifier().to_le_bytes());
            expected.extend_from_slice(&(draft.bytes.len() as u64).to_le_bytes());
            for (index, bytes) in draft.bytes.chunks(GROUP).enumerate() {
                let root = vot_verifier::root(draft.suite, bytes).unwrap();
                expected.extend_from_slice(&((index * GROUP) as u64).to_le_bytes());
                expected.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                expected.extend_from_slice(&root);
            }
            assert_eq!(description, expected);
            assert_eq!(
                checkpoint.prepared.object_id(),
                prepare(draft.suite, &expected).object_id()
            );
        } else {
            assert_eq!(
                checkpoint.prepared.object_id(),
                &ObjectId {
                    suite: draft.suite.identifier(),
                    root: vot_verifier::root(draft.suite, &draft.bytes).unwrap(),
                    length: draft.bytes.len() as u64,
                }
            );
            for (index, bytes) in draft.bytes.chunks(GROUP).enumerate() {
                assert!(verify(&checkpoint.prepared, (index * GROUP) as u64, bytes));
            }
        }
        work
    }

    #[test]
    fn checkpoints_match_fresh_hashing_across_mutations() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for representation in [
                Representation::Full,
                Representation::Leaves,
                Representation::Composition,
            ] {
                let mut draft = Draft::new(suite, representation);
                check(&mut draft);
                for length in [
                    1,
                    1023,
                    1024,
                    GROUP - 1,
                    GROUP,
                    GROUP + 1,
                    2 * GROUP,
                    4 * GROUP + 7,
                    8 * GROUP + 1,
                ] {
                    draft.write(
                        draft.bytes.len(),
                        &vec![u8::try_from(length % 251).unwrap(); length - draft.bytes.len()],
                    );
                    check(&mut draft);
                }
                for offset in [GROUP - 1, 0, 5 * GROUP + 3, 2 * GROUP] {
                    draft.write(offset, b"changed");
                    check(&mut draft);
                }
                for offset in [4 * GROUP, GROUP, 0] {
                    draft.write(offset, b"unordered");
                }
                check(&mut draft);
                for length in [4 * GROUP, 2 * GROUP + 19, GROUP, GROUP - 1, 1, 0] {
                    draft.truncate(length);
                    check(&mut draft);
                }
                draft.write(0, &vec![9; 3 * GROUP + 1]);
                check(&mut draft);
                draft.truncate(GROUP + 11);
                draft.write(GROUP + 11, &vec![8; 2 * GROUP]);
                check(&mut draft);
                draft.write(0, &[]);
                draft.truncate(draft.bytes.len());
                let work = check(&mut draft);
                if !matches!(representation, Representation::Full) {
                    assert_eq!(work.payload_bytes, 0);
                }
            }
        }
    }

    #[test]
    fn changed_root_can_reuse_unchanged_bytes_with_new_proofs() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut draft = Draft::new(suite, Representation::Leaves);
            draft.write(0, &vec![7; 4 * GROUP + 11]);
            let (old, _) = draft.checkpoint();
            let mut received = draft.bytes.clone();
            draft.write(GROUP + 1, b"new header");
            let (new, work) = draft.checkpoint();
            assert_ne!(new.prepared.object_id(), old.prepared.object_id());
            assert_eq!(work.payload_bytes, GROUP as u64);
            let stale_cover = old.prepared.prove(0, GROUP as u64).unwrap();
            assert!(!verify_proof(
                new.prepared.object_id(),
                0,
                &received[..GROUP],
                stale_cover.proof()
            ));
            let mut transferred = 0;
            for (index, bytes) in received.chunks_mut(GROUP).enumerate() {
                let offset = index * GROUP;
                if !verify(&new.prepared, offset as u64, bytes) {
                    bytes.copy_from_slice(&draft.bytes[offset..offset + bytes.len()]);
                    assert!(verify(&new.prepared, offset as u64, bytes));
                    transferred += bytes.len();
                }
            }
            assert_eq!(transferred, GROUP);
            assert_eq!(received, draft.bytes);
            assert_eq!(
                vot_verifier::root(suite, &received).unwrap(),
                new.prepared.object_id().root
            );
            assert!(!verify(
                &old.prepared,
                GROUP as u64,
                &received[GROUP..2 * GROUP]
            ));
        }
    }

    #[test]
    fn small_rewrites_still_rebuild_metadata_for_the_whole_object() {
        for representation in [Representation::Leaves, Representation::Composition] {
            let mut draft = Draft::new(Suite::Blake3Bao64, representation);
            draft.write(0, &vec![4; 32 * GROUP]);
            check(&mut draft);
            let mut payload = 0;
            let mut metadata = 0;
            for value in 0..8 {
                draft.write(0, &[value]);
                let work = check(&mut draft);
                payload += work.payload_bytes;
                metadata += work.metadata_bytes;
            }
            assert_eq!(payload, 8 * GROUP as u64);
            let per_checkpoint = match representation {
                Representation::Leaves => 32 * 32,
                Representation::Composition => DESCRIPTION_DOMAIN.len() + 2 + 8 + 32 * 48,
                Representation::Full => unreachable!(),
            };
            assert_eq!(metadata, 8 * per_checkpoint as u64);
        }
    }
}
