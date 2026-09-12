//! Compares full cached-leaf rebuilding with shared checkpoint updates.
//! Input is owned and every mutation is supplied; no filesystem watching occurs.

use std::time::Instant;
use vot_object::{ObjectBuilder, ObjectCheckpoint, PreparedObject, Suite, proof_leaves_at};

const GROUP: usize = 65_536;

fn prepare(suite: Suite, bytes: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).unwrap();
    builder.update(bytes).unwrap();
    builder.finish().unwrap()
}

fn main() {
    let groups = std::env::args()
        .nth(1)
        .map_or(64, |value| value.parse::<usize>().unwrap());
    assert!(groups >= 2);
    println!("suite,workload,shared,checkpoints,payload_bytes,leaf_input_bytes,elapsed_ms");
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for workload in ["append", "rewrite", "truncate-regrow"] {
            for shared in [false, true] {
                let mut bytes = if workload == "append" {
                    Vec::new()
                } else {
                    vec![3; groups * GROUP]
                };
                let mut checkpoint = ObjectCheckpoint::new(suite)
                    .unwrap()
                    .updated(0, &bytes, bytes.len() as u64)
                    .unwrap();
                let mut leaves = prepare(suite, &bytes).proof_leaves().unwrap();
                let mut final_id = checkpoint.object_id().clone();
                let mut elapsed = std::time::Duration::ZERO;
                let mut payload_bytes = 0_u64;
                let mut leaf_input_bytes = 0_u64;
                for step in 0..1024 {
                    let previous_length = bytes.len();
                    let offset = match workload {
                        "append" => {
                            let offset = bytes.len() / GROUP * GROUP;
                            bytes.resize(bytes.len() + GROUP / 16, 7);
                            offset
                        }
                        "rewrite" => {
                            bytes[0] = u8::try_from(step % 251).unwrap();
                            0
                        }
                        _ => {
                            bytes.resize(
                                if step % 2 == 0 {
                                    (groups - 1) * GROUP + 17
                                } else {
                                    groups * GROUP
                                },
                                9,
                            );
                            (groups - 1) * GROUP
                        }
                    };
                    let offset = if previous_length <= GROUP { 0 } else { offset };
                    let end = if workload == "rewrite" {
                        GROUP.min(bytes.len())
                    } else {
                        bytes.len()
                    };
                    let fragment = &bytes[offset..end];
                    payload_bytes += fragment.len() as u64;
                    let started = Instant::now();
                    let prepared = if shared {
                        checkpoint = checkpoint
                            .updated(offset as u64, fragment, bytes.len() as u64)
                            .unwrap();
                        leaf_input_bytes += fragment.len().div_ceil(GROUP) as u64 * 32;
                        checkpoint.prepared()
                    } else if bytes.len() <= GROUP {
                        let prepared = prepare(suite, &bytes);
                        leaves = prepared.proof_leaves().unwrap();
                        leaf_input_bytes += leaves.len() as u64 * 32;
                        prepared
                    } else {
                        let changed =
                            proof_leaves_at(suite, offset as u64, fragment, bytes.len() as u64)
                                .unwrap();
                        leaves.resize(bytes.len().div_ceil(GROUP), [0; 32]);
                        leaves[offset / GROUP..offset / GROUP + changed.len()]
                            .copy_from_slice(&changed);
                        leaf_input_bytes += leaves.len() as u64 * 32;
                        PreparedObject::from_proof_leaves(suite, bytes.len() as u64, leaves.clone())
                            .unwrap()
                    };
                    final_id.clone_from(prepared.object_id());
                    std::hint::black_box(prepared.object_id());
                    drop(prepared);
                    elapsed += started.elapsed();
                }
                assert_eq!(final_id.root, vot_verifier::root(suite, &bytes).unwrap());
                assert_eq!(final_id.length, bytes.len() as u64);
                println!(
                    "{suite:?},{workload},{shared},1024,{payload_bytes},{leaf_input_bytes},{:.3}",
                    elapsed.as_secs_f64() * 1000.0
                );
            }
        }
    }
}
