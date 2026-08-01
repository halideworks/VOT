# Merged review backlog

These checks close correctness findings left on merged pull requests.

| Finding | Negative control | Catching evidence |
|---|---|---|
| Journal creation durability | Remove the parent directory `sync_all` call | The required `vot-journal` mutation run reports 97 caught, 9 unviable, and zero missed |
| Repeated verified write | Remove the pre-write state check | `repeated_verified_write_cannot_mutate_published_bytes` observes appended bytes instead of `first` |
| Recovery destination identity | Make `same_file` return true | `recovery_rejects_unrelated_destination_identity` accepts an unrelated destination and fails |
| Strict reader binding | Make the direct descriptor identity check accept another inode | `direct_reader_is_bound_to_the_staged_descriptor` fails; the required strict mutation run reports 31 caught, 8 unviable, and zero missed |
| Multipart ordering and retry | Store receipts in call order | `out_of_order_and_replaced_parts_complete_in_number_order` produces an invalid completion list |
| Receipt timestamp syntax | Relax any RFC 3339 separator or range check | The receipt mutation run has no surviving timestamp or numeric-bound mutant |
| S3 read-back comparison | Compare the GET checksum with itself | `retained_parts_detect_stable_read_back_corruption` accepts `oneXwo` and fails |
| Ambiguous S3 completion | Consume or poison the commit on response loss | `ambiguous_completion_preserves_state_and_reconciles_on_retry` cannot reach `PUBLISHED` on retry |
| S3 completion allocation | Clone `LiveUpload` before completion | `LiveUpload` is not `Clone`; completion removes and owns one upload record, restoring it only on failure |
| S3 consumed-upload retry | Treat `NoSuchUpload` as a definitive completion failure | `only_consumed_upload_service_error_enters_reconciliation` fails and the retry cannot reconcile an already published object |
| Bare relative journal path | Use an empty relative parent rather than the current directory | `bare_relative_journal_uses_current_directory_for_durability` fails |
| Planner complexity | Scan all jobs on every pop | `Planner::pop` uses the priority-ordered `BTreeSet::pop_first`; the required scheduler mutation run reports 27 caught, 6 unviable, and zero missed |
| Lowercase RFC 3339 separators | Accept uppercase `T` and `Z` only | `timestamps_require_rfc3339_syntax_and_ranges` exercises lowercase `t` and `z` independently and together |
| Private CLI manifest encoding | Write or read the removed `VOTPKG0` manifest instead of canonical CBOR pages and seal | `canonical_manifest_bundle_publishes_with_matching_receipt` decodes every CLI page and seal through `vot-manifest`; `tools/verify_wave4_package.py` independently parses the same canonical CBOR |
| CLI durability overclaim | Change the publication receipt from Fast/`TRANSIT_VERIFIED` to Balanced/`DURABLE` without a commit-journal durability transition | `publication_receipt_claims_only_performed_assurance` fails; the required `vot-cli` mutation run reports 206 caught, 20 unviable, and zero missed |
| Receipt publication race | Delete prepared receipt files after destination publication or overwrite an existing receipt | `receipt_publication_recovers_after_destination_publish` cannot recover after the simulated process exit; conflict tests reject mismatched existing outputs |
| TLS carrier without VOT ALPN | Treat handshake completion alone as authentication | `completed_tls_without_vot_alpn_exposes_no_plaintext` completes authenticated TLS with no ALPN and proves VOT reads and writes remain blocked |
| Advisory checkpoint window | Allow an already-active unit to complete after the checkpoint window fills | `full_window_blocks_completion_until_checkpoint_succeeds` requires `CheckpointRequired` and preserves the retransmission bound |
| Congested Careful Resume reuse | Return `Congestion` without deleting the saved parameters | `reconnaissance_congestion_discards_saved_state` proves the next attempt is `Unknown` until a fresh observation is stored |
| Windows checkpoint replacement | Use `std::fs::rename` when the checkpoint destination already exists | `repeated_checkpoints_replace_the_previous_snapshot` runs on native Windows CI; `vot-platform-fs` isolates `MoveFileExW` and retains `unsafe_code = "forbid"` elsewhere |
| Active Careful Resume refresh | Replace an in-use saved path through `observe` | `active_careful_resume_observation_cannot_be_replaced` requires `AlreadyInUse` and proves the existing permit remains exclusive |
| Unauthenticated receipt recovery | Finalize predictable prepared files without decoding, HMAC verification, and package-field checks | `receipt_recovery_authenticates_prepared_evidence` rejects wrong-key and tampered-summary preparations; `recovered_receipt_requires_every_publication_field` rejects each mismatched claim |
| Concurrent receipt preparation deletion | Delete deterministic preparation files before a competing publication finishes | `live_receipt_preparation_is_not_removed_by_a_contender` proves a second invocation can validate or reject the evidence but cannot remove it |
| Concurrent resume checkpoints | Remove the exclusive store lock or replace the durable map from a stale in-memory snapshot | `checkpoint_waits_for_the_store_transaction_lock` and `stale_store_writers_reload_and_merge_checkpointed_units` fail |
| Empty canonical package | Seal one empty manifest page with the empty package transcript root | `empty_canonical_manifest_cannot_publish` rejects it before destination or receipt publication |
| Resume store read race | Check metadata and then read a separately resolved path to EOF | `store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic` enforces the cap through one open handle |
| Unacknowledged congested reconnaissance | Check initial-flight acknowledgement before the congestion signal | `reconnaissance_congestion_discards_saved_state` requires `Congestion` and removes the saved state for either acknowledgement value |

The safe TLC capability model explores 2,389,496 distinct states without violation. `CommitUnsupportedAdvance.cfg` reaches `PUBLISHED` for an unsupported profile and TLC reports `Invariant UnsupportedNeverAdvanced is violated`.
