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

The safe TLC capability model explores 2,389,496 distinct states without violation. `CommitUnsupportedAdvance.cfg` reaches `PUBLISHED` for an unsupported profile and TLC reports `Invariant UnsupportedNeverAdvanced is violated`.
