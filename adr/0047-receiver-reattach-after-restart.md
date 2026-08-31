# ADR-0047: Receiver re-attach after restart

- Status: Accepted
- Date: 2026-08-31
- Decision owners: A00 architecture; A05 commit model; A06 POSIX provider
- Applies to: `crates/vot-coverage` (`Coverage` export and import),
  `crates/vot-sdk` (`ObjectCoverage`), `crates/vot-sdk-file`
  (`NativeFile::create` identity exposure, a new `NativeFile::resume`),
  `crates/vot-commit-posix` (a new `PosixCommit::reattach`). No change to any
  spec file, wire identifier, proof crate, or the journal record format.

## Context

A receiver that restarts loses every partial transfer, and today that loss is
structural, not incidental. Four facts pin it:

- The journal records lifecycle transitions only. The states
  `JOURNAL_ADMITTED` through `JOURNAL_PUBLISHED` are appended with empty
  payloads except link and publish, which carry a sealed inode identity. No
  range, offset, or coverage information is ever journaled, by design: the
  journal answers "how far did the lifecycle get", not "which bytes landed".
- `recover` classifies and reconstructs nothing. It replays a journal and
  returns a `RecoveryDisposition` naming what a cleaner should do with the
  remains. It does not produce a writable `PosixCommit`, and no code outside
  its own tests calls it.
- Every constructor is create-only. `PosixCommit::create` opens staging with
  `create_new` and a fresh journal; `NativeFile::create` mints a fresh
  `.vot-{pid}-{seq}-{nanos}.stage` and journal pair through `next_name`,
  which derives the 16-byte incarnation from sequence, pid, and time. The
  incarnation surfaces to the caller only inside the publish receipt, after
  the transfer is already whole. Before publication the caller has no way to
  learn it, and `vot_journal::replay` refuses a journal whose incarnation
  does not match.
- Coverage is memory-only and sealed. `Coverage` exposes `covered_bytes`,
  `contiguous_prefix`, and `fragment_count`; there is no iterator over the
  covered runs and no constructor from persisted runs. A consumer that wanted
  to persist its own extents cannot read them out, and could not load them
  back if it had them.

The fetch side has resume: `vot-resume` persists checkpointed unit ranges and
`vot-cli`'s fetch pipeline replays them. The receive side has nothing
equivalent, and the consumer that wants it is concrete: a receive portal whose
senders hold a 48 hour resume window on multi-hundred-gigabyte uploads. The
wire protocol already resumes from reported coverage while the receiving
process stays up; the portal's operational documentation has to warn that a
restart discards every partial and senders start those files over. The portal
can persist its own session records with any durability it likes; what it
cannot do is turn a surviving staging file back into a `NativeFile`.

## Decision

**Coverage becomes exportable and reloadable, staging identity becomes known
at creation, and a resume constructor reopens an admitted staging file with
caller-supplied runs. Resumed coverage is the receiver trusting its own
persisted bookkeeping, and the ADR says so plainly rather than pretending the
proofs still exist.**

1. **`Coverage::runs()` and `Coverage::from_runs`.** `runs()` iterates the
   covered extents as `(offset, length)` pairs in ascending order.
   `from_runs(object_len, runs)` rebuilds the structure, refusing before any
   allocation proportional to input: runs must be sorted, non-overlapping,
   non-empty, inside the object length, and no more numerous than
   `fragment_limit(object_len)` allows. `ObjectCoverage` in `vot-sdk` passes
   both through.

2. **Creation exposes what resume needs.** `NativeFile::create` returns,
   alongside the handle, the staging path, the journal path, and the
   incarnation, so a consumer can persist them with its session record the
   moment the transfer is admitted. Today the first two are private fields
   and the incarnation is unreadable until publication.

3. **`PosixCommit::reattach` and `NativeFile::resume`.**
   `NativeFile::resume(object, destination, staging_path, journal_path,
   incarnation, profile, runs)` reopens the staging file without
   `create_new`, replays the journal under the supplied incarnation, and
   refuses unless the replayed state is exactly Admitted: a journal that
   reached seal, link, or publish belongs to `recover`'s cleanup
   dispositions, not to resume. The `CommitProfile` travels with the caller
   because the state machine gates publication on it and the journal never
   records it; the consumer persists the profile beside the other identity
   values, and resuming with a different profile than the one the transfer
   was admitted under silently changes the publish guarantee, which is
   exactly where the trust stance in item 4 bites. On success `resume` seeds
   `ObjectCoverage` through `from_runs` and returns a `NativeFile`
   indistinguishable from one that never restarted; `accept`, `seal`,
   `publish`, and cancellation behave identically from there. `reattach` is
   the `PosixCommit` half: reopen staging, verify the journal, restore the
   state machine to its admitted state under the supplied profile.

4. **The trust stance, stated.** Proofs are checked by `verify_range` and
   discarded; nothing retains them, and bao cannot re-verify an arbitrary
   partial byte set against the root without them. Under the Fast and
   Balanced profiles `publish` checks coverage completeness and renames
   without rehashing; only `CommitProfile::Strict` reads the staged bytes
   back, compares them against the announced root, and poisons on mismatch.
   A resumed receiver on Fast or Balanced therefore trusts the run list it
   persisted, and a false list publishes bytes that do not match the
   announced identity, with nothing inside VOT positioned to notice. That is
   acceptable under one condition, which the documentation of `resume` must
   carry: the consumer stores its runs with the same durability and the same
   trust domain as the session record it already relies on, so a lying list
   requires the same compromise as a lying session record. Three
   conservative alternatives remain available to every caller: persist only
   `contiguous_prefix` and pass the single prefix run to `resume`, letting
   the sender re-prove everything past it; resume under
   `CommitProfile::Strict`, paying its read-back at publication to close the
   boundary inside VOT; or, once coverage completes, rehash the staging file
   against the root from outside before calling `publish`, which the exposed
   staging path makes possible. The choice is per call, made by what the
   consumer persists and checks.

5. **Out of scope.** No journal format change, no coverage persistence inside
   VOT, no automatic discovery of resumable staging files: the consumer knows
   its sessions, VOT re-attaches the one it is told about. The fetch-side
   `vot-resume` store stays fetch-side.

## Consequences

- A restart stops being a data-loss event for a receiver that persists a
  handful of small values per session: object identity, destination, staging
  path, journal path, incarnation, commit profile, and the run list. The
  portal's drain procedure becomes an optimization instead of the only safe
  upgrade path.
- The incarnation check turns the journal into the arbiter of identity: a
  stale or mismatched journal refuses resume before a byte is written, so a
  consumer cannot silently re-attach the wrong staging file to a session.
- `from_runs` is a new parser of consumer-supplied input and is bounded and
  validated like one: geometry checks precede allocation, and
  `fragment_limit` bounds memory exactly as live acceptance does.
- Sizes: `vot-coverage` S, `vot-sdk` S, `vot-sdk-file` M,
  `vot-commit-posix` M. Memory, CPU, storage, and wire impact: none beyond
  the run list itself, which is bounded by the existing fragment limit.
- Downstream rollout is a repin. The portal's repin procedure moves its six
  sync points together, and anyone running VOT's own tests keeps the umask
  002 staging hazard in mind.

## Rejected alternatives

- **Journal the ranges.** Appending every accepted range to the journal makes
  the journal a second coverage store with unbounded growth on
  multi-terabyte objects, and changes a frozen, deliberately tiny lifecycle
  record. The consumer already has a durable store; VOT does not need one.
- **Retain proofs so resume can re-verify.** Storing proof bundles for every
  accepted range costs a bounded but real fraction of the object again, and
  re-verifying terabytes at boot trades the restart-loss problem for a
  restart-latency problem. A caller that wants VOT to close the boundary
  already has `CommitProfile::Strict`, whose publication read-back checks
  the whole object once, at the moment it matters, instead of every range
  again at every restart.
- **Re-hash staging at resume and accept only the verified prefix.** Hashing
  a partial file against a bao tree verifies nothing past the first gap, so
  this degenerates to the contiguous-prefix fallback that callers can already
  choose by persisting only the prefix, without paying a mandatory rehash of
  what it can verify.
- **Automatic staging discovery, resume by directory scan.** The consumer's
  session store is the source of truth for what should resume; a scanner
  would guess, and a wrong guess attaches an orphan to nothing. Cleanup of
  unclaimed staging remains what it is today, the consumer's sweep plus
  `recover`'s classifications.

## Required verification

- Round trip: create, accept a fragmented subset of ranges, export `runs()`,
  drop the `NativeFile`, `resume` with the persisted identity and runs,
  accept the remainder, publish, and the destination bytes equal the source,
  for both suites.
- Refusals, each before any write: wrong incarnation; journal already past
  Admitted (sealed, linked, published, each); overlapping, unsorted, empty,
  or out-of-bounds runs; a run count past `fragment_limit`; a staging file
  shorter than the highest claimed run.
- Prefix fallback: `resume` with only the contiguous prefix run accepts
  re-sent ranges past the prefix and refuses replays inside it, matching
  live-session replay classification.
- Trust boundary pinned, per profile: a run list claiming bytes that were
  never written resumes and completes under every profile; under Fast and
  Balanced it publishes and the published bytes fail a full rehash against
  the announced root, and under Strict the publication read-back refuses and
  poisons instead. The pair of tests pins that VOT neither silently repairs
  a false list nor lets one through Strict, so the documented boundary stays
  true.
- Mutation gate per CONTRIBUTING: a mutant that skips the incarnation check
  in `reattach`, and one that accepts overlapping runs in `from_runs`, each
  killed by a test, recorded in `test-vectors/mutants/`.
