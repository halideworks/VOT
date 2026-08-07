# ADR-0032: a fetch resumes from what it already placed

Status: Accepted

## Context

A fetch that dies mid-transfer starts over: `BundleFetcher::begin`
refuses a destination that exists, and nothing records which ranges of
the partial bundle were verified and made durable. Over a WAN a blip at
90% of a large transfer costs the whole transfer again. The pieces for
better already exist: `vot-resume` is a persistent append-log store of
checkpointed unit ranges per object (`VOTRES02`, reserve/checkpoint/
snapshot records, `UnitRanges` run-length, identity-bound and
crash-safe by construction), and ADR-0029's sink already knows every
`WrittenRange` it placed. What is missing is wiring: a durable record
of placement beside the bundle, and a plan that starts from it.

## Decision

**A fetch keeps a resume store beside the bundle it builds, and a fetch
pointed at a partial bundle with a matching store continues it instead
of refusing it.**

- **The store lives in the bundle directory** (`resume.vot` beside the
  manifest directory), created by every wire fetch and deleted on
  completion, so a completed bundle looks exactly as it does today and
  a partial one carries its own continuation state.
- **Identity is the package root.** The store is bound to the root the
  manifest proves. On resume, a pin that disagrees with the store, or a
  served descriptor whose root disagrees, is refused before a byte is
  requested (`IdentityMismatch`, surfaced as the same refusal a wrong
  pin gets today). Trusting the local checkpoint is no more trust than
  the bundle itself gets: every published byte re-proves at receive.
- **Checkpoint follows durability.** A range is checkpointed only after
  the sink's sync makes it durable. Today the sink syncs when an object
  completes; a resumable fetch syncs at a counted interval of placed
  bytes as well, so a big object is resumable mid-way. The interval is
  counted in bytes (the same currency as the progress quantum), never a
  clock.
- **The plan starts from the store.** `FetchPlan` construction takes
  the checkpointed ranges and seeds `placed_before`/`next_offset`/the
  per-object skip set from them, so the handout simply never asks for
  what is already placed. This is the same seam ADR-0031 step 2 opens
  (the plan behind a lock with handout as a method); resume seeds the
  plan, rails stripe it, and neither knows about the other.
- **The manifest is re-fetched, not resumed.** It is bounded and small
  against the objects, and re-validating it fresh is what re-derives
  the identity the store is checked against.
- **`fetch` and `pull` resume by default** when the destination holds a
  store; a destination without one is refused exactly as today. No new
  flags.

## Consequences

- A resumed fetch re-requests at most one sync interval per object plus
  what was in flight, instead of everything.
- Every wire fetch pays one small append per checkpoint interval; the
  loopback acceptance shape will price it, expected noise.
- The bundle directory transiently holds one extra file; receive
  ignores it and completion removes it.
- The sim harness gains kill-and-resume tests: fetch to a byte budget,
  drop the session, begin again over the same directory, assert the
  re-requested spans exclude the checkpointed ranges and the published
  tree is byte-identical.

## Sequence

1. Store wiring: create/load/delete `resume.vot` in `BundleFetcher`,
   identity-bound to the root, no behavior change while it only
   records.
2. Counted sink syncs plus checkpoint-after-sync, gate-tested against
   a killed fetch (records only; still no resume).
3. Plan seeding: `begin` on a partial bundle with a store continues it;
   the sim kill-and-resume test and the wire test land here.
4. A wire run on the rig: kill at half of 4 GiB, resume, log the
   re-requested bytes in the perf log.
