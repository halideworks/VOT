# ADR-0051: Fetch keeps a window of objects in flight

- Status: Accepted
- Date: 2026-09-03
- Decision owners: A00 architecture; A10 transport
- Applies to: `spec/wire.md` section 1 (the sentence defining the cursor) and
  `crates/vot-cli` (`fetch`, `drive`, `wire/push`). No change to any frame
  encoding, to `spec/registries.md`, or to `vot-transport-api`.

## Context

The fetch plan is single-active-object by construction. `FetchPlan` holds one
`current` index, one `active` sink, and one set of per-object accounts
(`next_offset`, `covered`, `skip`, `syncing`), and `next_span` hands out
ranges only from `objects[current]`. `advance` completes exactly one object
per transition: the first rail to see coverage whole flushes the sink outside
the lock, checkpoints the whole object in the resume store, runs the
completion hook, and moves `current` forward. Every rail then opens the next
object and asks for its ranges.

For one large object this is fine: eight rails stripe its ranges and a 4 GiB
object into tmpfs reaches 13.9 to 14.3 gigabits per second at 4.5 cores over
loopback on a twenty-thread host, bounded by CPU. For a sequence of small
objects it is not. Each object runs alone: it never has enough ranges
outstanding to fill the rails, and while its sink flushes and its directory
syncs, every rail waits. A 256-object sequence of 16 MiB objects into tmpfs
reaches 5.6 to 6.6 gigabits per second at 0.7 to 1.0 cores on the same host
and rails. Onto ZFS the gap is wider still: the single object reaches 7.7 and
the sequence 1.3 to 1.9, because each object's completion sync serializes
through the ZIL as well. Nothing on the wire imposes this order: the serve
answers a range request for any object until a `GOAWAY` cursor bounds it, and
`spec/wire.md` section 1 constrains only the cursor, which the fetch client
sends at completion or cancel.

## Decision

**The fetch plan keeps up to K objects in flight. Ranges are handed out from
whichever in-flight object still has some, objects complete independently and
in any order, and the `GOAWAY` cursor is the in-order durable prefix. Nothing
on the wire changes.**

1. **A window replaces the current object.** `FetchPlan.active` is a map from
   object index to an `ActiveObject` carrying that object's sink, completion
   hook, `next_offset`, coverage, skip set, and `syncing` flag. `low` is the
   count of objects durable in manifest order and is what the cursor reports.
   `next_open` is the first object not yet opened. The window holds at most
   `window` objects; opening one is the per-object setup `advance` did for the
   current object, done up to `window` deep.

2. **Handout walks the window.** `next_span` returns the first unrequested
   span of the lowest-indexed in-flight object that has one, so a rail pulls
   work from whichever object still has ranges and eight rails stay busy across
   eight small objects.

3. **Completion is per object and out of order.** The first rail to see an
   object whole sets that object's `syncing`, flushes and checkpoints it
   outside the lock, runs its completion hook, and removes it from the window.
   Other objects keep transferring and completing meanwhile. Completion hooks
   therefore run in any order; a consumer that needs manifest order does not
   exist and none is promised.

4. **The cursor is the in-order durable prefix.** `low` advances over an
   object only once it and every object before it are durable. Completion
   sends `GOAWAY(low)` with `low` equal to the object count; cancellation sends
   `GOAWAY(low)`, discards every in-flight partial above it, and resets their
   resume checkpoints. An object durable above `low` at cancel stays on disk
   with its whole-object checkpoint, so a resume finds it whole and never asks
   for it. The cursor never exceeds what is durable and never decreases.

5. **The seal is the cursor reaching the end.** The bundle seal runs when
   `low` equals the object count. An object reaches the cursor only after it
   has left the window, so an empty window is implied by construction rather
   than a second condition.

6. **The window is sized by the rails.** `drive::fetch_striped` sets the
   window to `min(2 * rails, 16)`, floor one, and the push receiver takes the
   same width from the rail count its sender may open. Each admitted object
   holds one verifier reservation of receiver staging for as long as it is in
   flight, and advertised credit is what is left of the staging budget against
   the target, so a budget of the credit alone hands the rails a credit shrunk
   by the window's reservations. The fetch staging budget therefore carries one
   reservation for every object the widest window may hold, on top of the
   credit.

## Consequences

- Small-object sequences use the rails. Measured back to back on the same
  host at rails 8, twice each, the window at one and then at its default: the
  256-object sequence into tmpfs moves from 5.2 to 7.3 gigabits per second at
  0.7 to 1.0 cores, to 15.5 to 16.8 at 8.1 to 9.5; onto ZFS it moves from 2.5
  to 4.6 at 0.4 to 0.7 cores, to 4.8 to 9.1 at 1.7 to 3.2. The single 4 GiB
  object is unchanged, 13.6 to 14.3 gigabits per second before and 14.0 to
  14.7 after: a package of one object fills the window whatever its width is.
  Onto ZFS that single object measures anywhere from 4.4 to 12.4 seconds for
  either binary, so it says nothing either way; the pool's write-path state
  is what it measures.
- No frame change, no conformance vector change, no ADR-0050 change: the serve
  already answers any object's ranges before a cursor bounds it, and one
  sentence of `spec/wire.md` section 1 now says the cursor is the in-order
  prefix of what is done rather than the count of it, which is what a single
  active object made the same thing.
- Completion hooks run in any order. votport's push receive completes each
  object by its own key; the vot-cli fetch has no ordering consumer.
- The plan lock is unchanged. Rails touch different objects' accounts under
  one short hold each; contention drops rather than rising.

## Rejected alternatives

- **Parallelizing only the completion sync, keeping one object transferring.**
  Halves the wrong problem: the RAM measurement shows the serial transfer, not
  the sync, is the larger cost.
- **Batching parent-directory syncs across objects in `seal_namespace`.**
  Changes the crash-consistency ordering the commit model proves; a separate
  decision.
- **A wire-level object window negotiated with the serve.** Nothing to
  negotiate: the serve already answers any object before a cursor bounds it.

## Required verification

- With the window at one, the whole `vot-cli` suite passes unchanged: the
  refactor is behavior-identical at K = 1.
- A fetch with a window wider than one over a bundle of many objects of mixed
  sizes, including empty objects and one whole from a previous fetch, lands
  every object byte for byte.
- A fetch killed with several objects in flight resumes and lands every object
  byte for byte. This is the directory path only: a receive through a custom
  sink factory has no resume store and no resume, as before this decision.
- A fetch cancelled with several objects in flight reports `low` as its cursor,
  discards every partial above it, and resets their checkpoints.
- The cursor advance and the window fill each have a test that kills their
  mutants: the cursor does not move over a hole; the fill opens no object past
  the window, and opens none at all once the plan is abandoned.
- Measured before and after on the same host and method: a 4 GiB single
  object and a 256-object sequence, into tmpfs and onto ZFS, rails 8.
