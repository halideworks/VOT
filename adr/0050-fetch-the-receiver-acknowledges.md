# ADR-0050: Fetch, the receiver acknowledges

- Status: Accepted
- Date: 2026-09-02
- Decision owners: A00 architecture; A10 transport
- Applies to: `spec/wire.md` section 1 (the `GOAWAY` completion paragraph),
  `crates/vot-cli` (`serve`, `fetch`, `wire`, `drive`). No change to any frame
  encoding, to `spec/registries.md`, or to `vot-transport-api`.

## Context

ADR-0045 gave the push receiver a completion handshake. The receiver sends a
`GOAWAY` at the final transfer-object cursor once every object is durable and
every completion hook has succeeded, and the holder treats that final cursor as
the acknowledgement. The push sender drove its `ServeSession` until the
receiver's cursor reached the object count and then dropped the session, whose
carrier close the receiver's `await_push_close` observed; a disconnect before
the final cursor was failure.

A plain fetch is the same shape with the roles reversed. The fetch client is
the receiver of the data; the serving end is the holder. But the fetch client
never sent the acknowledgement. It detected completion locally, from
`plan.finished`, and tore its carrier down. The serve saw a bare disconnect,
not a final cursor, so `ServeReport.cursor` was `None` on a completed fetch and
the serve had no terminal state that told a completed fetch apart from a peer
that dropped mid-transfer. `ServeStatus` was `Active`, `Disconnected`, or
`Closed(code)`, none of which is a clean completion.

An embedder that accounts delivery per serve session could not read completion
off the report. It had to reconstruct it, crediting served bytes per token and
declaring delivery at the first crossing of the package length. That works only
while every delivered byte crosses one session and the package length is known
before the report, and it cannot tell a completed fetch from one stalled at the
last range. The distinction the final cursor makes exact was unavailable to the
fetch path because the fetch path never sent it.

## Decision

**A fetch acknowledges completion the way a push does, and the serve concludes
on it. The completing session sends a `GOAWAY` at the final transfer-object
cursor and waits for the serve's clean close before returning the package; the
serve ends the session when that cursor arrives. Nothing on the wire changes:
the frame, its payload, and its limit are what ADR-0045 wrote.**

1. **The fetch client acknowledges, best-effort.** On a completed fetch the
   wire layer (`drive::fetch_striped`) sends a final-cursor `GOAWAY` on the
   primary session and waits for the serve to close, then returns the package.
   The engine methods push used carry both paths, renamed from `acknowledge_push`
   and `await_push_close` to `acknowledge_completion` and `await_peer_close`. The
   package is proven before the client acknowledges, so a failed acknowledgement
   or a close that never arrives never fails the fetch: the client returns the
   proven package and the serve's own quiet-peer deadline reaps the session.
   This is the one substantive difference from push, where the acknowledgement
   is the holder's only completion signal and its failure fails the push.

2. **Only the primary acknowledges.** One acknowledgement per completed
   transfer is enough for the holder to conclude, and the primary always reaches
   completion whichever rail placed the last bytes, because every session sees
   the shared plan finish. The rails close abruptly, so their serve sessions end
   `Disconnected` with no cursor, and only the primary's session carries the
   final cursor.

3. **The serve concludes on the final cursor.** `BundleServer::service` returns
   a new `ServeStatus::Completed` when the received `GOAWAY` cursor equals the
   transfer-object count. `serve_one`'s `drive` settles on it, builds the report
   with the final cursor, and drops the session, whose carrier close the
   receiver's `await_peer_close` observes. The completion predicate is one pure
   function, `completion_acknowledged(cursor, objects)`, true only when the
   object count is nonzero and the cursor equals it, shared by the push sender's
   drive and the fetch serve so the mutation gate has one table to kill.

4. **The serve releases the carrier before the observer runs.** `serve_one`
   builds the `ServeReport` and drops the `ServeSession` before it calls the
   admission observer, so a receiver waiting on this session's clean close does
   not wait through the observer's own work, such as an embedder's durable
   write.

5. **The push sender loses its bespoke predicate.** It drove until a
   `push_completed` method returned true and then dropped; it now drives to
   `ServeStatus::Completed` and matches it, the same terminal the fetch serve
   reaches. No push behavior changes: the sender stops at the same cursor and
   closes by the same drop.

## Consequences

- `ServeReport.cursor` is `Some(object_count)` and the status is `Completed` on
  a completed fetch. An embedder marks delivery on one rule,
  `cursor == Some(objects)`, and needs no byte accounting against the package
  length. An abandoned fetch reports neither the final cursor nor `Completed`,
  and the rails of a completed fetch report a bare disconnect with no cursor, so
  the rule fires exactly once per completed transfer.
- The change is compatible in both directions with no negotiation. A new fetch
  client against an old serve that does not conclude on the final cursor waits
  out the thirty-second close deadline and then returns the already-proven
  package. An old fetch client against a new serve never sends the
  acknowledgement, so the serve never reaches `Completed` and the session ends
  on the client's disconnect, exactly as before.
- `GOAWAY` is unchanged on the wire: the same frame, the same one-varint
  payload, the same 4 KiB limit, and the same idempotence rule. No conformance
  vector is added or changed, and the frame's existing golden round-trip already
  covers the encoding. `spec/wire.md` section 1 replaces its push-scoped
  completion paragraph with one that states the rule for a receiver, the fetch
  client and the push server alike.

## Rejected alternatives

- **Leaving the fetch client to tear down silently, and reconstructing
  completion from byte counts in the embedder.** It works only while every
  delivered byte crosses one session and the package length is known before the
  report, and it cannot distinguish a completed fetch from one stalled at the
  last range. That distinction is the final cursor, which the fetch path was not
  sending.
- **A distinct completion close code on the carrier instead of a clean drop.**
  A coded application close reaches the peer as a poll error, not a disconnect
  event, so the receiver's wait for a clean close would fail on a successful
  transfer. The drop that push already uses delivers a plain disconnect, which
  is what `await_peer_close` returns on.
- **Every rail acknowledging.** The holder concludes on one acknowledgement, and
  the primary always reaches completion, so a per-rail acknowledgement would add
  a round trip per rail with no effect on the report the embedder reads.

## Required verification

- A railed fetch over the wire completes with exactly one serve session ending
  `Completed` at the final cursor and any rails ending disconnected with no
  cursor.
- `BundleServer::service` returns `Completed` on a `GOAWAY` whose cursor equals
  the object count and stays `Active` on a lower cursor.
- `completion_acknowledged` is true only when the object count is nonzero and
  the cursor equals it, pinned as a table.
- The push sender still completes over loopback, unchanged, now driving to
  `Completed` rather than its own predicate.

Implementation evidence (2026-09-02): the full `vot-cli` wire suite passes at
357 tests, and targeted mutation over the changed lines caught every mutant.
