# ADR-0048: Serve, the host admits

- Status: Accepted
- Date: 2026-09-02
- Decision owners: A00 architecture; A10 transport
- Applies to: `crates/vot-cli` (`bind_serve_listener`, `serve_on`,
  `ServePresentation`, `ServeAdmission`, `ServeReport`, the shared
  `accept_sessions` loop, `ServeSession::from_started_session`,
  `goaway_cursor`, `served_bytes`, `BundleServer::object_count`). No change
  to any spec file, wire identifier, or conformance vector. Companion to
  ADR-0045 (push, the holder dials), which gave the receive direction its
  embedding seam.

## Context

ADR-0045 let a host program receive pushes on a listener it bound itself:
`bind_push_listener` returns a Retry-protected listener and the identity a
peer pins, and `receive_push_on(listener, policy)` hands every session's
untrusted presentation to the host, which authenticates and authorizes it
and returns the admission the engine then serves. A portal such as votport
runs on that seam: one socket, per-session policy against keys it holds in
memory, its own accounting.

Serving had no such seam. `serve_bundle` binds its own socket, answers one
bundle directory for its lifetime, builds its capability requirement from
process environment variables, and reports nothing per session. A host
that serves many packages under credentials it manages, and that must
know when a session ended and how much it took, cannot be built on it
without reimplementing the accept loop from `vot-transport-quiche`
onward.

## Decision

`vot-cli` gains the serve twin of the push seam, under the `wire` feature.

- `bind_serve_listener(address, credentials)` returns a listener with
  stateless Retry enabled and no accept timeout, plus the blake3 identity
  of the certificate it presents. It is the same listener
  `bind_push_listener` returns.
- `serve_on(listener, policy)` accepts sessions and serves each on its own
  thread, at most `CONCURRENT_SESSIONS` at once, refusing a listener
  without Retry with `InvalidArguments`. Every session is challenged for a
  capability with a fresh nonce under `Binding::ProofOfPossession` and the
  VOT capability format; the seam offers the default extensions.
- `policy` receives a `ServePresentation` (peer, challenge, `SESSION_OPEN`,
  channel binding, now), the same five fields `PushPresentation` carries,
  and returns `Option<ServeAdmission>`: the `Arc<BundleServer>` to answer
  from, the encoded scope to grant (what `Requirement::decide` returns),
  and an optional observer. The policy chooses the bundle, so one socket
  serves every package the host holds.
- The seam holds the policy to its bundle. A granted scope must decode,
  name suite 1, carry no length and no ranges, and name the served
  bundle's package root; otherwise the session is refused with the one
  constant reason and detail every serve refusal carries. A policy bug
  cannot serve one package under a token for another.
- A presentation not admitted within ten seconds of the session's start is
  closed with `AUTHENTICATION_FAILED`, the deadline ADR-0045 requires of a
  public receiver, applied to a public serve. Traffic does not refresh it.
- When the session ends the observer receives a `ServeReport`: the peer,
  the receiver's last `GOAWAY` cursor if it sent one, the bundle's transfer
  object count, the bytes of answers the carrier took, and the session's
  final status or this end's failure. A fetch that completes sends no
  `GOAWAY`, so a completed session reports no cursor and an `Ok` status; a
  cancelled one reports the cursor it stopped at. The failure lives in the
  report; the accept loop only learns that the session failed.

Three accessors support the report without widening the wire:
`BundleServer::object_count` and `ServeSession::goaway_cursor` and
`served_bytes`, the last read from the outbound queue's count of bytes the
carrier took, which a close now clears rather than replaces so the count
survives to the report. `ServeSession::from_started_session` serves a
session whose handshake the seam already ran and whose authorization it
already answered.

## Consequences

- A host serves N packages on one listener with per-session policy and
  per-session accounting, mirroring how it already receives pushes.
- The wire is unchanged. Nothing new is negotiated, encoded, or sent; the
  conformance vectors do not move.
- Memory: one `ServeSession` per admitted session as before, plus the
  `Arc<BundleServer>` the admission clones. CPU: one scope decode per
  admission. Storage and wire amplification: none beyond `serve_bundle`;
  Retry is on, so no connection state exists for an address that did not
  answer.
- A refusal is invisible to the host by design: the policy already
  decided to admit, and the seam's root check is a second guard against a
  policy that named the wrong bundle, not an event the host acts on. The
  observer runs only for a session the seam granted.
- Not decided here: an open-serve mode without a capability (the seam
  always challenges), a per-peer session cap (the global bound still
  applies, and a policy may refuse by peer), sender-side transport tuning
  for a host-bound listener (`serve_bundle` reads congestion control, the
  initial window, and prefix duplication from the environment; the seam's
  listener uses the defaults), and a `BundleServer` built from a manifest
  and a root-to-path map rather than a bundle directory, which a host that
  already holds proof leaves will want next.

## Required verification

- `serve_on_admits_by_root_and_reports_each_session`: two bundles on one
  listener; a token for A is served from A to completion and the observer
  reports one object, no cursor, at least the object's bytes, and an `Ok`
  status; a token for an unknown root, and a token for B that the policy
  answers from A, are refused and write no object.
- `serve_on_refuses_a_listener_without_retry`.
- `serve_on_closes_a_silent_peer_at_the_deadline`: a carrier that
  completes the handshake and never opens a session is closed with
  `AUTHENTICATION_FAILED` when the deadline passes.
- Mutants recorded in `test-vectors/mutants/adr_0048_serve_seam.md`.
