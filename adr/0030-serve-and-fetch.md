# ADR-0030: serve and fetch complete the CLI over the wire

Status: Accepted

## Context

The CLI packs a directory into a bundle and receives a bundle into a
published destination with a signed receipt. Both ends of that flow touch
only the filesystem: moving the bundle between machines is left to the
user. Meanwhile the wire protocol for exactly that transfer is fully
specified and encoded: `PACKAGE_DESCRIPTOR`, `MANIFEST_REQUEST`,
`MANIFEST_PAGE`, `SEAL`, `RANGE_REQUEST`, `PROOF_BUNDLE`, `DATA_RECORD`,
and the session open/accept/reject flow all exist in `vot-codec` and
`spec/session.cddl`, and nothing outside the codec drives them. The
transport underneath is done: the quiche pump is the default engine
(ADR-0027), the range path verifies and places bytes through a sink with
bounded memory (ADR-0029), and the bench driver has carried gigabytes over
it. What is missing is the engine between the codec and the CLI.

## Decision

**Two commands, one composition: `vot serve` and `vot fetch`, and fetch's
output is a bundle directory the existing `vot receive` consumes
unchanged.** Fetch is replication, receive is publication. Nothing about
verification, unpacking, receipts, or destination discipline is
reimplemented for the wire; the wire only moves the bundle.

- `vot serve BUNDLE_DIR LISTEN_ADDR` answers sessions from one bundle:
  descriptor, manifest pages, seal, and proof-bearing ranges of each
  object, proofs built from the chaining-value layer the way the bench
  producer builds them (ADR-0025: the server never holds an object to
  prove a range of it).
- `vot fetch CONNECT_ADDR BUNDLE_DIR [PACKAGE_ROOT]` opens a session,
  fetches the descriptor, manifest pages, and seal, checks the manifest
  chain to the package root, then fetches every object the manifest
  names, each range root-verified on arrival by `ReliableReceiver` and
  placed through a `FileSink` into `BUNDLE_DIR/objects/`. The optional
  `PACKAGE_ROOT` pins what the fetch will accept; without it the fetch
  records what it saw and the pin lives in the receipt step.
- `vot pull` is fetch then receive in one invocation, for the common case.

**The engine is transport-agnostic and lives in `vot-cli`'s library,
written against `TransportAdapter`.** The serve loop and the fetch loop
speak frames to an adapter; the simulator adapter carries them in CI
loopback tests, and the quiche backend carries them for real behind the
same seam. This is the arrangement every landed transport component
already uses, and it is what keeps the engine inside the mutation gate
while the socket-owning backends stay feature-gated.

**Transport certificates are ephemeral and unverified, and that is not
where assurance comes from.** The server generates a throwaway
certificate per process; the client does not verify it. VOT's claim is
content-addressed end to end: every range proves to its object's root,
every object's root is named by the manifest, the manifest pages prove to
the seal's commitments, and the package root is either pinned by the
caller or bound into the signed receipt. A forged server can only serve
bytes that fail those proofs. What the unverified channel does not
provide is privacy against an active middle or peer authentication;
`AUTH_CONTEXT` exists in the codec for a later ADR to implement, and the
help text says plainly that the channel is unauthenticated.

**Quiche rides behind a `wire` feature on `vot-cli`.** Off, the crate
builds in seconds and serve/fetch return the unsupported error naming the
feature; on, the release binary carries the engine. CI runs the engine's
loopback tests always (simulator) and the live tests in the quiche-live
job, the same split every backend already has.

## Consequences

The PR sequence, each step reviewed and gated on its own:

1. This ADR.
2. The serve engine: a `BundleServer` over `TransportAdapter` answering
   descriptor, manifest, seal, and range requests from a bundle
   directory, with the prover layer built once at startup. Simulator
   loopback tests carry a whole bundle.
3. The fetch engine: a `BundleFetcher` over `TransportAdapter` driving
   requests and admitting ranges through `ReliableReceiver` into
   `FileSink`s, manifest chain checked before any object is fetched.
   The loopback test round-trips build_bundle -> serve -> fetch ->
   receive_bundle and diffs the published destination against the
   source.
4. The commands and the quiche wiring behind `wire`, with a live
   loopback test in the quiche-live job, and the wire run on the bench
   rig recorded in the perf log.

Request scheduling starts sequential per object with ranges pipelined,
the shape the bench proved at one rail; multi-rail fetch is a later
step and takes the bench's provisioned-rails arrangement when a
measurement asks for it.

`vot-cli` is a required mutation package and stays one: the engine's
framing, chain checking, and admission logic all land under the gate.
The codec frames gain their first non-test consumers, which is also the
first exercise of `MANIFEST_REQUEST` and `RANGE_REQUEST` outside golden
vectors; anything the engine finds unclear in `spec/session.cddl` gets a
spec clarification in the same PR that hits it.
