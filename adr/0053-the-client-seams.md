# ADR-0053: The client seams: a manifest built in place, a push from a held server, a fetch by options

- Status: Accepted
- Date: 2026-09-04
- Decision owners: A00 architecture; A10 transport
- Applies to: `crates/vot-cli` (`build_manifest`, `build_manifest_from`,
  `push_from`, `fetch_bundle_with`, `probe_serve`, `PushOptions`,
  `FetchOptions`, `Progress`, `proof_cache::{read, write}`) and the
  `platform-native` CI job. No
  change to any spec file, wire identifier, or conformance vector.
  Companion to ADR-0049 (assemble a server from what the host holds),
  whose server this ADR pushes from.

## Context

A desktop client that sends a facility's sequence has three problems with
the library as it stands.

`build_bundle` copies every file larger than a pack candidate into
`objects/<root>` before anything can be served or pushed. A 500 GB
sequence is read twice and written once before the first byte moves.
ADR-0049 lets a server be assembled from files where they sit, but nothing
public builds the manifest that assembly needs without also building the
bundle, and the leaf cache the assembly reads from is written only by
`send`, through a crate-private function.

`push_bundle` takes a bundle directory and opens it itself, so an
assembled server cannot be pushed from. It reports nothing while it runs.

A client that offers a push has to reserve a session on the receiver
before it can dial, and the receiver has to reserve staging and a
capability to answer. A network that will not carry QUIC to that receiver
(a blocked UDP port, a middlebox that drops it) is found only by the dial,
after both ends have reserved. Nothing public dials a serve and reports
whether the handshake completes; the connect and the identity check are
crate-private and wait ten seconds.

`fetch_bundle` reads its capability, holder key, serve identity, rail
count, and prover count from process environment variables, which a
long-lived client with two fetches in flight cannot set twice. The fetch
already has a placed-bytes callback (`BundleFetcher::report_placed`), but
the only way to reach it is the CLI's stderr printer.

The wire feature had never been compiled off Linux in CI, though the
platform crates it rests on are tested there.

## Decision

- `build_manifest(source, manifest_root, suite)` walks `source` with the
  rules `build_bundle` uses, hashes every file where it sits, writes only
  `manifest/` (pages and seal) under `manifest_root`, and returns the
  package summary and a map from stored root to `ServedSource { path,
  leaves }`, the argument `BundleServer::assemble` takes. Every entry is a
  direct object; nothing is packed, because a pack is a written object,
  the copy this build exists to avoid, and the votport receivers this
  serves refuse packed entries anyway. Two files with the same bytes are one stored
  object, served from the first path. The hashing pass is the one
  `copy_and_name` runs, without the write; `ObjectBuilder` holds the
  promised length and refuses a stream that ends elsewhere, which is the
  `SourceMutation` a bundle build reports.
- `build_manifest_from(sources, manifest_root, suite)` builds the same
  manifest from a list of package path and file pairs in any order, which
  is what a drop of loose files and folders is; `build_manifest` walks a
  directory into that list. A source that is not a regular file and two
  sources whose paths fold to one key are `InvalidPath`, as the walk
  reports them.
- `proof_cache::read` and `proof_cache::write` are public, so a caller
  keeps the leaves a manifest build returned under a directory of its
  own and hands them back to a later assembly, as `send` and `serve` do
  beside a bundle's objects.
- `push_from(server, PushOptions)` runs the push `push_bundle` ran, from
  a `BundleServer` the caller opened or assembled, with the receiver
  address, the capability holder, the certificate digest to pin, the rail
  count, the extensions to offer, and an optional progress observer.
  `push_bundle` is now open, refuse an empty bundle, load the holder, read
  the rail count and the extensions from the environment, and `push_from`.
- `fetch_bundle_with(FetchOptions, bundle)` runs the fetch `fetch_bundle`
  ran with every setting handed in: address, optional holder, optional
  serve identity, optional package root pin, rails, optional prover count,
  extensions, and an optional progress observer. The commands read their
  own settings from the environment in their wrappers (`fetch_bundle` the
  rails and the serve identity, `fetch_over` the extensions,
  `fetch_over_offering` the capability, holder key, provers, and stats
  request) and build the same call to one private `fetch_over_configured`.
  The process-wide carrier tuning (`VOT_DATAGRAM_BYTES`, `VOT_CONGESTION`,
  `VOT_INITIAL_CWND`, `VOT_PREFIX_DUP`) stays with the environment for
  every entry point, library or command: it describes the host's network,
  not one transfer.
- `probe_serve(address, identity, budget)` dials `address`, waits at most
  `budget` for the handshake, compares the certificate digest with
  `identity`, and closes. It carries no session, so the serve sees a
  connection come and go, which a push receiver's accept loop already
  takes for a vanished peer. A client asks this before its preflight, so a
  network that will not carry QUIC costs it the budget and no reserved
  state; a receiver whose accept loop is bounded spends one session on the
  probe, so the probe precedes the preflight, not a bounded receive. The
  carrier's idle timeout is the budget, so the probe and the drop that
  follows it are bounded by the budget, not the fetch's idle timeout.
- `Progress` is `Box<dyn FnMut(u64, Option<u64>) + Send>`, called at most
  once per `quantum` bytes and once at the end if the last quantum fell
  short of it; a zero quantum is refused before anything is opened or
  dialled. For a fetch it is the existing placed-bytes report, bytes
  placed and the package length once known, which fires at quantum
  crossings only, so `fetch_bundle_with` wraps the observer and reports
  the package length once after the fetch completes if the last crossing
  fell short; the command's stderr printer is handed to the fetcher
  unwrapped and prints what it printed before. For a push it is the sum over rails of the bytes the carriers
  have taken, framing included, with no total, because a sender does not
  know how much of what it offers the receiver will ask for. The sum is
  read and compared under the one lock the observer is called under, so
  it never goes backwards; a rail pays for that lock only when its own
  count crosses a quantum boundary.
- The `platform-native` CI job builds the wire feature on Windows and macOS
  and runs the live loopback tests of `vot-transport-quiche` on both and
  of `vot-cli` on macOS, in the debug profile, behind a cache keyed by
  runner, image toolchain, and lock file. On Windows the `vot-cli` tests
  are built and not run: receiving a push is Unix-only, and every push
  test asserts on the receiver. The one live test that asserted a 65507-byte loopback
  datagram now asserts that on Linux, whose loopback carries it, and a
  floor past a jumbo frame elsewhere: macOS `lo0` has a 16384-byte MTU and
  discovery settles just under it.

## Consequences

- A client sends without copying: the manifest and a leaf cache are the
  only bytes it writes. Memory and CPU on the sender are the read and the
  hash, as `send` pays them, without the write.
- Push progress is what the carrier took, not what the receiver proved;
  a client that wants the receiver's view has the completion cursor at
  the end and nothing between. Object completions on the sender are a
  later seam if a client needs them.
- The push and fetch behind the CLI commands are the same functions the
  library exposes; the commands are thin wrappers that read the
  environment.
- The wire feature building on Windows and macOS, and carrying a session
  over loopback there, is now a gate, at the cost of one BoringSSL build
  per lock-file or image change per runner, cached from main.

## Required verification

- `a_manifest_built_in_place_serves_the_source_files_uncopied`: four
  files, two sharing their bytes, one small, one empty; three stored
  objects, every entry direct, no `objects/` under the manifest root, the
  manifest scans to the summary, an assembled server serves the package
  over a duplex pair.
- `a_manifest_build_refuses_what_a_bundle_build_refuses`: no source,
  empty source, existing manifest root; no directory left behind.
- `a_manifest_built_from_named_sources_orders_them_and_refuses_a_collision`:
  no source, a directory as a source, and two sources with one path
  refused with no directory left behind; two sources handed last first
  build the manifest a walk of the same tree builds, root for root.
- `a_manifest_build_keeps_leaves_a_serve_can_prepare_from`: the returned
  leaves round-trip through the public cache, a cache for another length
  is not believed, and an assembly from the cache prepares without a read.
- `a_push_from_an_assembled_manifest_reports_what_the_carriers_took`
  (Unix, since it receives): a zero rail count and a zero quantum refused
  before a dial; two rails from an assembled
  server cross a retrying live listener; progress strictly increases, is
  reported at least once, claims no total, and ends at or above the
  object bytes; the receiver's bundle scans to the same package.
- `a_fetch_through_options_reports_what_it_placed`: a rail count past the
  limit and a zero quantum refused before the bundle is opened; two rails
  with a pinned identity and root, twice: a quantum larger than the
  package reports exactly once, the end, as the package length; a quantum
  of one byte reports strictly increasing placements whose last is the
  package length, and the end adds nothing.
- `a_probe_confirms_the_serve_identity_within_its_budget`: a probe of a
  live listener with its identity succeeds and with another identity is a
  mismatch, the accept loop taking both connections and ending; a probe
  of a bound socket that answers nothing is `CarrierUnavailable` within
  its budget.
- `push_progress_reports_once_per_quantum_and_once_at_the_end`: the
  quantum-crossing and report-due arithmetic as tables, and the reporter
  over two rails: a rail's own crossing pays for the lock, sums arrive in
  order, and the end reports the tail once.
- `fetch_rail_count_uses_the_whole_supported_range`: zero and one past
  the limit refused, one and the limit accepted.
- `a_pair_carries_records_at_a_datagram_size_the_path_allows` on Linux,
  macOS, and Windows in the `platform-native` job.
- Mutants recorded in `test-vectors/mutants/adr_0053_client_seams.md`.
