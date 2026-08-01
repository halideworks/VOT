# Verified Object Transport (VOT) v0.3
## Adjusted Architecture Baseline and Agent Implementation Plan

**Status:** implementation baseline candidate
**Snapshot date:** 2026-07-31
**Primary goal:** build an open, independently implementable, low-encumbrance verified-object transfer system for post-production workflows, then evaluate selective coding and verified-completion risk control as separate research layers.

---

## 1. Executive disposition

The final review is accepted. It does not reopen the architecture. VOT remains four separable systems:

1. **Verified Object Layer** — immutable objects, manifests, range proofs, package structure, cache reuse, and multi-source retrieval.
2. **Commit Layer** — explicit assurance states and crash-consistent publication across POSIX and object-store backends.
3. **Transport Group** — reliable QUIC lanes, fallback carriers, receiver admission, rails, and congestion domains.
4. **Verified Completion Risk Control (VCRC)** — experimental scheduling of FEC, ARQ, paths, sources, and receiver resources against completion-tail objectives.

The research claim remains deliberately narrow:

> VCRC is online tail-risk control of durable, verified coflow completion under joint network, source, receiver, and storage uncertainty.

Content addressing, Merkle verification, multi-source retrieval, hedging, QUIC carriage, and FEC are engineering ingredients and prior art, not individually claimed inventions.

The implementation order is fixed:

```text
specification and test vectors
→ object/proof layer
→ commit correctness
→ deterministic simulator
→ reliable single-rail transfer
→ resume and fallback
→ data-plane ceiling work
→ relay/broker and multi-job scheduling
→ experimental FEC
→ VCRC
→ multipath and congestion-control research
```

No agent may implement later-layer behavior by changing an earlier frozen invariant without an accepted architecture decision record (ADR).

---

## 2. Normative v0.3 decisions

### 2.1 Strict at-rest verification

The Strict assurance profile must verify bytes through a path independent of the write-side page cache.

Accepted Strict mechanisms are:

- A durability barrier followed by an aligned direct/unbuffered read through a separately opened descriptor or handle.
- An independently generated backend checksum whose semantics meet the commit provider's declared guarantee.
- A provider-specific integrity mechanism approved by a conformance profile.

On Linux, the POSIX provider uses `fsync`/`fdatasync`, closes or separates the buffered writer, reopens with `O_DIRECT`, obeys filesystem alignment requirements, and hashes the returned bytes. A buffered read is not Strict verification. `POSIX_FADV_DONTNEED` is only advisory and is not a conforming substitute.

If the destination cannot provide an independent read or trustworthy backend checksum, the receiver must report Strict as unsupported. It must not silently downgrade.

The Strict POSIX publication sequence is:

1. Create a unique temporary object and journal incarnation.
2. Reserve staging capacity.
3. Write ranges and perform transit verification.
4. Flush the data file; any write or flush error poisons the incarnation.
5. Flush the durable journal record.
6. Perform independent read-back or delegated backend verification.
7. Flush the at-rest verification record.
8. Atomically link or rename into place without overwriting an unrelated object.
9. Flush the parent directory.
10. Emit a `PUBLISHED` receipt identifying the assurance provider and level.

A retry after a failed flush does not rehabilitate the incarnation. Recovery must revalidate or reconstruct affected ranges.

### 2.2 Receiver assurance ladder

The protocol exposes five non-equivalent states:

1. `ADMITTED`
2. `TRANSIT_VERIFIED`
3. `DURABLE`
4. `AT_REST_VERIFIED`
5. `PUBLISHED`

A receipt must include:

- Object/package identity.
- Assurance level.
- Commit-provider identifier and version.
- Session and incarnation identifiers.
- Monotonic receipt sequence.
- Wall-clock observation with declared clock source.
- Verification suite.
- Any downgrade, delegation, or unsupported feature flags.

The invariant is:

> VOT never emits a receipt claiming a stronger assurance level than the receiver actually performed.

### 2.3 VCRC decision objective and estimator

VCRC uses **CVaR95** for online action ranking in v0.3. It does not claim to estimate decision-time CVaR99 from a few hundred scenarios.

The default scenario procedure is:

- Paired, block-resampled scenarios using common random numbers across candidate actions.
- Initial ensemble: 256 scenarios.
- Candidate pruning on a cheaper first pass.
- Adaptive expansion to 1,024 or more scenarios when the top actions' paired uncertainty intervals overlap.
- Explicit ablation of block length and trace-window length.
- p99 and CVaR99 retained as end-to-end experimental reporting metrics, not online optimization claims.

A parametric or extreme-value tail model may be added later behind an experiment flag. It is not required for v0.3.

### 2.4 Risk certificate and budget exhaustion

A **protection decision** is a decision epoch that allocates a risk charge to a defined set of currently critical units and a defined first transmission wave.

For decision `t`, define `F_t` as:

> At least one protected unit in that decision fails to reach `TRANSIT_VERIFIED` by the end of its scheduled first wave and therefore requires an additional network action.

The spend-down ledger is:

```text
0 ≤ delta_t ≤ B_t
B_(t+1) = B_t - delta_t
B_0 = delta_job
```

The certificate concerns first-wave failure risk on protected critical-frontier work. It is **not** a certificate of end-to-end deadline attainment. Deadline, first-usable-subset, and full-publication outcomes are reported empirically.

When `B_t` reaches zero:

- No new speculative parity is authorized.
- No new hedged duplicate request is authorized.
- Reliable repair and ordinary retransmission continue.
- Existing in-flight work may complete.
- The controller emits `vcrc.budget_exhausted` with the job, epoch, and remaining frontier state.
- Automatic budget reset is forbidden. An operator or higher-level policy may start a new explicitly logged budget epoch.

The VCRC ledger receives its own state-machine model and deterministic tests; it is not treated as informal scheduler bookkeeping.

### 2.5 Congestion-control research branch

No custom congestion controller gates the first production-capable release.

VOT profiles remain:

- **Shared Internet:** one congestion fairness domain per presumed bottleneck; CUBIC baseline; no lossy-LFN throughput claim.
- **Bulk Internet experimental:** model-based controller plugins, including BBRv3 as a comparator only after legal and coexistence review.
- **Provisioned path:** operator-declared capacity, explicit administrative cap, receiver backpressure, ECN/queue/delivery-rate safety backoff, and multiple rails only by policy.

The clean-room research law is dimensionally normalized before any implementation:

```text
u_t = a(1 - r_t / b_hat_t)
      - b * max(q_t - q_star, 0) / max(d_min_t, epsilon)
      - c * e_t
      - d * p_cong_t

r_(t+1) = clip(r_t * exp(eta * u_t))
```

Updates occur once per feedback epoch measured in smoothed RTTs, not at a fixed wall-clock interval. Required safeguards include:

- Application-limited detection before updating `b_hat_t`.
- Windowed minimum RTT and reset on route/path change.
- Persistent-congestion and missing-feedback fallback.
- Explicit coexistence behavior against loss-based competitors, or an honest provisioned-path-only scope.
- Evaluation against RFC 9743 criteria.

This branch must include prior-art positioning against Copa, PCC/Vivace, Veno/Westwood, BBR, and related rate/delay controllers. It remains simulator-only until the reliable transport and benchmark harness are stable.

### 2.6 Proof suites and proof transport

VOT v1 freezes exactly two verification suites.

#### Suite 0x0001 — `blake3-bao64`

- Object identity: `(suite_id, BLAKE3 root, byte length)`.
- Verification group: 64 KiB, represented as a Bao/BLAKE3 chunk group.
- Proof encoding: a frozen VOT profile of Bao range encoding, with published byte-for-byte vectors.
- Relay sidecar: canonical pre-order outboard representation for serving range proofs.

#### Suite 0x0002 — `sha256-bep52-64k`

- Object identity: `(suite_id, BEP 52-compatible SHA-256 file root, byte length)`.
- Base leaves: 16 KiB, exactly as in BEP 52.
- Verification piece: 64 KiB.
- Tree construction, padding, piece roots, request geometry, and proof ordering follow BEP 52 rather than inventing a new SHA-256 tree.
- VOT adds only its envelope and object identity rules.

#### Mandatory proof transport

VOT v1 uses **in-band range proof bundles**. A sender or relay serves the requested data range together with the suite-specific proof needed to authenticate it to the object root. Contiguous ranges use multiproofs or streaming encodings to amortize proof nodes.

A full outboard or piece-layer object is not a mandatory network prefetch in v1. Relays may maintain canonical sidecars locally, and a later extension may advertise a cacheable verification-index object.

This decision avoids:

- A large proof-index bootstrap before useful data can flow.
- Recursively defining how a proof-index object proves itself.
- A new bespoke SHA-256 proof system.

Progressive ingest uses authenticated manifest pages carrying verification-group commitments. The final `SEAL` commits those pages to the canonical suite root.

#### Dual-suite equivalence

A dual-hash equivalence record is accepted only after one trusted verifier reads the complete byte string and computes both identities. When policy permits, a relay must index both identities to the same stored extent rather than duplicate bytes. Equivalence records are signed, scoped to exact length, and revocable only by deleting the mapping—not by changing object identity.

### 2.7 Wire-version and extension mechanism

Prototype ALPN: `vot-draft-03`.

The production ALPN will be registered before a stable v1 release. The prototype must not claim that `vot/1` is already registered.

VOT v1 adds no mandatory custom QUIC transport parameters. Application negotiation occurs on the first client-initiated bidirectional control stream.

Control frames use:

```text
QUIC-varint frame_type
QUIC-varint frame_length
frame_length bytes of payload
```

Rules:

- Unknown critical frames close the VOT session with a registered error.
- Unknown optional frames are skipped using their length.
- Reserved grease frame types are injected in tests and occasionally in live handshakes.
- Major incompatible changes use a new ALPN.
- Minor compatible features use `SETTINGS`, extension identifiers, and optional frames.
- All integer fields use QUIC varints unless a suite explicitly fixes a byte array.

Registries must be frozen for:

- Frame types.
- Settings.
- Extension identifiers.
- Hash/proof suites.
- Compression suites.
- Commit providers and assurance levels.
- Error codes.
- Telemetry event names.

Initial error-code classes:

- Protocol/version.
- Authentication/authorization.
- Manifest/object/proof integrity.
- Storage/commit.
- Resource/admission.
- Fallback/path.
- Experimental/research.

### 2.8 Connection behavior, CIDs, and flow-control cadence

Default connection settings:

- Idle timeout: 90 seconds.
- Active-transfer keepalive: 20 seconds when no other traffic is flowing.
- Keepalive disabled when no active reservation or resumable transfer lease exists.
- Deployment-configurable keepalive range: 10–30 seconds.

Server connection IDs are opaque to VOT application logic. The transport adapter must support a deployment-supplied CID generator/router. The default relay profile reserves a nonzero 16-byte server CID, enabling future routable-CID schemes. QUIC-LB compatibility is optional and cannot be a normative dependency while its specification remains unfinished.

Reliable mode uses QUIC flow control as the hard receiver-admission mechanism:

- Target connection window is derived from BDP estimate, assigned staging capacity, and configured maximum.
- The receiver extends credit when remaining credit falls below one quarter of the current target window.
- It restores credit toward the target in increments no smaller than one eighth of that window.
- It never grants credit exceeding the bytes it is prepared to stage.
- Capacity telemetry is advisory; it does not form a second hard credit loop.

Datagram mode uses a monotonic `credit_epoch`, not wall-clock expiry. Each new epoch supersedes the previous epoch. Credits specify absolute maxima for unretired bytes, active generations, and decode work. A new connection or session begins with zero datagram credit.

### 2.9 Rails and congestion domains

A rail is an execution unit. A congestion domain is the fairness and pacing unit.

For shared/public paths in v1:

- One rail per presumed bottleneck is the default and only production-supported configuration.
- Multi-worker execution inside one rail may be used if the QUIC implementation permits it.
- Multiple uncoupled rails over one shared bottleneck are not production-supported.

For provisioned paths:

- Multiple rails are allowed by explicit operator policy.
- The aggregate administrative and receiver caps apply across all rails.
- Telemetry discloses rail count and aggregate behavior.

Public-path multi-rail remains experimental until both exist:

1. A validated coupled congestion-control scheme, such as an adapted LIA/OLIA-class design.
2. Shared-bottleneck detection, with RFC 8382-class behavior or a justified successor.

Coupling unrelated bottlenecks is a performance failure; failing to couple a shared bottleneck is a fairness failure. This is the dependency that keeps public multi-rail out of v1.

### 2.10 Restored requirements

The following round-1 requirements are reinstated.

#### Commit overhead gate

Balanced assurance must add no more than 5% to clean-path completion time against the same verified transfer with durability journaling disabled. The stretch objective is 3%. Strict is measured separately.

#### Resume and mobility program

A named experiment covers process kill, VM reset, NAT rebinding, address change, Wi-Fi/Ethernet transition, path loss, Careful Resume, and mid-transfer QUIC-to-TCP fallback without loss of object state.

#### Pack objects

- Candidate logical files: at most 256 KiB by default.
- Target pack size: 64 MiB; hard maximum: 128 MiB.
- Deterministic order: canonical package path.
- Raw file contents with deterministic zero padding to 8-byte alignment.
- A logical file never straddles packs.
- Manifest mapping: logical path → pack object identity, offset, length, logical-file hash, and metadata.
- Pack objects use the same 64 KiB integrity groups as every other object.
- Pack sealing occurs before a pack is advertised as immutable.

#### Compression profile

- Optional zstd compression per transport record.
- No cross-record dictionary in v1.
- Object identity and integrity are computed over plaintext.
- Compression is enabled only when sampling predicts a minimum configured gain; default threshold 5%.
- Encoded and decoded lengths are explicit and bounded.
- Maximum expansion ratio is enforced.
- Media types known to be incompressible are skipped by default.

#### Legal benchmark gate

Counsel must review the applicable commercial transfer-product license before named benchmark publication. Until cleared, reports use neutral baseline labels.

#### Media security mapping

A security workstream maps VOT controls and operational responsibilities to current TPN/MPA expectations. This is a deployment-readiness artifact, not a claim of certification.

#### Garbage collection and retention

Staging incarnations, orphaned progressive sessions, pack build areas, and relay-cache entries all require explicit lease, retention, tombstone, and grace-period rules. Active leases prevent collection. Deletion is auditable and idempotent.

#### Telemetry redaction

Three levels are defined:

- `minimal`: aggregate counters only.
- `pseudonymous` (default): deployment-keyed identifiers; no raw paths.
- `diagnostic`: explicit local opt-in; still excludes credentials, capability tokens, payload bytes, and unredacted secrets.

Raw filenames and manifest metadata are not written to ordinary qlog-compatible traces.

---

## 3. Frozen system invariants and initial constants

These values are defaults, not promises that every workload is optimal at them. Changing a wire-visible value requires an ADR and new test vectors.

| Item | v0.3 value |
|---|---:|
| Integrity group | 64 KiB |
| Scheduling/cache chunk | 4 MiB |
| Reliable data-record maximum | 256 KiB |
| Small-file pack threshold | 256 KiB |
| Pack target / maximum | 64 MiB / 128 MiB |
| Manifest page maximum | 1 MiB canonical bytes |
| Session/incarnation identifier | 128 random bits |
| Default reliable lane count | 16, locally tunable |
| Prototype ALPN | `vot-draft-03` |
| Default idle timeout | 90 s |
| Active keepalive | 20 s |
| Online VCRC objective | CVaR95 |
| Initial VCRC scenarios | 256, adaptive expansion |
| Datagram FEC field | GF(2^8) |
| Initial FEC geometry | 64 source symbols; repair cap 16 |

Global invariants:

- No unverified byte contributes to a verified object state.
- No transport ACK is interpreted as durability or application admission.
- No receiver receipt overstates assurance.
- No stale journal incarnation is accepted as current.
- No source mutation can produce a sealed package under the old identity.
- No speculative parity, hedge, or extra rail escapes the job and congestion-domain caps.
- No unknown critical extension is silently ignored.
- No parser allocates based on untrusted lengths without an enforced bound.
- No commercial proprietary implementation is used as source material.

---

## 4. Recommended implementation stack

### 4.1 Language and repository

Use a Rust 2024 workspace for protocol, object, commit, scheduler, simulator, CLI, and service code. Isolate transport FFI and platform-specific storage code behind narrow traits.

Reasons are practical rather than ideological: memory-safe parser code, good cross-platform support, mature BLAKE3 and CBOR ecosystems, strong property/fuzz tooling, and acceptable systems-level control.

### 4.2 QUIC backends

Define a transport-neutral `TransportAdapter` first.

Initial backends:

1. **Deterministic simulation adapter** — mandatory for every state-machine test.
2. **MsQuic adapter** — first cross-platform production candidate; selected for its C API, platform coverage, DATAGRAM support, and transport send-state feedback.
3. **quiche/Linux research adapter** — added after reliable MVP for explicit UDP I/O, pacing, GSO/GRO, custom event integration, and congestion-control experiments.
4. **TLS/TCP fallback adapter** — maps the same VOT object and control records onto a reliable byte stream.

The first transport-ceiling bakeoff may replace the production candidate, but no VOT core API may depend on MsQuic-specific types.

### 4.3 Core traits

```rust
trait VerificationSuite { /* root, range proof, streaming verifier */ }
trait CommitProvider { /* reserve, write, durable, verify_at_rest, publish, abort */ }
trait TransportAdapter { /* control, reliable lanes, datagrams, path events */ }
trait CongestionDomain { /* aggregate cap, pacing budget, rail membership */ }
trait ObjectStore { /* immutable extents, aliases, cache lease, GC */ }
trait Clock { /* monotonic first; wall clock only for audit */ }
trait EventSink { /* redacted protocol and application events */ }
```

All externally parsed structures have a borrowed decode path and an owned validated form. Validation occurs before state mutation.

### 4.4 Suggested workspace layout

```text
/spec
  architecture.md
  object.md
  manifest.cddl
  proofs.md
  commit.md
  wire.md
  security.md
  telemetry.md
  registries.md
/adr
/models/tla
/crates
  vot-types
  vot-codec
  vot-manifest
  vot-proof-blake3
  vot-proof-sha256
  vot-pack
  vot-object-store
  vot-journal
  vot-platform-fs
  vot-commit-posix
  vot-commit-platform
  vot-commit-object
  vot-transport-api
  vot-transport-sim
  vot-transport-msquic
  vot-transport-tcp
  vot-transport-quiche
  vot-scheduler
  vot-fec
  vot-vcrc
  vot-security
  vot-telemetry
  vot-cli
  vot-relay
  vot-broker
/sim
/fuzz
/test-vectors
/bench
/tools
```

---

## 5. Development governance for agents

### 5.1 Repository rules

- AGPL-3.0-only for the implementation and project files. Apache-2.0 for
  `spec/`, `test-vectors/`, and `models/` so independent implementations can
  consume the protocol artifacts without implementation copyleft.
- Explicit Apache-2.0 section 3 style patent grant across both license scopes.
- A signed contributor license agreement for non-trivial outside contributions;
  DCO sign-off remains required for provenance but does not grant relicensing
  rights.
- `NOTICE`, `SECURITY.md`, `PATENTS.md`, `PRIOR_ART.md`, and contributor provenance policy from the first commit.
- Signed-off commits or equivalent provenance attestation.
- No copied proprietary code, decompiled logic, or undocumented protocol cloning.
- Black-box commercial benchmarking only after legal approval.
- Reproducible dependency lockfile and software bill of materials.
- Unsafe Rust allowed only in isolated platform/FFI modules with explicit safety notes and dedicated tests.

### 5.2 Agent contract

Every agent receives:

- One bounded ownership area.
- Required ADRs and specifications.
- Input/output APIs.
- Acceptance tests.
- Explicit non-goals.

Every implementation pull request must contain:

- Tests demonstrating the new behavior.
- Updated conformance vectors for wire-visible changes.
- Failure-path tests, not only happy paths.
- Telemetry events for externally diagnosable state changes.
- No silent fallback or assurance downgrade.
- A note on memory, CPU, storage, and wire amplification.
- For every claimed acceptance criterion, a passing test, a minimal deliberate
  mutant, and captured output proving the test rejects that mutant under
  `test-vectors/mutants/`.

Agents may not:

- Assign numeric wire identifiers outside `registries.md`.
- Change object identity rules locally.
- add a hash, compression, congestion, or FEC algorithm without an ADR and provenance review.
- Treat transport ACKs as application completion.
- Introduce wall-clock dependence into correctness state machines.
- Merge an experimental feature into the default profile before its gate passes.

### 5.3 Integration discipline

- Trunk remains buildable and testable.
- Features land disabled behind capability negotiation until conformance tests exist.
- One agent owns each shared schema or public trait at a time.
- Cross-cutting changes are split into a schema/trait PR followed by implementation PRs.
- Deterministic simulator coverage precedes live-network coverage for new protocol states.

---

## 6. Implementation waves

### Wave 0 — Specification, registries, and governance

**Purpose:** eliminate wire and correctness ambiguity before broad coding.

Work:

- Incorporate all v0.3 decisions into normative specifications.
- Freeze identifiers and extension rules.
- Write ADRs for proof transport, Strict verification, assurance receipts, rail policy, VCRC certificate semantics, and telemetry redaction.
- Publish CDDL schemas and initial error registry.
- Create prior-art and patent-provenance logs.
- Write the threat model.
- Establish CI, dependency policy, fuzz runners, and reproducible builds.

Deliverables:

- `spec/` baseline.
- ADR set `0001` through `0010`.
- Empty but compiling workspace.
- Registry allocation tests.
- Security-abuse-case matrix.

Gate W0:

- No unresolved R1–R8 item.
- Proof suite byte formats are specified sufficiently to generate independent vectors.
- Commit assurance semantics have no undefined transition.
- Unknown-frame behavior and version negotiation are testable.

### Wave 1 — Object, proof, manifest, and pack layer

**Purpose:** produce independently verifiable immutable package data without networking.

Work:

- Implement canonical object identifiers.
- Implement `blake3-bao64` range encoder/decoder and sidecar generation.
- Implement `sha256-bep52-64k` tree, piece layer, and proof bundles by reference to BEP 52.
- Implement deterministic CBOR manifest pages and CDDL validation.
- Implement portable and raw-POSIX path profiles.
- Implement sealed and progressive page-chain ingest.
- Implement package `SEAL` validation.
- Implement deterministic small-file packs.
- Implement dual-suite equivalence records and alias indexing.
- Implement HAVE-map RLE encoding.

Required tests:

- Golden vectors for empty, 1-byte, boundary, odd-tree, sparse, and multi-terabyte logical lengths.
- Proof rejection for wrong length, wrong root, reordered siblings, missing nodes, and corrupted data.
- Cross-suite identity separation.
- Progressive truncation, reorder, replay, and source-mutation tests.
- Cross-platform path collision corpus.
- Pack extraction and logical-file hash validation.

Gate W1:

- Two independent implementations or one implementation plus a minimal independent verifier agree on every published vector.
- Arbitrary requested 64 KiB groups can be verified without reading unrelated object bytes.
- No package becomes sealed after a detected source mutation.
- One-million-file manifest construction and indexed lookup remain bounded in memory.

### Wave 2 — Commit state machine and storage providers

**Purpose:** establish the strongest product invariant before transport optimization.

Work:

- Model the assurance ladder, journal incarnation, poisoning, recovery, and publication in TLA+.
- Implement append-only journal with checksummed records and compacted checkpoints.
- Implement POSIX Fast, Balanced, and Strict providers.
- Implement independent Linux direct-read verification.
- Implement directory durability and no-overwrite publication.
- Implement an object-store multipart provider against a mock, then one real S3-compatible backend.
- Implement leases, tombstones, orphan recovery, and garbage collection.
- Implement signed/authenticated receipts.

Fault tests:

- Crash after every modeled transition.
- Torn journal record and stale valid journal.
- Short write, writeback failure, failed flush, failed rename, failed directory flush.
- Device-level corruption after write and before Strict read-back.
- Object-store part mismatch and failed completion.
- Restore of an old VM snapshot with a stale incarnation.

Gate W2:

- TLA+ finds no trace that reaches `PUBLISHED` without required predecessor states.
- Zero false publication across deterministic and injected fault campaigns.
- Strict detects the device-level corruption test; a deliberately buffered control implementation must fail that test.
- Balanced overhead is no more than 5% on the declared clean-path storage benchmark.
- Recovery retransmits or rehashes only the checkpoint window and active unsealed units.

### Wave 3 — Deterministic simulator and protocol codec

**Purpose:** make the full distributed state machine testable without nondeterministic networks.

Work:

- Implement a seeded virtual clock.
- Simulate reliable streams, datagrams, reordering, loss bursts, MTU changes, NAT rebinding, path removal, and transport switch.
- Simulate receiver memory, hash, decode, disk, journal, and commit queues.
- Implement frame codec, settings negotiation, extension handling, greasing, and error mapping.
- Add parser fuzz targets and resource bounds.
- Add trace shrinking or minimized replay output.

Gate W3:

- Every core protocol transition is reproducible from a seed.
- Unknown optional frames survive; unknown critical frames fail predictably.
- Grease frames are tolerated.
- Fuzzing finds no unbounded allocation or panic on malformed input.
- Simulator can replay all later benchmark scenarios from versioned trace files.
- The negative-control transport is caught when it drops a reliable frame,
  reorders manifest pages, replays an old incarnation, or publishes before its
  assurance predecessors.
- Codec acceptance and parsed structure agree with the independent Python
  decoder over the differential fuzz corpus.

### Wave 4 — Reliable single-rail transfer MVP

**Purpose:** deliver a correct, resumable, root-verified package over QUIC before FEC.

Work:

- Implement session handshake and capability negotiation.
- Implement manifest bootstrap and proof-bearing range requests.
- Implement control stream and reliable lane pool.
- Implement data records capped at 256 KiB.
- Map staging capacity to QUIC flow-control credit.
- Implement advisory capacity telemetry and drop attribution.
- Implement HAVE exchange, request planning, and verified chunk completion.
- Implement CLI sender and receiver.
- Implement authentication hooks and an initial signed capability format.
- Emit qlog-compatible and VOT application events with default redaction.

Required scenarios:

- Single large object.
- Frame sequence.
- One million small files through packs.
- Mixed package.
- High-cache-hit receive.
- Concurrent jobs with basic priority.

Gate W4:

- End-to-end `PUBLISHED` receipt matches independently recomputed package root.
- Transport disconnection never causes verified object state to regress.
- Receiver staging remains within advertised bounds.
- No QUIC ACK is surfaced as object durability.
- Reliable mode reaches the declared clean-path target without FEC or multiple public-path rails.

### Wave 5 — Resume, mobility, and fallback

**Purpose:** validate the headline bounded-waste recovery claim.

Work:

- Implement persistent session discovery by package/object identity, not old connection identity.
- Implement connection migration and rebinding handling.
- Implement RFC 9959 Careful Resume where the transport backend exposes sufficient state.
- Implement TLS/TCP fallback with identical VOT records.
- Implement happy-eyeballs-style QUIC/TCP startup and degraded-UDP detection.
- Preserve verified/durable state across carrier changes.
- Add platform-native commit providers for Windows and macOS to the supported assurance level.

Named experiment E-RESUME:

- Random process kills at 1–99% completion.
- VM reset and stale snapshot.
- NAT rebinding.
- Address and interface change.
- UDP blackhole or policing introduced mid-transfer.
- QUIC-to-TCP switch.
- Relay/source loss and alternate-source recovery.

Gate W5:

- Resent bytes are bounded by the checkpoint window plus active unverified units.
- Carrier switch does not redownload verified chunks.
- No stale path state is reused outside Careful Resume's safety conditions.
- All platform receipts state their actual assurance capabilities.

### Wave 6 — Data-plane ceiling and transport-engine bakeoff

**Purpose:** find the real CPU, packet, and storage ceilings before adding coding complexity.

Work:

- Benchmark MsQuic and quiche adapters against the same VOT workload.
- Measure one rail/one worker, one rail/multiple workers, provisioned multi-rail, and shared-domain aggregation.
- Implement Linux `UDP_SEGMENT`, `UDP_GRO`, batching, RSS-aware placement, and kernel/NIC pacing where available.
- Implement Windows offload path where available and a macOS no-offload tier.
- Separate control and fixed-size bulk packet trains.
- Instrument cycles/byte and queueing for read, hash, proof, encrypt, packet, receive, verify, write, and journal stages.
- Add BDP-derived windows and behavior when memory cannot satisfy them.

Predeclared hypothesis:

> A single connection with multiple payload workers will improve throughput but retain a serialized packet-number/loss-detection/ACK spine, and will top out below independent provisioned rails on sufficiently fast hardware.

This is a hypothesis, not a result.

Gate W6:

- Select the default production QUIC backend from measured results.
- Reliable RAM-to-RAM transfer reaches at least 95% of attainable link rate on the primary 10 Gbit/s Linux target.
- Clean-path performance regression from proof and object machinery is quantified and within the release budget.
- CPU-per-verified-GiB and memory high-water marks are published.
- Shared-path tests use one rail; multi-rail results are labeled provisioned/experimental.

### Wave 7 — Relay, broker, cache, and cross-job scheduling

**Purpose:** turn the transfer engine into a usable Faspex-class package service.

Work:

- Implement broker package records, recipients, expiration, and audit state.
- Implement capability issuance bound to package/object root, audience, direction, and expiry.
- Implement relay immutable object cache and dual-suite alias index.
- Implement authorized multi-source chunk scheduling.
- Implement source scoring, timeout, quarantine, and cancellation.
- Implement job priority classes, administrative caps, preemption at record/generation boundaries, and first-usable-subset SLOs.
- Implement pack materialization and metadata preflight reports.
- Implement cache and progressive-session GC.

Gate W7:

- A malicious or slow source cannot prevent completion when an honest authorized source exists.
- Cross-job resource use remains within network, staging, hash, decode, and storage quotas.
- First-usable-subset and full-publication receipts are distinct.
- Cache deletion cannot remove data held by an active lease.
- Default telemetry contains no raw filename or capability token.

### Wave 8 — Experimental datagram/FEC profile

**Purpose:** reduce repair-round tail without changing congestion-accounting rules.

Work:

- Implement epoch-fixed systematic Reed–Solomon over GF(2^8).
- Initial geometry: 64 source symbols and at most 16 repair symbols.
- Implement absolute epoch-scoped datagram credits.
- Implement transport ACK/loss hints and authoritative `GEN_STATE`/`GEN_DONE` application feedback.
- Implement reliable repair fallback.
- Handle PMTU change by closing the datagram epoch and finishing through a compatible path; never mutate geometry mid-epoch.
- Enforce priority: source data, critical reliable repair, critical repair symbols, then speculative repair.
- Count every source, repair, and duplicate byte against congestion and administrative caps.

Gate W8:

- Coded mode is within a few percent of reliable mode on clean paths when the selector keeps it disabled.
- Enabled coding improves p95 or p99 verified completion by at least 20% in a preregistered target region.
- Speculative wire overhead is bounded by the configured budget; initial release target is at most 5% in enabled regions.
- Receiver overload reduces credit; it never triggers an uncontrolled parity loop.
- Congestion control still observes recovered packet loss.

### Wave 9 — VCRC research controller

**Purpose:** test the specific research hypothesis after all actuators and measurements are trustworthy.

Work:

- Implement trace ingestion and block-resampled scenarios.
- Implement CVaR95 paired candidate ranking with adaptive ensemble expansion.
- Implement the spend-down ledger and conservative exhausted state.
- Model network, source, receiver, hash, decode, storage, and journal uncertainty.
- Implement common actuator interface: source, repair, parity, path, hedge, preempt, or wait.
- Implement shadow prices for wire, CPU, I/O, fairness, and staging.
- Implement hindsight oracle at generation granularity.
- Add deterministic model and state-machine tests for budget accounting.

Required comparisons:

- Reliable only.
- Fixed FEC.
- Mean-loss adaptive FEC.
- Quantile-only FEC.
- VCRC without sink state.
- VCRC with sink state.
- VCRC with all actuators.
- Hindsight oracle.

Gate W9:

- Decision-time CVaR level and estimator uncertainty are reported honestly.
- Observed first-wave miss rates are compared with allocated risk under stationary and shifted traces.
- VCRC demonstrates material tail improvement over strong adaptive baselines, not only no-FEC.
- Oracle regret is published for wire, completion, and compute cost.
- No end-to-end deadline certificate is claimed from the frontier-risk ledger.
- VCRC remains experimental if any target-region gate fails.

### Wave 10 — Multipath and congestion-control research

**Purpose:** explore high-rate and lossy-path behavior without contaminating the core release.

Work:

- Integrate standardized Multipath QUIC when a stable implementation is available.
- Preserve VOT's object scheduler above transport path scheduling.
- Implement provisioned multi-rail aggregation.
- Evaluate BBRv3 as a comparator/plugin after legal review.
- Implement the normalized clean-room controller in simulation only, then guarded live tests.
- Investigate coupled congestion control and shared-bottleneck detection for public multi-rail.
- Evaluate route-change and application-limited failure modes.

Gate W10:

- No public multi-rail default without fairness evidence and shared-bottleneck handling.
- No custom controller ships without RFC 9743-style safety, fairness, AQM, mixed-controller, and persistent-congestion evaluation.
- No lossy-LFN marketing claim precedes measured results for the chosen congestion profile.

### Wave 11 — Security, compliance, interoperability, and public release

**Purpose:** make the implementation deployable and independently implementable.

Work:

- Complete amplification, replay, token theft, staging exhaustion, malicious-source, metadata-privacy, and multi-tenant tests.
- Complete TPN/MPA control mapping.
- Complete legal review of named commercial benchmarks.
- Publish protocol drafts, registries, CDDL, proof vectors, journal vectors, wire captures, simulator traces, and interoperability harness.
- Run third-party security review.
- Run cross-platform interoperability event.
- Produce migration and compatibility policy.

Release gate:

- Independent implementation can read manifests, verify both suites, and complete a reliable transfer from published materials.
- No open critical security or false-publication defect.
- All default features have bounded resource behavior.
- Experimental features are distinctly negotiated, disabled by default, and labeled in receipts and telemetry.

---

## 7. Agent work packages

### A00 — Program/specification lead

Owns: architecture baseline, ADR process, registries, integration sequencing.
Must not own production implementation modules.
Done when: W0 passes and every cross-agent API has one canonical specification.

### A01 — Wire protocol and codec

Owns: frame envelope, settings, versioning, greasing, errors, control state machine, codec fuzzing.
Depends on: A00.
Done when: optional/critical extension tests, malformed-length tests, and golden frame vectors pass.

### A02 — BLAKE3/Bao verification

Owns: `blake3-bao64`, canonical sidecar, range proofs, streaming verification vectors.
Depends on: proof ADR.
Done when: independent verifier agrees and all corruption/proof-order tests pass.

### A03 — SHA-256/BEP 52 verification

Owns: `sha256-bep52-64k`, exact tree rules, piece roots, proof envelopes, vectors.
Depends on: proof ADR.
Done when: BEP 52-derived vectors and VOT range-proof vectors pass without a bespoke alternate tree.

### A04 — Manifest, path profiles, progressive ingest, and packs

Owns: deterministic CBOR/CDDL, pagination/indexing, page chain, `SEAL`, path preflight, pack construction.
Depends on: A02/A03 object identity APIs.
Done when: million-file, path-collision, progressive-truncation, and pack extraction tests pass.

### A05 — Commit model and formal verification

Owns: TLA+ model for assurance ladder, journal, incarnation, poisoning, publication, and VCRC ledger extension.
Depends on: A00.
Done when: model checks all bounded crash interleavings and emits executable transition fixtures.

### A06 — POSIX commit provider

Owns: journal, Fast/Balanced/Strict Linux path, direct read-back, atomic publish, recovery, fault injection.
Depends on: A05 and object API.
Done when: W2 POSIX gates pass.

### A07 — Object-store commit provider and GC

Owns: multipart abstraction, checksums, completion, leases, tombstones, orphan cleanup, one S3-compatible adapter.
Depends on: A05 and object API.
Done when: mock and live integration tests pass with identical assurance receipts.

### A08 — Deterministic simulator and fault harness

Owns: virtual clock, network/path/storage models, seed replay, trace shrinker, fault API.
Depends on: A00/A01 interfaces.
Done when: W3 passes and every later agent can add scenarios without real sleeps.

### A09 — Transport abstraction and reliable scheduler

Owns: transport-neutral APIs, control/lane orchestration, request planning, flow-control mapping, capacity telemetry.
Depends on: A01/A04/A08.
Done when: reliable transfer passes entirely over the simulator.

### A10 — MsQuic backend

Owns: FFI safety wrapper, stream/datagram events, connection lifecycle, migration, qlog bridge.
Depends on: A09.
Done when: live QUIC reliable MVP matches simulator semantics and leak/race tests pass.

### A11 — TCP fallback and mobility

Owns: TLS/TCP carrier, carrier race, degraded-UDP detector, resume discovery, connection migration, Careful Resume integration.
Depends on: A09/A10/A06.
Done when: E-RESUME passes without verified-state loss.

### A12 — Fast-path and platform performance

Owns: GSO/GRO, batching, pacing, RSS/NUMA, Windows/macOS tiers, cycles-per-byte instrumentation, backend bakeoff.
Depends on: reliable MVP.
Done when: W6 report and backend selection are complete.

### A13 — Broker, relay, cache, and cross-job scheduling

Owns: capabilities, package workflow, relay cache, source scoring, quotas, priorities, first-usable-subset scheduling.
Depends on: W4/W5 and A07.
Done when: W7 passes.

### A14 — Datagram/FEC profile

Owns: RS coding, epochs, credits, dual feedback, reliable repair, PMTU behavior.
Depends on: A09/A10/A08 and W6 measurements.
Done when: W8 passes; otherwise remains an off-by-default experiment.

### A15 — VCRC research

Owns: scenario engine, CVaR95 ranking, spend ledger, shadow prices, oracle, calibration reports.
Depends on: A08/A13/A14.
Done when: W9 report is reproducible from public traces and seeds.

### A16 — Security, identity, and telemetry

Owns: threat model, capability format, token/channel binding, quotas, redaction, audit receipts, fuzz/security tests, TPN/MPA mapping support.
Depends on: A00/A01.
Done when: no default trace leaks paths/tokens and abuse cases have enforced limits.

### A17 — Benchmark and interoperability harness

Owns: impairment lab, workload corpus, baseline adapters, statistical protocol, legal-label switch, public result bundles.
Depends on: A08 and each feature wave.
Done when: every gate has a reproducible command, configuration, seed set, and machine-readable result.

---

## 8. Dependency graph

```text
A00 ─┬─ A01 ─┬─ A08 ─┬─ A09 ─┬─ A10 ─┬─ A11
     │       │       │       │       └─ A12
     │       │       │       └──────── A14 ─ A15
     │       │       └──────────────── A17
     │       └──────────────────────── A16
     ├─ A02 ─┐
     ├─ A03 ─┼─ A04 ───────── A09
     └─ A05 ─┬─ A06 ───────── A11
             └─ A07 ───────── A13

A09 + A11 + A07 ─ A13 ─ A15
A16 and A17 span all waves but do not own core wire identifiers.
```

Parallelism is intentional in Waves 1–3. The reliable transfer wave begins only when object vectors, commit transitions, and simulator APIs are stable.

---

## 9. Protocol message families to allocate in the registry

The registry agent assigns numeric values; feature agents use symbolic names only.

Handshake/session:

- `HELLO`
- `SETTINGS`
- `SETTINGS_ACK`
- `AUTH_CONTEXT`
- `SESSION_OPEN`
- `SESSION_ACCEPT`
- `SESSION_REJECT`

Object/package:

- `PACKAGE_DESCRIPTOR`
- `MANIFEST_REQUEST`
- `MANIFEST_PAGE`
- `PROGRESSIVE_PAGE`
- `SEAL`
- `HAVE`
- `RANGE_REQUEST`
- `PROOF_BUNDLE`
- `DATA_RECORD`
- `RANGE_CANCEL`

Receiver state:

- `CAPACITY`
- `TRANSIT_VERIFIED`
- `CHUNK_DURABLE`
- `CHUNK_AT_REST_VERIFIED`
- `PUBLISH_RECEIPT`

Datagram/FEC experimental:

- `DATAGRAM_CREDIT`
- `CODING_EPOCH_OPEN`
- `GEN_STATE`
- `GEN_DONE`
- `CODING_EPOCH_CLOSE`

Control and errors:

- `PING`
- `GOAWAY`
- `ERROR`
- `SOURCE_SCORE_HINT`
- `JOB_PRIORITY_UPDATE`

Every message specification must state idempotence, replay behavior, maximum encoded size, authorization requirement, and whether it is valid in 0-RTT. The default is **not valid in 0-RTT** unless explicitly proven safe and idempotent.

---

## 10. Test and benchmark matrix

### Correctness dimensions

- Object sizes: 0 bytes through multi-terabyte sparse logical objects.
- Boundary sizes around 16 KiB, 64 KiB, 256 KiB, 4 MiB, pack maximum, and FEC epoch geometry.
- Path/pathname edge cases on Linux, Windows, and macOS.
- Manifest counts through at least one million logical files.
- Cache states: none, sparse, nearly complete, wrong-suite aliases, stale aliases.
- Storage faults at every commit transition.
- Session replay, old incarnation, duplicate frame, reordered frame, and transport switch.

### Network dimensions

- RTT: 1, 20, 80, 160, 300 ms.
- Rates: 100 Mbit/s, 1, 10, 25, 40, and available 100 Gbit/s tiers.
- IID loss and burst loss.
- Reordering, duplication, MTU blackholes, and PMTU changes.
- ECN and shallow/deep queues.
- UDP block, policing, and deprioritization.
- NAT rebinding and interface changes.
- Competing CUBIC/Reno-like and interactive traffic.

### Receiver dimensions

- RAM only.
- Local NVMe.
- HDD/RAID.
- Network filesystem.
- S3-compatible object store.
- Hash-limited, disk-limited, journal-limited, and decode-limited states.
- Linux offload, Windows offload, and macOS no-offload tiers.

### Workloads

- One 500 GB mezzanine object.
- 10,000-frame sequence averaging 50 MB/frame.
- One million small files and sidecars.
- Mixed video/audio/proxy/LUT/EDL package.
- 90% receiver cache hit.
- Repeated slightly revised package.
- First-usable-subset priority package.

### Baselines

- Tuned HTTPS/TCP with strong parallel chunking.
- Parallel HTTPS/TCP with BBR where legally and operationally available.
- Stock reliable QUIC using the selected library.
- VOT reliable mode.
- VOT plus receiver-aware flow control.
- Fixed and adaptive FEC variants.
- A licensed FASP-class product only under approved publication terms.

Primary result is **time to root-verified, declared-assurance publication**, not socket throughput.

---

## 11. Project kill gates

These gates prevent sunk-cost escalation.

1. **Proof gate:** abandon or redesign a suite if independent vectors cannot converge or range-proof overhead is unacceptable.
2. **Commit gate:** no transport release if any fault trace can create a false `PUBLISHED` state.
3. **Overhead gate:** redesign Balanced journaling if its clean-path overhead exceeds 5%.
4. **Reliable transport gate:** do not begin FEC optimization until reliable mode is close to the attainable clean-path ceiling on target hardware.
5. **Resume gate:** do not market bounded-waste recovery until E-RESUME passes across carrier switch and crash cases.
6. **FEC gate:** remove coded mode from the release profile if it cannot materially improve predefined tail regions without excessive wire/CPU cost.
7. **VCRC gate:** retain VCRC as a paper/simulator artifact if it does not beat strong adaptive baselines or if estimator noise dominates action selection.
8. **Public multi-rail gate:** prohibit by default until coupling and shared-bottleneck detection pass fairness tests.
9. **Custom CC gate:** do not ship without RFC 9743-style evaluation and legal review.
10. **Benchmark gate:** do not publish named commercial comparisons without license review.

---

## 12. First integration demonstrations

The team should produce demos in this exact order.

### Demo 1 — Offline object proof

Create a package, emit both suite identities, request disjoint 64 KiB ranges, verify proofs, corrupt one byte, and show deterministic rejection.

### Demo 2 — Crash-safe local publication

Receive an object into the POSIX provider, kill after every commit step, recover, and prove that no run emits a false receipt. Demonstrate Strict catching a backing-device mutation that a buffered reread would miss.

### Demo 3 — Reliable localhost transfer

Transfer a sealed package over the simulator and live QUIC, materialize packs, publish atomically, and independently recompute the package root.

### Demo 4 — Interrupted WAN transfer

Transfer over an impaired path, kill both endpoints, resume over a new connection, then force TCP fallback. Show bounded resent bytes and unchanged verified state.

### Demo 5 — Relay and first usable subset

Upload once, retrieve from two authorized sources, prioritize EDL/LUT/audio/proxy and selected frames, then complete the full package. Show source cancellation and assurance receipts.

### Demo 6 — Coded endgame experiment

Enable FEC only on the completion-critical frontier, compare against reliable mode, and show both tail benefit and total extra bytes.

### Demo 7 — VCRC replay

Replay public traces against fixed FEC, adaptive FEC, VCRC, and the hindsight oracle. Publish seeds, estimator settings, calibration, and regret.

---

## 13. Definition of done for the first public alpha

The first public alpha is complete when:

- The object, proof, manifest, commit, and reliable wire specifications are public.
- Both proof suites have independent conformance vectors.
- Linux POSIX Fast/Balanced/Strict and one object-store provider work.
- Reliable QUIC and TLS/TCP fallback interoperate through the transport abstraction.
- Resume survives process crash, reconnection, and carrier switch.
- Pack objects and one-million-file manifests are supported.
- Default telemetry is pseudonymous and credentials are never logged.
- The deterministic simulator and fuzz corpus are public.
- Experimental FEC and VCRC, if present, are negotiated and disabled by default.
- No lossy-LFN, public multi-rail, or custom-controller performance claim exceeds the evidence.

The broker UI, managed cloud service, end-to-end encrypted manifests, content-defined chunking, random linear network coding, RaptorQ, kernel bypass, and public-path coupled multi-rail are not alpha blockers.

---

## 14. Instructions to the dev agents

Start with Wave 0 issues only. Agents A02, A03, A04, A05, A08, and A16 may begin in parallel once their ADR dependencies merge. A09 must not finalize transport-facing object APIs before the W1 vectors and W2 transition fixtures stabilize. A14 and A15 should initially contribute only simulator interfaces and experiment designs; production FEC or VCRC code before W6 is premature and should not merge.

The first implementation checkpoint is not “bytes moved quickly.” It is:

> The same package identity can be independently generated, partially proven, crash-safely committed, recovered, and published without an overstated assurance receipt.

Once that holds, the team can optimize the transport without compromising the product's defining guarantee.
