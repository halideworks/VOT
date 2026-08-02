# VOT v0.3 Architecture

Status: normative implementation baseline candidate
Version: v0.3
Snapshot: 2026-07-31

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and
**MAY** are to be interpreted as described by BCP 14 when, and only when, they
appear in all capitals.

An implementation is conforming only for the profiles and capabilities it
advertises. Unsupported capabilities MUST be reported explicitly. A provider
MUST NOT silently substitute a weaker capability.

## 2. Scope

VOT transfers immutable, content-addressed objects and packages and reports
receiver work as explicit assurance states. Its primary completion metric is
time to root-verified publication at the declared assurance profile, not socket
throughput.

The architecture has four separable systems:

1. The **Verified Object Layer** defines object identity, manifests, range
   proofs, package structure, cache reuse, and multi-source retrieval.
2. The **Commit Layer** defines assurance states and crash-consistent
   publication for storage providers.
3. The **Transport Group** defines reliable QUIC lanes, fallback carriers,
   receiver admission, rails, and congestion domains.
4. **Verified Completion Risk Control (VCRC)** is an experimental controller
   for FEC, repair, path, source, and receiver-resource decisions.

The implementation order is normative:

```text
specification and test vectors
-> object and proof layer
-> commit correctness
-> deterministic simulator
-> reliable single-rail transfer
-> resume and fallback
-> data-plane ceiling work
-> relay, broker, and multi-job scheduling
-> experimental FEC
-> VCRC
-> multipath and congestion-control research
```

A later layer MUST NOT weaken an earlier invariant. A wire-visible or
identity-visible change requires an accepted ADR and new conformance vectors.

## 3. Global invariants

Every implementation and test harness MUST preserve these invariants:

- No unverified byte contributes to verified object state.
- A transport acknowledgement is never application admission, verification,
  durability, or publication.
- A receipt never claims a stronger assurance level than the receiver
  performed.
- A stale journal incarnation is never accepted as current.
- A source mutation cannot produce a seal under the prior object or package
  identity.
- Speculative parity, hedges, and extra rails remain within job, receiver, and
  congestion-domain caps.
- Unknown critical extensions are never ignored.
- A parser never allocates from an untrusted length before enforcing a bound.
- Proprietary implementations are not source material for VOT.

Experimental features are disabled by default: datagram FEC, VCRC, public
multi-rail, custom congestion control, and Multipath QUIC.

## 4. Object and proof architecture

An object identity is the tuple `(suite_id, root, byte_length)`. Roots from
different suites are not interchangeable, even when they describe the same
bytes.

VOT v1 defines exactly two verification suites:

| Suite | Identifier | Identity and geometry |
|---|---:|---|
| `blake3-bao64` | `0x0001` | BLAKE3 root; 64 KiB Bao/BLAKE3 verification groups; canonical pre-order relay outboard |
| `sha256-bep52-64k` | `0x0002` | BEP 52 SHA-256 file root; 16 KiB base leaves; 64 KiB verification pieces; BEP 52 tree and padding rules |

Both suites use in-band range-proof bundles. A response carries requested data
and the suite-specific proof necessary to authenticate it to the object root.
Contiguous ranges SHOULD use a multiproof or streaming encoding. A receiver
MUST NOT have to fetch a complete proof index before verifying useful data.

Relays MAY keep canonical proof sidecars. A sidecar is local supporting data,
not a mandatory network bootstrap object. Progressive ingest uses authenticated
manifest pages containing verification-group commitments; `SEAL` commits the
page sequence to the final canonical suite root.

A dual-suite equivalence record is valid only when a trusted verifier has read
the complete bytes and computed both identities. It is signed, exact-length
scoped, and creates an alias rather than a new identity. Policy permitting, an
object store SHOULD map both identities to one immutable extent.

## 5. Commit and assurance architecture

### 5.1 States

VOT exposes five non-equivalent successful observations:

1. `ADMITTED`: bounded receiver resources have been reserved.
2. `TRANSIT_VERIFIED`: received bytes authenticate to the advertised identity.
3. `DURABLE`: the commit provider has completed its declared durability
   barrier and durably recorded the transition.
4. `AT_REST_VERIFIED`: a conforming independent read or delegated backend
   integrity mechanism verified the durable bytes.
5. `PUBLISHED`: the object was made visible according to the provider's atomic
   publication contract and the namespace durability step completed.

The states are monotonic observations within one `(session_id,
incarnation_id)`. A transition never moves backward. `POISONED` and `ABORTED`
are terminal outcomes, not assurance levels. Recovery creates or selects a
current incarnation and MUST reject a stale one.

Publication has profile-specific required predecessors:

| Requested profile | Minimum predecessor to publication |
|---|---|
| Fast | `TRANSIT_VERIFIED` and provider-declared atomic visibility work |
| Balanced | `DURABLE` |
| Strict | `AT_REST_VERIFIED` |

The final publication receipt MUST identify the requested profile, commit
provider, and actual predecessor assurance. Skipped non-required observations
MUST NOT be implied. If the requested predecessor cannot be performed, the
provider returns `UNSUPPORTED` or fails the operation; it MUST NOT downgrade.

Any write or durability-barrier error poisons the incarnation. Retrying a
failed flush cannot make that incarnation successful. Recovery MUST revalidate
or reconstruct affected ranges before a new publication attempt.

### 5.2 Strict POSIX sequence

A Strict POSIX provider performs, in order:

1. Create a unique temporary object and journal incarnation.
2. Reserve bounded staging capacity.
3. Write ranges and perform transit verification.
4. Flush the data file; poison the incarnation on any write or flush error.
5. Flush the durable journal record.
6. Verify via an independent read path or conforming delegated mechanism.
7. Flush the at-rest verification record.
8. Atomically link or rename without overwriting an unrelated object.
9. Flush the parent directory.
10. Emit `PUBLISHED` with provider and assurance details.

On Linux, an independent local read uses a separately opened `O_DIRECT`
descriptor, satisfies filesystem alignment, and hashes the bytes read after the
durability barrier. A buffered read and `POSIX_FADV_DONTNEED` do not satisfy
Strict. A backend checksum is acceptable only when its declared semantics meet
the conformance profile. Otherwise Strict is unsupported.

### 5.3 Receipts

Every receipt contains:

- object or package identity;
- observed assurance state;
- requested profile and actual predecessor assurance where applicable;
- commit-provider identifier and version;
- session and incarnation identifiers;
- a monotonic sequence number scoped to the receipt issuer;
- wall-clock observation and named clock source;
- verification suite; and
- downgrade, delegation, experimental, or unsupported flags.

Correctness transitions use a monotonic clock or logical ordering. Wall clock is
audit metadata only.

## 6. Wire and transport architecture

The prototype ALPN is `vot-draft-04`. It MUST NOT claim the unregistered
`vot/1` ALPN. A major incompatible version uses a new ALPN; compatible features
use `SETTINGS`, registered extension identifiers, and optional frames.

Application negotiation begins on the first client-initiated bidirectional
control stream. VOT v1 requires no custom QUIC transport parameter. Each frame
has this envelope:

```text
QUIC-varint frame_type
QUIC-varint frame_length
frame_length bytes of payload
```

The decoder MUST enforce the per-frame bound before allocation. Unknown
optional frames are skipped by length. Unknown critical frames close the VOT
session with the registered error. Grease frame types are exercised in tests
and MAY be sent in live handshakes.

Reliable QUIC flow control is the hard receiver-admission loop. Connection
credit is bounded by the BDP-derived target, assigned staging capacity, and a
configured maximum. A receiver extends credit below one quarter of the target,
restoring toward the target in increments of at least one eighth, but never
beyond bytes it can stage. Capacity telemetry is advisory.

Datagram mode begins with zero credit. A monotonic `credit_epoch` supersedes
older credit and places absolute caps on unretired bytes, active generations,
and decode work. Wall-clock expiry is not a correctness mechanism.

Default connection settings are a 90-second idle timeout and a 20-second
active-transfer keepalive. Keepalive is disabled without an active reservation
or resumable lease; deployments may configure it within 10--30 seconds. Server
connection IDs are opaque to application logic. The default relay profile uses
a nonzero 16-byte server CID and transport adapters support a deployment-supplied
CID generator or router.

## 7. Rails and congestion domains

A rail is an execution unit. A congestion domain is a fairness and pacing unit.
On shared/public paths, production v1 uses one rail per presumed bottleneck.
Multiple workers within that rail are allowed. Multiple uncoupled rails over a
shared bottleneck are not production-supported.

Provisioned paths may use multiple rails under explicit operator policy. The
aggregate administrative and receiver caps apply across them, and telemetry
discloses rail count and aggregate behavior.

Public-path multi-rail remains experimental until VOT has both validated
coupled congestion control and shared-bottleneck detection. Coupling unrelated
bottlenecks is a performance failure; failing to couple a shared bottleneck is
a fairness failure.

## 8. VCRC architecture

VCRC is an optional experiment for online tail-risk control of durable,
verified coflow completion under network, source, receiver, and storage
uncertainty. Its online action-ranking objective is CVaR95.

Candidate actions use paired, block-resampled scenarios with common random
numbers. The initial ensemble is 256 scenarios. Candidate pruning may use a
cheaper first pass; overlapping paired uncertainty intervals trigger adaptive
expansion to at least 1,024 scenarios. p99 and CVaR99 are reporting metrics, not
v0.3 online-estimation claims.

For protection decision `t`, `F_t` means at least one protected critical unit
fails to reach `TRANSIT_VERIFIED` by the end of its scheduled first wave and
requires another network action. The risk ledger is:

```text
0 <= delta_t <= B_t
B_(t+1) = B_t - delta_t
B_0 = delta_job
```

At `B_t = 0`, no new parity or hedge is authorized. Reliable repair and normal
retransmission continue, in-flight work may finish, and
`vcrc.budget_exhausted` is emitted with job, epoch, and frontier state. There is
no automatic reset. A separately authorized and logged budget epoch is needed
to resume spending. This is a first-wave frontier-risk certificate, never an
end-to-end deadline certificate.

## 9. Frozen initial constants

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
| Prototype ALPN | `vot-draft-04` |
| Default idle timeout | 90 s |
| Active keepalive | 20 s |
| Online VCRC objective | CVaR95 |
| Initial VCRC scenarios | 256, adaptively expanded |
| Datagram FEC field | GF(2^8) |
| Initial FEC geometry | 64 source symbols; repair cap 16 |

## 10. Final-review disposition record

The R1--R8 labels below normalize the eight v0.3 final-review topics into a
stable implementation record. All are accepted; none are waived.

| Review item | Disposition | Normative resolution |
|---|---|---|
| R1: Strict at-rest semantics | Accept | Independent read path or conforming delegated integrity; no buffered substitute or silent downgrade. See ADR-0001. |
| R2: VCRC estimator claim | Accept | Online CVaR95 with paired block resampling, 256 initial scenarios, and adaptive expansion; p99/CVaR99 are reporting metrics. |
| R3: Risk certificate and exhaustion | Accept | First-wave frontier event and monotonic spend-down ledger; reliable-only behavior at exhaustion; no automatic reset. See ADR-0002. |
| R4: Congestion-control scope | Accept | Production does not depend on custom CC; clean-room controller remains simulator-only pending safety, coexistence, and legal review. |
| R5: Proof suites and transport | Accept | Exactly two v1 suites and in-band range proofs; no mandatory proof-index bootstrap. See ADR-0003. |
| R6: Versioning and extensions | Accept | `vot-draft-04`, length-delimited frames, critical/optional handling, greasing, and registries. |
| R7: Connection, CID, and credit behavior | Accept | Fixed initial timeout/keepalive defaults, opaque deployable CIDs, bounded reliable flow control, monotonic datagram credit epochs. |
| R8: Rail policy and restored requirements | Accept | Single production public rail per bottleneck; provisioned multi-rail by policy; restored commit, resume, pack, compression, legal, security, GC, and telemetry gates remain normative. See ADR-0004. |

## 11. Change control

Normative architecture changes require an ADR. Numeric identifiers are assigned
only in `spec/registries.md`. Wire-visible changes also require updated golden
vectors. New hash, compression, congestion-control, or FEC algorithms require
an ADR and provenance review. Experimental behavior remains negotiated,
off-by-default, and identified in receipts and telemetry until its gate passes.
