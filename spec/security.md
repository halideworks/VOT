# VOT v0.3 Security Architecture

Status: normative Wave 0 threat model

## 1. Security objectives

VOT's defining security objective is that an authorized receiver publishes only
the immutable object or package it requested and reports no assurance stronger
than it performed. The system also protects availability through bounded
resource admission and protects workflow metadata from routine telemetry
disclosure.

Conforming implementations MUST:

- authenticate object bytes to an exact `(suite_id, root, byte_length)`;
- authorize every package, object, range, upload, and publication operation;
- bind successful state to current session and journal incarnations;
- preserve verified state without accepting stale or conflicting state;
- enforce memory, storage, CPU, decode, network, job, and tenant limits before
  expensive work;
- prevent unauthenticated reflection or bulk response amplification;
- keep credentials, capability tokens, payload bytes, and raw workflow paths out
  of ordinary telemetry; and
- fail closed on unknown critical behavior or unsupported assurance.

## 2. Assets

Protected assets include:

- object and package integrity and exact length;
- commit-state and receipt integrity;
- capability tokens, private keys, TLS secrets, and channel-binding material;
- unpublished media and manifest metadata;
- receiver staging capacity, durable storage, hash/decode CPU, and network
  capacity;
- tenant isolation, quotas, relay-cache authorization, and active leases;
- session, incarnation, receipt-sequence, credit-epoch, and budget-epoch
  freshness; and
- the accuracy and privacy of audit and performance data.

## 3. Trust boundaries

VOT crosses these boundaries:

1. client to transport library and TLS implementation;
2. authenticated peer to VOT frame parser and session state machine;
3. session state to object/proof verifier;
4. verified bytes to staging and commit provider;
5. commit provider to filesystem, device, or object-store integrity mechanism;
6. principal and job to shared receiver, relay, cache, and scheduler resources;
7. protocol state to telemetry and audit sinks; and
8. carrier-specific state to carrier-neutral resume state.

Bytes crossing a boundary are untrusted until that boundary's validation has
completed. Validation MUST precede owned allocation and correctness-state
mutation.

## 4. Threat actors and assumptions

The model includes:

- a passive or active network attacker;
- an unauthenticated client able to spoof source addresses where the carrier
  permits it;
- an authenticated but malicious or compromised principal;
- a malicious, stale, or faulty source or relay;
- a tenant attempting cross-job or cross-tenant resource theft;
- a process crash, torn write, stale VM snapshot, faulty storage backend, or
  corrupt backing representation; and
- an operator accidentally enabling an unsupported experimental policy.

The selected TLS implementation, operating-system isolation, hardware root of
trust, and cryptographic primitive implementations are dependencies. VOT tests
their integration and failure behavior but does not claim to prove them. A fully
malicious authorized receiver can disclose plaintext it is authorized to read;
preventing that is outside the protocol's scope.

End-to-end encrypted manifests, DRM, endpoint compromise recovery, and traffic
analysis resistance are not v0.3 guarantees. TLS protects content and metadata
in transit between adjacent VOT peers; authorized relays may see the data their
capabilities permit.

## 5. Authentication and authorization

All live carriers MUST provide TLS 1.3 or a security profile with equivalent
peer authentication, confidentiality, integrity, and downgrade protection.
Production policy MUST authenticate the server. Client authentication may use a
certificate, an application identity authenticated above TLS, or both.

A capability is signed or authenticated data containing at least:

- issuer, audience, and subject or holder constraint;
- allowed operation set;
- package/object identity scope, including suite, root, and exact length when
  known;
- allowed byte ranges or bounded package scope;
- tenant, job, storage, wire, and concurrency limits;
- not-before, expiry, and unique token identifier;
- delegation constraints; and
- signing key identifier and capability format version.

Capabilities MUST be verified before protected operations. Unknown mandatory
claims fail closed. Bearer capabilities SHOULD be bound to a TLS exporter, peer
key, or proof-of-possession key. When deployment constraints require an unbound
bearer token, its shorter lifetime and replay exposure MUST be declared in
policy and audit data.

Authorization is checked again when a request expands scope, switches source or
carrier, publishes an object, creates an alias, or renews a lease. Cache presence
does not confer read authorization. A dual-suite alias does not broaden the
capability's identity scope.

## 6. Replay, freshness, and rollback

No v0.3 application frame is valid in 0-RTT. Session and incarnation identifiers
are independent random 128-bit values. Request identifiers, receipt sequences,
credit epochs, coding epochs, and budget epochs are monotonic within their
declared scope.

Exact replay of an idempotent request returns or reuses the original result. A
duplicate identifier with different content is rejected. Stale epochs are
ignored or rejected and never replace current state.

Journal recovery authenticates record checksums, selects only the current
incarnation, and treats a valid but stale journal or restored VM snapshot as a
rollback attempt. It MUST NOT publish from stale state. A poisoned incarnation
cannot be rehabilitated by replaying a successful-looking transition.

## 7. Amplification and reflection control

Before carrier address validation and application authentication, the server
MUST NOT send manifest pages, proof bundles, data records, source lists, or
capability-derived metadata. Pre-authentication traffic is limited to bounded
handshake, settings, authentication challenge, and error data and remains within
the carrier's amplification limit. For QUIC this includes the path validation
and three-times-received-byte restriction.

After authentication, every bulk response requires an authorized request with a
bounded range and exact object identity. Servers enforce per-principal and
per-path response, request, and concurrency budgets. An `ERROR` frame is capped
at 64 KiB and SHOULD be much smaller than the triggering request. Repeated
invalid requests are rate-limited before cryptographically or storage-expensive
work.

## 8. Parser and resource admission

The frame decoder enforces the 16 MiB hard ceiling and registered per-frame
limits from the header before payload allocation. Unknown optional frames are
stream-discarded; unknown critical frames terminate the VOT session. Counts and
nested lengths are bounded by both remaining payload bytes and schema limits.

An object or package length is not trusted merely because it parsed. Before
`ADMITTED`, the receiver verifies authorization and identity context, applies a
configured maximum, checks arithmetic for overflow, and atomically reserves
staging against all applicable limits:

- principal and tenant;
- job and package;
- connection and session;
- memory and unretired bytes;
- filesystem or object-store staging;
- active hash, proof, decode, and journal work; and
- rail and congestion domain.

Flow-control credit never exceeds assigned staging capacity. Capacity telemetry
is advisory and cannot bypass the hard credit loop. Reservation release is tied
to verified state-machine outcomes, not transport acknowledgement.

## 9. Malicious source and proof handling

Every range is verified against the requested exact-length object identity
before contributing to verified state. Wrong roots, lengths, proof order,
missing nodes, corrupt bytes, and suite confusion are rejected. Bytes from
different sources may satisfy disjoint ranges only after independent proof
verification.

A proof failure affects the source's score and may quarantine the source, but it
does not erase already verified bytes from other sources. Source hints are
advisory and never override local verification or authorization. Progressive
page reorder, replay, gaps, truncation, or source mutation prevent `SEAL`.

At least one authorized honest source should be sufficient for eventual
progress in the later multi-source scheduler. Hedges and alternate sources count
against ordinary quotas and congestion-domain caps.

## 10. Commit, publication, and receipts

The Commit Layer follows `spec/architecture.md` and ADR-0001. A transport ACK is
never admission, verification, durability, or publication. Write or flush errors
poison the current incarnation. No publication receipt is emitted until the
requested profile's predecessor and the provider's namespace durability work
complete.

Receipts MUST be authenticated when they cross a trust boundary. Their signed
or MACed representation binds every mandatory receipt field, including object or
package identity, provider and version, requested profile, actual assurance,
session and incarnation, sequence, clock source, verification suite, and flags.
Receipt verification keys and algorithms are selected by the deployment
identity profile; none is silently inferred from an object proof suite.

Strict unsupported is an error, not a Balanced result. Delegated backend
integrity is explicitly identified in the receipt.

## 11. Multi-tenant cache and garbage collection

Immutable extent deduplication is allowed only after identity verification.
Alias lookup and extent reuse remain authorization-scoped. Responses MUST NOT
reveal whether another tenant possesses an object unless policy explicitly
permits that disclosure.

Staging objects, progressive sessions, pack areas, and relay-cache entries have
leases, retention rules, tombstones, and grace periods. Active authenticated
leases prevent collection. Lease creation and renewal consume quota. Deletion is
idempotent and auditable. Orphan cleanup cannot follow untrusted paths outside
the provider's configured staging root.

## 12. Datagram, FEC, and VCRC containment

Datagram mode begins with zero credit. A newer `credit_epoch` replaces older
credit and sets absolute maxima for unretired bytes, active generations, and
decode work. Zero credit stops new generations. Receiver overload cannot
increase parity without bound, and reliable repair remains available.

FEC, VCRC, public multi-rail, custom congestion control, and Multipath QUIC are
negotiated and disabled by default. VCRC cannot authorize parity or hedges after
risk-budget exhaustion. Experimental actions remain inside tenant, job,
receiver, and congestion-domain limits.

## 13. Carrier fallback and path changes

TLS/TCP fallback authenticates the peer and applies the same frame,
authorization, and receipt rules as QUIC. Carrier switching preserves only
carrier-neutral verified, durable, and request state. It does not carry old
packet-number, congestion, RTT, address-validation, or unsafe Careful Resume
state onto a new path.

## 14. Metadata and telemetry privacy

Telemetry follows `spec/telemetry.md`. The default level is pseudonymous. Raw
paths, filenames, manifest metadata, capability tokens, credentials, payload
bytes, TLS secrets, and unredacted stable object identities are prohibited in
ordinary VOT and qlog-compatible traces.

Peer diagnostics are treated as disclosure surfaces and use registered codes
plus bounded, non-secret context. Security-sensitive failures SHOULD avoid
distinguishing nonexistent from unauthorized resources when that distinction
would create an enumeration oracle.

## 15. Key and dependency hygiene

Secrets are obtained through deployment key providers and are not stored in
configuration committed with source. Implementations zeroize secret buffers
where the language and provider permit, do not include them in panic or crash
reports, and rotate pseudonymization keys independently from authentication
keys.

Dependencies are locked reproducibly, inventoried in an SBOM, and reviewed for
license and provenance. Unsafe Rust is forbidden in the core codec and parser.
Platform and transport FFI modules isolate unsafe code, document each safety
invariant, and receive dedicated race, lifetime, and fault tests.

## 16. Required security tests

The machine-readable cases in `security/abuse-cases.yaml` are the minimum test
matrix. Release gates require, at minimum:

- address and application amplification limits;
- token theft, expiry, audience, scope, channel-binding, and replay cases;
- untrusted length and aggregate staging exhaustion cases;
- parser truncation, length, unknown-critical, and grease cases;
- malicious proof, source mutation, and suite-confusion cases;
- stale journal, stale incarnation, and snapshot rollback cases;
- silent assurance downgrade rejection;
- cross-tenant cache presence and alias isolation;
- FEC credit and VCRC exhaustion containment;
- carrier-switch authentication and state preservation; and
- trace scanning proving default telemetry contains no raw path or token.
