# VOT v0.3 Telemetry and Redaction Policy

Status: normative Wave 0 policy

## 1. Goals

VOT telemetry supports protocol diagnosis, assurance auditing, capacity
analysis, and reproducible experiments without turning traces into a copy of
workflow metadata. Telemetry does not drive correctness transitions and cannot
grant flow-control, storage, or risk-budget authority.

The default level is `pseudonymous`. An implementation MUST produce a useful
default trace without raw paths or capability tokens.

## 2. Levels

| Value | Name | Permitted data |
|---:|---|---|
| `0` | `minimal` | aggregate counters, coarse outcome classes, and process-local timing only |
| `1` | `pseudonymous` | minimal data plus deployment-keyed identifiers and bounded protocol metadata |
| `2` | `diagnostic` | pseudonymous data plus locally enabled detailed timing, queue, and state-transition context |

`diagnostic` requires explicit local opt-in, has a bounded duration, records the
operator policy that enabled it, and reverts automatically according to that
policy. It is not peer-selectable.

## 3. Data forbidden from ordinary telemetry

The following MUST NOT appear at any ordinary VOT level, including diagnostic
and qlog-compatible output:

- credentials, bearer capabilities, proof-of-possession secrets, or token
  signatures;
- TLS keys, exporters, session tickets, private keys, or raw channel bindings;
- payload bytes, proof bytes, manifest bytes, or decoded media metadata;
- raw filenames, package paths, filesystem paths, object-store keys, URLs, query
  strings, or endpoint user information;
- unredacted manifest fields or application comments;
- raw stable object roots, package roots, session IDs, incarnation IDs, request
  IDs, tenant IDs, principal IDs, or job IDs;
- peer-provided free-form error strings; and
- memory contents, stack locals containing secrets, or unfiltered panic data.

Authenticated receipts and dedicated operator audit records are separate from
ordinary telemetry. They may carry protocol-required identities but still never
carry credentials, tokens, secrets, or payload bytes. Access, retention, and
export policy for those artifacts is deployment-owned.

## 4. Pseudonymous identifiers

At `pseudonymous` and `diagnostic`, stable identifiers are transformed by a
deployment-local keyed pseudorandom function. The default construction is:

```text
pseudonym = first_128_bits(
    HMAC-SHA-256(K_telemetry_epoch, domain_separator || 0x00 || raw_identifier)
)
```

The domain separator is distinct for `object`, `package`, `session`,
`incarnation`, `request`, `job`, `tenant`, `principal`, `source`, and `path`.
This prevents equality correlation across identifier classes. A deployment MAY
use another approved keyed PRF with at least 128 bits of output.

`K_telemetry_epoch` is independent of TLS, capability, receipt, and object
verification keys. It is rotated on a declared schedule and never exported with
the trace. Traces carry a non-secret key-epoch label so operators can understand
correlation boundaries. Rotation intentionally breaks cross-epoch correlation.

Network endpoints are reduced to configured categories or separately
pseudonymized. Raw IP addresses, ports, interface names, SSIDs, and route labels
are excluded from default output.

## 5. Common event envelope

Every event has these fields:

| Field | Requirement | Notes |
|---|---|---|
| `name` | required | registered event name |
| `schema_version` | required | positive integer |
| `sequence` | required | monotonic within the event sink |
| `monotonic_time_ns` | required | correctness-neutral ordering and duration source |
| `wall_time` | optional | audit observation only |
| `wall_clock_source` | required when wall time exists | e.g. system UTC, externally disciplined UTC |
| `level` | required | actual redaction level applied |
| `component` | required | bounded registered component name |
| `outcome` | optional | registered enum, never peer free-form text |
| `fields` | required | event-specific bounded map |

Wall clock MUST NOT determine protocol, journal, credit, lease, or VCRC
correctness transitions. Event field counts, string lengths, and serialized event
size are locally bounded. Oversized diagnostic context is dropped and counted,
not truncated in a way that might split an escape or reveal adjacent memory.

## 6. Registered events

The canonical names are allocated in `spec/registries.md`.

### `vot.session.opened`

Allowed fields: pseudonymous session and principal, negotiated ALPN, negotiated
extensions, carrier class, commit profile, and policy label. No peer address.

### `vot.session.closed`

Allowed fields: pseudonymous session, registered outcome/error code, duration,
verified bytes, durable bytes, published object count, and carrier class.

### `vot.frame.unknown_optional`

Allowed fields: numeric frame type, validated payload length, stream class, and
whether the type was grease. Payload is never recorded.

### `vot.frame.unknown_critical`

Allowed fields: numeric frame type, declared length if decoded, stream class,
and registered close code.

### `vot.receiver.admitted`

Allowed fields: pseudonymous session/job/object, bounded reservation sizes,
commit profile, and quota class. Raw target path is forbidden.

### `vot.range.transit_verified`

Allowed fields: pseudonymous object/request/source, suite ID, offset bucket,
verified length, verification duration, and outcome. Exact offsets MAY appear
only under diagnostic policy when they do not expose a filename mapping.

### `vot.chunk.durable`

Allowed fields: pseudonymous object/incarnation, provider ID and version,
durable length, barrier duration, and registered outcome.

### `vot.chunk.at_rest_verified`

Allowed fields: pseudonymous object/incarnation, provider ID and version,
verification mechanism class, verified length, duration, delegation flag, and
registered outcome.

### `vot.object.published`

Allowed fields: pseudonymous object/package/session/incarnation, requested
profile, actual predecessor assurance, provider ID and version, receipt sequence,
publication duration, and flags. Raw receipt signatures and roots are excluded.

### `vot.commit.poisoned`

Allowed fields: pseudonymous object/incarnation, provider ID, failed transition,
registered storage error class, and recovery action. Raw OS error messages and
paths are excluded; a bounded numeric OS error code MAY be diagnostic-only.

### `vot.carrier.switched`

Allowed fields: pseudonymous session/job, source and destination carrier classes,
reason enum, preserved verified/durable byte counts, and bounded resent bytes.
Raw addresses and interface names are excluded.

### `vcrc.budget_exhausted`

Allowed fields: pseudonymous job, budget epoch, decision epoch, zero remaining
budget, protected frontier counts and byte totals, in-flight action counts, and
reliable-only transition. It MUST NOT label the event as a deadline failure or
deadline certificate.

## 7. qlog-compatible mapping

Transport adapters MAY emit qlog-compatible transport events. Application event
names remain in the `vot.*` namespace. Before an event reaches a qlog sink, the
same redaction filter used for VOT events processes it.

Default qlog-compatible traces exclude:

- raw connection IDs when they are routable or stable; use a pseudonym;
- raw source and destination addresses;
- TLS or capability material;
- STREAM payloads and application frame payloads;
- filenames, paths, object roots, and manifest metadata; and
- deployment routing labels that reveal customer or facility identity.

Packet number, size, direction, loss, ACK, congestion, pacing, and timing fields
may be recorded because they are required for transport diagnosis. Deployments
perform a traffic-analysis review before exporting those fields outside their
trust boundary.

## 8. Metrics and cardinality

Metrics labels MUST come from bounded registries or configuration allowlists.
Pseudonymous object, request, session, principal, source, or job identifiers MUST
NOT be metric labels. They belong only in bounded traces. This prevents
attacker-controlled cardinality and memory exhaustion.

Histograms use declared units and bucket sets. The required unit appears in the
metric name or schema. Byte counters distinguish sent, retransmitted,
speculative, verified, durable, and published bytes; those meanings are never
collapsed into a transport-throughput completion claim.

## 9. Error handling and peer input

Peer-visible diagnostics contain a registered error code and an optional bounded
safe context code. Implementations never copy peer strings, paths, tokens,
manifest values, or arbitrary frame payload into local events. Text intended for
an operator is selected locally from the registered code.

Repeated identical errors may be sampled after counters are incremented.
Sampling decisions and dropped-event counts are observable. Security-relevant
terminal events, commit poisoning, assurance downgrade rejection, and budget
exhaustion are not silently sampled away.

## 10. Retention, access, and export

Each deployment declares retention separately for metrics, ordinary traces,
diagnostic traces, receipts, and audit records. Diagnostic traces receive the
shortest default retention. Access is least-privilege and audited. Exports carry
the schema version, redaction level, pseudonymization key-epoch label, sampling
configuration, and software version.

Deletion is auditable and idempotent. Retention expiry does not delete an active
commit or cache lease; telemetry retention and object retention are separate
state machines.

## 11. Conformance tests

A telemetry implementation is conforming only when automated tests prove:

- the default is `pseudonymous`;
- representative success and every registered failure path contain no raw path,
  filename, token, credential, payload sentinel, raw root, or TLS secret;
- the same raw identifier is stable within one domain and key epoch;
- different domains and key epochs produce different pseudonyms;
- minimal mode contains no stable per-object or per-user identifier;
- peer-controlled strings cannot become event names, field names, labels, or
  operator text;
- metric label cardinality remains bounded under attacker-controlled IDs;
- diagnostic mode requires local opt-in and expires; and
- receipt/audit output cannot be accidentally routed to an ordinary qlog sink.
