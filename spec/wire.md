# VOT v0.3 Wire Protocol

Status: frozen envelope for prototype ALPN `vot-draft-03`

## 1. Transport binding and versioning

The prototype ALPN is the ASCII string `vot-draft-03`. Implementations MUST NOT
advertise or claim registration of `vot/1`. A major incompatible protocol change
uses a new ALPN. Compatible additions use settings, extension negotiation, and
optional length-delimited frames.

VOT v1 defines no mandatory custom QUIC transport parameters. Application
negotiation starts on the first client-initiated bidirectional control stream.
The client sends `HELLO` followed by `SETTINGS`. The server sends its `SETTINGS`
and then `SETTINGS_ACK`. Frames that require an authenticated session are invalid
until the authentication policy succeeds and `SESSION_ACCEPT` is sent.

The `HELLO` payload is:

```text
QUIC-varint draft_revision       ; 3 for vot-draft-03
QUIC-varint endpoint_role        ; 0 client, 1 server
QUIC-varint extension_count      ; at most 256
extension_count * QUIC-varint extension_id
```

An unsupported revision causes `UNSUPPORTED_VERSION`. A role inconsistent with
the stream initiator causes `MALFORMED_FRAME`. Duplicate extension identifiers
are rejected.

The `SETTINGS` payload is a sequence of `(setting_id, setting_value)` QUIC-varint
pairs bounded by the frame length. Duplicate identifiers are rejected. Values
are validated against `spec/registries.md` before state mutation.
`SETTINGS_ACK` has an empty payload and confirms that all preceding peer settings
were parsed and accepted.

## 2. Frame envelope

Every control or reliable-record frame is encoded as:

```text
QUIC-varint frame_type
QUIC-varint frame_length
frame_length bytes payload
```

QUIC varints are one, two, four, or eight octets. The two most significant bits
of the first octet encode the width. Values are limited to `2^62 - 1`. Encoders
MUST use the shortest representation. Decoders MUST accept every legal QUIC
representation and MUST perform checked arithmetic.

Frame criticality is encoded in the type's least-significant bit:

- even type: optional; an unknown type is skipped by its validated length;
- odd type: critical; an unknown type closes the VOT session with
  `UNKNOWN_CRITICAL_FRAME`.

Grease frame types are registered optional types with deliberately unspecified
payloads. They are handled exactly like unknown optional frames. Implementations
MUST exercise them in conformance tests and SHOULD occasionally send them in
live handshakes.

## 3. Bounded decoding

The hard payload ceiling for any v0.3 frame is 16 MiB. The default negotiated
control-frame ceiling is 1 MiB. Known frames also have the lower per-type limits
in section 5. `DATA_RECORD` is always limited to 256 KiB.

A decoder performs these steps in order:

1. Read at most eight bytes to decode `frame_type`.
2. Read at most eight bytes to decode `frame_length`.
3. Determine the applicable limit without allocating the payload.
4. Reject a length above that limit with `FRAME_TOO_LARGE`.
5. For an unknown critical type, close with `UNKNOWN_CRITICAL_FRAME`; payload
   allocation is unnecessary.
6. For an unknown optional or grease type, stream-discard exactly
   `frame_length` bytes. The implementation MUST NOT allocate a buffer sized from
   the unknown length.
7. For a known type, obtain no more than its validated payload length and parse
   into a borrowed representation.
8. Validate counts, offsets, identities, authorization, and state before
   constructing an owned value or mutating session state.

End-of-stream inside a varint or payload is `MALFORMED_FRAME`. On stream
transports, a decoder may report `incomplete` while more bytes can still arrive;
it becomes malformed only when the carrier declares end-of-stream.

Negotiation cannot raise the 16 MiB hard ceiling or a fixed lower limit such as
the data-record, manifest-page, or proof-suite limit. Implementations MAY set
lower local limits and reject negotiation they cannot support.

## 4. Replay and 0-RTT rules

No v0.3 application frame is valid in 0-RTT. A receiver MUST reject application
frames received as early data. A future frame may opt in only after its operation
is proven safe and idempotent and this table is revised.

Request identifiers, session identifiers, incarnation identifiers, receipt
sequences, credit epochs, and coding epochs are scoped fields in their owning
payload specifications. Exact duplicate idempotent operations reuse the original
result. A duplicate identifier with different content is a protocol or integrity
error. Stale monotonic epochs never replace newer state.

## 5. Frame behavior registry

The maximum below includes the frame payload only. "Auth" means a successfully
authenticated and authorized session is required.

| Frame | Maximum | Idempotence and replay | Auth | 0-RTT |
|---|---:|---|---|---|
| `HELLO` | 4 KiB | once per VOT session; duplicate is an error | no | no |
| `SETTINGS` | 16 KiB | once per direction; duplicate setting or frame is an error | no | no |
| `SETTINGS_ACK` | 0 | duplicate acknowledgement is ignored | no | no |
| `AUTH_CONTEXT` | 64 KiB | policy-defined nonce/channel binding; replay is rejected | no | no |
| `SESSION_OPEN` | 64 KiB | exact duplicate session ID reuses result; conflicting duplicate rejected | yes | no |
| `SESSION_ACCEPT` | 64 KiB | exact duplicate result is idempotent | yes | no |
| `SESSION_REJECT` | 64 KiB | exact duplicate result is idempotent | yes | no |
| `PACKAGE_DESCRIPTOR` | 1 MiB | keyed by package identity; conflicting duplicate rejected | yes | no |
| `MANIFEST_REQUEST` | 64 KiB | exact request ID is idempotent | yes | no |
| `MANIFEST_PAGE` | 1 MiB | page identity and index deduplicate; conflicting page rejected | yes | no |
| `PROGRESSIVE_PAGE` | 1 MiB | chain position deduplicates; reorder, replay conflict, or gap rejected | yes | no |
| `SEAL` | 256 KiB | exact package identity is idempotent; conflicting seal rejected | yes | no |
| `HAVE` | 4 MiB | newer map sequence supersedes; stale map ignored | yes | no |
| `RANGE_REQUEST` | 1 MiB | exact request ID is idempotent; conflicting duplicate rejected | yes | no |
| `PROOF_BUNDLE` | 16 MiB | request/range identity deduplicates; invalid proof rejected | yes | no |
| `DATA_RECORD` | 256 KiB | exact range bytes deduplicate; conflicting verified identity rejected | yes | no |
| `RANGE_CANCEL` | 64 KiB | cancellation is idempotent; cannot revoke verified state | yes | no |
| `CAPACITY` | 4 KiB | latest monotonic sample supersedes; advisory only | yes | no |
| `TRANSIT_VERIFIED` | 64 KiB | monotonic receipt sequence; exact duplicate ignored | yes | no |
| `CHUNK_DURABLE` | 64 KiB | monotonic receipt sequence; exact duplicate ignored | yes | no |
| `CHUNK_AT_REST_VERIFIED` | 64 KiB | monotonic receipt sequence; exact duplicate ignored | yes | no |
| `PUBLISH_RECEIPT` | 64 KiB | monotonic receipt sequence; exact duplicate ignored | yes | no |
| `DATAGRAM_CREDIT` | 4 KiB | newer credit epoch replaces; stale epoch ignored | yes | no |
| `CODING_EPOCH_OPEN` | 64 KiB | exact epoch geometry is idempotent; geometry conflict rejected | yes | no |
| `GEN_STATE` | 64 KiB | newer generation sequence supersedes | yes | no |
| `GEN_DONE` | 64 KiB | terminal and idempotent for generation | yes | no |
| `CODING_EPOCH_CLOSE` | 64 KiB | terminal and idempotent for epoch | yes | no |
| `PING` | 0 | duplicate has no semantic effect | no | no |
| `GOAWAY` | 4 KiB | lower/equal final accepted ID is idempotent; increase rejected | yes | no |
| `ERROR` | 64 KiB | terminal error replay has no additional effect | depends on phase | no |
| `SOURCE_SCORE_HINT` | 64 KiB | advisory; latest sample supersedes | yes | no |
| `JOB_PRIORITY_UPDATE` | 64 KiB | monotonic update sequence; stale update ignored | yes | no |

Experimental FEC frames are invalid unless `DATAGRAM_FEC` is negotiated. VCRC
actions additionally require `VCRC`. A known but unnegotiated experimental frame
causes `EXPERIMENT_NOT_NEGOTIATED`; its optional criticality only defines how an
implementation that does not know the frame skips it.

## 6. State and assurance constraints

Wire receipt frames report observations; they do not cause the receiver's local
commit transition. The receiver emits them only after the corresponding provider
operation succeeds and its journal requirement is satisfied.

Publication prerequisites are frozen as:

- Fast: `TRANSIT_VERIFIED`;
- Balanced: `DURABLE`; and
- Strict: `AT_REST_VERIFIED`.

`PUBLISH_RECEIPT` identifies the requested commit profile, provider identifier
and version, actual predecessor assurance, object or package identity,
verification suite, session and incarnation IDs, monotonic receipt sequence,
wall-clock observation and clock source, and all delegation, downgrade,
unsupported, or experimental flags. A requested unsupported profile fails; the
wire protocol never silently selects a weaker profile.

Transport ACKs are internal to the carrier and MUST NOT synthesize any receipt.

## 7. Carrier mapping

QUIC uses one client-initiated bidirectional control stream plus negotiated
reliable payload lanes. VOT frame boundaries are independent of QUIC STREAM
frame boundaries. A frame may span transport reads; multiple VOT frames may
arrive in one read.

The TLS/TCP fallback uses the identical VOT frame bytes on a reliable byte
stream. Switching carriers preserves object, package, verified-range, durable,
and receipt state; it does not reuse unsafe path or congestion state.

An implementation SHOULD start QUIC first and start authenticated TLS/TCP after
a short configurable delay rather than waiting for a long UDP timeout. It may
switch from selected QUIC only after TLS authentication succeeds and bounded
observation windows show no QUIC data or probe acknowledgement. Connection IDs
are carrier-local and never key resume state. Resume discovery uses immutable
object or package identity.

## 8. Conformance vectors

`test-vectors/wire/frame-envelope.json` is normative for the envelope. Each case
contains the complete encoded bytes and an expected result. Encoders must match
successful canonical vectors byte-for-byte. Decoders must also accept legal
non-minimal QUIC varints even though encoders never produce them.

The vector set covers:

- all QUIC-varint width boundaries;
- known empty and payload frames;
- unknown optional skipping;
- unknown critical failure;
- grease tolerance;
- pre-allocation length rejection;
- truncation; and
- mixed frame sequences.
