# VOT v0.3 Registries

Status: frozen for `vot-draft-05`

Identifier tables are assigned in `spec/registries.yaml`. This document is
the human view of those tables.

All integer registry values are unsigned QUIC variable-length integers unless a
table says otherwise. Values not listed here are unassigned. Implementations
MUST use symbolic names in source and MUST NOT allocate values outside this
document.

## 1. Registry policy

- `0x0000` is reserved unless explicitly assigned.
- Frame and setting identifiers use the least-significant bit for unknown-value
  handling: even is optional and odd is critical.
- Unknown optional identifiers are ignored after their enclosing length is
  validated. Unknown critical identifiers terminate the VOT session.
- Experimental allocations are unstable across draft ALPNs and are disabled by
  default.
- Stable allocations require an accepted ADR, provenance review when an
  algorithm is involved, specification text, and conformance vectors.

## 2. Frame types

| Value | Name | Handling | Status |
|---:|---|---|---|
| `0x01` | `HELLO` | critical | draft |
| `0x03` | `SETTINGS` | critical | draft |
| `0x05` | `SETTINGS_ACK` | critical | draft |
| `0x07` | `AUTH_CONTEXT` | critical | draft |
| `0x09` | `SESSION_OPEN` | critical | draft |
| `0x0b` | `SESSION_ACCEPT` | critical | draft |
| `0x0d` | `SESSION_REJECT` | critical | draft |
| `0x21` | `PACKAGE_DESCRIPTOR` | critical | draft |
| `0x23` | `MANIFEST_REQUEST` | critical | draft |
| `0x25` | `MANIFEST_PAGE` | critical | draft |
| `0x27` | `PROGRESSIVE_PAGE` | critical | draft |
| `0x29` | `SEAL` | critical | draft |
| `0x2b` | `HAVE` | critical | draft |
| `0x2d` | `RANGE_REQUEST` | critical | draft |
| `0x2f` | `PROOF_BUNDLE` | critical | draft |
| `0x31` | `DATA_RECORD` | critical | draft |
| `0x33` | `RANGE_CANCEL` | critical | draft |
| `0x40` | `CAPACITY` | optional | draft |
| `0x43` | `TRANSIT_VERIFIED` | critical | draft |
| `0x45` | `CHUNK_DURABLE` | critical | draft |
| `0x47` | `CHUNK_AT_REST_VERIFIED` | critical | draft |
| `0x49` | `PUBLISH_RECEIPT` | critical | draft |
| `0x60` | `DATAGRAM_CREDIT` | optional | experimental |
| `0x62` | `CODING_EPOCH_OPEN` | optional | experimental |
| `0x64` | `GEN_STATE` | optional | experimental |
| `0x66` | `GEN_DONE` | optional | experimental |
| `0x68` | `CODING_EPOCH_CLOSE` | optional | experimental |
| `0x80` | `PING` | optional | draft |
| `0x83` | `GOAWAY` | critical | draft |
| `0x85` | `ERROR` | critical | draft |
| `0x86` | `SOURCE_SCORE_HINT` | optional | draft |
| `0x89` | `JOB_PRIORITY_UPDATE` | critical | draft |

Even values from `0x1f00` through `0x1ffe` inclusive are reserved grease frame
types. A sender chooses among them without attaching semantics. A receiver MUST
skip them after enforcing the frame-length bound.

## 3. Settings

| Value | Name | Default | Valid range | Handling |
|---:|---|---:|---:|---|
| `0x01` | `MAX_CONTROL_FRAME_PAYLOAD` | 1 MiB | 1 KiB--16 MiB | critical |
| `0x03` | `MAX_DATA_RECORD_PAYLOAD` | 256 KiB | 64 KiB--256 KiB | critical |
| `0x05` | `MAX_MANIFEST_PAGE_PAYLOAD` | 1 MiB | 64 KiB--1 MiB | critical |
| `0x07` | `RELIABLE_LANE_LIMIT` | 16 | 1--256 | critical |
| `0x09` | `IDLE_TIMEOUT_MS` | 90000 | 1000--600000 | critical |

Setting values are QUIC varints. A duplicate setting is a protocol error. An
unknown optional setting is ignored; an unknown critical setting closes the VOT
session. A value outside its registered range is `INVALID_SETTING`.

`IDLE_TIMEOUT_MS` is negotiated and validated but not installed. QUIC fixes its
own idle timeout during the handshake, before these are negotiated, and what
closes an idle connection is the carrier's timeout, taken from the default
above. ADR-0035 has the reasoning and what installing it would require.

`0x0b`, `0x20`, and `0x22` are retired and MUST NOT be reassigned. They were
`ACTIVE_KEEPALIVE_MS`, `COMPRESSION_MIN_GAIN_BPS`, and `TELEMETRY_LEVEL`, and
ADR-0035 removed them because nothing installed any of them: there is no
keepalive timer, no compressor, and no telemetry level. Each returns with the
thing it configures.

## 4. Extension identifiers

| Value | Name | Status | Default |
|---:|---|---|---|
| `0x00` | `CORE_RELIABLE` | draft | enabled |
| `0x01` | `DATAGRAM_FEC` | experimental | enabled |
| `0x02` | `ZSTD_RECORDS` | draft optional | disabled |
| `0x03` | `VCRC` | experimental | disabled |
| `0x04` | `PUBLIC_MULTI_RAIL` | experimental | disabled |
| `0x05` | `CUSTOM_CONGESTION_CONTROL` | experimental | disabled |
| `0x06` | `MULTIPATH_QUIC` | experimental | disabled |
| `0x07` | `FEC_COVER_EPOCHS` | experimental | enabled |
| `0x08` | `PUSH` | experimental | disabled |

Advertising an extension does not authorize its use. Both endpoints must
negotiate it and local policy must enable it.

## 5. Verification suites

| Value | Name | Root length | Status |
|---:|---|---:|---|
| `0x0001` | `blake3-bao64` | 32 bytes | required v1 |
| `0x0002` | `sha256-bep52-64k` | 32 bytes | required v1 |

## 6. Compression suites

| Value | Name | Status |
|---:|---|---|
| `0x0000` | `none` | required |
| `0x0001` | `zstd-record` | optional |

Compression is per record, has explicit encoded and decoded lengths, and never
changes plaintext object identity.

## 7. Commit profiles, providers, and assurance levels

### 7.1 Commit profiles

| Value | Name | Publication predecessor |
|---:|---|---|
| `0x01` | `FAST` | `TRANSIT_VERIFIED` |
| `0x02` | `BALANCED` | `DURABLE` |
| `0x03` | `STRICT` | `AT_REST_VERIFIED` |

### 7.2 Provider identifiers

| Value | Name | Status |
|---:|---|---|
| `0x0001` | `POSIX_LOCAL` | draft |
| `0x0002` | `OBJECT_STORE` | draft |
| `0x0003` | `WINDOWS_LOCAL` | reserved for implementation profile |
| `0x0004` | `MACOS_LOCAL` | reserved for implementation profile |

Provider versions are carried separately and do not alter the identifier.

### 7.3 Assurance levels

| Value | Name |
|---:|---|
| `0x01` | `ADMITTED` |
| `0x02` | `TRANSIT_VERIFIED` |
| `0x03` | `DURABLE` |
| `0x04` | `AT_REST_VERIFIED` |
| `0x05` | `PUBLISHED` |

`POISONED`, `ABORTED`, and `UNSUPPORTED` are outcomes, not assurance levels.

## 8. Error codes

Error classes occupy `0x0100` blocks.

| Value | Name | Class |
|---:|---|---|
| `0x0101` | `UNKNOWN_CRITICAL_FRAME` | protocol/version |
| `0x0102` | `MALFORMED_FRAME` | protocol/version |
| `0x0103` | `FRAME_TOO_LARGE` | protocol/version |
| `0x0104` | `UNSUPPORTED_VERSION` | protocol/version |
| `0x0105` | `INVALID_SETTING` | protocol/version |
| `0x0106` | `DUPLICATE_SETTING` | protocol/version |
| `0x0201` | `AUTHENTICATION_FAILED` | authentication/authorization |
| `0x0202` | `AUTHORIZATION_FAILED` | authentication/authorization |
| `0x0203` | `REPLAY_REJECTED` | authentication/authorization |
| `0x0301` | `MANIFEST_INVALID` | manifest/object/proof integrity |
| `0x0302` | `OBJECT_IDENTITY_MISMATCH` | manifest/object/proof integrity |
| `0x0303` | `PROOF_INVALID` | manifest/object/proof integrity |
| `0x0304` | `SOURCE_MUTATED` | manifest/object/proof integrity |
| `0x0401` | `STORAGE_WRITE_FAILED` | storage/commit |
| `0x0402` | `DURABILITY_FAILED` | storage/commit |
| `0x0403` | `AT_REST_VERIFICATION_FAILED` | storage/commit |
| `0x0404` | `PUBLICATION_FAILED` | storage/commit |
| `0x0405` | `STALE_INCARNATION` | storage/commit |
| `0x0406` | `ASSURANCE_UNSUPPORTED` | storage/commit |
| `0x0501` | `ADMISSION_DENIED` | resource/admission |
| `0x0502` | `RESOURCE_LIMIT` | resource/admission |
| `0x0503` | `FLOW_CONTROL_VIOLATION` | resource/admission |
| `0x0601` | `CARRIER_UNAVAILABLE` | fallback/path |
| `0x0602` | `PATH_STATE_REJECTED` | fallback/path |
| `0x0701` | `EXPERIMENT_NOT_NEGOTIATED` | experimental/research |
| `0x0702` | `RISK_BUDGET_EXHAUSTED` | experimental/research |
| `0x0703` | `CODING_EPOCH_CONFLICT` | experimental/research |

An `ERROR` frame carries a registered code and bounded diagnostic data. Default
telemetry and peer-visible diagnostics MUST NOT contain raw paths, credentials,
tokens, or payload bytes.

## 9. Telemetry event names

| Name | Stability | Minimum redaction |
|---|---|---|
| `vot.session.opened` | draft | pseudonymous |
| `vot.session.closed` | draft | pseudonymous |
| `vot.frame.unknown_optional` | draft | minimal |
| `vot.frame.unknown_critical` | draft | minimal |
| `vot.receiver.admitted` | draft | pseudonymous |
| `vot.range.transit_verified` | draft | pseudonymous |
| `vot.chunk.durable` | draft | pseudonymous |
| `vot.chunk.at_rest_verified` | draft | pseudonymous |
| `vot.object.published` | draft | pseudonymous |
| `vot.commit.poisoned` | draft | pseudonymous |
| `vot.carrier.switched` | draft | pseudonymous |
| `vcrc.budget_exhausted` | experimental | pseudonymous |

Telemetry names are strings, not wire integers. Renaming or changing semantics
requires a registry update. Raw filenames and capability tokens are forbidden at
all ordinary telemetry levels.


## 10. Receipt authentication schemes

| Value | Name | Authenticator length | Status |
|---:|---|---:|---|
| `0x0001` | `ED25519` | 64 bytes | required v1 |
| `0x0002` | `HMAC_SHA256` | 32 bytes | optional |

Ed25519 follows RFC 8032. HMAC-SHA-256 follows RFC 2104 with SHA-256. Deployment
policy selects acceptable schemes and key provenance. Object verification suite
selection never implies a receipt authentication scheme.

A receipt that crosses a trust boundary uses `ED25519`. A symmetric MAC cannot
serve that case: any party able to verify it is equally able to forge it, so the
auditor a receipt exists for either cannot check it or becomes able to
manufacture it. `HMAC_SHA256` remains registered for receipts that never leave
one trust domain, where the shared key is already common to both sides.

The authenticator covers a domain separator, the two-byte scheme value, the key
identifier prefixed by its length in a single byte, and the canonical receipt
bytes, in that order. The identifier is 1 to 64 bytes, as `receipt.cddl`
requires, so the prefix always fits.

Binding the scheme means an authenticator produced under one scheme is not valid
input for another. Binding the key identifier means a verifier may use it to
tell one issuing context from another. It names the key the issuer claimed to be
using, and `commit.md` has the verifier check it; left outside the authenticated
bytes it is a label that any holder of the receipt can rewrite, so a receipt the
same issuer produced for another purpose could be relabelled without disturbing
its signature. A witness signature already covers its own key identifier, as a
field of the statement it signs.

## 11. Capability formats

| Value | Name | Status |
|---:|---|---|
| `0x0001` | `ed25519-cbor-v1` | retired |
| `0x0002` | `ed25519-cbor-tls-exporter-v1` | draft |

`0x0000` is reserved and MUST NOT be advertised or sent.

A capability format names the encoding and verification rules for the opaque
capability bytes in `SESSION_OPEN`. The format identifier travels outside those
bytes so a server can reject a format it does not implement without parsing
anything an unauthenticated peer chose the shape of.

`ed25519-cbor-v1` is the legacy nonce-only proof format. It does not bind the
holder's proof to the channel that carries it. A `vot-draft-05` implementation
MUST NOT advertise or send it. Its capability uses the canonical schema in
`spec/capability.cddl`. Its issuer signature input is the ASCII bytes
`VOT capability v0`, one zero byte, `0x0001` in network byte order, the key
identifier length in one byte, the key identifier, and the canonical capability
bytes. Its holder proof input is the ASCII bytes `VOT capability pop v0`, one
zero byte, `0x0001` in network byte order, the 16-byte token identifier, the
16-byte session identifier, and the `AUTH_CONTEXT` nonce, in that order. A
decoder accepts the retired identifier's wire representation so it can report an
unsupported format rather than a malformed frame; no current policy selects it.

`ed25519-cbor-tls-exporter-v1` is defined by `spec/capability.cddl`, with the
issuer anchor it verifies against defined by ADR-0023. Its capability is Ed25519
over canonical CBOR, signed as the bytes it travels as rather than as a
re-encoding of its claims. The capability signature input is the ASCII bytes
`VOT capability v0`, one zero byte, the two-byte format value in network byte
order, the key identifier length in one byte, the key identifier, and the
canonical capability bytes, in that order.

The holder proof for `ed25519-cbor-tls-exporter-v1` is an Ed25519 signature under
the holder key in the capability. It covers these fields in order:

| Field | Encoding |
|---|---|
| domain separator | ASCII `VOT capability pop v1` followed by one zero byte |
| capability format | `0x0002` as two bytes in network byte order |
| token identifier | 16 bytes from the capability |
| session identifier | 16 bytes from `SESSION_OPEN` |
| nonce length | two bytes in network byte order |
| nonce | the 16 to 64 bytes from `AUTH_CONTEXT` |
| channel binding | 32 bytes exported by the presenting TLS session |

The channel binding is TLS 1.3 exporter keying material with the exact label
`EXPORTER-VOT-Channel-Binding`, no exporter context, and an output length of 32
bytes. Each endpoint computes it locally after the TLS handshake. It is an input
to the proof and never travels in a VOT frame.

A server advertising `ed25519-cbor-tls-exporter-v1` advertises proof of
possession in `AUTH_CONTEXT`. It fails closed if its carrier cannot supply the
exporter. A client MUST NOT answer that challenge with `ed25519-cbor-v1`, and a
server MUST NOT fall back to that retired format after advertising the bound
format. A server advertising no format requires no authentication, which
`spec/wire.md` section 1.1 describes.

`test-vectors/capability/capability.json` is normative for the canonical
capability and envelope bytes. `tools/validate_capability_vectors.py` rebuilds
the format-2 issuer-signing transcript independently, derives the test issuer
key, recomputes each accepted envelope signature, and proves that the same
signature fails under the retired format value. The possession transcript and
its positive and negative signatures are normative in
`test-vectors/capability/possession-transcript.json`.

A format defines its own delegation rules, and one that defines none refuses a
capability claiming any. Chained delegation is therefore a new identifier rather
than a new claim inside an existing format: a verifier that does not implement
chains never advertises the format that carries them.

## 12. Capability operations

An operation names something a capability authorizes. `spec/security.md` section
5 requires a capability to carry an allowed operation set, and every value in
that set comes from here.

| Value | Name | Status |
|---:|---|---|
| `0x0001` | `PUBLISH` | draft |
| `0x0002` | `READ_MANIFEST` | draft |
| `0x0003` | `READ_RANGES` | draft |

`0x0000` is reserved and MUST NOT appear in a capability.

An operation is coarser than a frame type, because authorization is a decision
about what a peer may ask for rather than about one message. Each names the
frames it authorizes, in the direction the holder sends them:

- `PUBLISH` covers offering an object and causing its publication:
  `PACKAGE_DESCRIPTOR`, `MANIFEST_PAGE`, `PROGRESSIVE_PAGE`, `SEAL`,
  `PROOF_BUNDLE`, and `DATA_RECORD`. The assurance frames and `PUBLISH_RECEIPT`
  that come back are the receiver's answer to it rather than separate
  operations.
- `READ_MANIFEST` covers `MANIFEST_REQUEST`, whose answer is manifest pages and
  a seal.
- `READ_RANGES` covers `HAVE`, `RANGE_REQUEST`, and `RANGE_CANCEL`, whose answer
  is proof bundles and data records.

When `PUSH` is negotiated, `READ_MANIFEST` and `READ_RANGES` are not consulted.
Their request frames are the receiver's answer to the `PUBLISH` offer.

Reading metadata and reading payload are separate because a deployment may allow
a holder to learn that an object exists and what shape it is without allowing it
to fetch the bytes. Granting both is two values in the set.

An unknown operation identifier in a capability's set grants nothing, and does
not invalidate the capability. A verifier authorizes the values it recognizes and
ignores the rest, which stays fail-closed: an operation a verifier cannot name is
one it never authorizes. Rejecting the whole capability instead would make a
token issued for a later revision unusable for the operations this revision does
implement.

The relay and broker layer adds operations for source lists, alias creation, and
lease renewal, which `spec/security.md` section 5 already names as points where
authorization is rechecked. They are not numbered here, because nothing defines
what they authorize yet; they arrive with the layer that does.

## 13. Capability resource limits

A resource limit is a ceiling a capability puts on its holder. `spec/security.md`
section 5 requires a capability to carry them, and every identifier in that map
comes from here.

| Value | Name | Unit | Status |
|---:|---|---|---|
| `0x0001` | `CONCURRENT_LANES` | reliable lanes open at once | draft |
| `0x0002` | `WIRE_BYTES` | bytes on the wire under this capability | draft |
| `0x0003` | `STORAGE_BYTES` | bytes stored at the receiver | draft |

`0x0000` is reserved and MUST NOT appear in a capability.

A limit a capability does not state is not a grant of unlimited use. The
deployment's own ceilings still apply, and a verifier applies the lower of the
two.

An unknown limit identifier MUST fail closed: the capability is refused. This is
the opposite of the rule section 12 gives an unknown operation, and deliberately
so. An operation is a grant, so one a verifier cannot name is one it never
authorizes and ignoring it grants nothing. A limit is a restriction, so ignoring
one a verifier cannot name would lift it, and a capability that says "at most this
much" would be honoured as "as much as you like".

Cross-job and cross-tenant quotas are the broker's, which schedules across both.
They are not numbered here for the reason the relay's operations are not: nothing
defines what they bound yet, and `VOT_v0.3_Agent_Backlog.yaml` puts
`quotas_enforced_across_network_CPU_IO_storage` in wave 7.
