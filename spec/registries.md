# VOT v0.3 Registries

Status: frozen for `vot-draft-03`

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
| `0x0b` | `ACTIVE_KEEPALIVE_MS` | 20000 | 10000--30000 | critical |
| `0x20` | `COMPRESSION_MIN_GAIN_BPS` | 500 | 0--10000 | optional |
| `0x22` | `TELEMETRY_LEVEL` | 1 | 0--2 | optional |

Setting values are QUIC varints. A duplicate setting is a protocol error. An
unknown optional setting is ignored; an unknown critical setting closes the VOT
session. A value outside its registered range is `INVALID_SETTING`.

## 4. Extension identifiers

| Value | Name | Status | Default |
|---:|---|---|---|
| `0x00` | `CORE_RELIABLE` | draft | enabled |
| `0x01` | `DATAGRAM_FEC` | experimental | disabled |
| `0x02` | `ZSTD_RECORDS` | draft optional | disabled |
| `0x03` | `VCRC` | experimental | disabled |
| `0x04` | `PUBLIC_MULTI_RAIL` | experimental | disabled |
| `0x05` | `CUSTOM_CONGESTION_CONTROL` | experimental | disabled |
| `0x06` | `MULTIPATH_QUIC` | experimental | disabled |

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
| `0x0001` | `ED25519` | 64 bytes | draft |
| `0x0002` | `HMAC_SHA256` | 32 bytes | draft |

Ed25519 follows RFC 8032. HMAC-SHA-256 follows RFC 2104 with SHA-256. Deployment
policy selects acceptable schemes and key provenance. Object verification suite
selection never implies a receipt authentication scheme.
