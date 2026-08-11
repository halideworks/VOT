# VOT v0 Static Proof Catalog

Status: optional normative storage profile for `vot-draft-05`

## 1. Purpose and trust

A static proof catalog supplies canonical VOT range proofs for immutable
range-readable storage that cannot compute proofs. It is not wire material and
does not contribute to object or package identity.

The caller supplies the authoritative object identity `(suite, root, length)`.
The catalog identity MUST match it exactly before an index-controlled read or
allocation. Proof verification MUST use the caller-supplied identity. A catalog
checksum, signature, or root is not a trust anchor.

All multibyte integers are unsigned big-endian. All additions and
multiplications below are checked before use.

## 2. Version-zero constants

| Name | Value |
| --- | ---: |
| Magic | ASCII `VOTPCAT\0` |
| Header length | 128 bytes |
| Version | 0 |
| Index-entry length | 16 bytes |
| Profile | 1 |
| Verification group | 65,536 bytes |
| Profile range | 4,194,304 bytes |
| Maximum proof length | 8,192 bytes |
| Maximum object length | 9,223,372,036,854,775,807 bytes |

Profile 1 permanently identifies consecutive 4 MiB ranges. Different range
geometry requires another format version.

## 3. Header

| Offset | Length | Field | Version-zero rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `56 4f 54 50 43 41 54 00` |
| 8 | 2 | version | 0 |
| 10 | 2 | header length | 128 |
| 12 | 4 | flags | 0 |
| 16 | 2 | suite | 1 or 2 |
| 18 | 2 | profile | 1 |
| 20 | 4 | reserved | all zero |
| 24 | 32 | object root | exact VOT root |
| 56 | 8 | object length | at most the maximum object length |
| 64 | 8 | record count | exact derived count |
| 72 | 8 | index offset | 128 |
| 80 | 8 | index length | `record_count * 16` |
| 88 | 8 | proof-blob offset | `128 + index_length` |
| 96 | 8 | proof-blob length | sum of indexed proof lengths |
| 104 | 8 | catalog length | `proof_blob_offset + proof_blob_length` |
| 112 | 16 | reserved | all zero |

A complete decoder MUST require physical length to equal catalog length. A
range-reading client MAY use storage length for availability decisions, but it
MUST still validate every fetched offset and proof against these bounds.

## 4. Record geometry

For object length `L` and profile range `R = 4,194,304`:

```text
record_count = L / R + (if L % R is zero then 0 else 1)
```

This form avoids the potentially overflowing addition in `(L + R - 1) / R`.
For ordinal `i`, where `0 <= i < record_count`:

```text
data_offset = i * R
data_length = min(R, L - data_offset)
```

Every non-final record covers exactly 4 MiB. The final record covers every
remaining byte. A 4 MiB-aligned object has no empty trailing record. An empty
object has zero records and its catalog is exactly the 128-byte header.

Record `i` stores the canonical proof returned by:

```text
prove(object, data_offset, data_length)
```

The returned cover MUST exactly equal `(data_offset, data_length)`. Catalogs do
not define new BLAKE3 or SHA-256 proof geometry.

## 5. Index and proof blob

Index entry `i` begins at `index_offset + i * 16`.

| Entry offset | Length | Field | Version-zero rule |
| ---: | ---: | --- | --- |
| 0 | 8 | proof offset | relative to proof-blob start |
| 8 | 4 | proof length | 0 through 8,192, multiple of 32 |
| 12 | 4 | reserved | 0 |

Proof bytes begin at `proof_blob_offset + proof_offset`.

A complete decoder MUST enforce all of these canonicality rules:

1. The first proof offset is zero.
2. Each later offset equals the preceding offset plus its proof length.
3. The final proof end equals proof-blob length.
4. No gap, overlap, reordered record, or trailing proof byte exists.
5. Zero-length proofs are allowed. Equal consecutive offsets are allowed only
   when the preceding proof length is zero.
6. Record position implicitly defines increasing data offset. Data offset and
   record number are not encoded again.

A random-access client need not fetch neighboring entries before using one
entry. It MUST validate the selected entry's reserved word, proof length, and
checked proof range against the header. Full-index canonicality can be checked
when the complete catalog is ingested. In either mode, only proof verification
against the expected root authenticates bytes.

## 6. Bounds

At maximum object length:

```text
verification groups = 2^47
catalog records      = 2^41
index length         = 2^45 bytes
```

For BLAKE3, a 4 MiB range contains at most 63 internal parent records and has
at most 41 ancestors in a maximum-size object. Its proof therefore needs at
most `104 * 64 = 6,656` bytes. SHA-256 needs fewer bytes. The version-zero 8 KiB
limit is a checked conservative bound.

The maximum proof blob is `2^54` bytes. The maximum catalog length is
`128 + 2^45 + 2^54` bytes. These values authorize arithmetic, not allocation.
A decoder MUST NOT allocate proportional to record count, index length, proof
blob length, or catalog length merely to answer one lookup. A proof length is
rejected before proof allocation or retrieval when it exceeds 8 KiB.

## 7. Random-access procedure

1. Read exactly 128 header bytes.
2. Validate magic, version, fixed fields, bounds, flags, and reserved bytes.
3. Compare header identity with the caller's expected object identity.
4. Derive and validate record count, index length, proof-blob offset, proof-blob
   length, and catalog length.
5. Derive the record ordinal for the desired object position.
6. Read exactly one 16-byte index entry at its checked fixed address.
7. Validate that entry before using its proof offset or length.
8. Read the named proof bytes and the derived object-data range.
9. Verify both against the caller-supplied suite, root, and length.

## 8. Outcomes

Implementations distinguish these local outcomes without allocating new wire
error codes:

- `IDENTITY_MISMATCH`: catalog identity differs from the expected object.
- `MALFORMED_CATALOG`: fixed fields, canonical layout, or arithmetic are wrong.
- `UNSUPPORTED_CATALOG`: version, suite, or profile is unknown.
- `PROOF_INVALID`: structure is valid but proof or data does not reconstruct
  the expected root.
- `CATALOG_UNAVAILABLE`: required header, index, or proof bytes are missing.

## 9. Version evolution

The magic remains fixed and version selects the complete header and index
interpretation. A version-zero decoder rejects unknown flags and requires its
header length and reserved fields exactly. New flags, profile semantics, index
widths, proof encodings, or integrity mechanisms require a new version. Version
evolution never changes the underlying VOT object identity.

## 10. Vectors

`test-vectors/static-proof-catalog/vectors.json` and its binary fixtures freeze
the header, index addressing, proof bytes, both suites, boundary geometry,
hostile arithmetic, identity mismatch, truncation, canonicality failures, and
proof corruption. Coverage includes single-group payload corruption, the exact
8,192-byte proof limit, sparse selected-entry reads that occur only after object
identity authentication, and short selected-entry and proof reads. The validator
independently regenerates cold proof bytes and requires each catalog record to
match them exactly.
