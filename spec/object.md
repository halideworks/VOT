# VOT v0.3 Object and Package Model

Status: normative Wave 0 specification

## 1. Immutable object identity

An object is an exact finite byte string. Its identity is:

```text
ObjectId = (suite_id, root[32], byte_length)
```

All three fields participate in equality. A root from one suite never matches a
root from another suite. A root with a different byte length never matches,
including when a proof decoder could otherwise parse the bytes.

Object lengths are unsigned integers from zero through `2^63 - 1` in v0.3.
Implementations MAY impose a smaller configured limit. They MUST reject a length
before allocation when it exceeds that limit or cannot be represented by the
storage provider.

## 2. Verification and scheduling geometry

- A verification group is 64 KiB (`65,536` bytes).
- Group `i` starts at `i * 65,536`.
- Every non-final group is exactly 65,536 bytes.
- The final group ends at `byte_length` and may be shorter.
- An empty object has one logical empty verification group for root validation
  but no transferable byte range.
- A scheduling/cache chunk is 4 MiB and contains 64 consecutive verification
  groups except at end of object.

Verified state is recorded only in complete verification groups. A request that
names an unaligned byte range is expanded outward to the smallest covering set of
verification groups. The receiver exposes only the originally requested bytes
to the caller after every covering group verifies.

## 3. Verification suites

Suite `0x0001`, `blake3-bao64`, uses the standard 32-byte BLAKE3 digest of the
complete byte string. Its 64 KiB transfer groups are BLAKE3 chunk groups and do
not change the standard BLAKE3 root.

Suite `0x0002`, `sha256-bep52-64k`, uses the BEP 52 SHA-256 file-tree root for a
non-empty byte string, with 16 KiB base leaves and zero-hash padding. A VOT
verification piece is the tree node covering four base leaves, or the truncated
right-edge equivalent. For an empty byte string, for which BEP 52 omits a
`pieces root`, the VOT envelope defines the 32-byte root as `SHA-256("")`. This
empty-only rule supplies a total VOT object identity and does not alter BEP 52
metainfo or non-empty tree geometry.

The byte-level proof profiles are in `spec/proofs.md`.

## 4. Deterministic CBOR

VOT manifests, proof envelopes, receipts, and equivalence records use the core
deterministic encoding requirements of RFC 8949 section 4.2.1:

- preferred, shortest serialization for integers and lengths;
- definite-length strings, arrays, and maps only;
- map keys sorted by the bytewise lexicographic order of their deterministic
  encodings;
- no floating-point values unless a future schema explicitly admits them; and
- no semantically optional CBOR tags.

Decoders MUST reject a valid but non-deterministic representation when the bytes
are hashed, signed, used as an identity, or published as a conformance vector.
Unknown optional map keys are permitted only where the owning CDDL socket says
so. Unknown required keys or wrong types fail before state mutation.

Schemas use CDDL as defined by RFC 8610 and its grammar update RFC 9682. A CDDL
schema constrains the data model; the deterministic-encoding rules above remain
an additional requirement.

## 5. Manifest pages

A manifest is a sequence of deterministic CBOR pages. Each encoded page is at
most 1 MiB. The page schema is `spec/manifest.cddl`.

Entries are ordered by canonical package path. Page boundaries occur only
between entries. Each page states its zero-based index, total page count for a
sealed manifest, previous-page digest, and entry range. Lookup indexes store
page and entry positions rather than duplicating entry metadata, allowing a
million-file manifest to be processed with bounded resident memory.

A sealed manifest has a fixed ordered page list and package identity. A
progressive manifest uses a page chain whose total is initially absent. Every
accepted page authenticates its predecessor and its contained verification-group
commitments. `SEAL` binds the final page count, terminal page digest, and
canonical package root. Reorder, replay conflict, omission, truncation, or source
mutation prevents sealing.

### 5.1 Canonical package root

The v0 package identity uses `blake3-bao64` over one canonical transcript. The
transcript begins with the bytes `VOT package v0` followed by one zero byte.
Each regular-file entry then contributes the following fields in canonical path
order:

1. the four-byte big-endian length of the encoded path;
2. the encoded path, consisting of a two-byte big-endian component count and,
   for every UTF-8 component, its two-byte big-endian byte length and bytes;
3. the two-byte big-endian logical object suite identifier;
4. the eight-byte big-endian logical file length; and
5. the 32-byte logical object root.

The package transcript describes logical files. Pack roots, pack offsets, and
carrier choices do not affect package identity. v0 package entries use the
`sha256-bep52-64k` logical object suite identifier `2`.

## 6. Path profiles

Manifest paths are arrays of components, never separator-containing strings.
Empty components, `.` and `..`, NUL, and platform separators are forbidden.

The portable profile additionally rejects:

- invalid UTF-8;
- absolute, drive-qualified, UNC, or device paths;
- Windows reserved device names after case folding and trailing-dot/space
  normalization;
- Win32 reserved punctuation, control characters, bidi overrides, isolated join
  controls, and names that normalize to dot components under NFKC;
- collisions after Unicode normalization and platform case folding; and
- components or total paths above declared portable limits.

The raw-POSIX profile carries byte-string components of 1 to 255 bytes. It
excludes NUL, `/`, and `\`, and the components `.` and `..` exactly. A name
that merely begins with a dot is a name. Excluding `\` refuses a filename that
is legal on POSIX, because a component holding a separator stops being one
component on a host that extracts with that separator; such a name belongs in
the portable profile. A path is at most 256 components. A receiver MUST
preflight collisions and target-policy validity before creating any path. Sanitization does not silently merge two manifest entries;
the package is rejected or an explicit, audited materialization mapping is used.
Portable collision keys conservatively fold the Turkish dotted and dotless I
pairs to the same key. This is locale independent and prevents a package that is
distinct on one host from colliding under a Turkish locale on another.

The raw-POSIX rules for `.`, `..`, and `\` narrowed in draft revision 5. A
manifest written before it that used any of them decodes as invalid rather
than as a path, which is the intended outcome: those are the components that
let an extraction leave its destination.

## 7. Pack objects

Files no larger than 256 KiB are pack candidates by default. Candidate files are
ordered by canonical package path. A pack targets 64 MiB and MUST NOT exceed
128 MiB. A logical file never straddles packs.

Each file is stored as raw bytes followed by zero padding to the next 8-byte
boundary, except that padding after the final file MAY be omitted. Padding is
part of the pack object's bytes and identity but not the logical file. The
manifest maps each logical path to pack object identity, byte offset, byte
length, logical-file hash, and metadata. Offset plus length MUST remain inside
the pack without overflow.

A pack is completely built and sealed before its immutable identity is
advertised. Pack objects use the same verification suites and 64 KiB groups as
ordinary objects.

## 8. Compression

Compression is optional per transport record and never changes object identity.
V0.3 defines `none` and `zstd-record`; it defines no cross-record dictionary.
Encoded and decoded lengths are explicit and bounded before allocation. A
maximum expansion ratio is enforced.

Senders sample content and enable compression only when predicted gain meets the
configured threshold, 5% by default. Media types known to be incompressible are
skipped unless policy overrides them. Receivers verify plaintext bytes against
the object identity after decompression.

## 9. Dual-suite equivalence

An equivalence record contains both complete object identities, the trusted
verifier identity, verification time and clock source, policy scope, and an
authenticated signature or MAC. It is created only after the trusted verifier
reads the entire byte string and computes both roots.

An equivalence record is exact-length scoped and does not create a third object
identity. Revocation deletes the alias mapping; it never changes either object
identity. An authorized store SHOULD reference one immutable extent from both
identities rather than duplicate bytes.

## 10. HAVE maps

HAVE state describes verified 64 KiB groups. It is suite- and exact-length
scoped. The canonical representation is a sequence of non-overlapping runs
sorted by start group:

```text
(start_group, group_count)
```

Both values are positive QUIC varints except `start_group`, which may be zero.
Adjacent runs MUST be merged. Runs outside the object geometry, overlapping
runs, zero counts, arithmetic overflow, wrong-suite maps, and stale map sequence
numbers are rejected. A HAVE map never represents merely received or
transport-acknowledged bytes.

## 11. References

- BLAKE3 official specification and implementation:
  <https://github.com/BLAKE3-team/BLAKE3>
- Bao encoding specification:
  <https://docs.rs/crate/bao/latest/source/docs/spec.md>
- Grouped Bao tree implementation documentation:
  <https://docs.rs/bao-tree/latest/bao_tree/>
- BEP 52:
  <https://www.bittorrent.org/beps/bep_0052.html>
- RFC 8949 deterministic CBOR:
  <https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2>
- RFC 8610 CDDL:
  <https://www.rfc-editor.org/rfc/rfc8610.html>
- RFC 9682 CDDL grammar update:
  <https://www.rfc-editor.org/rfc/rfc9682.html>
