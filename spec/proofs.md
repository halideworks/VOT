# VOT v0.3 Proof Profiles

Status: normative byte-format freeze for `vot-draft-03`

## 1. Common range-proof bundle

A range response is one logical bundle carried in-band as one `PROOF_BUNDLE`
followed by one or more `DATA_RECORD` frames. All frames in a bundle use the
same request and bundle identifiers. Proof metadata arrives first so the
receiver can reserve bounded state before data.

The deterministic CBOR payload of `PROOF_BUNDLE` is defined by
`spec/proof-bundle.cddl`. Integer map keys and core deterministic CBOR are
mandatory. The payload identifies:

- bundle format version `0`;
- 128-bit request ID and 128-bit bundle ID;
- complete object identity;
- requested offset and length;
- covered group-aligned offset and length;
- data-record count and exact total plaintext length; and
- suite-specific proof bytes.

The covered range is the smallest set of complete 64 KiB verification groups
covering the request. The last group ends at object length. Offset and length
arithmetic is checked before reservation. A zero-length application request is
invalid; an empty object is verified from its identity vector without a range
bundle.

`DATA_RECORD` payloads carry `(bundle_id, record_index, plaintext_offset,
plaintext_length, encoding, encoded_length, bytes)` under the wire schema. Each
plaintext record is at most 256 KiB. Indices begin at zero, are contiguous, and
their concatenated plaintext exactly covers the bundle range. Duplicates must be
byte-identical. Missing, overlapping, conflicting, or excess records invalidate
the bundle.

Proof bytes authenticate the covered data but are not themselves object bytes.
No data contributes to verified state until its complete 64 KiB group verifies.

## 2. Suite 0x0001: `blake3-bao64`

### 2.1 Root and geometry

The object root is the standard 32-byte BLAKE3 digest of the exact complete byte
string. BLAKE3 uses 1,024-byte chunks. The VOT Bao block size is fixed to chunk
group log `6`, giving `2^6` chunks or 65,536 bytes per verification group. This
grouping changes outboard density and range granularity, not the BLAKE3 root.

Let `N = max(1, ceil(byte_length / 1024))` be the BLAKE3 chunk count and let a
VOT block contain 64 chunks except for the final block. Standard BLAKE3 chunk
counters and flags are used. The root node uses the standard BLAKE3 `ROOT` flag.
Implementations MUST NOT hash an independently padded final chunk or group.

### 2.2 Canonical relay outboard

The canonical sidecar is:

```text
u64 little-endian object byte_length
zero or more 64-byte parent records in pre-order
```

A parent record is the 32-byte left child chaining value followed by the 32-byte
right child chaining value. Traversal is parent, left subtree, right subtree.
Only parent nodes at or above the 64 KiB block level are persisted. The final
partial block is hashed from its actual BLAKE3 chunks. For zero or one VOT block,
the outboard contains only the eight-byte length.

The number and positions of parent records are derived from exact length and the
fixed block size. Extra, missing, or trailing bytes make an outboard invalid.

### 2.3 Range proof bytes

The proof byte string is a concatenation of 64-byte parent records in the same
pre-order traversal used by a Bao slice, with selected leaf-group data omitted
because it is carried in correlated `DATA_RECORD` frames.

Starting at the root:

1. If the node is a 64 KiB block selected by the covered range, consume its data
   records and compute its BLAKE3 chaining value from the standard chunks.
2. If a parent intersects selected and unselected blocks, emit its complete
   `(left_cv, right_cv)` record, then recurse in pre-order only into selected
   children. The computed selected child CV MUST equal the corresponding CV in
   the parent record before continuing.
3. If both children are fully selected, emit the parent record and recurse left
   then right. Both computed child CVs MUST match the record.
4. If neither child is selected, emit and consume nothing.
5. At the root, compute the standard BLAKE3 root output and compare all 32 bytes
   with the object identity.

The tree shape, left/right split, chunk counters, chaining values, and root
output follow the BLAKE3 and Bao tree definitions. Because requested ranges are
whole VOT blocks, no proof descends below chunk-group log 6.

The decoder knows the exact number and order of proof records from object length
and covered range. A proof has no count prefix. Any leftover, missing, swapped,
or mutated record invalidates it.

### 2.4 Empty object

The empty root is standard BLAKE3 of the empty byte string. No range bundle is
valid. The canonical outboard is eight zero bytes.

## 3. Suite 0x0002: `sha256-bep52-64k`

### 3.1 Root and geometry

For a non-empty object, divide bytes into consecutive 16 KiB leaves. The final
leaf is hashed at its actual length. Each present leaf is `SHA-256(leaf_bytes)`.
Extend the leaf-hash list to the next power of two with 32 zero bytes per missing
leaf. A parent is `SHA-256(left_hash || right_hash)`. Repeating to one node yields
the BEP 52 file root.

A VOT verification piece is 64 KiB, the tree layer two levels above 16 KiB
leaves. It covers four leaves except at the right edge. Padding remains the BEP
52 zero-hash padding; implementations MUST NOT hash zero-filled byte blocks to
construct missing leaves.

BEP 52 omits `pieces root` for an empty file. VOT's empty object identity is the
special envelope rule `SHA-256("")`, and it has no BEP 52 piece layer or range
proof.

### 3.2 Canonical local piece layer

For every 64 KiB verification piece containing at least one object byte, store
its 32-byte tree hash in increasing piece index. Hashes covering only padding
beyond end of object are omitted. Concatenation has no header; exact object
length determines its expected number of hashes.

Rebuilding the upper tree derives each missing piece node from four zero 32-byte
leaf nodes and recursively hashes missing subtrees until the next power of two.
This is the exact result of the underlying BEP 52 leaf padding; using a raw zero
node at the piece layer would produce a different root. The resulting root MUST match the object identity.

### 3.3 Range proof bytes

The covered range identifies consecutive 64 KiB piece indices. The decoder
computes every covered piece hash from its received 16 KiB leaves.

Proof bytes are a concatenation of 32-byte hashes in BEP 52 order:

1. hashes from the 64 KiB base layer needed to complete the smallest aligned
   power-of-two window containing the covered pieces, in increasing index;
2. then at most one uncle hash from each higher proof layer, starting with the
   layer closest to the base window and ending with the uncle closest to the
   root.

The aligned base window has power-of-two length and is expanded to at least two
piece positions when the tree contains more than one piece. Covered piece hashes
are computed locally and therefore omitted from proof bytes. Positions beyond
the object's piece count use the implicit all-zero padding node for that layer
and are also omitted. At each layer the left/right position is determined by the
aligned index; no direction bits are encoded.

This is the VOT envelope profile of BEP 52 `hash request`/`hashes` geometry: base
hashes precede proof-layer hashes, indices are aligned to a power-of-two window,
and proof hashes progress from the base layer toward the root. The exact object
length and covered range determine how many hashes are consumed. Extra, missing,
reordered, or trailing hashes invalidate the proof.

### 3.4 Single-piece object

For an object of 1 through 65,536 bytes, the receiver computes the complete BEP
52 root from its 16 KiB leaves and implicit zero-hash padding. Proof bytes are
empty.

## 4. Verification procedure

For either suite, a receiver:

1. validates the common envelope and exact object identity;
2. validates range geometry and reserves bounded staging;
3. parses proof structure without allocating from an untrusted count;
4. accepts correlated data records within the declared exact total;
5. decompresses each record under encoded, decoded, and expansion bounds;
6. computes group hashes and validates every proof node to the advertised root;
7. marks only complete successful groups `TRANSIT_VERIFIED`; and
8. discards or quarantines the failed bundle without regressing earlier verified
   state.

A proof for one suite cannot authenticate an identity from the other suite. A
transport ACK, valid compression checksum, or valid record framing is not proof
verification.

## 5. Vector requirements

Each suite publishes object identity, sidecar or piece layer, range geometry,
proof bytes, data records, and expected result for:

- empty and one-byte objects;
- 16 KiB and 64 KiB boundaries on both sides;
- odd and non-power-of-two trees;
- first, middle, final, and multi-group ranges;
- wrong length and wrong root;
- corrupt data and corrupt proof;
- missing, extra, and reordered proof nodes; and
- sparse multi-terabyte logical-length geometry without allocating the object.

Independent implementations MUST agree byte-for-byte before W1 passes.

## 6. Normative references

- BLAKE3 official specification repository:
  <https://github.com/BLAKE3-team/BLAKE3-specs>
- Bao encoding format:
  <https://docs.rs/crate/bao/latest/source/docs/spec.md>
- `bao-tree` grouped geometry and range encoding:
  <https://docs.rs/bao-tree/latest/bao_tree/>
- BEP 52 tree and hash request/response rules:
  <https://www.bittorrent.org/beps/bep_0052.html>
