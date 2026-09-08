# ADR-0049: Assemble a server from what the host holds

- Status: Accepted
- Date: 2026-09-02
- Decision owners: A00 architecture; A10 transport
- Applies to: `crates/vot-cli` (`BundleServer::assemble`, `ServedSource`,
  `ServedObject::build_at`, `prepared_from_leaves`). No change to any spec
  file, wire identifier, or conformance vector. Companion to ADR-0048
  (serve, the host admits), whose seam takes the server this ADR builds.

## Context

`BundleServer::open` takes a bundle directory: `manifest/` with pages and
seal, and `objects/<root>` for every stored object. A host that serves
files it already keeps under their own names, such as a portal serving a
delivery of library files or received uploads, would have to lay a bundle
directory out per package, by copy or hard link, before it could serve.

Opening also reads and hashes every object unless a `.leaves` cache sits
beside it, about 1.4 seconds a gigabyte on one core. Only `send` writes
that cache. A host that hashed the same files when it took them in already
holds their proof leaves and has nowhere to hand them over.

## Decision

`BundleServer::assemble(manifest_root, sources)` builds the same server
`open` builds, from a manifest directory and a map from stored object root
to `ServedSource { path, leaves }`.

- `manifest_root` holds `manifest/` with its pages and seal, exactly as a
  bundle does. The chain walk, the seal check, and the page digests are
  the ones `open` performs; both go through one `from_manifest` that
  resolves each stored object once, in ascending root order.
- Sources are keyed by stored root, not logical root. Entries the manifest
  packs share one stored root, and the host supplies that pack as one
  source; a host that builds its own manifest from direct entries has no
  packs and supplies one file per entry.
- A source with `leaves` rebuilds its proving layer from them and checks
  the object's length and its first and last groups at open, as the cache
  path does. The layer must name the source's root; a source whose leaves
  or bytes name another object is refused with `RootMismatch`. Leaves the
  host supplies are its claim and a stale claim is refused, not quietly
  replaced by a read, so the host learns its leaves are stale.
- A source without `leaves` is read once, as `open` reads an uncached
  object. So is an object of one group or less whatever leaves accompany
  it: it has no tree to rebuild.
- The file's own failures to stat, seek, or read are surfaced as they
  are, not as a verdict on the leaves.
- A manifest naming an object `sources` lacks, and a source the manifest
  never names, are both `InvalidBundle`: the first cannot be served and the
  second is a host naming the wrong package. A source read in full that
  ends short is `SourceMutation`, as when opening a bundle.
- The witness, the served-groups set, mutation checks, and everything that
  answers a range are unchanged; an assembled server serves through the
  same `service` as an opened one.

## Consequences

- A host serves what it holds where it holds it. With leaves, a server
  over a 100 GiB delivery opens in the time it takes to stat and sample
  its files rather than read them.
- Memory: one `ServedObject` per stored object as before; the leaves the
  host passes are the layer's own material, 32 bytes per 64 KiB group.
  CPU: two group hashes per object with leaves, a full read without.
  Storage and wire: none.
- Not decided here: writing leaves at publish so a received bundle carries
  them like a sent one, and a manifest handed over in memory rather than
  as a directory, which the page-by-page reads in `service` would need to
  change for.

## Required verification

- `an_assembled_server_serves_from_where_the_host_keeps_its_objects`: two
  direct objects copied out of a bundle under host names, one with its
  leaves and one without; the bundle's `objects/` removed; the assembled
  server reports the package and two objects, prepared exactly one from
  leaves, and a fetch over a duplex pair completes and names the package.
- `an_assembled_server_reads_a_one_group_object_whatever_its_leaves`.
- `an_assembled_server_refuses_leaves_that_name_another_object`: another
  object's leaves, and the right leaves with one middle leaf altered, which
  only the rebuilt root catches.
- `an_assembled_server_refuses_a_truncated_object_behind_valid_leaves`:
  bytes appended, which only the length catches, and truncation.
- `an_assembled_server_refuses_a_missing_or_unnamed_source`.
- Mutants recorded in `test-vectors/mutants/adr_0049_assemble.md`.
