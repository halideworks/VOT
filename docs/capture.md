# Capture integration

[Back to VOT](../README.md)

VOT has the primitives for preparing changing content and retaining verified
bytes on disk. It does not yet provide a watch-folder uploader or a mounted
remote filesystem. The CLI still transfers immutable packages.

## Available APIs

- `vot_object::ObjectCheckpoint` updates canonical object identities and proof
  metadata from complete changed verification groups. It retains no payload.
  The caller must control the source and report every change.
- `vot_sdk::verify::RetainedRange` owns verified bytes and can authenticate
  unchanged groups against a new checkpoint without rehashing those bytes.
- `vot_sdk_file::capture::CaptureSource` captures an independently opened producer
  file, refreshes dirty groups and changed tails, and verifies the full source
  at explicit completion. The host must keep the producer stopped during finish.
- `vot_sdk_file::capture::CaptureFile` owns private disk staging, invalidates
  coverage before overwriting, and records verified groups after data flushes.
  `select` changes the target identity; `reuse` requires proofs for that target.
  Dropping preserves recovery files. `open` rehashes surviving cached groups.

Capture supports local Unix storage and local NTFS on Windows. Its durability
contract is not qualified for mutable staging on SMB/NFS or other Windows
filesystems. The caller provides an owner-only directory, exclusive same-user
access, a stable incarnation identifier, a group limit, and disk-space quotas.

Payload I/O uses 64 KiB groups and metadata uses one 48 KiB page. The source
adapter adds a reusable 65,537-byte buffer. Journal replay has a separate 64
MiB file bound plus decoded records. Proof metadata also has its own cost;
these limits are not a cap on total process memory.

Capture progress describes durable local bookkeeping. It is not producer
completion, receiver publication, or an at-rest verification receipt. Existing
checkpoint proofs also do not preserve old payload versions automatically.

## Remaining integration

The source adapter leaves filesystem watching and producer coordination to the
host. Refresh hints may miss old writes; final verification refuses a mismatching
source. Replacement requires a new handle, and reopen never preserves completion.
A quiet interval or unchanged metadata does not prove rendering finished.

Live checkpoint transport and receiver publication are next. Cross-platform
destination preflight must reject unrepresentable or colliding names before
materialization. Names such as macOS `XML:EDL` must not be silently renamed on
Windows, where that would also risk breaking project links.

See [incremental checkpoints](../adr/0057-incremental-object-checkpoints.md),
[disk staging](../adr/0059-disk-capture-staging.md),
[paged metadata](../adr/0060-paged-capture-metadata.md),
[Windows capture](../adr/0061-native-windows-capture.md),
[source lifecycle](../adr/0063-growing-file-source-lifecycle.md), and
[filename boundaries](../adr/0062-cross-platform-name-materialization.md).
