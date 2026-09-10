# Mounted SMB and NFS storage

## Qualified Linux receiving

`vot_sdk_file::ReceiveDirectory` receives directly onto the selected filesystem.
It creates a private `.vot-stage` child automatically. Payload bytes are written
once. Publication hard-links the verified inode to its final name, waits for
the required storage acknowledgments, then removes its temporary name. It does
not reserve or copy a second payload. The selected folder's permissions remain
unchanged. Final filenames become visible after verification.

Use `NasContract::ServerAcknowledged` only after the administrator qualifies:

- stable SMB FLUSH or NFS WRITE/COMMIT acknowledgments and synchronous namespace
  operations on the actual server/export;
- actual receiving-account ownership and owner-only temporary data and metadata,
  including named ACL entries and private access at directory creation;
- for Linux CIFS, server ACLs that prevent other principals from renaming or
  replacing the private child and every ancestor while receiving.

Same-account namespace mutations must be serialized. Displayed CIFS mode bits
and mapped UIDs alone cannot prove the server ACL or ownership. A retained Linux
CIFS directory descriptor does not provide remote directory-identity continuity.
POSIX directory creation or a qualified server creation policy must establish
private access immediately; VOT does not repair permissions with a later chmod.

The library additionally requires SMB3 with `serverino` and `cifsacl` or POSIX
permissions, or hard-mounted NFS4. It refuses disabled flushes, loose caching,
synthetic permissions, read-only storage and a vanished NAS mount. These client
checks do not establish server power-loss behavior. Qualification applies to the
tested configuration, not to every server bearing the same product name.

Qualified NAS can use Balanced: authenticated ranges, stable file acknowledgment
and durable publication. Strict remains unsupported because client direct I/O
does not establish independent server-side readback. Default Linux pathname
constructors refuse detected NAS; they cannot implicitly assert this contract.

Reuse a `ReceiveDirectory` for a sequence. `resume_state()` plus `abandon()` parks
each file without retaining its descriptors. Persist the object identity, final
name, contract and resume state together in trusted local control storage.
After an uncertain restart, verify covered bytes before publishing. When the
final name exists and the journal remains, `recover_publication(..., active)` rechecks the
bound journal, exact object contents and storage acknowledgments without copying.
Use `publish_retaining_journal()` when completion also needs an application
database checkpoint. Both that operation and recovery retain the journal;
call `forget_publication()` only after the checkpoint succeeds. It checks the
bound final identity and Published state without another payload read.
Preserve unresolved journals and files. A consumer must reconcile completion
that outlives its own checkpoint before collecting recovery metadata.

Native custom sinks can implement `ReceiveSink::resumed_prefix()` to skip an
object's trusted contiguous checkpoint. Return zero for a fresh object. Non-final
prefixes must be range-unit aligned and no prefix may exceed the object length.
Keep the checkpoint bound to the exact object and verify uncertain stored bytes
before completion. A directory resume map never seeds a custom sink.

Qualified NAS receipts use provider `POSIX_NAS` (`0x0005`), with the actual
selected profile. This separates server-acknowledged durability from local
storage and does not assert independent NAS readback.

Run both mounted suites with an explicitly qualified disposable test location:

```sh
VOT_TEST_DIRECTORY=/mnt/smb/vot-validation cargo +1.97.1 test -p vot-sdk-file --test shared_directory --locked
VOT_TEST_DIRECTORY=/mnt/nfs/vot-validation VOT_TEST_RENAME_DIRECTORY=/mnt/nfs/vot-validation cargo +1.97.1 test -p vot-sdk-file --test shared_directory --locked
```

The rename case defaults to local storage and can explicitly target NFS. CIFS
requires server-enforced ancestor protection instead of this rename guarantee.
The mounted cases fail on missing or unqualified storage; they do not skip.

For separately generated large fixtures, the component harness admits and parks
every file, verifies ranges, resumes large files halfway, and asserts publication
preserves inode identity (and allocated blocks on local storage):

```sh
cargo +1.97.1 run --release -p vot-sdk-file --example receive_directory -- /test/source /mnt/nfs/new-destination nas balanced
```

Use a fresh destination. Keep fixture source and receive capacity separate.
Independently hash all outputs after the timed run. Measure NAS allocation on
the server; CIFS client block counts can be cached or synthetic. This harness includes sender
preparation and storage publication, but does not measure network transport.
See [ADR-0054](../adr/0054-direct-receiving-on-shared-storage.md).

## Windows and existing CLI sinks

VOT can write through the operating system's existing SMB mount. On Windows,
use a mapped drive such as `X:\` or its UNC path. Authentication and the SMB
connection remain the operating system's responsibility.

```powershell
vot receive C:\VOT\bundle X:\Deliveries\Job-123 X:\Deliveries\Job-123.cbor env:RECEIPT_KEY 2026-09-07T20:00:00Z
```

The destination must not already exist. Staging stays beside the destination
on the same share. Give the receiving account an exclusive staging/delivery
directory through the server's ACLs; a client's displayed Unix mode bits do
not establish exclusion of other SMB clients.

## Initial support and assurance

- Windows native file publication uses the existing Fast profile. Balanced
  and Strict remain unsupported. CLI package receipts also use Fast, with
  transit verification as their predecessor; they do not claim independent
  server-side at-rest verification.
- Samba may reject `FileDispositionInfoEx`. VOT retries only unsupported
  operation/parameter errors with handle-based `FileDispositionInfo`.
  It closes the staging handle to complete deletion, including cancellation
  while the caller retains the sink. Access-denied and unrelated I/O errors
  are not retried through this fallback.
- Publication still requires atomic no-overwrite operations and file identity
  checks. There is no copy-and-delete fallback for a server without hard links.
  Windows package publication uses `MoveFileExW` without replacement enabled.
- Linux default POSIX pathname commits refuse detected kernel SMB/NFS. The
  qualified directory API above admits Balanced under its explicit contract.
  Standalone Strict readback refuses NAS. Other filesystem types are not
  certified by this detection; macOS SMB mounts have not been qualified.
- Any CLI sink write or data-flush failure remains fatal for that sink. A
  later successful flush cannot clear it. Disjoint writes run concurrently;
  final flush and cancellation wait for in-flight writes, and stride
  checkpoints remain serialized.

Linux CIFS directory `fsync` is a no-op because directory operations are
synchronous, and `nostrictsync` disables server flush requests. Neither a
successful directory flush nor opening with direct I/O establishes the
server's power-loss or independent-readback guarantees. Those need a separate
backend conformance profile. See the [Linux CIFS implementation](https://github.com/torvalds/linux/blob/master/fs/smb/client/cifsfs.c),
[mount documentation](https://kernel.org/doc/html/latest/admin-guide/cifs/usage.html),
and [Strict readback requirements](../adr/0001-strict-readback.md).

## Run the share checks

Use a dedicated test directory, never an active media delivery. The tests
create their own child directories and remove them after successful checks.
Failures may leave those test directories for inspection.

```powershell
New-Item -ItemType Directory X:\VOT-validation
$env:VOT_TEST_DIRECTORY = 'X:\VOT-validation'
cargo +1.97.1 test -p vot-sdk-file --test native_file --locked
cargo +1.97.1 test -p vot-cli --test mounted_share --locked -- --ignored
```

The first suite checks out-of-order verified writes, duplicate ranges,
completeness, conflicting destinations, cancellation, and competing publishers.
For qualified Linux SDK receiving use the `shared_directory` suite above.
The opt-in CLI test publishes a bundle with
both packed and direct objects, checks its receipt and contents, retries
receipt recovery, and checks cancellation while retaining the sink.

For sink throughput, compare the same compiler, directory, and worker counts:

```powershell
cargo +1.97.1 run --release -p vot-cli --example measure_sink -- X:\VOT-validation 4
```

This writes and flushes 128 MiB, then checks every byte outside the timed
section. It does not measure VOT network transport or prove crash durability.

Windows services and SSH sessions may not inherit the interactive user's drive
mappings or SMB authentication. Test in the session that owns the mapping, or
configure the service account's access explicitly. A UNC path does not supply
missing credentials.

The initial [Windows-to-Samba results](../bench/results/mounted-share-2026-09-07.md)
record the reproduced failure, passing share tests, and before/after timings.

The recovery callback must report whether the application still owns receiving
storage and permits recovery. It is checked before each bounded read and before
changing publication state. Cancellation returns an interrupted I/O error,
retains recovery files, and produces no publication observation.
