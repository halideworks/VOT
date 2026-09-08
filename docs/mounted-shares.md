# Mounted SMB shares

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
- Linux POSIX commits refuse Balanced and Strict on detected kernel SMB/NFS
  filesystems at creation and reattachment. Standalone Strict readback also
  refuses them. Other filesystem types are not certified by this detection;
  macOS SMB mounts have not been qualified.
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
On Linux it also checks that remote filesystems refuse stronger profiles
without leaving staging files. The opt-in CLI test publishes a bundle with
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
