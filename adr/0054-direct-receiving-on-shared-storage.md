# ADR-0054: Direct receiving on shared SMB and NFS storage

- Status: Accepted
- Date: 2026-09-10
- Applies to: `vot-platform-fs`, `vot-journal`, `vot-commit-posix`,
  `vot-commit-strict`, `vot-sdk-file`, `vot-verified-range`, `vot-sdk`,
  `vot-scheduler`, `vot-cli`, and `vot-receipt`. No transfer wire format or receipt
  assurance identifiers change. Receipt provider `0x0005` identifies `POSIX_NAS`.

## Context

Facilities receive media onto shared storage. Requiring local payload staging,
a second full-size copy, or an administrator-provisioned staging share defeats
that workflow. Existing POSIX publication already links a temporary name to its
final name on the same filesystem; this is one inode, not a payload copy.
However, cleanup requires a parent that other users cannot modify, so a shared
project directory cannot safely serve as that temporary namespace.

Linux SMB and NFS clients provide server flush and stable-write operations.
The current blanket refusal of Balanced on those filesystems prevents a
qualified deployment from using them. Successful syscalls do not establish the
server's configuration or power-loss behavior. Direct I/O bypasses the client
page cache and does not establish independent server-side readback.

## Decision

The receiver writes the payload once on the selected filesystem, under an
application-managed `.vot-stage` child. The application creates and protects
this child; the administrator does not provision a separate location. The
selected directory's permissions remain unchanged. Publication creates the
final hard link without replacement, checks its identity, makes the namespace
operation durable, and removes the private temporary name. A server without
these operations is refused; there is no fallback payload copy.

Open directory handles anchor subsequent operations on filesystems with
relative namespace semantics, including the tested Linux NFS client. The destination and
private child handles can be shared across receivers. Journal creation,
compaction, replay, removal, staging access, identity checks and directory
flushes use retained directories. Lookups reject symlinks and non-regular files.
Staging read access reopens a read-only descriptor and compares it with the held
staging identity. A cloned writable descriptor is not read-only access.

Only a protected directory permits identity-check followed by unlink. Retaining
a shared parent handle alone cannot make that pair atomic. Cancellation never
unlinks a final name in a shared directory, and never removes the private child
by name from its shared parent. Ambiguous publication retains recovery evidence
and cannot emit a success receipt. Consumers must preserve and reconcile such
records before attempting cleanup. Incoming package paths reserve `.vot-stage`,
including case variants when hidden files are otherwise allowed.

`NasContract::ServerAcknowledged` is an explicit administrator assertion of
stable server acknowledgments and server-enforced access controls. The qualification includes actual service
ownership and owner-only access across all named users and groups. On Linux
CIFS it must also exclude other principals from renaming or replacing the
private namespace and every path ancestor while receiving. CIFS implements
VFS directory-relative operations using full remote pathnames; a retained Linux
directory descriptor does not anchor those operations to a remote FileId.
CIFS mode/UID mappings alone do not establish actual ACL exclusion or ownership.
Default pathname constructors therefore refuse detected Linux NAS mounts.
The distinct qualified-directory constructor requires this complete contract.
The consumer
persists it with its storage configuration and transfer recovery state. On Linux,
VOT additionally checks the held file's mount identity and effective client
options: SMB3, server inode identities and real ACL/POSIX permission support;
or hard-mounted NFS4. Read-only mounts, disabled strict sync, loose caching,
synthetic dynamic permissions, mode-from-SID presentation and disabled client
permission checks are refused.
An unattached mount is refused rather than resolved onto its underlying local
directory. Server configuration must honor SMB FLUSH, NFS stable WRITE/COMMIT,
and synchronous namespace operations. NAS model names do not imply this
configuration. Other platforms retain their existing supported profiles until
the corresponding client contract is qualified.

Qualified Linux NAS receiving can request Balanced. The ordinary transfer
verifies authenticated ranges before writing, then waits for file and namespace
acknowledgments before reporting completion. It requires neither a second payload
write nor an unconditional full readback. Strict remains unsupported on NAS;
no receipt claims independent at-rest verification without that evidence.
Uncertain restart recovery can require reading and verifying existing bytes.
It must not turn uncertain coverage into trusted coverage merely because the
journal or an open call succeeded.

The scheduler passes its opaque verification witness through counting and
shared sink adapters. An SDK consumer converts that witness without copying
the bytes or verifying the same proof twice. Native receive hooks can write
directly into their final receiver instead of a transport object followed by
a second payload copy. Plain file sinks keep their existing placement method.

A custom `ReceiveSink` can report its own trusted contiguous checkpoint prefix.
The fetch validates its length and range-unit alignment, seeds request coverage
and placed-byte accounting, and invokes the completion flush even when the whole
object was retained. The callback runs outside the plan lock; abandonment or a
callback failure discards the chosen sink before any request can use it. Custom
sinks never inherit the transport directory's checkpoint map. The consumer still
verifies uncertain stored bytes before reporting successful completion. The
prefix adds no payload allocation or hashing; retries avoid retransmitting that
prefix. No wire format, object identity or assurance level changes.

Applications can retain a successful publication journal until their own
metadata checkpoint is committed. Dropping or parking the receiver releases
handles while keeping that journal. Forgetting it requires the bound final
identity and a Published journal state; it does not hash an ordinary completed
file again. A restart before that checkpoint uses the bounded content-verifying
recovery operation. An unresolved or conflicting publication stays preserved.

The final filename becomes visible after verification. Exposing it from the
first byte would let unrelated editors and watch folders consume incomplete
media. Temporary and final names share the same allocation during publication;
there is no second payload reservation. A consumer's reception workflow must
also avoid a hidden snapshot-copy prerequisite: it can pin the received source
and verify outgoing ranges, refusing source changes, or use a qualified native
snapshot without a full-copy fallback.

## Verification

Correctness checks cover shared-parent permissions, actual server ACL exclusion,
ancestor renames, substituted symlinks and files, conflicting publishers, flush
errors, lost publication acknowledgments, cancellation and restart recovery.
Adversarial variants must fail without deleting unrelated entries or producing
a stronger receipt. Directory descriptors remain bounded when receivers park.

The NAS sanity workload includes 100,000 valid EXR frames and a fully written
large file of at least 32 GiB. Both SMB and NFS exercise actual authenticated
receiving, byte verification, interruption/resume and allocation accounting.
Measurements include sender preparation through verified receiver completion,
including final storage acknowledgment. Baseline and candidate use the same rig,
workload and assurance. Sparse allocation alone is not a throughput result.
Large fixtures run separately from ordinary unit and mutation suites.

Samba and Linux NFS fixtures qualify only their tested configuration. They do
not qualify PowerScale, Qumulo or another appliance, and a process interruption
test is not an appliance power-loss test.

## References

- [Linux CIFS mount behavior](https://kernel.org/doc/html/latest/admin-guide/cifs/usage.html)
- [Linux CIFS directory operations](https://github.com/torvalds/linux/blob/master/fs/smb/client/cifsfs.c)
- [SMB3 POSIX extensions](https://smb3posix.org/spec/latest/smb3_posix_extensions.html)
- [NFSv4.1 stable storage and COMMIT](https://www.rfc-editor.org/rfc/rfc8881.html)
- [Strict readback](0001-strict-readback.md)

## Observed implementation constraints

An isolated Samba experiment renamed a held private directory through the server
filesystem and installed a replacement. The client immediately reported the old
private inode through `fstat`, while `openat` created a new file in the replacement.
After attribute cache expiry, `fstat` returned `ESTALE` but `openat` still followed
the replacement. This rejects the hypothesis that Linux CIFS dirfds independently
provide remote namespace continuity. Such mutation must be excluded by the
server contract; otherwise this provider cannot qualify that receiving location.

Post-creation chmod is not a safe workaround for SMB's inherited directory ACL:
`mkdirat` followed by `openat` does not establish that the reopened directory is
the one just created. The receiver never changes an existing directory's ACL.
Private-at-creation semantics must come from negotiated POSIX creation or the
qualified server's ACL inheritance/creation policy.

The NFS fixture exposed a retained SDK writable descriptor after publication,
which left a `.nfs` temporary alias until the receiver was dropped. The SDK now
closes that capability before sealing and publication. The mounted NFS tests
then passed while retaining the completed receiver object.

The 32 GiB Samba fixture exposed stale client allocation accounting: `st_blocks`
reported 16 GiB before publication and 32 GiB afterward for the same inode. An
independent server stat found one link and 32 GiB plus one allocation block;
SHA-256 verified the complete payload. The component harness now asserts inode
continuity on NAS and leaves physical allocation measurement to the server.
Client block-count equality is retained only for the local fixture.
