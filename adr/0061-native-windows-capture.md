# ADR-0061: Native Windows capture

- Status: Accepted design for local NTFS.
- Date: 2026-09-12
- Applies to: `vot-sdk-file::capture`, `vot-journal`, and `vot-platform-fs`.
- Extends ADR-0059 and ADR-0060 to local NTFS.

## Decision

Use the existing capture state machine, paged metadata, journal format and
recovery ordering on Windows. Native directory, ownership, sparse-file and
positioned-I/O operations live in `vot-platform-fs`. There is no second capture
engine or platform-specific capture format.

Admit local NTFS only. Query the filesystem and remote-device flag through the
retained directory handle. Reject reparse directories and other filesystems.
NTFS's directory flush covers persistent directory structure; other Windows
filesystems can return success without implementing that operation. A successful
generic flush call alone is insufficient admission evidence. This does not
qualify SMB, ReFS, FAT, power-loss behavior, or arbitrary storage hardware.

The retained directory permits reads and writes but denies deletion sharing.
Every child operation uses one validated leaf relative to that handle through
`NtCreateFile`. Payload and metadata handles permit read sharing only. The
journal also permits deletion sharing so it can be atomically replaced, while
denying write sharing for its entire lifetime. This ownership rule applies to
aliases of the same file. Windows journals report sharing violations as
`Error::Locked`; Unix retains its existing advisory lock.

Created files receive an explicit protected ACL granting access only to the
current owner, administrators, and LocalSystem. Every write-capable child open
checks the file's owner and ACL before bytes are written or replayed. Parent
permissions alone do not protect a child with an explicit permissive ACL.
Parent mutation checks remain required for replacement and removal. Same-user
coordination remains the caller's responsibility, including journal namespace
changes and ACL changes while an owner is active.

Compaction flushes metadata and the replacement journal, then uses
`FileRenameInformationEx` with replacement and POSIX semantics relative to the
held destination directory. Both journal handles remain open through rename and
directory flush. The common journal code then adopts the new handle. Failure
after an ambiguous rename poisons the owner; no close-and-reopen ownership gap
or path-based copy fallback is introduced.

NTFS's volume serial number and 64-bit file index fit the existing `VOTCAP02`
binding fields. Link counts and identities still gate capture admission and
operations. Read sharing can permit a new hard-link alias; the alias cannot open
a second writer, and the changed link count refuses further capture use and
recovery until the alias is removed. No format bump or compatibility reader is needed.

## Resource boundary

Payload I/O borrows the caller's slice. Recovery reuses one 64 KiB payload
buffer; metadata retains its 48 KiB page. Native sparse queries return one
allocated-range record at a time. File lookup reuses the metadata already read
for file-type validation. There is no payload-sized allocation, whole-file
copy, resident extent list, or new dependency.

## Validation

The shared capture suite and process-termination test compile on both Unix and
Windows. Native tests cover open-destination replacement, writer exclusion,
directory flushing, sparse holes, non-inheritable parent ACLs, permissive child
ACLs, and rejected leaf names including `XML:EDL` and alternate streams.
`proof-store-native` runs journal, file SDK and platform tests on Windows;
the corresponding Unix adapters remain covered on Linux and macOS.

Seven alternating warm-cache recoveries of the same 512 MiB capture on the same
Linux/ZFS host measured these medians against `9eb500d`:

| Journal state | Before | Windows capture change | Peak RSS, both versions |
| --- | ---: | ---: | ---: |
| Uncompacted | 1.747 s | 1.647 s | 5,120 KiB |
| Compacted | 0.235 s | 0.225 s | 2,240 KiB |

The uncompacted samples vary substantially (0.48 to 2.55 seconds for the base);
these medians are not evidence of a reliable speedup. The runs found no
shared-engine recovery or process-memory regression. They
measure local recovery, including rehashing payload, rather than transfer speed.
Raw samples and the method are in
`test-vectors/experiments/adr_0061_capture_recovery.json`. Native execution results
are recorded by the required CI jobs on the implementation PR. Mutation evidence is in
`test-vectors/mutants/adr_0061_windows_capture.md`.

Source lifecycle, render completion, live capture transport and publication
remain separate milestones. VOTPort is unchanged.

## References

- [MS-FSA flush operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0de7dc40-9627-437e-a4df-c4696cdc3d02).
- [MS-FSA product behavior, directory-flush footnote](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4e3695bd-7574-4f24-a223-b4679c065b63).
- [File rename information and open-destination replacement](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information).
- [Windows traverse privilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/checking-for-traverse-privilege-on-irp-mj-create).
