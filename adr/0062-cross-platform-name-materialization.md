# ADR-0062: Cross-platform name materialization

- Status: Accepted architectural boundary; destination preflight is not implemented.
- Date: 2026-09-12
- Applies to: future capture source, package materialization, and mounted namespace adapters.

## Problem

A macOS project folder named `XML:EDL` cannot be opened through ordinary Windows
filename APIs. Windows reserves colons for stream syntax. A valid source name
therefore does not imply a usable destination path. Existing VOT portable
packages already reject this component and alternate-stream names. The
regression corpus now names this production example explicitly.

Portable validation is necessary but does not establish compatibility with
every destination. The manifest collision key has fixed normalization and
folding rules. Actual filesystem equivalence can differ, and full path limits
include the selected root and native character encoding. The existing receiver
does not yet preflight these destination-specific constraints before staging.

## Decision

Keep content identity independent of a filename. Preserve original source name
components in the namespace; do not substitute them into capture payload or
journal filenames. A rename must not change content identity or require copying
payload. The current `CaptureFile` internal names already satisfy this boundary.

Portable package ingress rejects incompatible names with their original path
and a specific reason. It must never silently turn `XML:EDL` into `XML_EDL`:
both names may already exist, and project references can depend on the original.
Raw POSIX names remain explicitly nonportable. Do not change canonical manifest
normalization to emulate one host's filesystem.

Before materializing a namespace, the destination adapter must validate the
whole proposed tree against its actual target capabilities and existing names:

- Illegal characters, reserved device names, streams, trailing spaces and dots.
- Native case and Unicode equivalence, including decomposed forms and names
  whose equivalence differs from the manifest's collision key.
- Component and full path limits in native units, including the selected root.
- File-versus-directory conflicts, aliases, and escape through links or reparse
  points. Writes remain relative to retained, validated directory handles.

Preflight reports conflicting original paths before creating staging entries or
transferring payload. Final creation still refuses overwrites and revalidates
containment because the destination may change after preflight.

A future mounted namespace may offer an explicit reversible name projection.
That projection must preserve original names separately, reserve its escape
syntax, detect collisions with literal escaped names, and persist the same
mapping across clients and restarts. It must not promise that renaming is
transparent to editing applications or their embedded path references. Without
an approved projection, report incompatibility; do not expose an inaccessible
directory as a successful mount result.

## Implementation boundary

This decision adds no mapping table, mount driver, new namespace format, or
destination capability framework now. Implement destination preflight when
extending package materialization; implement projection only with the mounted
namespace that needs it. Native regression cases must include `XML:EDL`, stream
syntax, case and normalization collisions, reserved names with extensions,
long selected roots, and a pre-existing name that conflicts with a projection.

[Microsoft's filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
and [path length rules](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
define the Windows side of this boundary. Application compatibility remains a
separate requirement from what the filesystem itself can store.
