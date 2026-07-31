# Reproducible Builds and Results

The repository pins the Rust edition, minimum toolchain, lockfile, registry
allocations, schemas, and conformance vectors. CI runs without real sleeps for
deterministic state-machine tests.

A release or benchmark result bundle records:

- source commit and dirty-worktree state;
- toolchain and dependency lock hashes;
- target triple, operating system, kernel, filesystem, storage-provider, CPU,
  memory, NIC, and relevant firmware metadata;
- build profile and feature flags;
- simulator seed, scenario version, trace hash, and configuration;
- telemetry redaction and sampling settings;
- impairment and workload definitions; and
- raw machine-readable results plus the command used to produce them.

Release builds use locked dependencies. SBOM and provenance attestations are
produced alongside artifacts. Rebuilding with the declared environment must
reproduce protocol vectors byte-for-byte; binary reproducibility is a release
goal and any known platform variance is documented.

Named commercial baselines are excluded unless an explicit legal-review flag is
present. The primary benchmark metric is time to root-verified publication at
the declared assurance profile.
