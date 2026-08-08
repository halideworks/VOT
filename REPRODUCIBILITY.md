# Reproducible Builds and Results

The repository pins the Rust edition, minimum toolchain, lockfile, registry
allocations, schemas, and conformance vectors. CI runs without real sleeps for
deterministic state-machine tests.

## Result bundle

A release or benchmark result bundle records:

- source commit and dirty-worktree state;
- toolchain and dependency lock hashes;
- target triple, OS, kernel, filesystem, CPU, memory, NIC, firmware;
- build profile and feature flags;
- simulator seed, scenario version, trace hash, configuration;
- telemetry redaction and sampling settings;
- impairment and workload definitions;
- raw machine-readable results and the command used to produce them.

Release builds use locked dependencies. SBOM and provenance attestations are
produced alongside artifacts.

Rebuilding with the declared environment must reproduce protocol vectors
byte-for-byte. Binary reproducibility is a release goal; any known platform
variance is documented.

The primary benchmark metric is time to root-verified publication at the
declared assurance profile.
