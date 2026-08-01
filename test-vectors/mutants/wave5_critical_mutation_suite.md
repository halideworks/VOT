# Wave 5 critical mutation suite

Wave 5 mutation tests use cargo-mutants 26.0.0 and Rust 1.85.0. Every Wave 5
crate is required in CI.

```text
vot-transport-tcp:    78 total,  69 caught,  9 unviable, 0 missed
vot-resume:          118 total, 111 caught,  7 unviable, 0 missed
vot-commit-platform:  16 total,   9 caught,  7 unviable, 0 missed
aggregate:           212 total, 189 caught, 23 unviable, 0 missed
```

The review-critical publication and recovery dependencies are also required:

```text
vot-cli:         203 total, 183 caught, 20 unviable, 0 missed
vot-receipt:     219 total, 215 caught,  4 unviable, 0 missed
vot-platform-fs:   1 total,   1 caught,  0 unviable, 0 missed
aggregate:       423 total, 399 caught, 24 unviable, 0 missed
```

Across the Wave 5 crates and those dependencies, 635 mutants were tested: 588
were caught, 47 were unviable, and none were missed.

The only platform exclusions are the thin native `sync_file` and `sync_parent`
standard-library wrappers. Their required operation ordering is mutation-tested
through the injected `Operations` implementation, and CI executes the native
provider on Windows and macOS.

The Windows-only `MoveFileExW` wrapper is excluded from Linux mutation because
it is not compiled there. Its safe Unix counterpart remains required in
mutation testing, and native Windows CI executes repeated replacement.
