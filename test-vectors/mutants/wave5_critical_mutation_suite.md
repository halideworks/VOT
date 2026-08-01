# Wave 5 critical mutation suite

Wave 5 mutation tests use cargo-mutants 26.0.0 and Rust 1.85.0. Every Wave 5
crate is required in CI.

```text
vot-transport-tcp:    90 total,  81 caught,  9 unviable, 0 missed
vot-resume:          130 total, 122 caught,  8 unviable, 0 missed
vot-commit-platform:  28 total,  21 caught,  7 unviable, 0 missed
aggregate:           248 total, 224 caught, 24 unviable, 0 missed
```

The review-critical publication and recovery dependencies are also required:

```text
vot-cli:         226 total, 206 caught, 20 unviable, 0 missed
vot-receipt:     219 total, 215 caught,  4 unviable, 0 missed
vot-platform-fs:   1 total,   1 caught,  0 unviable, 0 missed
aggregate:       446 total, 422 caught, 24 unviable, 0 missed
```

The shared carrier dependencies changed during the final review also remain
required:

```text
vot-transport-api:     22 total, 21 caught, 1 unviable, 0 missed
vot-transport-msquic:  45 total, 43 caught, 2 unviable, 0 missed
aggregate:             67 total, 64 caught, 3 unviable, 0 missed
```

Across the Wave 5 crates and those dependencies, 761 mutants were tested: 710
were caught, 51 were unviable, and none were missed.

The only platform exclusions are the thin native `sync_file` and `sync_parent`
standard-library wrappers. Their required operation ordering is mutation-tested
through the injected `Operations` implementation, and CI executes the native
provider on Windows and macOS.

The Windows-only `MoveFileExW` wrapper is excluded from Linux mutation because
it is not compiled there. Its safe Unix counterpart remains required in
mutation testing, and native Windows CI executes repeated replacement.
