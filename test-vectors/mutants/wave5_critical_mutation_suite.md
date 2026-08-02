# Wave 5 critical mutation suite

Wave 5 mutation tests use cargo-mutants 26.0.0 and Rust 1.88.0. Every Wave 5
crate is required in CI.

```text
vot-transport-tcp:    90 total,  81 caught,  9 unviable, 0 missed
vot-resume:          153 total, 146 caught,  7 unviable, 0 missed
vot-commit-platform:  21 total,  14 caught,  7 unviable, 0 missed
aggregate:           264 total, 241 caught, 23 unviable, 0 missed
```

The review-critical publication and recovery dependencies are also required:

```text
vot-cli:         227 total, 207 caught, 20 unviable, 0 missed
vot-receipt:     219 total, 215 caught,  4 unviable, 0 missed
vot-platform-fs:  11 total,  11 caught,  0 unviable, 0 missed
aggregate:       457 total, 433 caught, 24 unviable, 0 missed
```

The shared carrier dependencies changed during the final review also remain
required:

```text
vot-transport-api:     36 total, 35 caught, 1 unviable, 0 missed
vot-transport-msquic:  45 total, 43 caught, 2 unviable, 0 missed
aggregate:             81 total, 78 caught, 3 unviable, 0 missed
```

Across the Wave 5 crates and those dependencies, 802 mutants were tested: 752
were caught, 50 were unviable, and none were missed.

The only platform exclusions are the thin native `sync_file` and `sync_parent`
standard-library wrappers. Their required operation ordering is mutation-tested
through the injected `Operations` implementation, and CI executes the native
provider on Windows and macOS.

The Windows-only `MoveFileExW` and file-identity wrappers are excluded from
Linux mutation because they are not compiled there. Their safe Unix
counterparts remain required in mutation testing, and native Windows CI
executes repeated replacement and linked-publication recovery.
