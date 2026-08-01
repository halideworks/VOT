# Wave 5 critical mutation suite

Wave 5 mutation tests use cargo-mutants 26.0.0 and Rust 1.85.0. Every Wave 5
crate is required in CI.

```text
vot-transport-tcp:    78 total,  69 caught,  9 unviable, 0 missed
vot-resume:          118 total, 111 caught,  7 unviable, 0 missed
vot-commit-platform:  16 total,   9 caught,  7 unviable, 0 missed
aggregate:           212 total, 189 caught, 23 unviable, 0 missed
```

The only platform exclusions are the thin native `sync_file` and `sync_parent`
standard-library wrappers. Their required operation ordering is mutation-tested
through the injected `Operations` implementation, and CI executes the native
provider on Windows and macOS.
