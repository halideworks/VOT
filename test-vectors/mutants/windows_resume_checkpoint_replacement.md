# Windows resume checkpoint replacement

Criterion: a compacted resume snapshot atomically replaces the previous log
snapshot on Windows.

Passing evidence: `repeated_checkpoints_append_and_replay` appends two
checkpoint windows and reopens both units. Native Windows CI runs this test
and `replacement_overwrites_existing_file_atomically` in `vot-platform-fs`.

Mutant: use `std::fs::rename` on Windows after the destination exists.

Observed failure:

```text
The second checkpoint returned an AlreadyExists operating-system error.
```

The safe Unix wrapper has one required mutant and catches it. The Windows-only
FFI body is excluded from Linux mutation and executed on native Windows CI.
