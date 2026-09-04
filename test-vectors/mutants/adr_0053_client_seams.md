# ADR-0053 client seams

Criterion: `build_manifest` names every source in place and refuses what a
bundle build refuses; `push_from` and `fetch_bundle_with` refuse bad
arguments before a dial and report progress in order, once per quantum,
once at the end.

Passing evidence: `cargo mutants --in-diff` over the change, run twice.

Featureless (`.cargo/mutants.toml`, `crates/vot-cli/src/package/build.rs`):
14 mutants, 7 caught, 7 unviable, none missed, no timeouts. The read loop
in `name_stream` is bounded by the promised length; an earlier shape that
looped until end of file hung under `replace == with != in name_stream`
on an empty source, and was restructured rather than waived.

Wire (`--features wire --config .cargo/mutants-live.toml --timeout 300
--jobs 2`, `wire/push.rs` and `wire/fetch.rs`): 56 mutants, 45 caught,
11 unviable, none missed, no timeouts. An earlier shape kept the quantum
arithmetic inline in `Reporter` and missed thirteen mutants a loopback
push cannot reach (one pass takes the whole object); the arithmetic is
now `crossed_quantum` and `report_due`, killed by
`push_progress_reports_once_per_quantum_and_once_at_the_end`. The fetch
rail bound is `valid_fetch_rails`, killed by
`fetch_rail_count_uses_the_whole_supported_range`; the end-report
comparison in `fetch_bundle_with` is killed by the two fetches in
`a_fetch_through_options_reports_what_it_placed` (a quantum past the
package, then a quantum of one).

Observed failure for the bounded loop, hand-applied `replace > with >= in
name_stream`:

```text
a_manifest_built_in_place_serves_the_source_files_uncopied: SourceMutation
```
