# ADR-0053 client seams

Criterion: `build_manifest` and `build_manifest_from` name every source in
place, in canonical order, and refuse what a bundle build refuses;
`push_from` and `fetch_bundle_with` refuse bad arguments before a dial and
report progress in order, once per quantum, once at the end; `probe_serve`
answers within its budget.

Passing evidence: `cargo mutants --in-diff` over the change, run twice.

Featureless (`.cargo/mutants.toml`, over the whole change): 27 mutants,
13 caught, 14 unviable, none missed, no timeouts. `probe_serve` returns
`Result<(), Error>`, so its `nowire.rs` stub has a viable `Ok(())` body
mutant, killed by `the_wire_commands_name_the_feature_they_need`;
`push_from` and `fetch_bundle_with` return `Result<PackageSummary,
Error>`, whose default-body mutant is unviable. In `build.rs`, the read loop
in `name_stream` is bounded by the promised length; an earlier shape that
looped until end of file hung under `replace == with != in name_stream`
on an empty source, and was restructured rather than waived.

Wire (`--features wire --config .cargo/mutants-live.toml --timeout 300
--jobs 2`, `wire/push.rs` and `wire/fetch.rs`): 74 mutants, 56 caught,
18 unviable, none missed, no timeouts. An earlier shape kept the quantum
arithmetic inline in `Reporter` and missed thirteen mutants a loopback
push cannot reach (one pass takes the whole object); the arithmetic is
now `crossed_quantum` and `report_due`, killed by
`push_progress_reports_once_per_quantum_and_once_at_the_end`. The probe's
wait and its certificate comparison are `certified_within`, shared with
`verify_serve_identity`, and its budget clamp is `probe_idle_ms`, killed
by `a_probe_confirms_the_serve_identity_within_its_budget` and
`a_probe_clamps_its_idle_timeout_to_the_ceiling`. The fetch
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
