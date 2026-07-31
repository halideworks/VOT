# VOT

Verified Object Transport is a protocol and implementation for transferring
immutable objects and publishing them with explicit receiver assurance.

The project is in early development. The v0.3 specifications are in `spec/`.
Implementation order and acceptance gates are defined in
`VOT_v0.3_Agent_Backlog.yaml`.

## Validation

```sh
python3 tools/validate_registries.py
python3 tools/validate_wire_vectors.py
python3 tools/validate_security_matrix.py
python3 tools/validate_wave0.py
python3 tools/verify_wave1_vectors.py
python3 tools/verify_manifest_pack_vectors.py
python3 tools/validate_commit_fixtures.py
cargo test --workspace --locked
```

## License

GNU Affero General Public License version 3 only. See `LICENSE`.
