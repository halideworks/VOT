# ADR-0011: VOT implementation uses AGPL-3.0-only

- Status: Accepted
- Date: 2026-07-31
- Decision owner: David Torcivia

## Decision

VOT implementation source and project material are licensed under the GNU
Affero General Public License version 3 only, identified by SPDX expression
`AGPL-3.0-only`.

The protocol specifications, conformance and falsification vectors, and formal
models in `spec/`, `test-vectors/`, and `models/` are licensed under Apache-2.0.
This exception permits independent implementations without licensing the VOT
implementation itself under permissive terms.

The complete license texts are stored in `LICENSE` and `LICENSE-APACHE`. Source
distributions retain both files, the directory license markers, and the project
notice. Dependency licenses remain their own and must pass the dependency
policy.

## Consequences

Modified implementation versions offered to users over a network must provide
corresponding source as required by section 13 of the AGPL. Contributions are
accepted under the license of the target path and require the contributor
license agreement in `CLA.md` when non-trivial, preserving the Project Owners
ability to offer commercial implementation licenses. Proprietary source and
incompatible dependencies are not accepted.
