#!/usr/bin/env python3
"""Write crates/vot-codec/src/generated.rs from spec/registries.yaml."""

from __future__ import annotations

if __package__:
    from .registries import GENERATED_PATH, REGISTRY_PATH, ROOT, load_registries, render_identifiers
else:
    from registries import GENERATED_PATH, REGISTRY_PATH, ROOT, load_registries, render_identifiers


def main() -> int:
    document = load_registries(REGISTRY_PATH)
    GENERATED_PATH.write_text(render_identifiers(document), encoding="utf-8")
    print(f"wrote {GENERATED_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
