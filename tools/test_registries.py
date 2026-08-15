#!/usr/bin/env python3
"""The registry checker rejects a table the source does not authorize."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

if __package__:
    from .registries import (
        GENERATED_PATH,
        REGISTRY_PATH,
        check_registries,
        load_registries,
    )
else:
    from registries import (
        GENERATED_PATH,
        REGISTRY_PATH,
        check_registries,
        load_registries,
    )

ROOT = Path(__file__).resolve().parents[1]


def sources() -> tuple[dict, str, str, str, str]:
    document = load_registries(REGISTRY_PATH)
    markdown = (ROOT / "spec/registries.md").read_text(encoding="utf-8")
    rust = (ROOT / "crates/vot-codec/src/lib.rs").read_text(encoding="utf-8")
    wire = (ROOT / "spec/wire.md").read_text(encoding="utf-8")
    generated = GENERATED_PATH.read_text(encoding="utf-8")
    return document, markdown, rust, wire, generated


class RegistrySourceSync(unittest.TestCase):
    def test_committed_sources_agree(self) -> None:
        document, markdown, rust, wire, generated = sources()
        self.assertEqual(check_registries(document, markdown, rust, wire, generated), [])

    def test_dropped_frame_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = copy.deepcopy(document)
        mutated["frames"] = [row for row in mutated["frames"] if row["name"] != "HELLO"]
        failures = check_registries(mutated, markdown, rust, wire, generated)
        self.assertTrue(
            any("HELLO" in item or "frame" in item for item in failures),
            failures,
        )

    def test_swapped_operation_value_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = generated.replace(
            "pub const PUBLISH: u64 = 0x0001;",
            "pub const PUBLISH: u64 = 0x0004;",
            1,
        )
        self.assertNotEqual(generated, mutated)
        failures = check_registries(document, markdown, rust, wire, mutated)
        self.assertTrue(any("operation" in item or "stale" in item for item in failures), failures)

    def test_stale_generated_file_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = generated.replace("IDLE_TIMEOUT_MS", "IDLE_TIMEOUT", 1)
        self.assertNotEqual(generated, mutated)
        failures = check_registries(document, markdown, rust, wire, mutated)
        self.assertTrue(any("generated.rs is stale" in item for item in failures), failures)

    def test_markdown_missing_a_row_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = markdown.replace(
            "| `0x0001` | `PUBLISH` | draft |\n",
            "",
            1,
        )
        self.assertNotEqual(markdown, mutated)
        failures = check_registries(document, mutated, rust, wire, generated)
        self.assertTrue(
            any("markdown operations" in item or "markdown view" in item for item in failures),
            failures,
        )

    def test_markdown_receipt_length_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = markdown.replace(
            "| `0x0001` | `ED25519` | 64 bytes | required v1 |",
            "| `0x0001` | `ED25519` | 32 bytes | required v1 |",
            1,
        )
        self.assertNotEqual(markdown, mutated)
        failures = check_registries(document, mutated, rust, wire, generated)
        self.assertTrue(
            any("receipt_schemes" in item for item in failures),
            failures,
        )

    def test_handling_parity_is_rejected(self) -> None:
        document, markdown, rust, wire, generated = sources()
        mutated = copy.deepcopy(document)
        capacity = next(row for row in mutated["frames"] if row["name"] == "CAPACITY")
        capacity["handling"] = "critical"
        failures = check_registries(mutated, markdown, rust, wire, generated)
        self.assertTrue(
            any("CAPACITY" in item and "critical" in item for item in failures),
            failures,
        )


if __name__ == "__main__":
    unittest.main()
