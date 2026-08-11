#!/usr/bin/env python3

import tomllib
import unittest
from pathlib import Path

if __package__:
    from .ci_mutation_packages import EXCLUDED_PACKAGES
    from .ci_mutation_plan import PACKAGES, WIRE_SHARDS, plan
else:
    from ci_mutation_packages import EXCLUDED_PACKAGES
    from ci_mutation_plan import PACKAGES, WIRE_SHARDS, plan


class MutationPlanTests(unittest.TestCase):
    def test_package_registry_names_are_unique(self) -> None:
        self.assertEqual(len(PACKAGES), len(set(PACKAGES)))

    def test_package_registry_covers_the_workspace(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        members = workspace["workspace"]["members"]
        names = []
        for member in members:
            manifest = tomllib.loads(
                (root / member / "Cargo.toml").read_text(encoding="utf-8")
            )
            name = manifest["package"]["name"]
            self.assertEqual(Path(member).name, name)
            names.append(name)

        registered = set(PACKAGES)
        excluded = set(EXCLUDED_PACKAGES)
        self.assertEqual(len(EXCLUDED_PACKAGES), len(excluded))
        self.assertTrue(registered.isdisjoint(excluded))
        self.assertEqual(set(names), registered | excluded)

    def test_non_rust_change_starts_no_mutation_jobs(self) -> None:
        self.assertEqual(
            plan([".gitignore"]),
            {"packages": [], "wire": [], "quiche": False, "msquic": False},
        )

    def test_crate_source_selects_only_its_package(self) -> None:
        result = plan(["crates/vot-object-store/src/lib.rs"])
        self.assertEqual(
            result["packages"],
            [{"package": "vot-object-store", "required": True, "features": "s3-live"}],
        )

    def test_feature_gated_live_sources_select_their_own_jobs(self) -> None:
        quiche = plan(["crates/vot-transport-quiche/src/live.rs"])
        self.assertTrue(quiche["quiche"])
        self.assertFalse(quiche["msquic"])

        msquic = plan(["crates/vot-transport-msquic/src/live.rs"])
        self.assertFalse(msquic["quiche"])
        self.assertTrue(msquic["msquic"])

    def test_wire_source_selects_only_its_shard(self) -> None:
        result = plan(["crates/vot-cli/src/fetch/protocol.rs"])
        self.assertEqual(
            [entry["shard"] for entry in result["wire"]], ["fetch-protocol"]
        )

    def test_mutation_infrastructure_selects_the_full_sweep(self) -> None:
        for path in [".github/workflows/ci.yml", "tools/ci_mutation_plan.py"]:
            with self.subTest(path=path):
                result = plan([path])
                self.assertEqual(len(result["packages"]), len(PACKAGES))
                self.assertEqual(len(result["wire"]), len(WIRE_SHARDS))
                self.assertTrue(result["quiche"])
                self.assertTrue(result["msquic"])

    def test_package_registry_is_not_full_sweep_infrastructure(self) -> None:
        self.assertEqual(
            plan(["tools/ci_mutation_packages.py"]),
            {"packages": [], "wire": [], "quiche": False, "msquic": False},
        )

    def test_registry_change_plus_crate_source_selects_only_that_package(self) -> None:
        result = plan(
            [
                "tools/ci_mutation_packages.py",
                "crates/vot-object-store/src/lib.rs",
            ]
        )
        self.assertEqual(
            result["packages"],
            [{"package": "vot-object-store", "required": True, "features": "s3-live"}],
        )

    def test_future_crate_addition_shape_remains_targeted(self) -> None:
        result = plan(
            [
                "tools/ci_mutation_packages.py",
                "Cargo.toml",
                "Cargo.lock",
                "crates/vot-object-store/Cargo.toml",
                "crates/vot-object-store/src/lib.rs",
            ]
        )
        self.assertEqual(
            result["packages"],
            [{"package": "vot-object-store", "required": True, "features": "s3-live"}],
        )

    def test_main_push_selects_the_full_sweep(self) -> None:
        result = plan([], full=True)
        self.assertEqual(len(result["packages"]), len(PACKAGES))
        self.assertEqual(len(result["wire"]), len(WIRE_SHARDS))


if __name__ == "__main__":
    unittest.main()
