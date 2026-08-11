#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

if __package__:
    from .ci_mutation_packages import EXCLUDED_PACKAGES
    from .ci_mutation_plan import PACKAGES, WIRE_SHARDS, plan
    from .ci_mutation_scope import _write_diff, mutation_revision
else:
    from ci_mutation_packages import EXCLUDED_PACKAGES
    from ci_mutation_plan import PACKAGES, WIRE_SHARDS, plan
    from ci_mutation_scope import _write_diff, mutation_revision


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

    def test_crate_manifest_selects_only_its_package(self) -> None:
        result = plan(["crates/vot-object-store/Cargo.toml"])
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

    def test_pure_wasm_and_workspace_metadata_start_no_mutation_jobs(self) -> None:
        self.assertEqual(
            plan(
                [
                    ".github/workflows/pure-wasm.yml",
                    "Cargo.toml",
                    "Cargo.lock",
                    "test-vectors/public-api/vot-verified-range.txt",
                    "tools/ci_mutation_packages.py",
                ]
            ),
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
                ".github/workflows/pure-wasm.yml",
                "crates/vot-object-store/Cargo.toml",
                "crates/vot-object-store/src/lib.rs",
                "test-vectors/public-api/vot-object-store.txt",
            ]
        )
        self.assertEqual(
            result["packages"],
            [{"package": "vot-object-store", "required": True, "features": "s3-live"}],
        )

    def test_explicit_full_sweep_selects_every_package_and_wire_shard(self) -> None:
        result = plan([], full=True)
        self.assertEqual(len(result["packages"]), len(PACKAGES))
        self.assertEqual(len(result["wire"]), len(WIRE_SHARDS))

    def test_pull_request_uses_the_merge_base_diff(self) -> None:
        self.assertEqual(
            mutation_revision("pull_request", "main", "", lambda _: True),
            "origin/main...HEAD",
        )

    def test_push_uses_the_exact_pushed_range(self) -> None:
        before = "a" * 40
        self.assertEqual(
            mutation_revision("push", "", before, lambda _: True),
            f"{before}..HEAD",
        )

    def test_push_without_reachable_ancestry_uses_a_full_sweep(self) -> None:
        for before, exists in [
            ("", True),
            ("0" * 40, True),
            ("not-a-sha", True),
            ("a" * 40, False),
        ]:
            with self.subTest(before=before, exists=exists):
                self.assertIsNone(
                    mutation_revision("push", "", before, lambda _: exists)
                )

    def test_explicit_and_unknown_events_use_a_full_sweep(self) -> None:
        for event_name in ["schedule", "workflow_dispatch", "merge_group"]:
            with self.subTest(event_name=event_name):
                self.assertIsNone(
                    mutation_revision(event_name, "main", "a" * 40, lambda _: True)
                )


class MutationScopeMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = os.environ.get("VOT_TEST_TMPDIR")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vot-ci-scope-", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.script = Path(__file__).with_name("ci_mutation_scope.py")

        self.git("init", "--quiet")
        (self.repo / "tracked.txt").write_text("before\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git(
            "-c",
            "user.name=VOT CI",
            "-c",
            "user.email=ci@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "before",
        )
        self.before = self.git("rev-parse", "HEAD").stdout.decode().strip()
        (self.repo / "tracked.txt").write_text("after\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git(
            "-c",
            "user.name=VOT CI",
            "-c",
            "user.email=ci@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "after",
        )

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            stdout=subprocess.PIPE,
            check=True,
        )

    def scope(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, self.script, *args],
            cwd=self.repo,
            stdout=subprocess.PIPE,
            check=True,
        )

    def test_cli_materializes_patch_names_and_clears_full_output(self) -> None:
        output = self.repo / "changed.diff"
        result = self.scope(
            "--event-name",
            "push",
            "--before-sha",
            self.before,
            "--output",
            str(output),
        )
        self.assertEqual(result.stdout, b"targeted\n")
        patch = output.read_bytes()
        self.assertIn(b"-before\n", patch)
        self.assertIn(b"+after\n", patch)

        result = self.scope(
            "--event-name",
            "push",
            "--before-sha",
            self.before,
            "--name-only",
            "--output",
            str(output),
        )
        self.assertEqual(result.stdout, b"targeted\n")
        self.assertEqual(output.read_bytes(), b"tracked.txt\0")

        result = self.scope(
            "--event-name", "schedule", "--output", str(output)
        )
        self.assertEqual(result.stdout, b"full\n")
        self.assertFalse(output.exists())

    def test_failed_diff_preserves_destination_and_removes_temporary(self) -> None:
        output = self.repo / "changed.diff"
        output.write_bytes(b"keep")
        with self.assertRaises(subprocess.CalledProcessError):
            _write_diff(output, "missing..HEAD", name_only=False)
        self.assertEqual(output.read_bytes(), b"keep")
        self.assertFalse((self.repo / ".changed.diff.tmp").exists())


if __name__ == "__main__":
    unittest.main()
