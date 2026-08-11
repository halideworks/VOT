#!/usr/bin/env python3

import unittest

from tools.ci_mutation_plan import PACKAGES, WIRE_SHARDS, plan


class MutationPlanTests(unittest.TestCase):
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
        result = plan([".github/workflows/ci.yml"])
        self.assertEqual(len(result["packages"]), len(PACKAGES))
        self.assertEqual(len(result["wire"]), len(WIRE_SHARDS))
        self.assertTrue(result["quiche"])
        self.assertTrue(result["msquic"])

    def test_main_push_selects_the_full_sweep(self) -> None:
        result = plan([], full=True)
        self.assertEqual(len(result["packages"]), len(PACKAGES))
        self.assertEqual(len(result["wire"]), len(WIRE_SHARDS))


if __name__ == "__main__":
    unittest.main()
