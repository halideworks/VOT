import unittest

from tools.check_wasm_dependencies import ALLOWED_PACKAGES, unexpected_packages


class WasmDependencyBoundaryTests(unittest.TestCase):
    def test_rejects_host_network_storage_and_runtime_families(self) -> None:
        packages = {
            "aws-sdk-s3",
            "getrandom",
            "hmac",
            "reqwest",
            "tokio",
            "vot-object-store",
            "vot-platform-fs",
            "vot-session",
            "vot-transport-quiche",
        }
        self.assertEqual(unexpected_packages(packages), sorted(packages))

    def test_rejects_unknown_packages_until_reviewed(self) -> None:
        self.assertEqual(
            unexpected_packages({"serde-wasm-bindgen", "vot-wasm"}),
            ["serde-wasm-bindgen"],
        )

    def test_allows_exactly_the_reviewed_pure_graph(self) -> None:
        self.assertEqual(unexpected_packages(set(ALLOWED_PACKAGES)), [])


if __name__ == "__main__":
    unittest.main()
