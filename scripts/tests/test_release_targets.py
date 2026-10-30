"""Regression tests for the release target matrix (no Go build required)."""

import subprocess
import sys
import unittest
from pathlib import Path


RELEASE_SCRIPT = Path(__file__).resolve().parents[1] / "release.py"


def list_targets(*extra_args):
    result = subprocess.run(
        [sys.executable, str(RELEASE_SCRIPT), "--list-targets", *extra_args],
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.splitlines()


class ReleaseTargetsTest(unittest.TestCase):
    def test_amd64_variants(self):
        self.assertEqual(
            list_targets("--amd64-only"),
            [
                "mosdns-linux-amd64",
                "mosdns-windows-amd64",
                "mosdns-linux-amd64-v2",
                "mosdns-linux-amd64-v3",
                "mosdns-windows-amd64-v2",
                "mosdns-windows-amd64-v3",
            ],
        )

    def test_full_matrix_contains_variants_without_duplicates(self):
        targets = list_targets()
        self.assertEqual(len(targets), len(set(targets)))
        self.assertTrue(set(list_targets("--amd64-only")).issubset(targets))
        self.assertIn("mosdns-linux-arm64", targets)
        self.assertIn("mosdns-linux-mipsle-softfloat", targets)

    def test_first_target_index(self):
        self.assertEqual(list_targets("-i", "0"), ["mosdns-darwin-amd64"])


if __name__ == "__main__":
    unittest.main()
