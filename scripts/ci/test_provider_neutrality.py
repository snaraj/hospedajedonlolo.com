"""Requirement 6: the origin is provider-neutral.

It speaks standard HTTP (RFC 9110/9111) only; ingress, DNS, edge and access are
injected deployment concerns. A deployment-provider name may therefore appear
in exactly one sanctioned place -- the chart's `values.yaml` ingress defaults,
the provider binding point -- and never in the server, the published site, or
the chart templates. This suite walks those trees and fails closed on any
occurrence, in any casing, in any file.

Each needle is assembled from fragments so this file never spells the banned
name itself; the connector daemon's name is listed although the base name
subsumes it, so a failure names the exact coupling found.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PROVIDER_MARKS = (
    "cloud" + "flare",  # the current edge provider's name
    "cloud" + "flared",  # its tunnel connector daemon
)

# chart/values.yaml is deliberately absent: its ingress defaults are the one
# sanctioned provider binding point.
NEUTRAL_TREES = ("cmd", "internal", "site", "chart/templates")


def provider_couplings(root: Path) -> list[str]:
    """Every `<file>: <mark>` coupling under the neutral trees of `root`."""
    found: list[str] = []
    for tree in NEUTRAL_TREES:
        base = root / tree
        if not base.is_dir():
            found.append(f"{tree}: the neutral tree is missing, so nothing proves it neutral")
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            content = path.read_bytes().decode("utf-8", errors="replace").lower()
            for mark in PROVIDER_MARKS:
                if mark in content:
                    found.append(f"{path.relative_to(root).as_posix()}: {mark}")
    return found


class ProviderNeutralityTests(unittest.TestCase):
    def test_the_neutral_trees_name_no_provider(self):
        self.assertEqual(
            provider_couplings(ROOT),
            [],
            "the origin is provider-neutral (requirement 6): chart/values.yaml's ingress "
            "defaults are the only sanctioned place for a provider name -- override values "
            "there; never wire a provider into code, the site or chart templates",
        )

    def test_the_sanctioned_binding_point_does_name_the_provider(self):
        """Positive control: the walk would see the name if it were there."""
        values = (ROOT / "chart" / "values.yaml").read_text(encoding="utf-8").lower()
        self.assertIn(PROVIDER_MARKS[0], values)

    def test_a_planted_coupling_is_refused_in_every_tree_and_casing(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for tree in NEUTRAL_TREES:
                (root / tree).mkdir(parents=True)
                (root / tree / "clean.txt").write_text("standard HTTP only\n", encoding="utf-8")
            self.assertEqual(provider_couplings(root), [])
            for tree in NEUTRAL_TREES:
                for spelling in ("Cloud" + "Flare", "CLOUD" + "FLARED"):
                    planted = root / tree / "nested" / "planted.bin"
                    planted.parent.mkdir(exist_ok=True)
                    planted.write_bytes(b"\x00prefix " + spelling.encode() + b" suffix\xff")
                    with self.subTest(tree=tree, spelling=spelling):
                        self.assertTrue(provider_couplings(root))
                    planted.unlink()
            # A missing tree is a refusal, never a silent pass.
            shutil.rmtree(root / "site")
            self.assertEqual(
                provider_couplings(root),
                ["site: the neutral tree is missing, so nothing proves it neutral"],
            )


if __name__ == "__main__":
    unittest.main()
