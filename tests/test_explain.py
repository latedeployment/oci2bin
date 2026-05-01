"""
Smoke tests for scripts/explain.py.

Builds against the standard oci2bin.img if present (the Makefile
default target produces it). When oci2bin.img is not built we skip,
because explain needs a real binary to inspect.
"""

import json
import pathlib
import subprocess
import sys
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "explain.py"
_IMG = _ROOT / "oci2bin.img"


def _run(args):
    return subprocess.run(
        [sys.executable, str(_SCRIPT)] + args,
        capture_output=True, text=True, timeout=30)


@unittest.skipUnless(_IMG.exists(),
                     f"{_IMG} not built (run `make` first)")
class ExplainTest(unittest.TestCase):
    def test_human_output_has_expected_sections(self):
        r = _run([str(_IMG)])
        # explain may exit 1 if a required host check is MISSING.
        # That's fine for this assertion; we only check sections.
        for header in ("Binary:", "Build metadata:",
                       "Signature:", "SBOM:", "Host capabilities:"):
            self.assertIn(header, r.stdout, msg=r.stdout)

    def test_json_output_has_documented_keys(self):
        r = _run([str(_IMG), "--json"])
        data = json.loads(r.stdout)
        for key in ("binary", "size", "image", "build_metadata",
                    "trust", "host_checks", "missing_required"):
            self.assertIn(key, data)
        self.assertIn("signature_present", data["trust"])
        self.assertIn("sbom_present", data["trust"])
        self.assertIsInstance(data["host_checks"], list)
        self.assertIsInstance(data["missing_required"], list)

    def test_help(self):
        r = _run(["--help"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("explain", r.stdout.lower())


if __name__ == "__main__":
    unittest.main()
