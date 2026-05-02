"""
Smoke tests for the extended human + JSON output of inspect_image.py.
"""

import json
import pathlib
import subprocess
import sys
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "inspect_image.py"
_IMG = _ROOT / "oci2bin.img"


def _run(args):
    return subprocess.run(
        [sys.executable, str(_SCRIPT)] + args,
        capture_output=True, text=True, timeout=15)


@unittest.skipUnless(_IMG.exists(),
                     f"{_IMG} not built (run `make` first)")
class InspectExtendedTest(unittest.TestCase):
    def test_human_output_has_new_sections(self):
        r = _run([str(_IMG)])
        out = r.stdout
        for header in ("User:", "Signature:", "SBOM:"):
            self.assertIn(header, out, msg=out)

    def test_json_includes_new_keys(self):
        r = _run([str(_IMG), "--json"])
        data = json.loads(r.stdout)
        for key in ("user", "env", "exposed_ports", "healthcheck",
                    "volumes", "labels", "extracted_size_bytes",
                    "signature_present", "sbom_present"):
            self.assertIn(key, data, msg=data)
        self.assertIsInstance(data["env"], list)
        self.assertIsInstance(data["volumes"], list)
        self.assertIsInstance(data["labels"], dict)
        self.assertIsInstance(data["signature_present"], bool)
        self.assertIsInstance(data["sbom_present"], bool)


class RedactEnvTest(unittest.TestCase):
    def test_redact_env(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "inspect_image", _SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        out = mod.redact_env([
            "PATH=/usr/bin:/bin",
            "API_KEY=abc",
            "MY_TOKEN=xyz",
            "DB_PASSWORD=hunter2",
            "USER=root",
        ])
        self.assertIn("PATH=/usr/bin:/bin", out)
        self.assertIn("USER=root", out)
        self.assertIn("API_KEY=<redacted>", out)
        self.assertIn("MY_TOKEN=<redacted>", out)
        self.assertIn("DB_PASSWORD=<redacted>", out)


if __name__ == "__main__":
    unittest.main()
