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


class RenderFormatTest(unittest.TestCase):
    def _mod(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "inspect_image", _SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _root(self):
        return {
            "Image": "redis:7",
            "Architecture": "amd64",
            "Layers": 3,
            "Config": {
                "User": "redis",
                "Env": ["PATH=/bin"],
                "Labels": {"team": "infra", "tier": "cache"},
                "ExposedPorts": {"6379/tcp": {}},
            },
            "Signature": "present",
        }

    def test_field_path(self):
        mod = self._mod()
        root = self._root()
        self.assertEqual(mod.render_format("{{.Config.User}}", root), "redis")
        self.assertEqual(
            mod.render_format("{{.Architecture}}", root), "amd64")
        self.assertEqual(mod.render_format("{{.Layers}}", root), "3")

    def test_missing_field_is_no_value(self):
        mod = self._mod()
        self.assertEqual(
            mod.render_format("{{.Config.Nope}}", self._root()),
            "<no value>")

    def test_json_action(self):
        mod = self._mod()
        out = mod.render_format("{{json .Config.Labels}}", self._root())
        self.assertEqual(json.loads(out), {"team": "infra", "tier": "cache"})

    def test_index_action(self):
        mod = self._mod()
        self.assertEqual(
            mod.render_format('{{index .Config.Labels "team"}}',
                              self._root()),
            "infra")

    def test_literal_and_mixed_text(self):
        mod = self._mod()
        out = mod.render_format(
            "user={{.Config.User}} arch={{.Architecture}}", self._root())
        self.assertEqual(out, "user=redis arch=amd64")

    def test_map_renders_as_json(self):
        mod = self._mod()
        out = mod.render_format("{{.Config.Labels}}", self._root())
        self.assertEqual(json.loads(out), {"team": "infra", "tier": "cache"})

    def test_bad_action_raises(self):
        mod = self._mod()
        with self.assertRaises(ValueError):
            mod.render_format("{{bogus .Config}}", self._root())


if __name__ == "__main__":
    unittest.main()
