"""
Smoke tests for the extended human + JSON output of inspect_image.py.
"""

import json
import io
import pathlib
import subprocess
import struct
import sys
import tarfile
import tempfile
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


class ReadOciDataTest(unittest.TestCase):
    def _mod(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "inspect_image", _SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _tar_bytes(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as tf:
            data = b"{}"
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        return out.getvalue()

    def _binary_with_markers(self, order):
        blob = self._tar_bytes()
        oci_offset = 4096
        loader = bytearray(512)
        if order == "offset-size":
            loader[128:136] = struct.pack("<Q", oci_offset)
            loader[136:144] = struct.pack("<Q", len(blob))
        else:
            loader[128:136] = struct.pack("<Q", len(blob))
            loader[136:144] = struct.pack("<Q", oci_offset)
        return bytes(loader) + b"\0" * (oci_offset - len(loader)) + blob, blob

    def test_read_oci_data_accepts_offset_size_marker_order(self):
        mod = self._mod()
        data, blob = self._binary_with_markers("offset-size")
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            self.assertEqual(mod.read_oci_data(f.name), blob)

    def test_read_oci_data_accepts_size_offset_marker_order(self):
        mod = self._mod()
        data, blob = self._binary_with_markers("size-offset")
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            self.assertEqual(mod.read_oci_data(f.name), blob)

    def test_read_oci_data_rejects_truncated_adjacent_size(self):
        mod = self._mod()
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as tf:
            leading = b"x" * 4096
            leading_info = tarfile.TarInfo("blobs/layer")
            leading_info.size = len(leading)
            tf.addfile(leading_info, io.BytesIO(leading))
            manifest = b"{}"
            manifest_info = tarfile.TarInfo("manifest.json")
            manifest_info.size = len(manifest)
            tf.addfile(manifest_info, io.BytesIO(manifest))
        blob = out.getvalue()
        oci_offset = 4096
        loader = bytearray(512)
        # Matches the compiled loader layout that exposed this regression:
        # true size, offset, then an unrelated but superficially plausible
        # small integer.
        loader[120:128] = struct.pack("<Q", len(blob))
        loader[128:136] = struct.pack("<Q", oci_offset)
        loader[136:144] = struct.pack("<Q", 2048)
        data = bytes(loader) + b"\0" * (oci_offset - len(loader)) + blob
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            self.assertEqual(mod.read_oci_data(f.name), blob)


class SignaturePresenceTest(unittest.TestCase):
    def _mod(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "inspect_image", _SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_loader_strings_are_not_a_signature(self):
        mod = self._mod()
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"prefix" + mod.SIG_MAGIC + b"middle" + mod.SIG_TRAILER)
            f.flush()
            self.assertFalse(mod.has_signature(f.name))

    def test_trailing_length_delimited_signature_is_detected(self):
        mod = self._mod()
        body = mod.SIG_MAGIC + b"\x01" + b"k" * 32
        body += struct.pack(">H", 3) + b"sig"
        total_size = len(body) + len(mod.SIG_TRAILER) + 4
        block = body + mod.SIG_TRAILER + struct.pack(">I", total_size)
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"artifact" + block)
            f.flush()
            self.assertTrue(mod.has_signature(f.name))


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
