"""scripts/from_chroot.py: layer contents and default config."""

import gzip
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "from_chroot", ROOT / "scripts" / "from_chroot.py")
fc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fc)


class FromChrootTest(unittest.TestCase):
    def test_symlink_to_directory_is_emitted(self):
        # Merged-/usr bases: bin -> usr/bin must survive, or /bin/sh is gone.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "usr", "bin"))
            with open(os.path.join(root, "usr", "bin", "sh"), "w") as f:
                f.write("#!x\n")
            os.symlink("usr/bin", os.path.join(root, "bin"))
            layer_gz, _ = fc.build_layer(root)
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(layer_gz))) \
                    as tf:
                m = tf.getmember("bin")
                self.assertTrue(m.issym())
                self.assertEqual(m.linkname, "usr/bin")
                self.assertIn("usr/bin/sh", tf.getnames())

    def _config(self, **kw):
        with tempfile.TemporaryDirectory() as root, \
                tempfile.TemporaryDirectory() as out:
            fc.build_oci_layout(root, out, **kw)
            index = json.load(open(os.path.join(out, "index.json")))
            mdig = index["manifests"][0]["digest"][7:]
            man = json.load(open(os.path.join(out, "blobs", "sha256", mdig)))
            cdig = man["config"]["digest"][7:]
            return json.load(open(os.path.join(out, "blobs", "sha256",
                                               cdig)))["config"]

    def test_entrypoint_without_cmd_gets_no_default_cmd(self):
        cfg = self._config(entrypoint=["/app"])
        self.assertIsNone(cfg["Cmd"])

    def test_no_entrypoint_defaults_to_shell(self):
        self.assertEqual(self._config()["Cmd"], ["/bin/sh"])


if __name__ == "__main__":
    unittest.main()
