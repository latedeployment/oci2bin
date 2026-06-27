"""Packaging manifest and installed-helper smoke tests."""

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "packaging" / "oci2bin-scripts.txt"
WRAPPER = ROOT / "oci2bin"


def _load_package_manifest():
    path = ROOT / "scripts" / "package_manifest.py"
    spec = importlib.util.spec_from_file_location("package_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package_manifest = _load_package_manifest()


class PackagingManifestTest(unittest.TestCase):
    def _manifest_names(self):
        return {Path(rel).name for rel in package_manifest.read_manifest(MANIFEST)}

    def test_manifest_covers_wrapper_helper_references(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        refs = set(re.findall(r'\$OCI2BIN_HOME/scripts/([^"\s]+\.py)',
                              wrapper))
        self.assertTrue(refs, "wrapper helper reference scan found nothing")
        self.assertLessEqual(refs, self._manifest_names())

    def test_bundled_package_scripts_match_manifest_sources(self):
        for rel in package_manifest.read_manifest(MANIFEST):
            src = ROOT / rel
            dst = ROOT / "oci2bin_pkg" / "scripts" / src.name
            self.assertTrue(dst.is_file(), f"missing bundled helper: {dst}")
            self.assertEqual(dst.read_bytes(), src.read_bytes(),
                             f"bundled helper is stale: {dst.name}")

    def test_install_scripts_uses_manifest(self):
        expected = self._manifest_names()
        with tempfile.TemporaryDirectory(prefix="oci2bin-install-scripts-") as td:
            dest = Path(td) / "scripts"
            installed = package_manifest.install_scripts(dest, ROOT, MANIFEST)
            self.assertEqual({path.name for path in installed}, expected)
            self.assertEqual({path.name for path in dest.glob("*.py")},
                             expected)
            for name in expected:
                self.assertEqual((dest / name).read_bytes(),
                                 (ROOT / "scripts" / name).read_bytes())

    def test_installed_wrapper_helper_smoke_commands(self):
        with tempfile.TemporaryDirectory(prefix="oci2bin-installed-") as td:
            tmp = Path(td)
            share = tmp / "share" / "oci2bin"
            scripts = share / "scripts"
            bin_dir = tmp / "bin"
            bin_dir.mkdir(parents=True)
            package_manifest.install_scripts(scripts, ROOT, MANIFEST)

            wrapper = bin_dir / "oci2bin"
            shutil.copy2(WRAPPER, wrapper)
            os.chmod(wrapper, 0o755)

            env = os.environ.copy()
            env["OCI2BIN_HOME"] = str(share)
            commands = [
                (["doctor", "--help"], "doctor"),
                (["explain", "--help"], "explain"),
                (["diff-fs", "--help"], "diff-fs"),
                (["freeze", "--help"], "freeze"),
                (["stack", "--help"], "stack"),
            ]
            for args, expected in commands:
                with self.subTest(command=args):
                    result = subprocess.run(
                        [str(wrapper)] + args,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env=env,
                    )
                    self.assertEqual(result.returncode, 0, msg=result.stderr)
                    self.assertIn(expected,
                                  (result.stdout + result.stderr).lower())

            direct_helpers = ["from_chroot.py", "dockerfile_build.py"]
            for helper in direct_helpers:
                with self.subTest(helper=helper):
                    result = subprocess.run(
                        [sys.executable, str(scripts / helper), "--help"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, msg=result.stderr)
                    self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
