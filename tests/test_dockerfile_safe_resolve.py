"""
Unit tests for the rootfs path-confinement helper used by
scripts/dockerfile_build.py to prevent symlink-based escape during
COPY, RUN --mount, WORKDIR, and layer extraction.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


# Load dockerfile_build by file path so we don't have to package it.
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build",
    _ROOT / "scripts" / "dockerfile_build.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)
sys.path.insert(0, str(_ROOT / "scripts"))
_SPEC.loader.exec_module(_MOD)


class SafeResolveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.rootfs = os.path.join(self.tmp, "rootfs")
        os.makedirs(self.rootfs)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plain_absolute_path(self):
        out = _MOD._safe_resolve(self.rootfs, "/etc/passwd")
        self.assertEqual(out,
                         os.path.join(os.path.realpath(self.rootfs),
                                      "etc", "passwd"))

    def test_root_path(self):
        out = _MOD._safe_resolve(self.rootfs, "/")
        self.assertEqual(out, os.path.realpath(self.rootfs))

    def test_relative_rejected_by_default(self):
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "etc/passwd")

    def test_dotdot_canonicalized(self):
        # posixpath.normpath sanitizes .. in absolute paths, so
        # `/etc/../etc/passwd` is semantically `/etc/passwd` and the
        # helper accepts it after canonicalization.
        out = _MOD._safe_resolve(self.rootfs, "/etc/../etc/passwd")
        self.assertEqual(out,
                         os.path.join(os.path.realpath(self.rootfs),
                                      "etc", "passwd"))

    def test_relative_input_rejected(self):
        # Relative paths must be made absolute by the caller (using
        # the current WORKDIR) before _safe_resolve sees them.
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "../../etc")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "")

    def test_absolute_symlink_to_host_path_raises(self):
        # An absolute symlink in the rootfs points at the host's /usr.
        # realpath of the parent escapes — must raise.
        os.symlink("/usr", os.path.join(self.rootfs, "usr-alias"))
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "/usr-alias/lib")

    def test_escape_via_symlink_raises(self):
        # /etc -> /tmp (planted by malicious layer)
        os.symlink("/tmp", os.path.join(self.rootfs, "etc"))
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "/etc/passwd")

    def test_escape_via_relative_symlink_raises(self):
        # /etc -> ../../etc  (relative escape from rootfs)
        os.symlink("../../etc", os.path.join(self.rootfs, "etc"))
        with self.assertRaises(ValueError):
            _MOD._safe_resolve(self.rootfs, "/etc/passwd")

    def test_internal_relative_symlink_ok(self):
        # /bin -> usr/bin  (internal relative symlink, common in alpine)
        os.makedirs(os.path.join(self.rootfs, "usr", "bin"))
        os.symlink("usr/bin", os.path.join(self.rootfs, "bin"))
        out = _MOD._safe_resolve(self.rootfs, "/bin/sh")
        self.assertEqual(
            os.path.realpath(out),
            os.path.realpath(os.path.join(self.rootfs, "usr", "bin", "sh")),
        )

    def test_leaf_symlink_not_followed(self):
        # /target.txt is itself a symlink pointing outside rootfs.
        # _safe_resolve resolves the parent only; the leaf should be
        # left for the caller to overwrite with _safe_unlink_if_present.
        os.symlink("/etc/passwd", os.path.join(self.rootfs, "target.txt"))
        out = _MOD._safe_resolve(self.rootfs, "/target.txt")
        self.assertEqual(out,
                         os.path.join(os.path.realpath(self.rootfs),
                                      "target.txt"))


if __name__ == "__main__":
    unittest.main()
