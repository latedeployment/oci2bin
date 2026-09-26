"""Tests for scripts/prune_cache.py (oci2bin prune)."""

import fcntl
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from contextlib import redirect_stdout


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "prune_cache.py"
WRAPPER = ROOT / "oci2bin"
KEY_A = "a" * 64
KEY_B = "b" * 64
KEY_C = "c" * 64


def load_module():
    spec = importlib.util.spec_from_file_location("prune_cache", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pc = load_module()


def make_entry(root, key, size=4096, last_used=None, valid=True):
    """Create a rootfs cache entry the way the loader lays it out."""
    entry = pathlib.Path(root) / key
    (entry / "rootfs" / "bin").mkdir(parents=True)
    (entry / "rootfs" / "bin" / "blob").write_bytes(b"x" * size)
    if valid:
        (entry / "meta").write_text(
            "oci2bin-rootfs-cache 1\n"
            f"key {key}\n"
            "fingerprint 0123456789abcdef\n"
            "entries 2\n"
            f"bytes {size}\n"
            f"created {int(time.time())}\n", encoding="utf-8")
        if last_used is not None:
            os.utime(entry / "meta", (last_used, last_used))
    (pathlib.Path(root) / f"{key}.lock").touch()
    return entry


def run_prune(**kwargs):
    out = io.StringIO()
    with redirect_stdout(out):
        result = pc.prune_rootfs(out=print, **kwargs)
    return result, out.getvalue()


class ParseSizeTest(unittest.TestCase):
    def test_units(self):
        self.assertEqual(pc.parse_size("1024"), 1024)
        self.assertEqual(pc.parse_size("2K"), 2048)
        self.assertEqual(pc.parse_size("1.5M"), int(1.5 * 1024 ** 2))
        self.assertEqual(pc.parse_size("10G"), 10 * 1024 ** 3)
        self.assertEqual(pc.parse_size("1GiB"), 1024 ** 3)
        self.assertEqual(pc.parse_size("3gb"), 3 * 1024 ** 3)

    def test_rejects_garbage(self):
        for bad in ("", "abc", "10X", "-1"):
            with self.assertRaises(ValueError):
                pc.parse_size(bad)


class RootfsCacheRootTest(unittest.TestCase):
    def test_honours_xdg_cache_home(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"XDG_CACHE_HOME": td}
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(pc.rootfs_cache_root(),
                                 os.path.join(td, "oci2bin", "rootfs"))

    def test_relative_xdg_falls_back_to_home(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"XDG_CACHE_HOME": "relative/path", "HOME": td}
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(
                    pc.rootfs_cache_root(),
                    os.path.join(td, ".cache", "oci2bin", "rootfs"))


class PruneRootfsTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="oci2bin-prune-")
        self.root = pathlib.Path(self._td.name) / "rootfs"
        self.root.mkdir()
        self.now = time.time()

    def tearDown(self):
        self._td.cleanup()

    def test_empty_cache(self):
        (removed, freed, skipped), text = run_prune(root=str(self.root))
        self.assertEqual((removed, freed, skipped), (0, 0, 0))
        self.assertIn("empty", text)

    def test_age_eviction_keeps_recent(self):
        old = make_entry(self.root, KEY_A, last_used=self.now - 40 * 86400)
        fresh = make_entry(self.root, KEY_B, last_used=self.now - 2 * 86400)
        (removed, freed, skipped), text = run_prune(
            root=str(self.root), max_age_days=30, now=self.now)
        self.assertEqual(removed, 1)
        self.assertGreater(freed, 0)
        self.assertEqual(skipped, 0)
        self.assertFalse(old.exists())
        self.assertFalse((self.root / f"{KEY_A}.lock").exists())
        self.assertTrue(fresh.exists())
        self.assertTrue((self.root / f"{KEY_B}.lock").exists())
        self.assertIn("days ago", text)

    def test_dry_run_removes_nothing(self):
        old = make_entry(self.root, KEY_A, last_used=self.now - 40 * 86400)
        (removed, _freed, _skipped), text = run_prune(
            root=str(self.root), max_age_days=30, now=self.now, dry_run=True)
        self.assertEqual(removed, 1)
        self.assertTrue(old.exists())
        self.assertIn("[dry-run] would remove", text)

    def test_size_cap_evicts_least_recently_used_first(self):
        make_entry(self.root, KEY_A, size=3000, last_used=self.now - 3 * 86400)
        make_entry(self.root, KEY_B, size=3000, last_used=self.now - 1 * 86400)
        make_entry(self.root, KEY_C, size=3000, last_used=self.now - 2 * 86400)
        # Each entry is ~3000 bytes of blob plus a meta file; a cap that fits
        # two entries must drop exactly the oldest-used one (A).
        two_entries = 2 * pc.dir_size(str(self.root / KEY_B)) + 10
        (removed, _freed, _skipped), _text = run_prune(
            root=str(self.root), max_age_days=30, max_bytes=two_entries,
            now=self.now)
        self.assertEqual(removed, 1)
        self.assertFalse((self.root / KEY_A).exists())
        self.assertTrue((self.root / KEY_B).exists())
        self.assertTrue((self.root / KEY_C).exists())

    def test_invalid_marker_is_evicted(self):
        bad = make_entry(self.root, KEY_A, last_used=self.now, valid=False)
        (removed, _freed, _skipped), text = run_prune(
            root=str(self.root), max_age_days=30, now=self.now)
        self.assertEqual(removed, 1)
        self.assertFalse(bad.exists())
        self.assertIn("no valid marker", text)

    def test_all_evicts_everything_not_in_use(self):
        make_entry(self.root, KEY_A, last_used=self.now)
        busy = make_entry(self.root, KEY_B, last_used=self.now)
        # Hold the shared lock the loader keeps for a running container.
        fd = os.open(str(self.root / f"{KEY_B}.lock"), os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            (removed, _freed, skipped), text = run_prune(
                root=str(self.root), remove_all=True, now=self.now)
        finally:
            os.close(fd)
        self.assertEqual(removed, 1)
        self.assertEqual(skipped, 1)
        self.assertFalse((self.root / KEY_A).exists())
        self.assertTrue(busy.exists())
        self.assertIn("in use", text)

    def test_abandoned_scratch_and_stale_locks_are_removed(self):
        stale = self.root / f".build-{KEY_A}-abc123"
        stale.mkdir()
        old = self.now - 2 * 86400
        os.utime(stale, (old, old))
        fresh = self.root / f".build-{KEY_B}-def456"
        fresh.mkdir()
        (self.root / f"{KEY_C}.lock").touch()   # entry already gone
        (removed, _freed, _skipped), _text = run_prune(
            root=str(self.root), now=self.now)
        self.assertEqual(removed, 1)
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())
        self.assertFalse((self.root / f"{KEY_C}.lock").exists())

    def test_non_entry_names_are_ignored(self):
        (self.root / "README").write_text("not an entry")
        (self.root / "short").mkdir()
        (removed, _freed, _skipped), _text = run_prune(
            root=str(self.root), remove_all=True, now=self.now)
        self.assertEqual(removed, 0)
        self.assertTrue((self.root / "README").exists())
        self.assertTrue((self.root / "short").exists())


class PruneBuildOutputsTest(unittest.TestCase):
    def test_keeps_newest_per_image(self):
        with tempfile.TemporaryDirectory(prefix="oci2bin-prune-build-") as td:
            root = pathlib.Path(td)
            for name, mtime in (("redis_7_" + "1" * 12, 100),
                                ("redis_7_" + "2" * 12, 200),
                                ("nginx_latest_" + "3" * 12, 50)):
                d = root / name
                d.mkdir()
                (d / "output").write_bytes(b"z" * 10)
                os.utime(d / "output", (mtime, mtime))
            (root / "rootfs").mkdir()   # the loader's cache; not an output
            out = io.StringIO()
            with redirect_stdout(out):
                deleted, freed = pc.prune_build_outputs(str(root), out=print)
            self.assertEqual(deleted, 1)
            self.assertEqual(freed, 10)
            self.assertFalse((root / ("redis_7_" + "1" * 12)).exists())
            self.assertTrue((root / ("redis_7_" + "2" * 12)).exists())
            self.assertTrue((root / ("nginx_latest_" + "3" * 12)).exists())
            self.assertTrue((root / "rootfs").exists())


class PruneCliTest(unittest.TestCase):
    def test_main_reports_both_caches(self):
        with tempfile.TemporaryDirectory(prefix="oci2bin-prune-cli-") as td:
            build_root = pathlib.Path(td) / "build"
            build_root.mkdir()
            rootfs_root = pathlib.Path(td) / "rootfs"
            rootfs_root.mkdir()
            make_entry(rootfs_root, KEY_A, last_used=time.time() - 90 * 86400)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--build-root", str(build_root),
                 "--rootfs-root", str(rootfs_root), "--max-age", "30"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("no superseded build outputs", result.stdout)
            self.assertIn("1 rootfs cache entry removed", result.stdout)
            self.assertFalse((rootfs_root / KEY_A).exists())

    def test_rejects_bad_size(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--max-size", "lots"],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)

    def test_wrapper_dispatches_to_script(self):
        with tempfile.TemporaryDirectory(prefix="oci2bin-prune-wrap-") as td:
            env = dict(os.environ, HOME=td, XDG_CACHE_HOME=str(
                pathlib.Path(td) / "xdg"))
            make_entry(pathlib.Path(td) / "xdg" / "oci2bin" / "rootfs",
                       KEY_A, last_used=time.time())
            (pathlib.Path(td) / "xdg" / "oci2bin" / "rootfs").mkdir(
                parents=True, exist_ok=True)
            result = subprocess.run(
                ["bash", str(WRAPPER), "prune", "--dry-run", "--all"],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("[dry-run] would remove", result.stdout)
            self.assertIn(KEY_A, result.stdout)


if __name__ == "__main__":
    unittest.main()
