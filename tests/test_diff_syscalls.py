"""
Tests for `oci2bin diff --syscalls`.  We exercise:
  - extract_syscalls_from_profile() on well-formed and malformed JSON
  - print_syscall_diff() output structure and exit code
  - --from-profile end-to-end via subprocess invocation
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
DIFF = ROOT / "scripts" / "diff_images.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


di = _load_module("diff_images", DIFF)


class TestExtractSyscalls(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-syscalls-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        p = self.tmpdir / name
        if isinstance(content, str):
            p.write_text(content)
        else:
            p.write_text(json.dumps(content))
        return p

    def test_well_formed_profile(self):
        path = self._write("p.json", {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [{
                "names":  ["read", "write", "openat"],
                "action": "SCMP_ACT_ALLOW",
            }],
        })
        out = di.extract_syscalls_from_profile(str(path))
        self.assertEqual(out, {"read", "write", "openat"})

    def test_unknown_top_level_keys_ignored(self):
        path = self._write("p.json", {
            "defaultAction":         "SCMP_ACT_ERRNO",
            "syscalls":              [{"names": ["read"],
                                       "action": "SCMP_ACT_ALLOW"}],
            "oci2binWritablePaths":  ["/tmp/x"],
        })
        out = di.extract_syscalls_from_profile(str(path))
        self.assertEqual(out, {"read"})

    def test_non_allow_entries_skipped(self):
        path = self._write("p.json", {
            "syscalls": [
                {"names": ["read"], "action": "SCMP_ACT_ALLOW"},
                {"names": ["mount"], "action": "SCMP_ACT_KILL"},
                {"names": ["execve"], "action": "SCMP_ACT_TRACE"},
            ],
        })
        out = di.extract_syscalls_from_profile(str(path))
        self.assertEqual(out, {"read"})

    def test_missing_syscalls_array_returns_empty(self):
        path = self._write("p.json", {"defaultAction": "SCMP_ACT_ALLOW"})
        out = di.extract_syscalls_from_profile(str(path))
        self.assertEqual(out, set())

    def test_oversized_profile_rejected(self):
        # Build > 4 MiB by repeating a name; cap is at the file-size check.
        big = self.tmpdir / "big.json"
        big.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        with self.assertRaises(RuntimeError):
            di.extract_syscalls_from_profile(str(big))

    def test_non_dict_root_rejected(self):
        path = self._write("p.json", [])  # list at root
        with self.assertRaises(RuntimeError):
            di.extract_syscalls_from_profile(str(path))


class TestPrintSyscallDiff(unittest.TestCase):
    def _capture(self, *args, **kw):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = di.print_syscall_diff(*args, **kw)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_no_difference_returns_zero(self):
        rc, out = self._capture("a", {"x", "y"}, "b", {"x", "y"})
        self.assertEqual(rc, 0)
        self.assertIn("0 added, 0 removed", out)

    def test_difference_returns_one(self):
        rc, out = self._capture("a", {"read", "write"},
                                "b", {"read", "openat"})
        self.assertEqual(rc, 1)
        self.assertIn("- write", out)
        self.assertIn("+ openat", out)
        self.assertIn("1 added, 1 removed, 1 unchanged", out)

    def test_output_is_sorted(self):
        rc, out = self._capture("a", set(),
                                "b", {"openat", "close", "read"})
        self.assertEqual(rc, 1)
        plus = [l for l in out.splitlines() if l.startswith("+ ")]
        self.assertEqual(plus, ["+ close", "+ openat", "+ read"])


class TestFromProfileEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-syscalls-e2e-"))
        self.p1 = self.tmpdir / "p1.json"
        self.p2 = self.tmpdir / "p2.json"
        self.p1.write_text(json.dumps({
            "syscalls": [{"names": ["read", "write", "open"],
                          "action": "SCMP_ACT_ALLOW"}],
        }))
        self.p2.write_text(json.dumps({
            "syscalls": [{"names": ["read", "write", "openat",
                                    "landlock_add_rule"],
                          "action": "SCMP_ACT_ALLOW"}],
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_from_profile_diff_runs(self):
        r = subprocess.run(
            ["python3", str(DIFF), "--syscalls", "--from-profile",
             str(self.p1), str(self.p2)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, msg=r.stderr)
        # `open` is only in p1, `openat` and `landlock_add_rule` only in p2.
        self.assertIn("- open", r.stdout)
        self.assertIn("+ landlock_add_rule", r.stdout)
        self.assertIn("+ openat", r.stdout)
        self.assertIn("2 added, 1 removed", r.stdout)

    def test_from_profile_identical_profiles_exit_zero(self):
        r = subprocess.run(
            ["python3", str(DIFF), "--syscalls", "--from-profile",
             str(self.p1), str(self.p1)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("0 added, 0 removed", r.stdout)

    def test_unknown_option_errors(self):
        r = subprocess.run(
            ["python3", str(DIFF), "--syscalls", "--bogus",
             str(self.p1), str(self.p2)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("--bogus", r.stderr)

    def test_invalid_timeout_errors(self):
        r = subprocess.run(
            ["python3", str(DIFF), "--syscalls",
             "--timeout", "abc", str(self.p1), str(self.p2)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("--timeout", r.stderr)


if __name__ == "__main__":
    unittest.main()
