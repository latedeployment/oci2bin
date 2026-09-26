"""
Smoke tests for scripts/doctor.py.

Each individual probe touches the real host, so we don't pretend to
unit-test the OK/MISSING decisions per check. We do verify:
  - the script runs without raising
  - --json produces a valid JSON list with the documented schema
  - human output contains every check name
  - exit code is 0 when no probe says MISSING (true on the dev host)
"""

import ctypes
import errno
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "doctor.py"


def _load():
    spec = importlib.util.spec_from_file_location("doctor", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(args=None):
    args = args or []
    return subprocess.run(
        [sys.executable, str(_SCRIPT)] + args,
        capture_output=True, text=True, timeout=30)


class DoctorTest(unittest.TestCase):
    def test_human_output_lists_every_check(self):
        r = _run()
        self.assertIn("check", r.stdout)
        for name in ("gcc", "seccomp", "landlock", "cgroup v2",
                     "tar/gzip/zstd"):
            self.assertIn(name, r.stdout, msg=r.stdout)

    def test_json_output_well_formed(self):
        r = _run(["--json"])
        data = json.loads(r.stdout)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 5)
        for entry in data:
            self.assertIn("name", entry)
            self.assertIn("status", entry)
            self.assertIn(entry["status"], ("OK", "DEGRADED", "MISSING"))
            self.assertIn("detail", entry)
            self.assertIn("fix", entry)

    def test_help_doesnt_crash(self):
        r = _run(["--help"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("doctor", r.stdout.lower())


class ProbeTest(unittest.TestCase):
    """--probe: the live checks, each on this host and with the failure
    paths driven through the helpers they call."""

    PROBE_NAMES = ("probe: user namespace", "probe: linkat(AT_EMPTY_PATH)",
                   "probe: /dev/kvm", "probe: tar extraction")

    def test_probe_flag_adds_the_live_checks(self):
        plain = json.loads(_run(["--json"]).stdout)
        probed = json.loads(_run(["--probe", "--json"]).stdout)
        self.assertEqual([r["name"] for r in plain],
                         [r["name"] for r in probed][:len(plain)])
        names = [r["name"] for r in probed[len(plain):]]
        self.assertEqual(names, list(self.PROBE_NAMES))
        for r in probed:
            self.assertIn(r["status"], ("OK", "DEGRADED", "MISSING"))
        human = _run(["--probe"]).stdout
        for name in self.PROBE_NAMES:
            self.assertIn(name, human)

    def test_unshare_probe(self):
        d = _load()
        with mock.patch.object(d, "_which", return_value="/usr/bin/unshare"), \
                mock.patch.object(d, "_run", return_value=(0, "", "")) as run:
            r = d._probe_unshare()
        self.assertEqual(r["status"], d.OK)
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [["unshare", "-Ur", "true"],
                          ["unshare", "-Urm", "true"]])
        with mock.patch.object(d, "_which", return_value="/usr/bin/unshare"), \
                mock.patch.object(d, "_run", return_value=(
                    1, "", "unshare: unshare failed: Operation not permitted")):
            r = d._probe_unshare()
        self.assertEqual(r["status"], d.MISSING)
        self.assertIn("Operation not permitted", r["detail"])
        self.assertIn("unprivileged_userns", r["fix"])
        with mock.patch.object(d, "_which", return_value="/usr/bin/unshare"), \
                mock.patch.object(d, "_run", side_effect=[
                    (0, "", ""), (1, "", "unshare: EPERM")]):
            r = d._probe_unshare()
        self.assertEqual(r["status"], d.MISSING)
        self.assertIn("mount namespace", r["detail"])
        self.assertIn("apparmor_restrict_unprivileged_userns", r["fix"])
        with mock.patch.object(d, "_which", return_value=None):
            self.assertEqual(d._probe_unshare()["status"], d.DEGRADED)

    def test_kvm_probe(self):
        d = _load()
        with mock.patch.object(d.os, "open", side_effect=FileNotFoundError(
                errno.ENOENT, "No such file or directory")):
            r = d._probe_kvm_open()
        self.assertEqual(r["status"], d.DEGRADED)
        self.assertIn("absent", r["detail"])
        with mock.patch.object(d.os, "open", side_effect=PermissionError(
                errno.EACCES, "Permission denied")):
            r = d._probe_kvm_open()
        self.assertEqual(r["status"], d.DEGRADED)
        self.assertIn("refused", r["detail"])
        self.assertIn("kvm group", r["fix"])
        with mock.patch.object(d.os, "open", return_value=99), \
                mock.patch.object(d.os, "close") as close:
            r = d._probe_kvm_open()
        self.assertEqual(r["status"], d.OK)
        close.assert_called_once_with(99)

    def test_linkat_probe(self):
        d = _load()
        live = d._probe_linkat_empty_path()
        self.assertIn(live["status"], (d.OK, d.DEGRADED))

        class FakeLibc:
            def linkat(self, *args):
                self.args = args
                ctypes.set_errno(errno.ENOENT)
                return -1
        fake = FakeLibc()
        with mock.patch.object(d.ctypes, "CDLL", return_value=fake):
            r = d._probe_linkat_empty_path()
        self.assertEqual(r["status"], d.DEGRADED)
        self.assertIn("No such file or directory", r["detail"])
        self.assertIn("/proc/self/fd", r["detail"])
        self.assertEqual(fake.args[1], b"")
        self.assertEqual(fake.args[4], d._AT_EMPTY_PATH)

    def test_tar_probe(self):
        d = _load()
        live = d._probe_tar_extract()
        self.assertEqual(live["status"], d.OK, live)
        self.assertIn("tar", live["detail"])
        with mock.patch.object(d, "_which", return_value=None):
            self.assertEqual(d._probe_tar_extract()["status"], d.MISSING)
        # A tar that rejects the loader's flags is MISSING, whatever it is.
        real_run = d._run

        def rejecting(argv, timeout=5):
            if argv[:2] == ["tar", "xf"]:
                return 2, "", "tar: unrecognized option '--acls'"
            return real_run(argv, timeout)
        with mock.patch.object(d, "_run", side_effect=rejecting):
            r = d._probe_tar_extract()
        self.assertEqual(r["status"], d.MISSING)
        self.assertIn("--acls", r["detail"])
        # The extraction runs with exactly the loader's flags.
        seen = []

        def recording(argv, timeout=5):
            seen.append(argv)
            return real_run(argv, timeout)
        with mock.patch.object(d, "_run", side_effect=recording):
            d._probe_tar_extract()
        extract = [a for a in seen if a[:2] == ["tar", "xf"]][0]
        for flag in d._LOADER_TAR_FLAGS:
            self.assertIn(flag, extract)


class FixTest(unittest.TestCase):
    """--fix runs the install command the summary prints, as an argv list."""

    def _results(self, d, missing=("gcc",)):
        return [d._result(n, d.MISSING, "gone", "") for n in missing] + \
               [d._result("seccomp", d.OK, "fine", "")]

    def test_fix_command_is_the_summary_command(self):
        d = _load()
        results = self._results(d, ("gcc", "age (image encryption)", "gcc"))
        with mock.patch.object(d.os, "geteuid", return_value=1000):
            argv = d._fix_command(results, "apt", "sudo apt install")
        self.assertEqual(argv, ["sudo", "apt", "install", "build-essential",
                                "age"])
        summary = d._install_summary(results, "apt", "sudo apt install", "x")
        self.assertIn("  " + " ".join(argv), summary)
        with mock.patch.object(d.os, "geteuid", return_value=0):
            argv = d._fix_command(results, "apt", "sudo apt install")
        self.assertEqual(argv[0], "apt", "sudo is dropped for root")
        self.assertIsNone(d._fix_command(self._results(d, ()), "apt",
                                         "sudo apt install"))
        self.assertIsNone(d._fix_command(results, None, None))

    def test_run_fix_invokes_the_package_manager_without_a_shell(self):
        d = _load()
        results = self._results(d)
        out = io.StringIO()
        with mock.patch.object(d.subprocess, "run") as run, \
                mock.patch.object(d.os, "geteuid", return_value=1000), \
                redirect_stdout(out):
            run.return_value = mock.Mock(returncode=0)
            rc = d._run_fix(results, "dnf", "sudo dnf install", "Fedora")
        self.assertEqual(rc, 0)
        run.assert_called_once_with(["sudo", "dnf", "install", "gcc"])
        self.assertNotIn("shell", str(run.call_args))
        self.assertIn("running sudo dnf install gcc", out.getvalue())
        with mock.patch.object(d.subprocess, "run") as run, \
                redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()):
            run.return_value = mock.Mock(returncode=100)
            self.assertEqual(
                d._run_fix(results, "apt", "sudo apt install", "Debian"), 100)
        err = io.StringIO()
        with mock.patch.object(d.subprocess, "run") as run, \
                redirect_stderr(err):
            self.assertEqual(d._run_fix(results, None, None, "Gentoo"), 1)
        run.assert_not_called()
        self.assertIn("unrecognized distro", err.getvalue())
        out = io.StringIO()
        with mock.patch.object(d.subprocess, "run") as run, \
                redirect_stdout(out):
            self.assertEqual(d._run_fix(self._results(d, ()), "apt",
                                        "sudo apt install", "Debian"), 0)
        run.assert_not_called()
        self.assertIn("nothing to install", out.getvalue())

    def test_main_fix_rechecks_after_installing(self):
        d = _load()
        calls = {"n": 0}
        missing = d._result("gcc", d.MISSING, "gone", "")
        fixed = d._result("gcc", d.OK, "there", "")

        def check():
            calls["n"] += 1
            return missing if calls["n"] == 1 else fixed
        with mock.patch.object(d, "CHECKS", [check]), \
                mock.patch.object(d, "_detect_pkgmgr",
                                  return_value=("apt", "sudo apt install",
                                                "Debian")), \
                mock.patch.object(d.subprocess, "run") as run, \
                mock.patch.object(d.os, "geteuid", return_value=1000), \
                mock.patch.object(sys, "argv", ["doctor", "--fix"]), \
                redirect_stdout(io.StringIO()):
            run.return_value = mock.Mock(returncode=0)
            d.main()    # no SystemExit: the re-check found gcc
        run.assert_called_once_with(["sudo", "apt", "install",
                                     "build-essential"])
        self.assertEqual(calls["n"], 2)

    def test_fix_and_json_are_exclusive(self):
        r = _run(["--fix", "--json"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--fix cannot be combined with --json", r.stderr)


if __name__ == "__main__":
    unittest.main()
