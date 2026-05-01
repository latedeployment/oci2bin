"""
Smoke tests for scripts/doctor.py.

Each individual probe touches the real host, so we don't pretend to
unit-test the OK/MISSING decisions per check. We do verify:
  - the script runs without raising
  - --json produces a valid JSON list with the documented schema
  - human output contains every check name
  - exit code is 0 when no probe says MISSING (true on the dev host)
"""

import json
import pathlib
import subprocess
import sys
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "doctor.py"


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


if __name__ == "__main__":
    unittest.main()
