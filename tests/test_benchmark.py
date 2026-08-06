"""Unit and smoke tests for the artifact benchmark helper."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "benchmark.py"


def load_module():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("benchmark", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkUnitTest(unittest.TestCase):
    def test_percentile_interpolates(self):
        module = load_module()
        self.assertEqual(module.percentile([10, 20, 30], 0.5), 20)
        self.assertEqual(module.percentile([10, 20], 0.5), 15)

    def test_summary_excludes_failed_latency(self):
        module = load_module()
        samples = [
            {"returncode": 0, "elapsed_ms": 10.0, "peak_rss_kib": 100},
            {"returncode": 1, "elapsed_ms": 50.0, "peak_rss_kib": 900,
             "error": "failed"},
            {"returncode": 0, "elapsed_ms": 20.0, "peak_rss_kib": 200},
        ]
        summary = module.summarize(samples)
        self.assertEqual(summary["successful_runs"], 2)
        self.assertAlmostEqual(summary["success_rate"], 2 / 3)
        self.assertEqual(summary["latency_ms"]["median"], 15)
        self.assertEqual(summary["peak_rss_kib"]["max"], 200)

    def test_lazy_preflight_requires_fuse_device(self):
        module = load_module()
        with mock.patch.object(module.shutil, "which",
                               return_value="/usr/bin/helper"), \
                mock.patch.object(module.os, "access", return_value=False):
            reason = module.mode_preflight(
                "lazy", {"rootfs_format": "squashfs"})
        self.assertIn("/dev/fuse", reason)

    def test_measure_once_records_success(self):
        module = load_module()
        sample = module.measure_once(["/bin/true"], timeout=5)
        self.assertEqual(sample["returncode"], 0)
        self.assertGreaterEqual(sample["elapsed_ms"], 0)


class BenchmarkCliTest(unittest.TestCase):
    def test_help(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("startup latency", result.stdout)

    def test_options_after_binary_are_not_treated_as_command(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "/bin/true",
             "--runs", "1", "--warmups", "0",
             "--modes", "extract", "--json"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["settings"]["runs"], 1)
        self.assertEqual(report["settings"]["warmups"], 0)
        self.assertEqual(report["settings"]["command"], ["/bin/true"])


if __name__ == "__main__":
    unittest.main()
