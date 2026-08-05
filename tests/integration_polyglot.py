"""
Docker-backed integration coverage for building an oci2bin polyglot.

The filename intentionally does not match test_*.py; run this module through
make test-integration.
"""

import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

from tests.test_polyglot import ROOT


def _alpine_available():
    try:
        info = subprocess.run(
            ['docker', 'info'], capture_output=True, timeout=5)
        if info.returncode != 0:
            return False
        inspect = subprocess.run(
            ['docker', 'image', 'inspect', 'alpine:latest'],
            capture_output=True, timeout=10,
        )
        return inspect.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(_alpine_available(),
                     'Docker + alpine:latest not available')
class TestBuildPolyglotIntegration(unittest.TestCase):
    def test_build_and_verify(self):
        arch = platform.machine()
        loader = ROOT / 'build' / f'loader-{arch}'
        if not loader.exists():
            loader = ROOT / 'build' / 'loader'
        if not loader.exists():
            self.skipTest('build/loader not found — run make loader first')

        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'test.img')
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'scripts' / 'build_polyglot.py'),
                    '--loader', str(loader),
                    '--image', 'alpine:latest',
                    '--output', output,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0,
                             f'build_polyglot.py failed:\n{result.stderr}')

            with open(output, 'rb') as f:
                data = f.read()

            self.assertEqual(data[0:4], b'\x7fELF')
            self.assertEqual(data[257:263], b'ustar\x00')
            self.assertNotIn(struct.pack('<Q', 0xDEADBEEFCAFEBABE), data)
            self.assertNotIn(struct.pack('<Q', 0xCAFEBABEDEADBEEF), data)
            self.assertNotIn(struct.pack('<Q', 0xAAAAAAAAAAAAAAAA), data)
            self.assertTrue(os.access(output, os.X_OK))


if __name__ == '__main__':
    unittest.main()
