"""Unit tests for scripts/diff_fs.py — overlayfs upperdir classification."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'diff_fs', ROOT / 'scripts' / 'diff_fs.py'
)
diff_fs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_fs)


def _have_mknod_whiteout(path):
    """Best-effort: try to create a (0,0) char device. Skip the test if
    the host kernel/user namespace forbids it."""
    try:
        os.mknod(path, 0o600 | 0o020000, os.makedev(0, 0))  # S_IFCHR
        return True
    except (PermissionError, OSError):
        return False


class TestWalkUpper(unittest.TestCase):

    def _layout(self, upper):
        """Create a representative overlayfs upper layout under `upper`."""
        os.makedirs(os.path.join(upper, 'etc'), exist_ok=True)
        with open(os.path.join(upper, 'etc', 'myapp.toml'), 'w') as f:
            f.write('# config\n')
        with open(os.path.join(upper, 'var-log.txt'), 'w') as f:
            f.write('log line\n')
        os.makedirs(os.path.join(upper, 'opaque-dir'), exist_ok=True)
        # Drop a regular file inside the would-be opaque dir.
        with open(os.path.join(upper, 'opaque-dir', 'kept.txt'), 'w') as f:
            f.write('kept\n')

    def test_walks_and_classifies_added(self):
        with tempfile.TemporaryDirectory() as upper:
            self._layout(upper)
            entries = diff_fs.walk_upper(upper)
            paths = [(op, p) for (op, p, _e) in entries]
            self.assertIn(('A', '/etc'), paths,
                          "directory itself should be reported as A")
            self.assertIn(('A', '/etc/myapp.toml'), paths)
            self.assertIn(('A', '/var-log.txt'), paths)
            self.assertIn(('A', '/opaque-dir'), paths)
            self.assertIn(('A', '/opaque-dir/kept.txt'), paths)
            # Output must be sorted by path for deterministic diffs.
            sorted_paths = sorted([p for (op, p, _e) in entries])
            self.assertEqual(sorted_paths, [p for (op, p, _e) in entries])

    def test_whiteout_classified_as_deleted(self):
        with tempfile.TemporaryDirectory() as upper:
            self._layout(upper)
            wh = os.path.join(upper, 'gone.txt')
            if not _have_mknod_whiteout(wh):
                self.skipTest('mknod char device (0,0) not permitted here')
            entries = diff_fs.walk_upper(upper)
            ops = {p: op for (op, p, _e) in entries}
            self.assertEqual(ops.get('/gone.txt'), 'D',
                             'whiteout char device must classify as D')
            # Non-whiteouts still classified as A.
            self.assertEqual(ops.get('/var-log.txt'), 'A')

    def test_opaque_directory_marked(self):
        with tempfile.TemporaryDirectory() as upper:
            self._layout(upper)
            opaque_dir = os.path.join(upper, 'opaque-dir')
            try:
                os.setxattr(opaque_dir, b'trusted.overlay.opaque', b'y')
            except (OSError, PermissionError):
                self.skipTest('trusted.overlay xattr not permitted here')
            entries = diff_fs.walk_upper(upper)
            extras = {p: extra for (op, p, extra) in entries}
            self.assertEqual(extras.get('/opaque-dir'), 'opaque')
            # Non-opaque dirs do not get the marker.
            self.assertIsNone(extras.get('/etc'))


class TestCLI(unittest.TestCase):

    def test_resolve_upper_auto_descends_into_subdir(self):
        with tempfile.TemporaryDirectory() as parent:
            upper = os.path.join(parent, 'upper')
            os.makedirs(upper)
            with open(os.path.join(upper, 'foo'), 'w') as f:
                f.write('hello\n')
            self.assertEqual(diff_fs._resolve_upper(parent), upper)

    def test_resolve_upper_uses_path_directly_if_no_upper_subdir(self):
        with tempfile.TemporaryDirectory() as upper:
            with open(os.path.join(upper, 'foo'), 'w') as f:
                f.write('hello\n')
            self.assertEqual(diff_fs._resolve_upper(upper), upper)

    def test_text_output(self):
        with tempfile.TemporaryDirectory() as upper:
            with open(os.path.join(upper, 'a.txt'), 'w') as f:
                f.write('a\n')
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts' / 'diff_fs.py'),
                 upper],
                capture_output=True, text=True, check=True)
            self.assertIn('A /a.txt', result.stdout)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as upper:
            with open(os.path.join(upper, 'a.txt'), 'w') as f:
                f.write('a\n')
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts' / 'diff_fs.py'),
                 upper, '--json'],
                capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            self.assertIsInstance(data, list)
            paths = [e['path'] for e in data]
            self.assertIn('/a.txt', paths)

    def test_nonexistent_path_exits_1(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'diff_fs.py'),
             '/tmp/does-not-exist-oci2bin-test'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('not a directory', result.stderr)


if __name__ == '__main__':
    unittest.main()
