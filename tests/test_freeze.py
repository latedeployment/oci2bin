"""Unit tests for scripts/freeze.py — SQLite quiesce helper."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'freeze', ROOT / 'scripts' / 'freeze.py'
)
freeze = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(freeze)


class TestValidName(unittest.TestCase):

    def test_accepts_typical_names(self):
        for ok in ('vault', 'redis-1', 'app_123', 'a'):
            self.assertTrue(freeze.VALID_NAME.match(ok), ok)

    def test_rejects_dotdot_and_slash(self):
        for bad in ('', '-x', '_x', '..', '../etc', 'a/b', 'a\nb', 'a b'):
            self.assertIsNone(freeze.VALID_NAME.match(bad), bad)


class TestFindDatabases(unittest.TestCase):
    """Verify find_databases walks the rootfs and filters skip prefixes."""

    def _make_rootfs(self, tmpdir):
        # We fake `/proc/<pid>/root` by symlinking to a tree we control.
        rootfs = Path(tmpdir) / 'rootfs'
        rootfs.mkdir()
        (rootfs / 'data').mkdir()
        (rootfs / 'data' / 'app.sqlite').write_bytes(b'sqlite3')
        (rootfs / 'data' / 'subdir').mkdir()
        (rootfs / 'data' / 'subdir' / 'nested.db').write_bytes(b'sqlite3')
        # Files under skip-prefixes must be ignored.
        (rootfs / 'usr').mkdir()
        (rootfs / 'usr' / 'should-skip.db').write_bytes(b'x')
        (rootfs / 'proc').mkdir()
        (rootfs / 'proc' / 'also.sqlite').write_bytes(b'x')
        # A non-db file shouldn't match.
        (rootfs / 'data' / 'README.txt').write_bytes(b'hi')
        return rootfs

    def test_finds_only_db_files_outside_skip_prefixes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = self._make_rootfs(tmpdir)
            dbs = freeze.find_databases_in_rootfs(str(rootfs))
        ctr_paths = sorted(c for c, _h in dbs)
        self.assertIn('/data/app.sqlite', ctr_paths)
        self.assertIn('/data/subdir/nested.db', ctr_paths)
        for p in ctr_paths:
            self.assertFalse(p.startswith('/usr/'), p)
            self.assertFalse(p.startswith('/proc/'), p)
        # The README must not appear.
        self.assertNotIn('/data/README.txt', ctr_paths)


class TestTokenLifecycle(unittest.TestCase):

    def test_token_round_trip(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                self.assertIsNone(freeze._read_token('demo'))
                token = freeze._write_token('demo', 4242,
                                            ['/data/foo.db.oci2bin-snap'])
                self.assertTrue(token.is_file())
                loaded = freeze._read_token('demo')
                self.assertEqual(loaded['pid'], 4242)
                self.assertEqual(loaded['snaps'],
                                 ['/data/foo.db.oci2bin-snap'])
                self.assertIn('taken_at', loaded)
                self.assertEqual(loaded['name'], 'demo')

    def test_token_directory_is_under_home(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                tdir = freeze._freeze_token_dir()
                self.assertEqual(
                    str(tdir),
                    os.path.join(home, '.local', 'share', 'oci2bin', 'freeze'))


class TestLoadState(unittest.TestCase):

    def test_rejects_invalid_name(self):
        with self.assertRaises(SystemExit):
            freeze.load_state('../oops')

    def test_missing_state_file_exits(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                with self.assertRaises(SystemExit):
                    freeze.load_state('nonexistent')

    def test_parses_well_formed_state(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'demo.json').write_text(json.dumps({
                    'pid': 12345,
                    'binary': '/usr/local/bin/demo',
                    'start_ticks': 9999,
                }))
                pid, binary, ticks = freeze.load_state('demo')
                self.assertEqual(pid, 12345)
                self.assertEqual(binary, '/usr/local/bin/demo')
                self.assertEqual(ticks, 9999)


class TestCmdFreezeNoDbFound(unittest.TestCase):

    def test_no_db_with_command_runs_command_anyway(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'app.json').write_text(json.dumps({
                    'pid': 1,
                    'binary': '/x',
                    'start_ticks': 0,
                }))
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'find_databases',
                                       return_value=[]), \
                     mock.patch.object(freeze.subprocess, 'call',
                                       return_value=42) as call_mock:
                    rc = freeze.cmd_freeze('app', ['/bin/echo', 'hi'])
                self.assertEqual(rc, 42)
                call_mock.assert_called_once()

    def test_no_db_no_command_returns_zero(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'app.json').write_text(json.dumps({
                    'pid': 1,
                    'binary': '/x',
                    'start_ticks': 0,
                }))
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'find_databases',
                                       return_value=[]):
                    rc = freeze.cmd_freeze('app', [])
                self.assertEqual(rc, 0)


class TestCmdFreezeHappyPath(unittest.TestCase):

    def test_freeze_writes_token_and_runs_snapshot_per_db(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'vault.json').write_text(json.dumps({
                    'pid': 555,
                    'binary': '/v',
                    'start_ticks': 0,
                }))
                fake_dbs = [
                    ('/data/db.sqlite', '/proc/555/root/data/db.sqlite'),
                    ('/data/cache.db', '/proc/555/root/data/cache.db'),
                ]
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'find_databases',
                                       return_value=fake_dbs), \
                     mock.patch.object(freeze, 'snapshot_one',
                                       side_effect=lambda pid, p:
                                           p + '.oci2bin-snap') as snap_mock:
                    rc = freeze.cmd_freeze('vault', [])
                self.assertEqual(rc, 0)
                self.assertEqual(snap_mock.call_count, 2)
                token = freeze._read_token('vault')
                self.assertEqual(token['pid'], 555)
                self.assertEqual(sorted(token['snaps']), sorted([
                    '/data/db.sqlite.oci2bin-snap',
                    '/data/cache.db.oci2bin-snap',
                ]))

    def test_freeze_aborts_and_cleans_up_on_failure(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'vault.json').write_text(json.dumps({
                    'pid': 555,
                    'binary': '/v',
                    'start_ticks': 0,
                }))
                fake_dbs = [
                    ('/data/db.sqlite', '/proc/555/root/data/db.sqlite'),
                    ('/data/broken.db', '/proc/555/root/data/broken.db'),
                ]
                snap_results = ['/data/db.sqlite.oci2bin-snap', None]
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'find_databases',
                                       return_value=fake_dbs), \
                     mock.patch.object(freeze, 'snapshot_one',
                                       side_effect=snap_results), \
                     mock.patch.object(freeze, 'remove_snapshot') as rm_mock:
                    rc = freeze.cmd_freeze('vault', [])
                self.assertEqual(rc, 1, 'partial snapshot failure aborts')
                # The first (successful) snap must have been cleaned up.
                rm_mock.assert_called_once_with(
                    555, '/data/db.sqlite.oci2bin-snap')
                self.assertIsNone(freeze._read_token('vault'),
                                  'no token on abort')

    def test_freeze_with_command_auto_thaws(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'app.json').write_text(json.dumps({
                    'pid': 7, 'binary': '/x', 'start_ticks': 0,
                }))
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'find_databases',
                                       return_value=[
                                           ('/a.db', '/proc/7/root/a.db')]), \
                     mock.patch.object(freeze, 'snapshot_one',
                                       return_value='/a.db.oci2bin-snap'), \
                     mock.patch.object(freeze.subprocess, 'call',
                                       return_value=0), \
                     mock.patch.object(freeze, 'remove_snapshot') as rm_mock:
                    rc = freeze.cmd_freeze('app', ['/bin/true'])
                self.assertEqual(rc, 0)
                # No token must be written when a command is given.
                self.assertIsNone(freeze._read_token('app'))
                rm_mock.assert_called_once_with(7, '/a.db.oci2bin-snap')


class TestCmdThaw(unittest.TestCase):

    def test_thaw_with_no_token_returns_1(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                rc = freeze.cmd_thaw('nope')
                self.assertEqual(rc, 1)

    def test_thaw_removes_snaps_and_token(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                # Write a state file
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                (state_dir / 'vault.json').write_text(json.dumps({
                    'pid': 99, 'binary': '/v', 'start_ticks': 0,
                }))
                # Write a token
                freeze._write_token('vault', 99,
                                    ['/data/foo.db.oci2bin-snap',
                                     '/data/bar.sqlite.oci2bin-snap'])
                with mock.patch.object(freeze, 'ensure_alive'), \
                     mock.patch.object(freeze, 'remove_snapshot') as rm_mock:
                    rc = freeze.cmd_thaw('vault')
                self.assertEqual(rc, 0)
                self.assertEqual(rm_mock.call_count, 2)
                self.assertIsNone(freeze._read_token('vault'),
                                  'thaw must remove the token')

    def test_thaw_pid_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {'HOME': home}):
                state_dir = freeze._state_dir()
                state_dir.mkdir(parents=True)
                # The container now has a different PID than the token recorded.
                (state_dir / 'vault.json').write_text(json.dumps({
                    'pid': 100, 'binary': '/v', 'start_ticks': 0,
                }))
                freeze._write_token('vault', 99, ['/foo.oci2bin-snap'])
                rc = freeze.cmd_thaw('vault')
                self.assertEqual(rc, 1)
                # Token must NOT be removed when we refuse to nsenter.
                self.assertIsNotNone(freeze._read_token('vault'))


if __name__ == '__main__':
    unittest.main()
