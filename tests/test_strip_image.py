"""
Unit tests for strip_image.py helper functions.

Covers: _norm, validate_prefix, should_strip.
No Docker or filesystem access required.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from strip_image import _norm, validate_prefix, should_strip, STRIP_PREFIXES


class TestNorm(unittest.TestCase):

    def test_plain_name(self):
        self.assertEqual(_norm('usr/share/doc/foo'), 'usr/share/doc/foo')

    def test_leading_dotslash(self):
        self.assertEqual(_norm('./usr/share/doc/foo'), 'usr/share/doc/foo')

    def test_leading_slash(self):
        self.assertEqual(_norm('/usr/share/doc/foo'), 'usr/share/doc/foo')

    def test_double_leading_slash(self):
        self.assertEqual(_norm('//etc/passwd'), 'etc/passwd')

    def test_triple_dots_not_stripped(self):
        # '...hidden' starts with dots but is not './' — must be preserved
        self.assertEqual(_norm('...hidden'), '...hidden')

    def test_dotdot_interior_preserved(self):
        # Interior '..' is not touched by _norm; path traversal must be
        # caught elsewhere (validate_prefix / path_has_dotdot_component)
        self.assertEqual(_norm('./foo/../bar'), 'foo/../bar')

    def test_empty_string(self):
        self.assertEqual(_norm(''), '')

    def test_single_dot(self):
        # A bare '.' (current-directory entry) normalises to ''
        self.assertEqual(_norm('.'), '')

    def test_dotslash_only(self):
        self.assertEqual(_norm('./'), '')


class TestValidatePrefix(unittest.TestCase):

    def test_valid_simple(self):
        validate_prefix('usr/share/doc/')  # must not raise

    def test_valid_nested(self):
        validate_prefix('var/cache/apt/')  # must not raise

    def test_rejects_leading_slash(self):
        with self.assertRaises(ValueError):
            validate_prefix('/etc/passwd')

    def test_rejects_dotdot_component(self):
        with self.assertRaises(ValueError):
            validate_prefix('../etc')

    def test_rejects_dotdot_middle(self):
        with self.assertRaises(ValueError):
            validate_prefix('var/cache/../apt/')

    def test_dotdot_substring_in_name_allowed(self):
        # '..hidden' is a valid directory name — not an actual '..' component
        validate_prefix('var/..hidden/')  # must not raise

    def test_rejects_dotdot_exact_component(self):
        with self.assertRaises(ValueError):
            validate_prefix('var/../lib/')


class TestShouldStrip(unittest.TestCase):

    def _prefixes(self):
        return list(STRIP_PREFIXES)

    def test_strips_doc(self):
        self.assertTrue(should_strip('usr/share/doc/foo', self._prefixes()))

    def test_strips_doc_leading_dotslash(self):
        # Names that come from tarballs may have leading './'
        self.assertTrue(should_strip('./usr/share/doc/foo', self._prefixes()))

    def test_strips_man(self):
        self.assertTrue(should_strip('usr/share/man/man1/ls.1', self._prefixes()))

    def test_strips_locale(self):
        self.assertTrue(should_strip('usr/share/locale/fr/LC_MESSAGES/foo.mo',
                                     self._prefixes()))

    def test_strips_apt_cache(self):
        self.assertTrue(should_strip('var/cache/apt/archives/foo.deb',
                                     self._prefixes()))

    def test_does_not_strip_etc(self):
        self.assertFalse(should_strip('etc/passwd', self._prefixes()))

    def test_does_not_strip_usr_bin(self):
        self.assertFalse(should_strip('usr/bin/python3', self._prefixes()))

    def test_strips_exact_prefix_match(self):
        # Entry name equals the prefix without trailing slash
        self.assertTrue(should_strip('usr/share/doc', self._prefixes()))

    def test_custom_prefix(self):
        self.assertTrue(should_strip('root/.cache/pip/wheels/foo',
                                     ['root/.cache/pip/']))

    def test_custom_prefix_no_match(self):
        self.assertFalse(should_strip('root/.cache/npm/foo',
                                      ['root/.cache/pip/']))

    def test_triple_dot_name_not_accidentally_stripped(self):
        # '...hidden' must not be treated as matching 'usr/share/doc/' etc.
        self.assertFalse(should_strip('...hidden', self._prefixes()))

    def test_strips_tmp(self):
        self.assertTrue(should_strip('tmp/somefile', self._prefixes()))

    def test_does_not_strip_tmpfs(self):
        # 'tmpfs' starts with 'tmp' but 'tmp/' prefix requires the slash
        self.assertFalse(should_strip('tmpfoo/bar', self._prefixes()))


if __name__ == '__main__':
    unittest.main()
