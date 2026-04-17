"""
Unit tests for strip_image.py helper functions.

Covers: _norm, validate_prefix, should_strip, strip_layer,
        autodetect_extra_prefixes.
No Docker or filesystem access required.
"""

import io
import json
import sys
import os
import tarfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from strip_image import (
    _norm, validate_prefix, should_strip, strip_layer,
    autodetect_extra_prefixes, STRIP_PREFIXES,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_layer_tar(*names):
    """Return raw (uncompressed) tar bytes containing empty files at *names*."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        for name in names:
            info = tarfile.TarInfo(name=name)
            info.size = 0
            tf.addfile(info, io.BytesIO(b''))
    return buf.getvalue()


def _layer_names(layer_bytes):
    """Return the list of member names in a raw-tar layer."""
    with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode='r:') as tf:
        return [m.name for m in tf.getmembers()]


def _make_image_tar(layers):
    """
    Build a minimal docker-save tar.

    layers: list of (layer_filename, raw_tar_bytes) pairs.
    Returns bytes of the image tar.
    """
    manifest = json.dumps([{'Layers': [fn for fn, _ in layers]}]).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        # manifest.json
        mi = tarfile.TarInfo(name='manifest.json')
        mi.size = len(manifest)
        tf.addfile(mi, io.BytesIO(manifest))
        # each layer
        for name, layer_bytes in layers:
            li = tarfile.TarInfo(name=name)
            li.size = len(layer_bytes)
            tf.addfile(li, io.BytesIO(layer_bytes))
    return buf.getvalue()


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


class TestStripLayer(unittest.TestCase):

    def test_strips_matching_member(self):
        layer = _make_layer_tar(
            'usr/share/doc/foo/README',
            'usr/bin/python3',
        )
        result = strip_layer(layer, list(STRIP_PREFIXES))
        names = _layer_names(result)
        self.assertNotIn('usr/share/doc/foo/README', names,
                         'strip_layer: doc entry must be removed')
        self.assertIn('usr/bin/python3', names,
                      'strip_layer: non-doc entry must be preserved')

    def test_preserves_all_when_no_match(self):
        layer = _make_layer_tar('etc/passwd', 'usr/bin/ls')
        result = strip_layer(layer, list(STRIP_PREFIXES))
        self.assertEqual(set(_layer_names(result)), {'etc/passwd', 'usr/bin/ls'})

    def test_strips_normalised_leading_dotslash(self):
        # Tar members may have leading './' — must still be stripped
        layer = _make_layer_tar('./usr/share/doc/foo', 'usr/bin/ls')
        result = strip_layer(layer, list(STRIP_PREFIXES))
        names = _layer_names(result)
        self.assertNotIn('./usr/share/doc/foo', names,
                         'strip_layer: leading ./ doc entry stripped')
        self.assertIn('usr/bin/ls', names)

    def test_strips_multiple_prefixes(self):
        layer = _make_layer_tar(
            'usr/share/doc/pkg/README',
            'usr/share/man/man1/ls.1',
            'usr/share/locale/fr/foo.mo',
            'usr/bin/ls',
        )
        result = strip_layer(layer, list(STRIP_PREFIXES))
        names = _layer_names(result)
        self.assertNotIn('usr/share/doc/pkg/README', names)
        self.assertNotIn('usr/share/man/man1/ls.1', names)
        self.assertNotIn('usr/share/locale/fr/foo.mo', names)
        self.assertIn('usr/bin/ls', names)

    def test_returns_original_on_corrupt_tar(self):
        bad = b'\x00' * 100
        result = strip_layer(bad, list(STRIP_PREFIXES))
        self.assertEqual(result, bad,
                         'strip_layer: corrupt tar must return original bytes')

    def test_empty_layer_roundtrip(self):
        layer = _make_layer_tar()
        result = strip_layer(layer, list(STRIP_PREFIXES))
        self.assertEqual(_layer_names(result), [])

    def test_custom_prefix(self):
        layer = _make_layer_tar('root/.cache/pip/wheels/foo', 'usr/bin/pip3')
        result = strip_layer(layer, ['root/.cache/pip/'])
        names = _layer_names(result)
        self.assertNotIn('root/.cache/pip/wheels/foo', names)
        self.assertIn('usr/bin/pip3', names)


class TestAutodetectExtraPrefixes(unittest.TestCase):

    def _image_with_markers(self, *marker_names):
        """Build a minimal image tar whose single layer contains *marker_names*."""
        layer = _make_layer_tar(*marker_names)
        return _make_image_tar([('layer.tar', layer)])

    def test_detects_apt(self):
        img = self._image_with_markers('var/lib/dpkg/status')
        buf = io.BytesIO(img)
        # autodetect_extra_prefixes expects a file path; write to tmp
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            f.write(img)
            tmp = f.name
        try:
            extra = autodetect_extra_prefixes(tmp)
        finally:
            os.unlink(tmp)
        self.assertIn('var/cache/apt/', extra)
        self.assertIn('var/lib/apt/lists/', extra)

    def test_detects_pip(self):
        import tempfile, os
        img = self._image_with_markers('usr/bin/pip3')
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            f.write(img)
            tmp = f.name
        try:
            extra = autodetect_extra_prefixes(tmp)
        finally:
            os.unlink(tmp)
        self.assertIn('root/.cache/pip/', extra)

    def test_no_markers_returns_empty(self):
        import tempfile, os
        img = self._image_with_markers('etc/passwd', 'usr/bin/ls')
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            f.write(img)
            tmp = f.name
        try:
            extra = autodetect_extra_prefixes(tmp)
        finally:
            os.unlink(tmp)
        self.assertEqual(extra, [])

    def test_detects_npm(self):
        import tempfile, os
        img = self._image_with_markers('usr/bin/npm')
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            f.write(img)
            tmp = f.name
        try:
            extra = autodetect_extra_prefixes(tmp)
        finally:
            os.unlink(tmp)
        self.assertIn('root/.npm/_cacache/', extra)


if __name__ == '__main__':
    unittest.main()
