"""
Tests for `oci2bin diff` file-content comparison.

Regression: regular files used to be compared by size alone, so two files of
identical length but different content were reported as unchanged. The
comparison now uses a streaming sha256 and falls back to size only when a
hash is unavailable.
"""
import importlib.util
import io
import tarfile
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


class Sha256StreamTest(unittest.TestCase):
    def test_hashes_stream_contents(self):
        # Known vector: sha256("abc")
        expected = ("ba7816bf8f01cfea414140de5dae2223"
                    "b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(di.sha256_stream(io.BytesIO(b"abc")), expected)

    def test_spans_multiple_chunks(self):
        data = b"x" * (3 * 1024 * 1024 + 7)
        one_shot = di.sha256_stream(io.BytesIO(data))
        chunked = di.sha256_stream(io.BytesIO(data), chunk_size=1024)
        self.assertEqual(one_shot, chunked)

    def test_none_stream_returns_none(self):
        self.assertIsNone(di.sha256_stream(None))

    def test_unreadable_stream_returns_none(self):
        class Boom:
            def read(self, _n):
                raise OSError("unreadable")

        self.assertIsNone(di.sha256_stream(Boom()))


class DiffDictsTest(unittest.TestCase):
    def test_same_size_different_content_is_modified(self):
        """The regression: equal sizes, different bytes."""
        a = {"/etc/passwd": ("file", 4, di.sha256_stream(io.BytesIO(b"aaaa")))}
        b = {"/etc/passwd": ("file", 4, di.sha256_stream(io.BytesIO(b"bbbb")))}
        added, removed, modified = di.diff_dicts(a, b)
        self.assertEqual(added, [])
        self.assertEqual(removed, [])
        self.assertEqual([m[0] for m in modified], ["/etc/passwd"])

    def test_identical_content_is_unchanged(self):
        digest = di.sha256_stream(io.BytesIO(b"same"))
        a = {"/bin/sh": ("file", 4, digest)}
        b = {"/bin/sh": ("file", 4, digest)}
        _, _, modified = di.diff_dicts(a, b)
        self.assertEqual(modified, [])

    def test_falls_back_to_size_when_hash_missing(self):
        a = {"/f": ("file", 10, None)}
        b = {"/f": ("file", 20, None)}
        _, _, modified = di.diff_dicts(a, b)
        self.assertEqual([m[0] for m in modified], ["/f"])

        same = {"/f": ("file", 10, None)}
        _, _, modified = di.diff_dicts(a, same)
        self.assertEqual(modified, [])

    def test_type_change_still_detected(self):
        a = {"/x": ("file", 1, di.sha256_stream(io.BytesIO(b"a")))}
        b = {"/x": ("dir", None)}
        _, _, modified = di.diff_dicts(a, b)
        self.assertEqual([m[0] for m in modified], ["/x"])

    def test_symlink_target_change_detected(self):
        a = {"/l": ("link", "/bin/sh")}
        b = {"/l": ("link", "/bin/bash")}
        _, _, modified = di.diff_dicts(a, b)
        self.assertEqual([m[0] for m in modified], ["/l"])

    def test_added_and_removed(self):
        a = {"/gone": ("file", 1, "d")}
        b = {"/new": ("file", 1, "d")}
        added, removed, modified = di.diff_dicts(a, b)
        self.assertEqual(added, ["/new"])
        self.assertEqual(removed, ["/gone"])
        self.assertEqual(modified, [])


class BuildFileDictTest(unittest.TestCase):
    """build_file_dict() must attach a hash to each regular file."""

    @staticmethod
    def _make_oci(files):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as tf:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        layer_bytes = layer.getvalue()

        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w") as tf:
            manifest = b'[{"Layers":["layer.tar"]}]'
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            tf.addfile(info, io.BytesIO(manifest))
            info = tarfile.TarInfo("layer.tar")
            info.size = len(layer_bytes)
            tf.addfile(info, io.BytesIO(layer_bytes))
        return outer.getvalue()

    def test_regular_files_carry_a_hash(self):
        oci = self._make_oci({"app/config": b"alpha"})
        d = di.build_file_dict(oci)
        entry = d["/app/config"]
        self.assertEqual(entry[0], "file")
        self.assertEqual(entry[1], 5)
        self.assertEqual(entry[2],
                         di.sha256_stream(io.BytesIO(b"alpha")))

    def test_same_size_layers_differ(self):
        d1 = di.build_file_dict(self._make_oci({"app/config": b"alpha"}))
        d2 = di.build_file_dict(self._make_oci({"app/config": b"bravo"}))
        _, _, modified = di.diff_dicts(d1, d2)
        self.assertEqual([m[0] for m in modified], ["/app/config"])


if __name__ == "__main__":
    unittest.main()
