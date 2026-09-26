"""Regression tests for scripts/squash_layers.py whiteout handling and
layer decompression."""

import gzip
import importlib.util
import io
import json
import lzma
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "squash_layers", ROOT / "scripts" / "squash_layers.py")
sq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sq)


def _layer(entries):
    """entries: list of (name, kind, data/mode)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, extra in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = extra
                tf.addfile(info)
            else:
                info.size = len(extra)
                tf.addfile(info, io.BytesIO(extra))
    return buf.getvalue()


def _image(layers):
    buf = io.BytesIO()
    names = []
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i, data in enumerate(layers):
            name = f"l{i}/layer.tar"
            names.append(name)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        cfg = json.dumps({"rootfs": {"type": "layers",
                                     "diff_ids": []}}).encode()
        for name, data in (("cfg.json", cfg), ("manifest.json", json.dumps(
                [{"Config": "cfg.json", "RepoTags": [],
                  "Layers": names}]).encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class SquashTest(unittest.TestCase):
    def _squash(self, layers):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "in.tar"
            out = pathlib.Path(td) / "out.tar"
            src.write_bytes(_image(layers))
            sq.squash_oci_tar(str(src), str(out))
            with tarfile.open(out) as tf:
                mf = json.loads(tf.extractfile("manifest.json").read())
                raw = gzip.decompress(tf.extractfile(mf[0]["Layers"][0]).read())
            with tarfile.open(fileobj=io.BytesIO(raw)) as lt:
                return {m.name: m for m in lt.getmembers()}

    def test_opaque_whiteout_keeps_directory_entry(self):
        base = _layer([("tmp", "dir", 0o1777), ("tmp/old", "file", b"x")])
        top = _layer([("tmp/.wh..wh..opq", "file", b""),
                      ("tmp/new", "file", b"y")])
        got = self._squash([base, top])
        self.assertIn("tmp", got)
        self.assertEqual(got["tmp"].mode & 0o7777, 0o1777)
        self.assertNotIn("tmp/old", got)
        # An opaque marker that sorts after its siblings must not delete
        # the layer's own files.
        self.assertIn("tmp/new", got)

    def test_whiteout_removes_directory_subtree(self):
        base = _layer([("d", "dir", 0o755), ("d/f", "file", b"x")])
        top = _layer([(".wh.d", "file", b"")])
        got = self._squash([base, top])
        self.assertNotIn("d", got)
        self.assertNotIn("d/f", got)

    def test_xz_layer_is_read(self):
        data = lzma.compress(_layer([("etc/x", "file", b"z")]))
        self.assertIn("etc/x", self._squash([data]))

    def test_unreadable_layer_fails_instead_of_dropping(self):
        with self.assertRaises(SystemExit):
            self._squash([b"\x28\xb5\x2f\xfd" + b"garbage" * 10])


if __name__ == "__main__":
    unittest.main()
