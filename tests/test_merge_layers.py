"""Regression tests for merge_layers.py metadata rewriting."""

import hashlib
import importlib.util
import io
import json
import os
import tempfile
import tarfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "merge_layers", ROOT / "scripts" / "merge_layers.py",
)
merge_layers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(merge_layers)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _make_layer_tar(name, data=b"x"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_image_tar(layers, *, cmd=None, diff_ids=None):
    if diff_ids is None:
        diff_ids = [f"sha256:{_sha256(layer_bytes)}"
                    for _name, layer_bytes in layers]
    config = {
        "architecture": "amd64",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }
    if cmd is not None:
        config["config"]["Cmd"] = cmd
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_name = f"{_sha256(config_bytes)}.json"
    manifest = json.dumps([{
        "Config": config_name,
        "RepoTags": ["test:latest"],
        "Layers": [name for name, _bytes in layers],
    }], separators=(",", ":")).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        ci = tarfile.TarInfo(name=config_name)
        ci.size = len(config_bytes)
        tf.addfile(ci, io.BytesIO(config_bytes))
        mi = tarfile.TarInfo(name="manifest.json")
        mi.size = len(manifest)
        tf.addfile(mi, io.BytesIO(manifest))
        for name, layer_bytes in layers:
            li = tarfile.TarInfo(name=name)
            li.size = len(layer_bytes)
            tf.addfile(li, io.BytesIO(layer_bytes))
    return buf.getvalue()


def _write_temp(data):
    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    with tmp:
        tmp.write(data)
    return tmp.name


def _empty_temp_path():
    fd, path = tempfile.mkstemp(suffix=".tar")
    os.close(fd)
    return path


def _read_member(tf, name):
    f = tf.extractfile(name)
    assert f is not None
    return f.read()


class MergeLayersMetadataTest(unittest.TestCase):
    def test_appends_diff_ids_and_recomputes_config_name(self):
        base_layer = _make_layer_tar("base.txt", b"base")
        overlay_layer = _make_layer_tar("overlay.txt", b"overlay")
        base = _make_image_tar([("base/layer.tar", base_layer)],
                               cmd=["/bin/base"])
        overlay = _make_image_tar([("overlay/layer.tar", overlay_layer)],
                                  cmd=["/bin/overlay"])
        base_path = _write_temp(base)
        overlay_path = _write_temp(overlay)
        out_path = _empty_temp_path()

        try:
            merge_layers.merge(base_path, [overlay_path], out_path)
            with tarfile.open(out_path, "r:") as tf:
                manifest = json.loads(_read_member(tf, "manifest.json"))[0]
                config_name = manifest["Config"]
                config_bytes = _read_member(tf, config_name)
                config = json.loads(config_bytes)
        finally:
            Path(base_path).unlink(missing_ok=True)
            Path(overlay_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

        self.assertEqual(manifest["Layers"],
                         ["base/layer.tar", "overlay/layer.tar"])
        self.assertEqual(config_name, f"{_sha256(config_bytes)}.json")
        self.assertEqual(config["rootfs"]["diff_ids"], [
            f"sha256:{_sha256(base_layer)}",
            f"sha256:{_sha256(overlay_layer)}",
        ])
        self.assertEqual(config["config"]["Cmd"], ["/bin/overlay"])

    def test_rejects_layer_diff_id_count_mismatch(self):
        base_layer = _make_layer_tar("base.txt", b"base")
        overlay_layer = _make_layer_tar("overlay.txt", b"overlay")
        base = _make_image_tar([("base/layer.tar", base_layer)],
                               diff_ids=[])
        overlay = _make_image_tar([("overlay/layer.tar", overlay_layer)])
        base_path = _write_temp(base)
        overlay_path = _write_temp(overlay)
        out_path = _empty_temp_path()

        try:
            with self.assertRaises(SystemExit):
                merge_layers.merge(base_path, [overlay_path], out_path)
        finally:
            Path(base_path).unlink(missing_ok=True)
            Path(overlay_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
