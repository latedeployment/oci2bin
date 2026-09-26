"""scripts/oci_tar.py: blob names, manifest.json and index.json must agree
with blob contents after build-time rewrites."""

import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "oci_tar", ROOT / "scripts" / "oci_tar.py")
ot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ot)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _layout(config, layer, *, stale_config=False, stale_layer=False):
    """A docker-save/OCI tar; optionally with manifest.json pointing at blobs
    whose names no longer match their content (what a rewrite used to
    leave behind)."""
    cfg_name = "blobs/sha256/" + ("1" * 64 if stale_config else _sha(config))
    lay_name = "blobs/sha256/" + ("2" * 64 if stale_layer else _sha(layer))
    oci_manifest = json.dumps({
        "schemaVersion": 2, "mediaType": ot.OCI_MANIFEST,
        "config": {"mediaType": ot.OCI_CONFIG, "digest": "sha256:" + "1" * 64,
                   "size": 1},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + "2" * 64, "size": 1}],
    }).encode()
    index = json.dumps({"schemaVersion": 2, "manifests": [{
        "mediaType": ot.OCI_MANIFEST, "digest": "sha256:" + _sha(oci_manifest),
        "size": len(oci_manifest),
        "annotations": {"io.containerd.image.name": "demo:latest"}}]}).encode()
    manifest = json.dumps([{"Config": cfg_name, "RepoTags": ["demo:latest"],
                            "Layers": [lay_name]}]).encode()
    return _tar([("blobs/sha256/" + _sha(oci_manifest), oci_manifest),
                 (cfg_name, config), (lay_name, layer),
                 ("index.json", index), ("manifest.json", manifest)])


def _read(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        return {m.name: tf.extractfile(m).read() for m in tf.getmembers()
                if m.isfile()}


class NormalizeTest(unittest.TestCase):
    def test_consistent_layout_is_returned_unchanged(self):
        cfg, layer = b'{"a":1}', gzip.compress(_tar([("f", b"x")]), mtime=0)
        data = _layout(cfg, layer)
        # Make index/manifest consistent first, then it must be a no-op.
        fixed = ot.normalize_oci_layout(data)
        self.assertEqual(ot.normalize_oci_layout(fixed), fixed)

    def test_stale_names_and_index_are_repaired(self):
        cfg, layer = b'{"a":2}', gzip.compress(_tar([("f", b"y")]), mtime=0)
        out = _read(ot.normalize_oci_layout(
            _layout(cfg, layer, stale_config=True, stale_layer=True)))
        mf = json.loads(out["manifest.json"])[0]
        self.assertEqual(mf["Config"], "blobs/sha256/" + _sha(cfg))
        self.assertEqual(mf["Layers"], ["blobs/sha256/" + _sha(layer)])
        # Every blobs/sha256 member is named by its content.
        for name, body in out.items():
            if name.startswith("blobs/sha256/"):
                self.assertEqual(name[-64:], _sha(body), name)
        index = json.loads(out["index.json"])
        desc = index["manifests"][0]
        self.assertEqual(desc["annotations"],
                         {"io.containerd.image.name": "demo:latest"})
        manifest = json.loads(out["blobs/sha256/" + desc["digest"][7:]])
        self.assertEqual(manifest["config"]["digest"], "sha256:" + _sha(cfg))
        self.assertEqual(manifest["layers"][0]["digest"],
                         "sha256:" + _sha(layer))
        self.assertTrue(manifest["layers"][0]["mediaType"].endswith("+gzip"))

    def test_legacy_save_without_index_untouched(self):
        data = _tar([("manifest.json", json.dumps([{
            "Config": "abc.json", "Layers": ["x/layer.tar"]}]).encode()),
            ("abc.json", b"{}"), ("x/layer.tar", _tar([("f", b"")]))])
        self.assertEqual(ot.normalize_oci_layout(data), data)


if __name__ == "__main__":
    unittest.main()
