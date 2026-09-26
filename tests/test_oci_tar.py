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



class SharedHelpersTest(unittest.TestCase):
    def _image(self):
        layer = b"layer-bytes"
        config = json.dumps({"rootfs": {"type": "layers",
                                        "diff_ids": ["sha256:" + _sha(layer)]},
                             "config": {"Cmd": ["/bin/sh"]}}).encode()
        cfg_name = "blobs/sha256/" + _sha(config)
        lay_name = "blobs/sha256/" + _sha(layer)
        manifest = json.dumps([{"Config": cfg_name, "RepoTags": ["t:1"],
                                "Layers": [lay_name]}]).encode()
        return _tar([("manifest.json", manifest), (cfg_name, config),
                     (lay_name, layer)]), cfg_name, lay_name, config, layer

    def test_make_and_copy_tar_info(self):
        info = ot.make_tar_info("a/b", 7, mode=0o600, mtime=42)
        self.assertEqual((info.name, info.size, info.mode, info.mtime,
                          info.uid, info.gid, info.uname, info.gname),
                         ("a/b", 7, 0o600, 42, 0, 0, "", ""))
        src = tarfile.TarInfo("old")
        src.size, src.mode, src.uid, src.gid, src.uname, src.mtime = (
            3, 0o640, 12, 34, "u", 99)
        dup = ot.copy_member_info(src, name="new", size=8)
        self.assertEqual((dup.name, dup.size, dup.mode, dup.uid, dup.gid,
                          dup.uname, dup.mtime, dup.type),
                         ("new", 8, 0o640, 12, 34, "u", 99, src.type))

    def test_read_manifest_and_config(self):
        data, cfg_name, lay_name, config, _ = self._image()
        manifest, name, cfg, raw = ot.read_manifest_and_config(data)
        self.assertEqual(name, cfg_name)
        self.assertEqual(raw, config)
        self.assertEqual(cfg["config"]["Cmd"], ["/bin/sh"])
        self.assertEqual(manifest[0]["Layers"], [lay_name])
        with self.assertRaises(KeyError):
            ot.read_manifest_and_config(_tar([("x", b"y")]))
        with self.assertRaises(ValueError):
            ot.read_manifest_and_config(_tar([("manifest.json", b"{}")]))
        with self.assertRaises(KeyError):
            ot.read_manifest_and_config(_tar([
                ("manifest.json", b'[{"Config":"missing"}]')]))

    def test_repack_replaces_appends_and_collapses(self):
        data = _tar([("a", b"1"), ("b", b"2"), ("c", b"3")])
        new_b = ot.make_tar_info("b2", 2)
        collapsed = ot.make_tar_info("same", 1)
        out = _read(ot.repack_oci_tar(
            data,
            {"b": (new_b, b"22"), "a": (collapsed, b"x"),
             "c": (ot.make_tar_info("same", 1), b"y")},
            [(ot.make_tar_info("extra", 3), b"new"),
             (ot.make_tar_info("same", 1), b"z")]))
        self.assertEqual(out, {"same": b"x", "b2": b"22", "extra": b"new"})
        with tarfile.open(fileobj=io.BytesIO(ot.repack_oci_tar(
                data, {}, []))) as tf:
            self.assertEqual([m.name for m in tf.getmembers()],
                             ["a", "b", "c"])

    def test_rebuild_with_new_config_renames_and_updates_manifest(self):
        data, cfg_name, lay_name, _, _ = self._image()
        manifest, name, cfg, _ = ot.read_manifest_and_config(data)
        cfg["config"]["Labels"] = {"k": "v"}
        extra = ot.make_tar_info("blobs/sha256/" + "e" * 64, 4)
        new_data, new_name = ot.rebuild_oci_with_new_config(
            data, manifest, name, cfg, extra_entries=[(extra, b"more")])
        out = _read(new_data)
        new_raw = json.dumps(cfg, separators=(",", ":")).encode()
        self.assertEqual(new_name, "blobs/sha256/" + _sha(new_raw))
        self.assertNotIn(cfg_name, out)
        self.assertEqual(out[new_name], new_raw)
        self.assertEqual(json.loads(out["manifest.json"])[0]["Config"],
                         new_name)
        self.assertEqual(out["blobs/sha256/" + "e" * 64], b"more")
        self.assertIn(lay_name, out)

    def test_content_name_for_and_diff_id(self):
        blob = b"payload"
        self.assertEqual(ot.content_name_for("blobs/sha256/" + "0" * 64, blob),
                         "blobs/sha256/" + _sha(blob))
        self.assertEqual(ot.content_name_for("1" * 64 + ".json", blob),
                         _sha(blob) + ".json")
        self.assertEqual(ot.content_name_for("abc/layer.tar", blob),
                         "abc/layer.tar")
        self.assertEqual(ot.layer_diff_id(blob), "sha256:" + _sha(blob))
        self.assertEqual(ot.layer_diff_id(gzip.compress(blob)),
                         "sha256:" + _sha(blob))


class LegacySymlinkedLayerTest(unittest.TestCase):
    def test_symlinked_layer_tar_is_materialised(self):
        """Old multi-image `docker save` shared a layer by symlinking
        <id>/layer.tar to another image's copy; the loader cannot open
        that, so normalize_oci_layout() gives it the target's bytes."""
        layer = b"shared-layer"
        config = json.dumps({"rootfs": {"type": "layers",
                                        "diff_ids": ["sha256:" + _sha(layer)]}
                             }).encode()
        cfg_name = _sha(config) + ".json"
        manifest = json.dumps([{"Config": cfg_name, "RepoTags": ["a:1"],
                                "Layers": ["bbb/layer.tar"]}]).encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in [("manifest.json", manifest),
                               (cfg_name, config),
                               ("aaa/layer.tar", layer)]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("bbb/layer.tar")
            link.type = tarfile.SYMTYPE
            link.linkname = "../aaa/layer.tar"
            tf.addfile(link)
        fixed = ot.normalize_oci_layout(buf.getvalue())
        with tarfile.open(fileobj=io.BytesIO(fixed)) as tf:
            member = tf.getmember("bbb/layer.tar")
            self.assertTrue(member.isfile())
            self.assertEqual(tf.extractfile(member).read(), layer)
            self.assertEqual(tf.extractfile("aaa/layer.tar").read(), layer)
        # Manifest names are untouched (legacy names are not
        # content-addressed) and a second pass is a no-op.
        out = _read(fixed)
        self.assertEqual(json.loads(out["manifest.json"])[0]["Layers"],
                         ["bbb/layer.tar"])
        self.assertEqual(ot.normalize_oci_layout(fixed), fixed)

    def test_dangling_symlink_left_alone(self):
        manifest = json.dumps([{"Config": "c.json",
                                "Layers": ["x/layer.tar"]}]).encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in [("manifest.json", manifest), ("c.json", b"{}")]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("x/layer.tar")
            link.type = tarfile.SYMTYPE
            link.linkname = "../nowhere/layer.tar"
            tf.addfile(link)
        data = buf.getvalue()
        self.assertEqual(ot.normalize_oci_layout(data), data)

if __name__ == "__main__":
    unittest.main()
