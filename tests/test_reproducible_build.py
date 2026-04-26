"""
Tests for `--reproducible` build mode.  We construct a synthetic OCI tar
with intentionally-perturbed mtimes / member ordering and verify that two
calls to build_polyglot with --reproducible produce byte-identical output.
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
BUILD_PY = ROOT / "scripts" / "build_polyglot.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_module("build_polyglot", BUILD_PY)


def _minimal_oci_tar(layer_payload=b"hello-world\n", member_order=None,
                     outer_mtime=None, layer_mtime_field=None):
    """Build a tiny valid Docker-save OCI tar with one layer.  member_order
    lets us shuffle entry order to validate the deterministic repacker.

    outer_mtime and layer_mtime_field default to live wall-clock values so
    the *raw* tar bytes vary between calls (proving the repacker has work
    to do), but the layer payload itself remains content-identical so the
    layer SHA stays the same — the repacker is a normaliser, not a
    re-hasher.  Pass deterministic values for byte-equality tests."""
    if outer_mtime is None:
        outer_mtime = int(time.time())
    # The gzip header mtime would change the layer's SHA if it differed
    # between calls.  Pin it so the layer SHA — and therefore the blob
    # filename embedded in manifest.json — stays the same.  Real
    # reproducible pipelines do the same upstream (e.g. SOURCE_DATE_EPOCH).
    if layer_mtime_field is None:
        layer_mtime_field = 100

    layer_buf = io.BytesIO()
    with tarfile.open(fileobj=layer_buf, mode="w:") as ltf:
        ti = tarfile.TarInfo(name="hello.txt")
        ti.size = len(layer_payload)
        ti.mtime = layer_mtime_field
        ltf.addfile(ti, io.BytesIO(layer_payload))
    layer_raw = layer_buf.getvalue()
    layer_sha = hashlib.sha256(layer_raw).hexdigest()
    layer_path = f"blobs/sha256/{layer_sha}"

    # Wrap the layer in gzip with a NON-ZERO mtime so the reproducible
    # repacker has something to normalise.  We pin it so two calls produce
    # the same gzipped bytes — content-equivalent input.
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb",
                       mtime=layer_mtime_field) as gz:
        gz.write(layer_raw)
    gz_layer = gz_buf.getvalue()

    config = {"architecture": "amd64", "config": {"Cmd": ["/bin/sh"]},
              "rootfs": {"type": "layers",
                         "diff_ids": [f"sha256:{layer_sha}"]}}
    config_raw = json.dumps(config, separators=(",", ":")).encode()
    config_sha = hashlib.sha256(config_raw).hexdigest()
    config_path = f"blobs/sha256/{config_sha}"

    manifest = [{"Config": config_path, "RepoTags": ["repro:test"],
                 "Layers": [layer_path]}]
    manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()

    entries = [
        ("manifest.json", manifest_raw),
        (config_path,    config_raw),
        (layer_path,     gz_layer),
    ]
    if member_order:
        entries = [next(e for e in entries if e[0] == n) for n in member_order]

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:") as tf:
        for name, data in entries:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = outer_mtime  # vary across calls to perturb input
            ti.uname = "builder"
            ti.gname = "builder"
            tf.addfile(ti, io.BytesIO(data))
    return out.getvalue()


def _stub_loader_path():
    """Use the real x86_64 loader if present; otherwise skip the test."""
    p = ROOT / "build" / "loader-x86_64"
    return p if p.is_file() else None


class TestRepackOciTarReproducible(unittest.TestCase):
    def test_zeros_mtime_uid_gid_uname_gname(self):
        oci = _minimal_oci_tar()
        out = bp.repack_oci_tar_reproducible(oci)
        with tarfile.open(fileobj=io.BytesIO(out), mode="r:") as tf:
            for m in tf.getmembers():
                self.assertEqual(m.mtime, 0, f"{m.name} mtime not zeroed")
                self.assertEqual(m.uid, 0, f"{m.name} uid not zeroed")
                self.assertEqual(m.gid, 0, f"{m.name} gid not zeroed")
                self.assertEqual(m.uname, "", f"{m.name} uname not zeroed")
                self.assertEqual(m.gname, "", f"{m.name} gname not zeroed")

    def test_member_order_is_deterministic(self):
        # Build the SAME content with DIFFERENT input member orderings.
        # The repacker sorts by name, so both repacked outputs must match.
        baseline = _minimal_oci_tar()
        # Discover the actual filenames so the test isn't tied to SHAs.
        with tarfile.open(fileobj=io.BytesIO(baseline), mode="r:") as tf:
            names = [m.name for m in tf.getmembers()]
        shuffled = list(reversed(names))
        a = bp.repack_oci_tar_reproducible(
            _minimal_oci_tar(member_order=names))
        b = bp.repack_oci_tar_reproducible(
            _minimal_oci_tar(member_order=shuffled))
        self.assertEqual(a, b,
                         "repack should sort members regardless of input order")

    def test_gzip_layer_mtime_zeroed(self):
        oci = _minimal_oci_tar()
        out = bp.repack_oci_tar_reproducible(oci)
        with tarfile.open(fileobj=io.BytesIO(out), mode="r:") as tf:
            for m in tf.getmembers():
                if m.name.startswith("blobs/sha256/") and \
                        m.name != "manifest.json":
                    f = tf.extractfile(m)
                    if not f:
                        continue
                    data = f.read()
                    if data[:2] == b"\x1f\x8b":
                        # bytes 4..8 of a gzip header are mtime little-endian.
                        mtime_le = struct.unpack("<I", data[4:8])[0]
                        self.assertEqual(
                            mtime_le, 0,
                            f"{m.name} gzip header mtime not zeroed")

    def test_idempotent(self):
        oci = _minimal_oci_tar()
        once = bp.repack_oci_tar_reproducible(oci)
        twice = bp.repack_oci_tar_reproducible(once)
        self.assertEqual(once, twice,
                         "repack should be idempotent (already deterministic)")


class TestBuildMetaReproducibleTimestamp(unittest.TestCase):
    def test_reproducible_timestamp_pin(self):
        a = bp.build_meta_block("img", reproducible=True)
        b = bp.build_meta_block("img", reproducible=True)
        self.assertEqual(a, b, "reproducible meta block must be identical")
        # The non-reproducible path embeds datetime.now(); skip strict
        # comparison there since two calls within a second can collide.

    def test_non_reproducible_includes_recent_timestamp(self):
        meta = bp.build_meta_block("img", reproducible=False)
        # The block layout is uint32 length + magic + json + NUL
        json_off = 4 + len(bp.META_MAGIC)
        body = meta[json_off:].rstrip(b"\x00")
        parsed = json.loads(body)
        self.assertNotEqual(parsed["timestamp"], bp.REPRODUCIBLE_TIMESTAMP)


class TestEndToEndReproducibleBuild(unittest.TestCase):
    """End-to-end: invoke build_polyglot.py twice with --reproducible and a
    fixed OCI tar input.  The two output files must be byte-identical."""

    def setUp(self):
        self.loader = _stub_loader_path()
        if not self.loader:
            self.skipTest("build/loader-x86_64 not present "
                          "(run `make build/loader-x86_64` first)")
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-repro-e2e-"))
        # Sleep a beat so the second run gets a different "now()" — proves
        # the timestamp pinning, not just same-clock luck.
        oci_a = self.tmpdir / "input-a.tar"
        oci_b = self.tmpdir / "input-b.tar"
        # Two slightly perturbed inputs — different mtimes, same content.
        # The reproducible repacker should normalise both to the same bytes.
        oci_a.write_bytes(_minimal_oci_tar())
        time.sleep(1.1)
        oci_b.write_bytes(_minimal_oci_tar())
        # Sanity check: the two raw inputs DIFFER (proves mtimes vary).
        self.assertNotEqual(oci_a.read_bytes(), oci_b.read_bytes(),
                            "test setup: raw OCI inputs should differ")
        self.input_a = oci_a
        self.input_b = oci_b

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build(self, input_tar, output, reproducible):
        cmd = ["python3", str(BUILD_PY),
               "--loader", str(self.loader),
               "--image", "repro:test",
               "--tar", str(input_tar),
               "--output", str(output)]
        if reproducible:
            cmd.append("--reproducible")
        r = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, msg=r.stderr)

    def test_two_reproducible_builds_are_byte_identical(self):
        out_a = self.tmpdir / "out-a.bin"
        out_b = self.tmpdir / "out-b.bin"
        self._build(self.input_a, out_a, reproducible=True)
        # Force the wall clock to advance further before the second run.
        time.sleep(1.1)
        self._build(self.input_b, out_b, reproducible=True)
        self.assertEqual(
            hashlib.sha256(out_a.read_bytes()).hexdigest(),
            hashlib.sha256(out_b.read_bytes()).hexdigest(),
            "two --reproducible builds of equivalent input "
            "produced different bytes",
        )

    def test_non_reproducible_builds_can_differ(self):
        # Without --reproducible the timestamp embeds datetime.now(); two
        # calls separated by >1s should produce different metadata blocks.
        out_a = self.tmpdir / "out-a.bin"
        out_b = self.tmpdir / "out-b.bin"
        self._build(self.input_a, out_a, reproducible=False)
        time.sleep(1.1)
        self._build(self.input_b, out_b, reproducible=False)
        self.assertNotEqual(
            out_a.read_bytes(), out_b.read_bytes(),
            "non-reproducible builds happened to be identical "
            "(unexpected — check timestamp embedding)",
        )


if __name__ == "__main__":
    unittest.main()
