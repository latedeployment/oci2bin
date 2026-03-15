"""
test_embed_loader.py — Tests for loader embedding and persistence.

TestEmbedLoaderLayer:   unit tests for embed_loader_as_layer (no Docker)
TestEmbedLoaderLabels:  unit tests for embed_loader_as_labels (no Docker)
TestEmbedLoaderDockerPersistence:
    integration tests — verify the embedded layer/labels survive a full
    docker load → docker save round-trip (requires Docker + alpine:latest)

Run all:          python3 -m unittest tests.test_embed_loader -v
Run unit only:    python3 -m unittest tests.test_embed_loader.TestEmbedLoaderLayer
                  python3 -m unittest tests.test_embed_loader.TestEmbedLoaderLabels
"""

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent

# ── load modules ──────────────────────────────────────────────────────────────

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

bp = _load_module('build_polyglot', ROOT / 'scripts' / 'build_polyglot.py')
rc = _load_module('reconstruct',    ROOT / 'scripts' / 'reconstruct.py')


# ── helpers ───────────────────────────────────────────────────────────────────

def _minimal_oci_tar(extra_layers=None):
    """
    Build a minimal but structurally valid docker-save OCI tar in memory.
    Returns (oci_bytes, config_sha, layer_sha).
    """
    # One fake layer blob
    layer_raw = b'\x00' * 1024
    layer_sha = hashlib.sha256(layer_raw).hexdigest()
    layer_path = f'blobs/sha256/{layer_sha}'

    config = {
        'architecture': 'amd64',
        'config': {'Cmd': ['/bin/sh'], 'Labels': {}},
        'rootfs': {'type': 'layers', 'diff_ids': [f'sha256:{layer_sha}']},
    }
    config_raw = json.dumps(config, separators=(',', ':')).encode()
    config_sha = hashlib.sha256(config_raw).hexdigest()
    config_path = f'blobs/sha256/{config_sha}'

    layers = [layer_path] + (extra_layers or [])
    manifest = [{'Config': config_path, 'RepoTags': ['test:latest'],
                 'Layers': layers}]
    manifest_raw = json.dumps(manifest, separators=(',', ':')).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        for name, data in [
            ('manifest.json', manifest_raw),
            (config_path, config_raw),
            (layer_path, layer_raw),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue(), config_sha, layer_sha


def _read_manifest_and_config(tar_bytes):
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:*') as tf:
        manifest = json.loads(tf.extractfile('manifest.json').read())
        config_path = manifest[0]['Config']
        config = json.loads(tf.extractfile(config_path).read())
    return manifest, config


def _docker_available():
    try:
        r = subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


# Prefer a small image that is likely to be cached locally.
_CANDIDATE_IMAGES = [
    'alpine:latest',
    'busybox:latest',
    'redis:7-alpine',
    'caddy:2-alpine',
    'memcached:1.6-alpine',
]


def _find_available_image():
    """Return the first locally-present image from _CANDIDATE_IMAGES, or None."""
    if not _docker_available():
        return None
    for img in _CANDIDATE_IMAGES:
        r = subprocess.run(['docker', 'image', 'inspect', img],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return img
    return None


_AVAILABLE_IMAGE = _find_available_image()


FAKE_LOADER = b'\x7fELF' + b'\xab' * 200   # 204-byte stub


# ── TestEmbedLoaderLayer ──────────────────────────────────────────────────────

class TestEmbedLoaderLayer(unittest.TestCase):

    def setUp(self):
        self.oci_data, self.config_sha, self.layer_sha = _minimal_oci_tar()
        self.result = bp.embed_loader_as_layer(
            self.oci_data, FAKE_LOADER, 'x86_64')

    # ── manifest checks ───────────────────────────────────────────────────────

    def test_layer_count_increases_by_one(self):
        manifest, _ = _read_manifest_and_config(self.result)
        self.assertEqual(len(manifest[0]['Layers']), 2)

    def test_original_layer_still_present(self):
        manifest, _ = _read_manifest_and_config(self.result)
        self.assertIn(f'blobs/sha256/{self.layer_sha}',
                      manifest[0]['Layers'])

    def test_new_layer_is_last(self):
        manifest, _ = _read_manifest_and_config(self.result)
        new_layer = manifest[0]['Layers'][-1]
        self.assertTrue(new_layer.startswith('blobs/sha256/'))

    def test_config_path_updated(self):
        # Config blob sha256 must change because labels were added
        manifest, _ = _read_manifest_and_config(self.result)
        self.assertNotEqual(manifest[0]['Config'],
                            f'blobs/sha256/{self.config_sha}')

    def test_config_blob_name_matches_content(self):
        with tarfile.open(fileobj=io.BytesIO(self.result), mode='r:*') as tf:
            manifest = json.loads(tf.extractfile('manifest.json').read())
            config_path = manifest[0]['Config']
            config_raw = tf.extractfile(config_path).read()
        expected_sha = hashlib.sha256(config_raw).hexdigest()
        self.assertIn(expected_sha, config_path)

    # ── label checks ─────────────────────────────────────────────────────────

    def test_loader_path_label(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        self.assertEqual(labels['oci2bin.loader.path'], '.oci2bin/loader')

    def test_loader_arch_label(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        self.assertEqual(labels['oci2bin.loader.arch'], 'x86_64')

    def test_loader_sha256_label_correct(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        expected = hashlib.sha256(FAKE_LOADER).hexdigest()
        self.assertEqual(labels['oci2bin.loader.sha256'], expected)

    # ── diff_ids check ────────────────────────────────────────────────────────

    def test_diff_ids_increases_by_one(self):
        _, config = _read_manifest_and_config(self.result)
        self.assertEqual(len(config['rootfs']['diff_ids']), 2)

    # ── layer content check ───────────────────────────────────────────────────

    def test_loader_binary_inside_layer(self):
        manifest, _ = _read_manifest_and_config(self.result)
        loader_layer_path = manifest[0]['Layers'][-1]
        extracted = rc._extract_file_from_layer(
            self.result, loader_layer_path, '.oci2bin/loader')
        self.assertEqual(extracted, FAKE_LOADER)

    def test_layer_blob_sha256_matches_path(self):
        manifest, _ = _read_manifest_and_config(self.result)
        loader_layer_path = manifest[0]['Layers'][-1]
        with tarfile.open(fileobj=io.BytesIO(self.result), mode='r:*') as tf:
            layer_gz = tf.extractfile(loader_layer_path).read()
        expected_sha = hashlib.sha256(layer_gz).hexdigest()
        self.assertIn(expected_sha, loader_layer_path)

    # ── strip round-trip ──────────────────────────────────────────────────────

    def test_strip_restores_original_layer_count(self):
        stripped = rc.strip_loader_layer(self.result)
        manifest, _ = _read_manifest_and_config(stripped)
        self.assertEqual(len(manifest[0]['Layers']), 1)

    def test_strip_removes_oci2bin_labels(self):
        stripped = rc.strip_loader_layer(self.result)
        _, config = _read_manifest_and_config(stripped)
        labels = config.get('config', {}).get('Labels', {})
        self.assertFalse(any(k.startswith('oci2bin.loader.')
                             for k in labels))

    def test_strip_config_sha256_consistent(self):
        stripped = rc.strip_loader_layer(self.result)
        with tarfile.open(fileobj=io.BytesIO(stripped), mode='r:*') as tf:
            manifest = json.loads(tf.extractfile('manifest.json').read())
            config_path = manifest[0]['Config']
            config_raw = tf.extractfile(config_path).read()
        expected = hashlib.sha256(config_raw).hexdigest()
        self.assertIn(expected, config_path)

    # ── extract_loader_from_layer ─────────────────────────────────────────────

    def test_extract_loader_round_trip(self):
        labels = rc._get_labels(
            _read_manifest_and_config(self.result)[1])
        extracted, arch = rc.extract_loader_from_layer(self.result, labels)
        self.assertEqual(extracted, FAKE_LOADER)
        self.assertEqual(arch, 'x86_64')

    def test_extract_detects_sha256_mismatch(self):
        _, config = _read_manifest_and_config(self.result)
        labels = dict(rc._get_labels(config))
        labels['oci2bin.loader.sha256'] = 'deadbeef' * 8  # wrong
        with self.assertRaises(ValueError):
            rc.extract_loader_from_layer(self.result, labels)


# ── TestEmbedLoaderLabels ─────────────────────────────────────────────────────

class TestEmbedLoaderLabels(unittest.TestCase):

    def setUp(self):
        self.oci_data, self.config_sha, _ = _minimal_oci_tar()
        self.result = bp.embed_loader_as_labels(
            self.oci_data, FAKE_LOADER, 'x86_64')

    # ── no extra layer ────────────────────────────────────────────────────────

    def test_layer_count_unchanged(self):
        manifest, _ = _read_manifest_and_config(self.result)
        self.assertEqual(len(manifest[0]['Layers']), 1)

    # ── label checks ─────────────────────────────────────────────────────────

    def test_chunks_label_present(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        self.assertIn('oci2bin.loader.chunks', labels)

    def test_arch_label(self):
        _, config = _read_manifest_and_config(self.result)
        self.assertEqual(
            config['config']['Labels']['oci2bin.loader.arch'], 'x86_64')

    def test_sha256_label_correct(self):
        _, config = _read_manifest_and_config(self.result)
        expected = hashlib.sha256(FAKE_LOADER).hexdigest()
        self.assertEqual(
            config['config']['Labels']['oci2bin.loader.sha256'], expected)

    def test_all_chunk_labels_present(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        n = int(labels['oci2bin.loader.chunks'])
        for i in range(n):
            self.assertIn(f'oci2bin.loader.{i}', labels)

    def test_no_extra_chunk_labels(self):
        _, config = _read_manifest_and_config(self.result)
        labels = config['config']['Labels']
        n = int(labels['oci2bin.loader.chunks'])
        self.assertNotIn(f'oci2bin.loader.{n}', labels)

    # ── round-trip ────────────────────────────────────────────────────────────

    def test_round_trip_default_chunk_size(self):
        labels = rc._get_labels(_read_manifest_and_config(self.result)[1])
        extracted, arch = rc.extract_loader_from_labels(self.result, labels)
        self.assertEqual(extracted, FAKE_LOADER)
        self.assertEqual(arch, 'x86_64')

    def test_round_trip_small_chunks(self):
        result = bp.embed_loader_as_labels(
            self.oci_data, FAKE_LOADER, 'x86_64', chunk_bytes=16)
        labels = rc._get_labels(_read_manifest_and_config(result)[1])
        extracted, _ = rc.extract_loader_from_labels(result, labels)
        self.assertEqual(extracted, FAKE_LOADER)

    def test_round_trip_large_chunk_size_single_chunk(self):
        result = bp.embed_loader_as_labels(
            self.oci_data, FAKE_LOADER, 'x86_64',
            chunk_bytes=len(FAKE_LOADER) * 2)
        labels = rc._get_labels(_read_manifest_and_config(result)[1])
        self.assertEqual(labels['oci2bin.loader.chunks'], '1')
        extracted, _ = rc.extract_loader_from_labels(result, labels)
        self.assertEqual(extracted, FAKE_LOADER)

    def test_chunk_count_matches_size(self):
        chunk_bytes = 50
        result = bp.embed_loader_as_labels(
            self.oci_data, FAKE_LOADER, 'x86_64', chunk_bytes=chunk_bytes)
        labels = rc._get_labels(_read_manifest_and_config(result)[1])
        expected = (len(FAKE_LOADER) + chunk_bytes - 1) // chunk_bytes
        self.assertEqual(int(labels['oci2bin.loader.chunks']), expected)

    def test_invalid_chunk_size_raises(self):
        with self.assertRaises(ValueError):
            bp.embed_loader_as_labels(self.oci_data, FAKE_LOADER, 'x86_64',
                                      chunk_bytes=0)

    # ── mismatch detection ────────────────────────────────────────────────────

    def test_extract_detects_sha256_mismatch(self):
        labels = dict(rc._get_labels(
            _read_manifest_and_config(self.result)[1]))
        labels['oci2bin.loader.sha256'] = 'deadbeef' * 8
        with self.assertRaises(ValueError):
            rc.extract_loader_from_labels(self.result, labels)

    def test_extract_detects_missing_chunk(self):
        labels = dict(rc._get_labels(
            _read_manifest_and_config(self.result)[1]))
        del labels['oci2bin.loader.0']
        with self.assertRaises(ValueError):
            rc.extract_loader_from_labels(self.result, labels)

    # ── config blob integrity ─────────────────────────────────────────────────

    def test_config_blob_name_matches_content(self):
        with tarfile.open(fileobj=io.BytesIO(self.result), mode='r:*') as tf:
            manifest = json.loads(tf.extractfile('manifest.json').read())
            config_path = manifest[0]['Config']
            config_raw = tf.extractfile(config_path).read()
        expected = hashlib.sha256(config_raw).hexdigest()
        self.assertIn(expected, config_path)

    # ── strip ─────────────────────────────────────────────────────────────────

    def test_strip_removes_oci2bin_labels(self):
        stripped = rc.strip_loader_labels(self.result)
        _, config = _read_manifest_and_config(stripped)
        labels = config.get('config', {}).get('Labels', {})
        self.assertFalse(any(k.startswith('oci2bin.loader.')
                             for k in labels))

    def test_strip_config_sha256_consistent(self):
        stripped = rc.strip_loader_labels(self.result)
        with tarfile.open(fileobj=io.BytesIO(stripped), mode='r:*') as tf:
            manifest = json.loads(tf.extractfile('manifest.json').read())
            config_path = manifest[0]['Config']
            config_raw = tf.extractfile(config_path).read()
        expected = hashlib.sha256(config_raw).hexdigest()
        self.assertIn(expected, config_path)


# ── TestEmbedLoaderDockerPersistence ─────────────────────────────────────────

@unittest.skipUnless(_AVAILABLE_IMAGE,
                     'Docker not available or no suitable local image found')
class TestEmbedLoaderDockerPersistence(unittest.TestCase):
    """
    Full round-trip: embed loader into a real OCI tar, docker load it under a
    unique test tag, then docker save it back out and verify the loader
    layer/labels survived.
    """

    @classmethod
    def setUpClass(cls):
        img = _AVAILABLE_IMAGE
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            tmp = f.name
        try:
            r = subprocess.run(
                ['docker', 'save', '-o', tmp, img],
                capture_output=True, timeout=120,
            )
            if r.returncode != 0:
                raise unittest.SkipTest(
                    f'docker save {img} failed: {r.stderr.decode()}')
            with open(tmp, 'rb') as f:
                cls.base_tar = f.read()
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        cls.loader_bytes = FAKE_LOADER

    def _retag(self, oci_bytes, new_tag):
        """
        Replace RepoTags in manifest.json with new_tag and strip index.json /
        oci-layout so Docker falls back to legacy manifest.json-only mode.
        Without this, containerd-backed Docker reads index.json for tag
        resolution and ignores our manifest.json change.
        """
        _STRIP = {'index.json', 'oci-layout'}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:') as out_tf:
            with tarfile.open(fileobj=io.BytesIO(oci_bytes), mode='r:*') as in_tf:
                for m in in_tf.getmembers():
                    if m.name in _STRIP:
                        continue
                    data = in_tf.extractfile(m)
                    if m.name == 'manifest.json':
                        mf = json.loads(data.read())
                        mf[0]['RepoTags'] = [new_tag]
                        raw = json.dumps(mf, separators=(',', ':')).encode()
                        m2 = tarfile.TarInfo(name='manifest.json')
                        m2.size = len(raw)
                        out_tf.addfile(m2, io.BytesIO(raw))
                    else:
                        out_tf.addfile(m, data)
        return buf.getvalue()

    def _docker_load_and_save(self, oci_bytes, tag):
        """
        Load oci_bytes into Docker under `tag`, save it back out.
        Returns saved_tar_bytes.  Cleans up the loaded image afterwards.
        """
        retagged = self._retag(oci_bytes, tag)
        load_r = subprocess.run(
            ['docker', 'load'],
            input=retagged, capture_output=True, timeout=120,
        )
        self.assertEqual(load_r.returncode, 0,
                         f'docker load failed: {load_r.stderr.decode()}')
        try:
            save_r = subprocess.run(
                ['docker', 'save', tag],
                capture_output=True, timeout=120,
            )
            self.assertEqual(save_r.returncode, 0,
                             f'docker save failed: {save_r.stderr.decode()}')
            return save_r.stdout
        finally:
            subprocess.run(['docker', 'rmi', '-f', tag],
                           capture_output=True, timeout=30)

    # ── layer approach ────────────────────────────────────────────────────────

    def test_layer_survives_docker_load_save(self):
        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-layer:latest')

        _, config = _read_manifest_and_config(saved)
        labels = config.get('config', {}).get('Labels', {})
        self.assertIn('oci2bin.loader.path', labels,
                      'loader.path label missing after docker load/save')
        self.assertEqual(labels['oci2bin.loader.arch'], 'x86_64')
        self.assertEqual(labels['oci2bin.loader.sha256'],
                         hashlib.sha256(self.loader_bytes).hexdigest())

    def test_layer_binary_extractable_after_docker_load_save(self):
        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-layer2:latest')

        labels = rc._get_labels(_read_manifest_and_config(saved)[1])
        extracted, arch = rc.extract_loader_from_layer(saved, labels)
        self.assertEqual(extracted, self.loader_bytes)
        self.assertEqual(arch, 'x86_64')

    def test_layer_count_preserved_after_docker_load_save(self):
        orig_manifest = json.loads(
            tarfile.open(fileobj=io.BytesIO(self.base_tar),
                         mode='r:*').extractfile('manifest.json').read())
        orig_layer_count = len(orig_manifest[0]['Layers'])

        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-layer3:latest')

        manifest, _ = _read_manifest_and_config(saved)
        self.assertEqual(len(manifest[0]['Layers']), orig_layer_count + 1)

    # ── labels approach ───────────────────────────────────────────────────────

    def test_labels_survive_docker_load_save(self):
        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-labels:latest')

        _, config = _read_manifest_and_config(saved)
        labels = config.get('config', {}).get('Labels', {})
        self.assertIn('oci2bin.loader.chunks', labels,
                      'loader.chunks label missing after docker load/save')
        self.assertIn('oci2bin.loader.0', labels,
                      'loader.0 label missing after docker load/save')

    def test_labels_binary_extractable_after_docker_load_save(self):
        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-labels2:latest')

        labels = rc._get_labels(_read_manifest_and_config(saved)[1])
        extracted, arch = rc.extract_loader_from_labels(saved, labels)
        self.assertEqual(extracted, self.loader_bytes)
        self.assertEqual(arch, 'x86_64')

    def test_labels_layer_count_unchanged_after_docker_load_save(self):
        orig_manifest = json.loads(
            tarfile.open(fileobj=io.BytesIO(self.base_tar),
                         mode='r:*').extractfile('manifest.json').read())
        orig_layer_count = len(orig_manifest[0]['Layers'])

        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, 'oci2bin-test-embed-labels3:latest')

        manifest, _ = _read_manifest_and_config(saved)
        self.assertEqual(len(manifest[0]['Layers']), orig_layer_count)


if __name__ == '__main__':
    unittest.main()
