"""
Docker load/save persistence coverage for embedded loaders.

The filename intentionally does not match test_*.py; run this module through
make test-integration.
"""

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import uuid

from tests import test_embed_loader as unit

bp = unit.bp
rc = unit.rc
FAKE_LOADER = unit.FAKE_LOADER
_read_manifest_and_config = unit._read_manifest_and_config

_CANDIDATE_IMAGES = [
    'alpine:latest',
    'busybox:latest',
    'redis:7-alpine',
    'caddy:2-alpine',
    'memcached:1.6-alpine',
]


def _find_available_image():
    """Return the first locally-present candidate image, or None."""
    try:
        info = subprocess.run(
            ['docker', 'info'], capture_output=True, timeout=5)
        if info.returncode != 0:
            return None
        for image in _CANDIDATE_IMAGES:
            inspect = subprocess.run(
                ['docker', 'image', 'inspect', image],
                capture_output=True, timeout=10,
            )
            if inspect.returncode == 0:
                return image
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return None


_AVAILABLE_IMAGE = _find_available_image()
_TAG_NAMESPACE = uuid.uuid4().hex


@unittest.skipUnless(_AVAILABLE_IMAGE,
                     'Docker not available or no suitable local image found')
class TestEmbedLoaderDockerPersistence(unittest.TestCase):
    """
    Verify embedded layers and labels survive a Docker load/save round trip.
    """

    def _tag(self, name):
        return f'oci2bin-test-{_TAG_NAMESPACE}-{name}:latest'

    @classmethod
    def setUpClass(cls):
        image = _AVAILABLE_IMAGE
        with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as f:
            tmp = f.name
        try:
            result = subprocess.run(
                ['docker', 'save', '-o', tmp, image],
                capture_output=True, timeout=120,
            )
            if result.returncode != 0:
                raise unittest.SkipTest(
                    f'docker save {image} failed: {result.stderr.decode()}')
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
        Replace RepoTags and remove OCI-index metadata so Docker uses the
        legacy manifest whose tag was changed.
        """
        strip_names = {'index.json', 'oci-layout'}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:') as out_tf:
            with tarfile.open(fileobj=io.BytesIO(oci_bytes),
                              mode='r:*') as in_tf:
                for member in in_tf.getmembers():
                    if member.name in strip_names:
                        continue
                    data = in_tf.extractfile(member)
                    if member.name == 'manifest.json':
                        manifest = json.loads(data.read())
                        manifest[0]['RepoTags'] = [new_tag]
                        raw = json.dumps(
                            manifest, separators=(',', ':')).encode()
                        replacement = tarfile.TarInfo(name='manifest.json')
                        replacement.size = len(raw)
                        out_tf.addfile(replacement, io.BytesIO(raw))
                    else:
                        out_tf.addfile(member, data)
        return buf.getvalue()

    def _docker_load_and_save(self, oci_bytes, tag):
        retagged = self._retag(oci_bytes, tag)
        load = subprocess.run(
            ['docker', 'load'],
            input=retagged, capture_output=True, timeout=120,
        )
        self.assertEqual(load.returncode, 0,
                         f'docker load failed: {load.stderr.decode()}')
        try:
            save = subprocess.run(
                ['docker', 'save', tag],
                capture_output=True, timeout=120,
            )
            self.assertEqual(save.returncode, 0,
                             f'docker save failed: {save.stderr.decode()}')
            return save.stdout
        finally:
            subprocess.run(
                ['docker', 'rmi', '-f', tag],
                capture_output=True, timeout=30,
            )

    def test_layer_survives_docker_load_save(self):
        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-layer'))

        _, config = _read_manifest_and_config(saved)
        labels = config.get('config', {}).get('Labels', {})
        self.assertIn('oci2bin.loader.path', labels)
        self.assertEqual(labels['oci2bin.loader.arch'], 'x86_64')
        self.assertEqual(
            labels['oci2bin.loader.sha256'],
            hashlib.sha256(self.loader_bytes).hexdigest(),
        )

    def test_layer_binary_extractable_after_docker_load_save(self):
        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-layer2'))

        labels = rc._get_labels(_read_manifest_and_config(saved)[1])
        extracted, arch = rc.extract_loader_from_layer(saved, labels)
        self.assertEqual(extracted, self.loader_bytes)
        self.assertEqual(arch, 'x86_64')

    def test_layer_count_preserved_after_docker_load_save(self):
        original_manifest = json.loads(
            tarfile.open(
                fileobj=io.BytesIO(self.base_tar),
                mode='r:*',
            ).extractfile('manifest.json').read())
        original_count = len(original_manifest[0]['Layers'])

        embedded = bp.embed_loader_as_layer(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-layer3'))

        manifest, _ = _read_manifest_and_config(saved)
        self.assertEqual(len(manifest[0]['Layers']), original_count + 1)

    def test_labels_survive_docker_load_save(self):
        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-labels'))

        _, config = _read_manifest_and_config(saved)
        labels = config.get('config', {}).get('Labels', {})
        self.assertIn('oci2bin.loader.chunks', labels)
        self.assertIn('oci2bin.loader.0', labels)

    def test_labels_binary_extractable_after_docker_load_save(self):
        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-labels2'))

        labels = rc._get_labels(_read_manifest_and_config(saved)[1])
        extracted, arch = rc.extract_loader_from_labels(saved, labels)
        self.assertEqual(extracted, self.loader_bytes)
        self.assertEqual(arch, 'x86_64')

    def test_labels_layer_count_unchanged_after_docker_load_save(self):
        original_manifest = json.loads(
            tarfile.open(
                fileobj=io.BytesIO(self.base_tar),
                mode='r:*',
            ).extractfile('manifest.json').read())
        original_count = len(original_manifest[0]['Layers'])

        embedded = bp.embed_loader_as_labels(
            self.base_tar, self.loader_bytes, 'x86_64')
        saved = self._docker_load_and_save(
            embedded, self._tag('embed-labels3'))

        manifest, _ = _read_manifest_and_config(saved)
        self.assertEqual(len(manifest[0]['Layers']), original_count)


if __name__ == '__main__':
    unittest.main()
