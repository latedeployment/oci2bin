"""
Unit tests for pack-level --label (apply_user_labels) and the label-filter
matching used by `oci2bin ps`/`list`. No Docker required.
"""

import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_module('build_polyglot', ROOT / 'scripts' / 'build_polyglot.py')


def _minimal_oci_tar(labels=None):
    layer_raw = b'\x00' * 1024
    layer_sha = hashlib.sha256(layer_raw).hexdigest()
    layer_path = f'blobs/sha256/{layer_sha}'

    config = {
        'architecture': 'amd64',
        'config': {'Cmd': ['/bin/sh'], 'Labels': dict(labels or {})},
        'rootfs': {'type': 'layers', 'diff_ids': [f'sha256:{layer_sha}']},
    }
    config_raw = json.dumps(config, separators=(',', ':')).encode()
    config_sha = hashlib.sha256(config_raw).hexdigest()
    config_path = f'blobs/sha256/{config_sha}'

    manifest = [{'Config': config_path, 'RepoTags': ['test:latest'],
                 'Layers': [layer_path]}]
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
    return buf.getvalue()


def _labels_of(tar_bytes):
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:*') as tf:
        manifest = json.loads(tf.extractfile('manifest.json').read())
        config = json.loads(tf.extractfile(manifest[0]['Config']).read())
    return config['config']['Labels']


class ApplyUserLabelsTest(unittest.TestCase):
    def test_adds_labels(self):
        out = bp.apply_user_labels(_minimal_oci_tar(),
                                   {'team': 'infra', 'tier': 'cache'})
        self.assertEqual(_labels_of(out),
                         {'team': 'infra', 'tier': 'cache'})

    def test_merges_and_overwrites(self):
        base = _minimal_oci_tar({'team': 'old', 'keep': 'yes'})
        out = bp.apply_user_labels(base, {'team': 'new'})
        labels = _labels_of(out)
        self.assertEqual(labels['team'], 'new')
        self.assertEqual(labels['keep'], 'yes')

    def test_empty_is_noop(self):
        base = _minimal_oci_tar({'a': 'b'})
        self.assertEqual(bp.apply_user_labels(base, {}), base)

    def test_config_blob_sha_consistent(self):
        out = bp.apply_user_labels(_minimal_oci_tar(), {'k': 'v'})
        with tarfile.open(fileobj=io.BytesIO(out), mode='r:*') as tf:
            manifest = json.loads(tf.extractfile('manifest.json').read())
            cfg_path = manifest[0]['Config']
            cfg_raw = tf.extractfile(cfg_path).read()
        self.assertEqual(cfg_path,
                         f'blobs/sha256/{hashlib.sha256(cfg_raw).hexdigest()}')


def _matches(labels, filters):
    """Mirror the (key, value-or-None) matcher used in ps/list."""
    parsed = []
    for it in filters:
        s = it[len("label="):]
        if "=" in s:
            k, v = s.split("=", 1)
            parsed.append((k, v))
        else:
            parsed.append((s, None))
    for k, v in parsed:
        if k not in labels:
            return False
        if v is not None and labels[k] != v:
            return False
    return True


class FilterMatchTest(unittest.TestCase):
    def setUp(self):
        self.labels = {'team': 'infra', 'tier': 'cache'}

    def test_key_value_match(self):
        self.assertTrue(_matches(self.labels, ['label=team=infra']))

    def test_key_value_mismatch(self):
        self.assertFalse(_matches(self.labels, ['label=team=web']))

    def test_key_only_presence(self):
        self.assertTrue(_matches(self.labels, ['label=tier']))
        self.assertFalse(_matches(self.labels, ['label=zone']))

    def test_all_filters_must_match(self):
        self.assertTrue(
            _matches(self.labels, ['label=team=infra', 'label=tier=cache']))
        self.assertFalse(
            _matches(self.labels, ['label=team=infra', 'label=tier=db']))


if __name__ == '__main__':
    unittest.main()
