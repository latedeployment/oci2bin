"""
Unit tests for build-side --compress-binary helpers in build_polyglot:
  - repack_oci_tar_uncompress_layers: inflates gzipped layer blobs while
    preserving member names/metadata and leaving non-gzip members untouched.
  - zstd_compress_payload: produces a zstd frame (magic 28 b5 2f fd) that the
    loader's blob_is_zstd_compressed() (C unit tests) recognises, round-tripping
    via `zstd -d`.

`zstd` is required only for the zstd_compress_payload test, which is skipped
when the binary is absent.
"""

import gzip
import importlib.util
import io
import pathlib
import shutil
import subprocess
import tarfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_module('build_polyglot', ROOT / 'scripts' / 'build_polyglot.py')


def _make_oci_tar():
    """Build a tiny fake OCI tar: a JSON manifest plus one gzipped layer."""
    buf = io.BytesIO()
    tar = tarfile.open(fileobj=buf, mode='w')

    manifest = b'[{"Config":"config.json","Layers":["layer.tar"]}]'
    mi = tarfile.TarInfo('manifest.json')
    mi.size = len(manifest)
    tar.addfile(mi, io.BytesIO(manifest))

    # A real (uncompressed) layer tar containing one file, then gzip it — this
    # mirrors how docker save stores layer blobs.
    inner = io.BytesIO()
    itar = tarfile.open(fileobj=inner, mode='w')
    payload = b'hello world\n' * 100
    fi = tarfile.TarInfo('etc/hello')
    fi.size = len(payload)
    itar.addfile(fi, io.BytesIO(payload))
    itar.close()
    layer_gz = gzip.compress(inner.getvalue())

    li = tarfile.TarInfo('layer.tar')
    li.size = len(layer_gz)
    tar.addfile(li, io.BytesIO(layer_gz))
    tar.close()
    return buf.getvalue()


class TestUncompressLayers(unittest.TestCase):
    def test_layer_is_inflated_and_extractable(self):
        oci = _make_oci_tar()
        out = bp.repack_oci_tar_uncompress_layers(oci)

        t = tarfile.open(fileobj=io.BytesIO(out))
        names = t.getnames()
        self.assertIn('manifest.json', names)
        self.assertIn('layer.tar', names)

        # The layer blob is no longer gzip-compressed...
        layer = t.extractfile('layer.tar').read()
        self.assertNotEqual(layer[:2], b'\x1f\x8b',
                            "layer should be inflated, not gzip")
        # ...but is still a valid tar the loader can extract with `tar xf`.
        inner = tarfile.open(fileobj=io.BytesIO(layer))
        self.assertEqual(inner.extractfile('etc/hello').read(),
                         b'hello world\n' * 100)

    def test_manifest_preserved_verbatim(self):
        oci = _make_oci_tar()
        out = bp.repack_oci_tar_uncompress_layers(oci)
        t = tarfile.open(fileobj=io.BytesIO(out))
        self.assertEqual(
            t.extractfile('manifest.json').read(),
            b'[{"Config":"config.json","Layers":["layer.tar"]}]')

    def test_idempotent_on_uncompressed_input(self):
        # Running twice (already-inflated layers) must not corrupt anything.
        oci = _make_oci_tar()
        once = bp.repack_oci_tar_uncompress_layers(oci)
        twice = bp.repack_oci_tar_uncompress_layers(once)
        a = tarfile.open(fileobj=io.BytesIO(once))
        b = tarfile.open(fileobj=io.BytesIO(twice))
        self.assertEqual(a.extractfile('layer.tar').read(),
                         b.extractfile('layer.tar').read())


@unittest.skipIf(shutil.which('zstd') is None, "zstd not installed")
class TestZstdCompress(unittest.TestCase):
    def test_zstd_magic_and_roundtrip(self):
        data = b'the quick brown fox ' * 1000
        comp = bp.zstd_compress_payload(data)
        self.assertEqual(comp[:4], b'\x28\xb5\x2f\xfd',
                         "compressed output must carry the zstd frame magic")
        back = subprocess.run(['zstd', '-d', '-q', '-c'],
                              input=comp, stdout=subprocess.PIPE,
                              check=True).stdout
        self.assertEqual(back, data)


if __name__ == '__main__':
    unittest.main()
