import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'build_polyglot', ROOT / 'scripts' / 'build_polyglot.py'
)
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)


class TestBuildMetaBlock(unittest.TestCase):
    def test_includes_update_fields(self):
        block = bp.build_meta_block(
            'demo:latest',
            digest='demo@sha256:' + 'a' * 64,
            self_update_url='https://example.com/demo.json',
            pin_digest='b' * 64,
        )
        self.assertEqual(block[4:4 + len(bp.META_MAGIC)], bp.META_MAGIC)
        total_size = int.from_bytes(block[:4], 'little')
        self.assertEqual(total_size, len(block))
        payload = block[4 + len(bp.META_MAGIC):-1]
        meta = json.loads(payload)
        self.assertEqual(meta['image'], 'demo:latest')
        self.assertEqual(meta['self_update_url'],
                         'https://example.com/demo.json')
        self.assertEqual(meta['pin_digest'], 'b' * 64)

    def test_patch_auto_pin_digest_replaces_placeholder(self):
        block = bp.build_meta_block('demo:latest', pin_digest='auto')
        self.assertIn(bp.PIN_DIGEST_PLACEHOLDER.encode(), block)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'demo.bin'
            path.write_bytes(b'prefix-data' + block)
            bp.patch_auto_pin_digest(str(path))
            patched = path.read_bytes()
        self.assertNotIn(bp.PIN_DIGEST_PLACEHOLDER.encode(), patched)
        self.assertIn(b'"pin_digest":"', patched)
        meta = json.loads(patched[patched.rfind(bp.META_MAGIC) + len(bp.META_MAGIC):-1])
        needle = f'"pin_digest":"{meta["pin_digest"]}"'.encode()
        repl = f'"pin_digest":"{bp.PIN_DIGEST_PLACEHOLDER}"'.encode()
        self.assertEqual(
            hashlib.sha256(patched.replace(needle, repl, 1)).hexdigest(),
            meta['pin_digest'],
        )

    def test_patch_algorithm_prefixed_auto_pin_digest(self):
        block = bp.build_meta_block('demo:latest', pin_digest='sha512:auto')
        self.assertIn(b'"pin_digest":"sha512:', block)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'demo.bin'
            path.write_bytes(b'prefix-data' + block)
            bp.patch_auto_pin_digest(str(path))
            patched = path.read_bytes()
        meta = json.loads(patched[patched.rfind(bp.META_MAGIC) + len(bp.META_MAGIC):-1])
        self.assertTrue(meta['pin_digest'].startswith('sha512:'))
        needle = f'"pin_digest":"{meta["pin_digest"]}"'.encode()
        repl = f'"pin_digest":"sha512:{"0" * bp.HASH_ALGORITHM_HEX_LENGTHS["sha512"]}"'.encode()
        self.assertEqual(
            hashlib.sha512(patched.replace(needle, repl, 1)).hexdigest(),
            meta['pin_digest'].split(':', 1)[1],
        )

    def test_invalid_pin_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            bp.build_meta_block('demo:latest', pin_digest='xyz')
        with self.assertRaises(ValueError):
            bp.build_meta_block('demo:latest', pin_digest='sha384:auto')


if __name__ == '__main__':
    unittest.main()
