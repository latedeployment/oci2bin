"""
test_build.py — Python unit tests for build_polyglot.py helper functions.

Runs standalone with:  python3 -m unittest tests.test_build -v
"""

import importlib.util
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

# ── Load build_polyglot without mutating sys.path ────────────────────────────

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'build_polyglot', ROOT / 'scripts' / 'build_polyglot.py'
)
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)


# ── TestTarOctal ─────────────────────────────────────────────────────────────

class TestTarOctal(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(bp.tar_octal(0, 8)), 8)
        self.assertEqual(len(bp.tar_octal(0o755, 8)), 8)
        self.assertEqual(len(bp.tar_octal(0, 12)), 12)

    def test_zero_padded(self):
        result = bp.tar_octal(0o755, 8)
        self.assertEqual(result, b'0000755\x00')

    def test_null_terminator(self):
        result = bp.tar_octal(42, 8)
        self.assertEqual(result[-1:], b'\x00')

    def test_zero_value(self):
        result = bp.tar_octal(0, 8)
        self.assertEqual(result, b'0000000\x00')

    def test_large_value(self):
        # 12-byte field used for size
        result = bp.tar_octal(1024 * 1024, 12)
        self.assertEqual(len(result), 12)
        self.assertEqual(result[-1:], b'\x00')
        # Value should round-trip via int(result[:-1], 8)
        val = int(result[:-1], 8)
        self.assertEqual(val, 1024 * 1024)

    def test_fits_within_width(self):
        # The octal representation must fit in width-1 chars
        result = bp.tar_octal(0o777, 8)
        self.assertEqual(len(result), 8)

    def test_width_1_edge(self):
        result = bp.tar_octal(0, 1)
        self.assertEqual(result, b'\x00')


# ── TestTarChecksum ──────────────────────────────────────────────────────────

class TestTarChecksum(unittest.TestCase):
    def test_blank_header(self):
        # All-zero 512-byte header: 8 bytes [148-155] treated as spaces (0x20=32 each)
        header = b'\x00' * 512
        self.assertEqual(bp.tar_checksum(header), 8 * 32)

    def test_chksum_field_treated_as_spaces(self):
        # Fill the chksum field with non-space bytes; checksum should still treat them as spaces
        header = bytearray(512)
        header[148:156] = b'\xff' * 8  # arbitrary non-space bytes
        result = bp.tar_checksum(bytes(header))
        # Same as all-zero since chksum field is always treated as spaces
        self.assertEqual(result, 8 * 32)

    def test_non_zero_bytes_outside_chksum(self):
        header = bytearray(512)
        header[0] = 1
        header[511] = 2
        result = bp.tar_checksum(bytes(header))
        self.assertEqual(result, 8 * 32 + 1 + 2)

    def test_roundtrip_via_build_tar_header(self):
        # Build a tar header and verify the checksum field encodes a parseable value
        h = bp.build_tar_header(b'testfile.txt', size=0)
        # Extract stored checksum (bytes 148-155: 6 octal digits + space + null)
        chk_field = h[148:155].rstrip(b'\x00 ')
        stored_chk = int(chk_field, 8)
        # Compute what it should be
        expected = bp.tar_checksum(h)
        self.assertEqual(stored_chk, expected)


# ── TestBuildTarHeader ───────────────────────────────────────────────────────

class TestBuildTarHeader(unittest.TestCase):
    def setUp(self):
        self.header = bp.build_tar_header(b'hello.txt', size=1234, mode=0o644)

    def test_length_512(self):
        self.assertEqual(len(self.header), 512)

    def test_ustar_magic_at_257(self):
        self.assertEqual(self.header[257:263], b'ustar\x00')

    def test_name_field(self):
        name = self.header[0:9]
        self.assertEqual(name, b'hello.txt')

    def test_name_padded_to_100(self):
        self.assertEqual(len(self.header[0:100]), 100)
        self.assertEqual(self.header[9:100], b'\x00' * 91)

    def test_size_field(self):
        size_octal = self.header[124:136].rstrip(b'\x00')
        self.assertEqual(int(size_octal, 8), 1234)

    def test_mode_field(self):
        mode_octal = self.header[100:108].rstrip(b'\x00')
        self.assertEqual(int(mode_octal, 8), 0o644)

    def test_elf_header_as_name(self):
        # Key polyglot invariant: ELF header (64 bytes) fits in 100-byte tar name field
        elf_hdr = bp.build_elf64_header(entry=0x401000, phoff=4096 + 64, phnum=2)
        h = bp.build_tar_header(elf_hdr, size=0)
        # ustar must still be intact at 257
        self.assertEqual(h[257:263], b'ustar\x00')
        # ELF magic preserved at byte 0
        self.assertEqual(h[0:4], b'\x7fELF')

    def test_typeflag(self):
        self.assertEqual(self.header[156:157], b'0')

    def test_uname_root(self):
        uname = self.header[265:269]
        self.assertEqual(uname, b'root')

    def test_gname_root(self):
        gname = self.header[297:301]
        self.assertEqual(gname, b'root')


# ── TestBuildElf64Header ─────────────────────────────────────────────────────

class TestBuildElf64Header(unittest.TestCase):
    def setUp(self):
        self.entry = 0x401000
        self.phoff = 4096 + 64
        self.phnum = 2
        self.hdr = bp.build_elf64_header(self.entry, self.phoff, self.phnum)

    def test_length_64(self):
        self.assertEqual(len(self.hdr), 64)

    def test_elf_magic(self):
        self.assertEqual(self.hdr[0:4], b'\x7fELF')

    def test_class_64(self):
        # EI_CLASS at byte 4
        self.assertEqual(self.hdr[4], 2)  # ELFCLASS64

    def test_data_lsb(self):
        # EI_DATA at byte 5
        self.assertEqual(self.hdr[5], 1)  # ELFDATA2LSB

    def test_type_exec(self):
        e_type = struct.unpack_from('<H', self.hdr, 16)[0]
        self.assertEqual(e_type, 2)  # ET_EXEC

    def test_machine_x86_64(self):
        e_machine = struct.unpack_from('<H', self.hdr, 18)[0]
        self.assertEqual(e_machine, 0x3e)  # EM_X86_64

    def test_entry_point(self):
        e_entry = struct.unpack_from('<Q', self.hdr, 24)[0]
        self.assertEqual(e_entry, self.entry)

    def test_phoff(self):
        e_phoff = struct.unpack_from('<Q', self.hdr, 32)[0]
        self.assertEqual(e_phoff, self.phoff)

    def test_phnum(self):
        e_phnum = struct.unpack_from('<H', self.hdr, 56)[0]
        self.assertEqual(e_phnum, self.phnum)

    def test_shnum_zero(self):
        # No section headers — they would collide with tar content
        e_shnum = struct.unpack_from('<H', self.hdr, 60)[0]
        self.assertEqual(e_shnum, 0)

    def test_fits_in_tar_name_field(self):
        # ELF header (64 bytes) must fit in tar's 100-byte name field
        self.assertLessEqual(len(self.hdr), 100)

    def test_shoff_zero(self):
        e_shoff = struct.unpack_from('<Q', self.hdr, 40)[0]
        self.assertEqual(e_shoff, 0)


# ── TestPatchMarkers ─────────────────────────────────────────────────────────

class TestPatchMarkers(unittest.TestCase):
    OFFSET_MARKER = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
    SIZE_MARKER   = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
    PATCHED_MARKER = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)

    def _make_data(self):
        return self.OFFSET_MARKER + self.SIZE_MARKER + self.PATCHED_MARKER

    def test_offset_replaced(self):
        data = self._make_data()
        result = bp.patch_markers(data, oci_offset=0x1234, oci_size=0x5678)
        self.assertIn(struct.pack('<Q', 0x1234), result)
        self.assertNotIn(self.OFFSET_MARKER, result)

    def test_size_replaced(self):
        data = self._make_data()
        result = bp.patch_markers(data, oci_offset=0x1234, oci_size=0x5678)
        self.assertIn(struct.pack('<Q', 0x5678), result)
        self.assertNotIn(self.SIZE_MARKER, result)

    def test_patched_flag_set_to_1(self):
        data = self._make_data()
        result = bp.patch_markers(data, oci_offset=0x1234, oci_size=0x5678)
        self.assertIn(struct.pack('<Q', 1), result)
        self.assertNotIn(self.PATCHED_MARKER, result)

    def test_noop_on_missing_markers(self):
        # Data with no markers: patch_markers should not crash, just return data
        data = b'\x00' * 64
        result = bp.patch_markers(data, oci_offset=100, oci_size=200)
        # No offset/size markers were present, so data is unchanged for those fields
        self.assertEqual(len(result), len(data))

    def test_all_occurrences_replaced(self):
        # Two copies of offset marker
        data = self.OFFSET_MARKER * 2 + self.SIZE_MARKER + self.PATCHED_MARKER
        result = bp.patch_markers(data, oci_offset=0xABCD, oci_size=0xEF01)
        self.assertNotIn(self.OFFSET_MARKER, result)
        # Both replaced with same value
        self.assertEqual(result.count(struct.pack('<Q', 0xABCD)), 2)


# ── TestTarPad ───────────────────────────────────────────────────────────────

class TestTarPad(unittest.TestCase):
    def test_already_aligned_unchanged(self):
        data = b'x' * 512
        self.assertEqual(bp.tar_pad(data), data)

    def test_pads_to_next_512(self):
        data = b'x' * 100
        result = bp.tar_pad(data)
        self.assertEqual(len(result), 512)
        self.assertEqual(result[100:], b'\x00' * 412)

    def test_zero_length(self):
        result = bp.tar_pad(b'')
        self.assertEqual(result, b'')

    def test_exactly_1024(self):
        data = b'x' * 1024
        self.assertEqual(bp.tar_pad(data), data)

    def test_1025_pads_to_1536(self):
        data = b'x' * 1025
        result = bp.tar_pad(data)
        self.assertEqual(len(result), 1536)

    def test_511_pads_to_512(self):
        data = b'y' * 511
        result = bp.tar_pad(data)
        self.assertEqual(len(result), 512)
        self.assertEqual(result[-1:], b'\x00')


class TestLayerCache(unittest.TestCase):
    @staticmethod
    def _make_oci_tar(layers):
        manifest = [{
            'Config': 'config.json',
            'RepoTags': ['example:latest'],
            'Layers': [name for name, _ in layers],
        }]
        config = {
            'rootfs': {
                'type': 'layers',
                'diff_ids': [
                    f'sha256:{hashlib.sha256(data).hexdigest()}'
                    for _, data in layers
                ],
            },
            'config': {},
        }

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:') as tf:
            manifest_raw = json.dumps(manifest, separators=(',', ':')).encode()
            manifest_info = tarfile.TarInfo('manifest.json')
            manifest_info.size = len(manifest_raw)
            tf.addfile(manifest_info, io.BytesIO(manifest_raw))

            config_raw = json.dumps(config, separators=(',', ':')).encode()
            config_info = tarfile.TarInfo('config.json')
            config_info.size = len(config_raw)
            tf.addfile(config_info, io.BytesIO(config_raw))

            for name, data in layers:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def _make_mismatched_oci_tar(self):
        """A tar whose layer bytes do not hash to the declared diff_id."""
        honest = self._make_oci_tar([('layer0/layer.tar', b'layer-zero')])
        tampered = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(honest), mode='r:*') as src, \
                tarfile.open(fileobj=tampered, mode='w:') as out:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == 'layer0/layer.tar':
                    data = b'tampered!!'
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
        return tampered.getvalue()

    def test_verify_layer_digests_populates_and_hits(self):
        layers = [
            ('layer0/layer.tar', b'layer-zero'),
            ('layer1/layer.tar', b'layer-one'),
        ]
        oci_data = self._make_oci_tar(layers)

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            stats = bp.verify_layer_digests(oci_data, use_cache=True)
            self.assertEqual(stats, {'hits': 0, 'misses': 2, 'verified': 2})

            cache_root = Path(bp.get_layer_cache_root())
            for _, data in layers:
                digest = hashlib.sha256(data).hexdigest()
                self.assertEqual((cache_root / f'{digest}.tar').read_bytes(), data)

            stats = bp.verify_layer_digests(oci_data, use_cache=True)
            self.assertEqual(stats, {'hits': 2, 'misses': 0, 'verified': 2})

    def test_verify_layer_digests_refreshes_corrupt_entry(self):
        layers = [('layer0/layer.tar', b'layer-zero')]
        oci_data = self._make_oci_tar(layers)
        digest = hashlib.sha256(layers[0][1]).hexdigest()

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            cache_root = Path(bp.get_layer_cache_root())
            cache_root.mkdir(parents=True, exist_ok=True)
            (cache_root / f'{digest}.tar').write_bytes(b'corrupt')

            stats = bp.verify_layer_digests(oci_data, use_cache=True)
            self.assertEqual(stats, {'hits': 0, 'misses': 1, 'verified': 1})
            self.assertEqual((cache_root / f'{digest}.tar').read_bytes(),
                             layers[0][1])

    def test_verify_layer_digests_no_cache_still_verifies(self):
        layers = [('layer0/layer.tar', b'layer-zero')]
        oci_data = self._make_oci_tar(layers)

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            stats = bp.verify_layer_digests(oci_data, use_cache=False)
            # --no-cache disables the cache, not the integrity check.
            self.assertEqual(stats, {'hits': 0, 'misses': 0, 'verified': 1})
            self.assertFalse(Path(bp.get_layer_cache_root()).exists())

    def test_verify_layer_digests_rejects_mismatch(self):
        """A layer whose bytes do not match its diff_id aborts the build."""
        oci_data = self._make_mismatched_oci_tar()
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            with self.assertRaises(SystemExit) as cm:
                bp.verify_layer_digests(oci_data, use_cache=True)
            self.assertEqual(cm.exception.code, 1)

    def test_verify_layer_digests_mismatch_not_masked_by_cache_hit(self):
        """
        The cache is keyed by the *claimed* diff_id, so a warm cache entry says
        nothing about the tar being built. A hit must not skip verification.
        """
        honest = self._make_oci_tar([('layer0/layer.tar', b'layer-zero')])
        tampered = self._make_mismatched_oci_tar()

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            # Warm the cache with the honest layer so the digest is a hit.
            bp.verify_layer_digests(honest, use_cache=True)
            digest = hashlib.sha256(b'layer-zero').hexdigest()
            self.assertTrue(
                (Path(bp.get_layer_cache_root()) / f'{digest}.tar').exists())

            with self.assertRaises(SystemExit) as cm:
                bp.verify_layer_digests(tampered, use_cache=True)
            self.assertEqual(cm.exception.code, 1)

    def _make_oci_tar_with_config(self, layers, mutate):
        """Build a tar, then rewrite config.json via `mutate`."""
        honest = self._make_oci_tar(layers)
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(honest), mode='r:*') as src, \
                tarfile.open(fileobj=out, mode='w:') as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == 'config.json':
                    cfg = json.loads(data)
                    mutate(cfg)
                    data = json.dumps(cfg, separators=(',', ':')).encode()
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))
        return out.getvalue()

    def test_verify_layer_digests_refuses_unverifiable(self):
        """
        Every reason the digests cannot be determined is reachable from the
        input tar alone, so warning and continuing would leave "delete
        rootfs.diff_ids" as a one-line bypass of the whole check.
        """
        layers = [('layer0/layer.tar', b'layer-zero')]
        cases = {
            'diff_ids deleted': lambda c: c['rootfs'].pop('diff_ids'),
            'diff_ids empty': lambda c: c['rootfs'].update(diff_ids=[]),
            'diff_ids not a list': lambda c: c['rootfs'].update(diff_ids='x'),
            'diff_ids not a digest':
                lambda c: c['rootfs'].update(diff_ids=['bogus']),
            'rootfs deleted': lambda c: c.pop('rootfs'),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                oci_data = self._make_oci_tar_with_config(layers, mutate)
                with tempfile.TemporaryDirectory() as td, \
                        mock.patch.dict(os.environ,
                                        {'XDG_CACHE_HOME': td}, clear=False):
                    with self.assertRaises(SystemExit) as cm:
                        bp.verify_layer_digests(oci_data, use_cache=True)
                    self.assertEqual(cm.exception.code, 1)

    def test_verify_layer_digests_rejects_bad_gzip(self):
        """A layer claiming gzip that does not decompress fails with an error,
        not an uncaught BadGzipFile traceback."""
        layers = [('layer0/layer.tar', b'\x1f\x8bnot really gzip')]
        oci_data = self._make_oci_tar(layers)
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            with self.assertRaises(SystemExit) as cm:
                bp.verify_layer_digests(oci_data, use_cache=True)
            self.assertEqual(cm.exception.code, 1)

    def test_write_cached_layer_does_not_follow_symlinks(self):
        """
        XDG_CACHE_HOME is user-settable, so a predictable temp path in a shared
        cache root was an arbitrary-file-write primitive.
        """
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ,
                                {'XDG_CACHE_HOME': td + '/cache'}, clear=False):
            victim = Path(td) / 'victim'
            victim.write_bytes(b'PRECIOUS')
            cache_root = Path(bp.get_layer_cache_root())
            cache_root.mkdir(parents=True, exist_ok=True)
            data = b'layer-zero'
            digest = hashlib.sha256(data).hexdigest()
            # the path the old implementation used
            os.symlink(victim, cache_root / f'{digest}.tar.tmp.{os.getpid()}')

            bp._write_cached_layer(str(cache_root), digest, data)

            self.assertEqual(victim.read_bytes(), b'PRECIOUS')
            self.assertEqual((cache_root / f'{digest}.tar').read_bytes(), data)
            self.assertEqual(
                (cache_root / f'{digest}.tar').stat().st_mode & 0o777, 0o600)

    def test_layer_cache_root_created_private(self):
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ,
                                {'XDG_CACHE_HOME': td + '/fresh'}, clear=False):
            root = bp.get_layer_cache_root()
            bp._write_cached_layer(root, hashlib.sha256(b'x').hexdigest(), b'x')
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)

    def test_verify_layer_digests_mismatch_not_masked_by_no_cache(self):
        oci_data = self._make_mismatched_oci_tar()
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.dict(os.environ, {'XDG_CACHE_HOME': td}, clear=False):
            with self.assertRaises(SystemExit) as cm:
                bp.verify_layer_digests(oci_data, use_cache=False)
            self.assertEqual(cm.exception.code, 1)


class TestSquashFSRootfs(unittest.TestCase):
    def test_runtime_config_resolves_named_user(self):
        with tempfile.TemporaryDirectory() as td:
            etc = Path(td) / 'etc'
            etc.mkdir()
            (etc / 'passwd').write_text(
                'app:x:1001:1002:App:/home/app:/bin/sh\n',
                encoding='utf-8')
            (etc / 'group').write_text(
                'workers:x:2002:\n',
                encoding='utf-8')
            bp._write_runtime_config(td, {
                'config': {
                    'Entrypoint': ['/bin/app'],
                    'Cmd': ['serve'],
                    'Env': ['MODE=prod'],
                    'WorkingDir': '/srv',
                    'User': 'app',
                    'Healthcheck': {'Test': ['CMD', '/bin/check']},
                },
            })
            cfg = json.loads(
                (Path(td) / '.oci2bin_config').read_text(encoding='utf-8'))
            self.assertEqual(cfg['User'], '1001:1002')
            self.assertEqual(cfg['Entrypoint'], ['/bin/app'])
            self.assertEqual(cfg['Healthcheck']['Test'],
                             ['CMD', '/bin/check'])

            self.assertEqual(
                bp._resolve_image_user(td, 'app:workers'), '1001:2002')
            self.assertEqual(
                bp._resolve_image_user(td, '1001:workers'), '1001:2002')
            self.assertEqual(
                bp._resolve_image_user(td, 'app:3003'), '1001:3003')
            self.assertEqual(
                bp._resolve_image_user(td, '1001:3003'), '1001:3003')

    def test_build_squashfs_invokes_hardened_extractor_and_mksquashfs(self):
        image_cfg = {'config': {'Cmd': ['/bin/true'], 'User': '0'}}

        def fake_extract(_tar_path, rootfs):
            (Path(rootfs) / 'payload').write_text('ok', encoding='utf-8')
            return image_cfg

        def fake_run(argv, **_kwargs):
            Path(argv[2]).write_bytes(b'hsqs-fake')
            return mock.Mock(returncode=0, stderr=b'')

        with mock.patch.object(bp.shutil, 'which',
                               return_value='/usr/bin/mksquashfs'), \
                mock.patch.object(bp, '_load_dockerfile_rootfs_extractor',
                                  return_value=fake_extract), \
                mock.patch.object(bp.subprocess, 'run',
                                  side_effect=fake_run) as run:
            result = bp.build_squashfs_payload(b'fake-oci',
                                               reproducible=True)

        self.assertEqual(result, b'hsqs-fake')
        argv = run.call_args.args[0]
        self.assertIn('-all-root', argv)
        self.assertIn('-mkfs-time', argv)
        self.assertIn('-all-time', argv)

    def test_build_squashfs_requires_mksquashfs(self):
        with mock.patch.object(bp.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(SystemExit, 'requires.*mksquashfs'):
                bp.build_squashfs_payload(b'fake-oci')


if __name__ == '__main__':
    unittest.main()
