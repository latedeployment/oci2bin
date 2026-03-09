"""
test_polyglot.py — Structural + build integration tests for the oci2bin polyglot.

TestExistingPolyglot: runs against the pre-built oci2bin.img (no Docker needed).
TestBuildPolyglotIntegration: builds a fresh polyglot in a tempdir (needs Docker + alpine).

Run all:       python3 -m unittest tests.test_polyglot -v
Run existing:  python3 -m unittest tests.test_polyglot.TestExistingPolyglot -v
"""

import importlib.util
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

# ── Load build_polyglot ───────────────────────────────────────────────────────

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'build_polyglot', ROOT / 'scripts' / 'build_polyglot.py'
)
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)

IMG = ROOT / 'oci2bin.img'
PAGE_SIZE = 4096
VADDR_BASE = 0x400000


def _docker_available():
    try:
        r = subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _alpine_available():
    if not _docker_available():
        return False
    try:
        r = subprocess.run(
            ['docker', 'image', 'inspect', 'alpine:latest'],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── TestExistingPolyglot ─────────────────────────────────────────────────────

@unittest.skipUnless(IMG.exists(), f'oci2bin.img not found at {IMG}')
class TestExistingPolyglot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(IMG, 'rb') as f:
            cls.data = f.read()

    # ── ELF magic ────────────────────────────────────────────────────────────

    def test_elf_magic_at_byte_0(self):
        self.assertEqual(self.data[0:4], b'\x7fELF')

    def test_elf_class_64(self):
        self.assertEqual(self.data[4], 2)  # ELFCLASS64

    def test_elf_machine_x86_64(self):
        e_machine = struct.unpack_from('<H', self.data, 18)[0]
        self.assertEqual(e_machine, 0x3e)

    def test_elf_type_exec(self):
        e_type = struct.unpack_from('<H', self.data, 16)[0]
        self.assertEqual(e_type, 2)  # ET_EXEC

    def test_elf_shnum_zero(self):
        e_shnum = struct.unpack_from('<H', self.data, 60)[0]
        self.assertEqual(e_shnum, 0)

    def test_elf_phoff_ge_page_size(self):
        e_phoff = struct.unpack_from('<Q', self.data, 32)[0]
        self.assertGreaterEqual(e_phoff, PAGE_SIZE)

    def test_elf_entry_ge_vaddr_base(self):
        e_entry = struct.unpack_from('<Q', self.data, 24)[0]
        self.assertGreaterEqual(e_entry, VADDR_BASE)

    # ── TAR magic ────────────────────────────────────────────────────────────

    def test_ustar_magic_at_byte_257(self):
        self.assertEqual(self.data[257:263], b'ustar\x00')

    # ── Marker patching ──────────────────────────────────────────────────────

    def test_raw_offset_marker_absent(self):
        offset_marker = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
        self.assertNotIn(offset_marker, self.data)

    def test_raw_size_marker_absent(self):
        size_marker = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
        self.assertNotIn(size_marker, self.data)

    def test_raw_patched_marker_absent(self):
        patched_marker = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)
        self.assertNotIn(patched_marker, self.data)

    def test_patched_flag_in_loader_region(self):
        # The loader binary starts at PAGE_SIZE (4096). The OCI data starts somewhere
        # after that. Patched flag (=1 as uint64 LE) must appear in the loader region.
        patched_flag = struct.pack('<Q', 1)
        loader_region = self.data[512:PAGE_SIZE * 2]  # conservative upper bound
        self.assertIn(patched_flag, loader_region)

    # ── TAR readability ──────────────────────────────────────────────────────

    def test_readable_as_tar(self):
        import io
        try:
            tf = tarfile.open(fileobj=io.BytesIO(self.data))
            names = tf.getnames()
            tf.close()
            self.assertIsInstance(names, list)
        except Exception as e:
            self.fail(f'Failed to open as tarfile: {e}')

    def test_tar_contains_manifest_json(self):
        import io
        tf = tarfile.open(fileobj=io.BytesIO(self.data))
        names = tf.getnames()
        tf.close()
        self.assertIn('manifest.json', names)

    def test_manifest_json_valid(self):
        import io
        tf = tarfile.open(fileobj=io.BytesIO(self.data))
        member = tf.getmember('manifest.json')
        f = tf.extractfile(member)
        content = json.loads(f.read())
        tf.close()
        # Docker manifest is a list of objects
        self.assertIsInstance(content, list)
        self.assertGreater(len(content), 0)
        entry = content[0]
        self.assertIn('Config', entry)
        self.assertIn('Layers', entry)

    # ── Embedded OCI tar ─────────────────────────────────────────────────────

    def test_embedded_oci_tar_valid(self):
        import io
        # Compute OCI offset: same formula as builder
        # TAR_BLOCK=512, loader starts at PAGE_SIZE, then padded
        # We can derive oci_offset by reading the patched uint64 at a known location.
        # Simpler: read it from the ELF-embedded data.  The builder patches
        # OCI_DATA_OFFSET as a uint64 in the loader segment.
        # For the test, find the offset by scanning the first 2 tar blocks worth
        # of data after block 0 for a value that, when used as offset, yields a valid tar.
        # More robust: use the formula from the builder directly.
        # We know: loader is at PAGE_SIZE, so we search for the uint64 that is a
        # plausible offset (>= PAGE_SIZE, < len(data), % 512 == 0).
        found = False
        for candidate_offset in range(PAGE_SIZE, len(self.data) - 512, 512):
            chunk = self.data[candidate_offset:candidate_offset + 512]
            if chunk[257:263] == b'ustar\x00' and chunk[0:4] != b'\x7fELF':
                # Looks like a tar header that isn't the first header
                oci_chunk = self.data[candidate_offset:]
                try:
                    tf2 = tarfile.open(fileobj=io.BytesIO(oci_chunk))
                    inner_names = tf2.getnames()
                    tf2.close()
                    if 'manifest.json' in inner_names:
                        found = True
                        break
                except Exception:
                    pass
        self.assertTrue(found, 'Could not find a valid OCI tar embedded in polyglot')

    # ── File permissions ─────────────────────────────────────────────────────

    def test_file_is_executable(self):
        self.assertTrue(os.access(IMG, os.X_OK))


# ── TestBuildPolyglotIntegration ─────────────────────────────────────────────

@unittest.skipUnless(_alpine_available(), 'Docker + alpine:latest not available')
class TestBuildPolyglotIntegration(unittest.TestCase):
    def test_build_and_verify(self):
        loader = ROOT / 'build' / 'loader'
        if not loader.exists():
            self.skipTest('build/loader not found — run make loader first')

        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'test.img')
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'scripts' / 'build_polyglot.py'),
                    '--loader', str(loader),
                    '--image', 'alpine:latest',
                    '--output', output,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0,
                             f'build_polyglot.py failed:\n{result.stderr}')

            with open(output, 'rb') as f:
                data = f.read()

            # ELF magic
            self.assertEqual(data[0:4], b'\x7fELF')
            # ustar magic
            self.assertEqual(data[257:263], b'ustar\x00')
            # Markers absent
            self.assertNotIn(struct.pack('<Q', 0xDEADBEEFCAFEBABE), data)
            self.assertNotIn(struct.pack('<Q', 0xCAFEBABEDEADBEEF), data)
            self.assertNotIn(struct.pack('<Q', 0xAAAAAAAAAAAAAAAA), data)
            # Executable
            self.assertTrue(os.access(output, os.X_OK))


if __name__ == '__main__':
    unittest.main()
