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
# Must match build_polyglot.PAGE_SIZE: the loader is placed at this file offset
# and every ELF segment p_offset is shifted by it. 64 KiB keeps the segments
# loadable on 4/16/64 KiB-page kernels (the Raspberry Pi 5 kernel uses 16 KiB).
PAGE_SIZE = 65536
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
        # The loader binary starts at PAGE_SIZE. The OCI data starts somewhere
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
        import platform
        arch = platform.machine()
        loader = ROOT / 'build' / f'loader-{arch}'
        if not loader.exists():
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


# ── TestPolyglotPageAlignment ────────────────────────────────────────────────

def _phdrs(data):
    """Yield (p_type, p_offset, p_vaddr, p_align) for each program header in an
    ELF64 image. Works on the polyglot too: its ELF header lives in bytes 0-63."""
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_align = struct.unpack_from('<Q', data, off + 48)[0]
        yield p_type, p_offset, p_vaddr, p_align


@unittest.skipUnless(sys.platform.startswith('linux'),
                     'loader is a static Linux ELF')
class TestPolyglotPageAlignment(unittest.TestCase):
    """Regression: shifting the loader's segments into the polyglot must
    preserve each PT_LOAD's p_offset == p_vaddr (mod p_align). The kernel
    requires p_offset == p_vaddr (mod runtime_page_size), and a correctly
    linked binary always has runtime_page_size dividing p_align, so preserving
    congruence mod p_align preserves it for every page size the target can use.

    The builder shifts segments by PAGE_SIZE (64 KiB). A 4 KiB shift kept
    congruence for x86_64 (p_align 0x1000) but broke it for aarch64, whose
    static binaries are linked with p_align 0x10000 (64 KiB) -- so the shift
    must be a multiple of 64 KiB. The old 4 KiB shift segfaulted on 16 KiB-page
    aarch64 kernels such as the Raspberry Pi 5.
    """

    PT_LOAD = 1

    @classmethod
    def setUpClass(cls):
        import platform
        loader = ROOT / 'build' / f'loader-{platform.machine()}'
        if not loader.exists():
            loader = ROOT / 'build' / 'loader'
        if not loader.exists():
            # Build one from source so the test is self-contained (no Docker).
            if not (gcc := __import__('shutil').which('gcc')):
                raise unittest.SkipTest('no prebuilt loader and gcc unavailable')
            cls._tmp = tempfile.TemporaryDirectory(prefix='oci2bin-pgalign-')
            loader = Path(cls._tmp.name) / 'loader'
            build = subprocess.run(
                [gcc, '-static', '-O2', '-s', '-o', str(loader),
                 str(ROOT / 'src' / 'loader.c')],
                capture_output=True, text=True,
            )
            if build.returncode != 0:
                raise unittest.SkipTest(f'loader build failed: {build.stderr}')
        cls.loader = loader

    @classmethod
    def tearDownClass(cls):
        if tmp := getattr(cls, '_tmp', None):
            tmp.cleanup()

    def _build_polyglot(self):
        with tempfile.TemporaryDirectory() as td:
            # Any tar works — the builder embeds it verbatim; the ELF layout
            # (what we assert on) is independent of the payload's contents.
            tar_path = os.path.join(td, 'payload.tar')
            with tarfile.open(tar_path, 'w') as tf:
                info = tarfile.TarInfo('hello')
                info.size = 0
                tf.addfile(info)
            out = os.path.join(td, 'out.img')
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts' / 'build_polyglot.py'),
                 '--loader', str(self.loader), '--tar', tar_path,
                 '--image-name', 'test:latest', '--output', out],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0,
                             f'build_polyglot.py failed:\n{result.stderr}')
            with open(out, 'rb') as f:
                return f.read()

    def test_load_segments_preserve_align_congruence(self):
        data = self._build_polyglot()
        loads = [(o, v, a) for t, o, v, a in _phdrs(data) if t == self.PT_LOAD]
        self.assertGreater(len(loads), 0, 'no PT_LOAD segments in polyglot')
        checked = 0
        for p_offset, p_vaddr, p_align in loads:
            if p_align <= 1:
                continue  # no alignment constraint on this segment
            checked += 1
            self.assertEqual(
                p_offset % p_align, p_vaddr % p_align,
                msg=(f'PT_LOAD offset=0x{p_offset:x} vaddr=0x{p_vaddr:x} '
                     f'not congruent mod p_align={p_align:#x}: the segment '
                     f'shift broke ELF load alignment and execve() would '
                     f'EINVAL on any kernel whose page size divides p_align'))
        self.assertGreater(checked, 0, 'no PT_LOAD segment had a page p_align')


if __name__ == '__main__':
    unittest.main()
