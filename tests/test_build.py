"""
test_build.py — Python unit tests for build_polyglot.py helper functions.

Runs standalone with:  python3 -m unittest tests.test_build -v
"""

import importlib.util
import struct
import sys
import unittest
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


if __name__ == '__main__':
    unittest.main()
