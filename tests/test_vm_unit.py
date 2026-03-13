"""
Unit tests for the VM backend helpers in build_polyglot.py.
No KVM required — all tests run on the host without any VM.
"""

import gzip
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest

# Add scripts/ to path so we can import build_polyglot
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts')
sys.path.insert(0, os.path.abspath(SCRIPTS_DIR))

import build_polyglot


class TestCpioInitramfs(unittest.TestCase):
    """Tests for build_polyglot.build_initramfs()"""

    def _make_rootfs(self, tmp):
        """Create a small rootfs tree for testing."""
        os.makedirs(os.path.join(tmp, 'bin'), exist_ok=True)
        os.makedirs(os.path.join(tmp, 'etc'), exist_ok=True)

        # Regular file
        with open(os.path.join(tmp, 'etc', 'hostname'), 'w') as f:
            f.write('testhost\n')

        # Binary with setuid bit (should be stripped)
        setuid_path = os.path.join(tmp, 'bin', 'su')
        with open(setuid_path, 'wb') as f:
            f.write(b'\x7fELF\x00' * 4)
        os.chmod(setuid_path, 0o4755)

        # Symlink
        os.symlink('/bin/sh', os.path.join(tmp, 'bin', 'ash'))

        return tmp

    def test_output_is_valid_gzip(self):
        with tempfile.TemporaryDirectory() as rootfs:
            self._make_rootfs(rootfs)
            with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as out:
                out_path = out.name
            try:
                build_polyglot.build_initramfs(rootfs, out_path)
                with open(out_path, 'rb') as f:
                    magic = f.read(2)
                self.assertEqual(magic, b'\x1f\x8b', "Output must start with gzip magic")
            finally:
                os.unlink(out_path)

    def test_cpio_contains_expected_paths(self):
        with tempfile.TemporaryDirectory() as rootfs:
            self._make_rootfs(rootfs)
            with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as out:
                out_path = out.name
            try:
                build_polyglot.build_initramfs(rootfs, out_path)
                # Extract cpio listing using the system cpio tool
                result = subprocess.run(
                    ['bash', '-c', f'zcat {out_path} | cpio -t 2>/dev/null'],
                    capture_output=True, text=True,
                )
                if result.returncode != 0:
                    self.skipTest("cpio tool not available for listing check")
                listing = result.stdout
                self.assertIn('bin/su', listing)
                self.assertIn('etc/hostname', listing)
                self.assertIn('bin/ash', listing)
            finally:
                os.unlink(out_path)

    def test_setuid_bit_stripped(self):
        """setuid bit (04000) must not appear in cpio output."""
        with tempfile.TemporaryDirectory() as rootfs:
            self._make_rootfs(rootfs)
            with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as out:
                out_path = out.name
            try:
                build_polyglot.build_initramfs(rootfs, out_path)
                raw = gzip.decompress(open(out_path, 'rb').read())
                # Scan cpio headers for mode fields containing setuid (04000)
                pos = 0
                found_su_setuid = False
                while pos + 110 <= len(raw):
                    if raw[pos:pos+6] != b'070701':
                        break
                    mode_hex = raw[pos+14:pos+22].decode('ascii', errors='replace')
                    namesize_hex = raw[pos+94:pos+102].decode('ascii', errors='replace')
                    try:
                        mode = int(mode_hex, 16)
                        namesize = int(namesize_hex, 16)
                    except ValueError:
                        break
                    # Read name
                    name_start = pos + 110
                    name_bytes = raw[name_start:name_start + namesize]
                    name = name_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
                    if 'su' in name and (mode & 0o4000):
                        found_su_setuid = True
                    # Advance to next entry
                    header_and_name = 110 + namesize
                    pad1 = build_polyglot._cpio_pad4(header_and_name)
                    filesize_hex = raw[pos+54:pos+62].decode('ascii', errors='replace')
                    try:
                        filesize = int(filesize_hex, 16)
                    except ValueError:
                        break
                    pad2 = build_polyglot._cpio_pad4(filesize)
                    pos += header_and_name + pad1 + filesize + pad2
                self.assertFalse(found_su_setuid,
                                 "setuid bit must be stripped from cpio output")
            finally:
                os.unlink(out_path)

    def test_symlink_included(self):
        """Symlinks must appear in cpio as symlinks (S_IFLNK = 0o120000)."""
        with tempfile.TemporaryDirectory() as rootfs:
            self._make_rootfs(rootfs)
            with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as out:
                out_path = out.name
            try:
                build_polyglot.build_initramfs(rootfs, out_path)
                raw = gzip.decompress(open(out_path, 'rb').read())
                pos = 0
                found_symlink = False
                S_IFLNK = 0o120000
                while pos + 110 <= len(raw):
                    if raw[pos:pos+6] != b'070701':
                        break
                    mode_hex = raw[pos+14:pos+22].decode('ascii', errors='replace')
                    namesize_hex = raw[pos+94:pos+102].decode('ascii', errors='replace')
                    filesize_hex = raw[pos+54:pos+62].decode('ascii', errors='replace')
                    try:
                        mode = int(mode_hex, 16)
                        namesize = int(namesize_hex, 16)
                        filesize = int(filesize_hex, 16)
                    except ValueError:
                        break
                    name_start = pos + 110
                    name = raw[name_start:name_start+namesize].rstrip(b'\x00').decode('utf-8', errors='replace')
                    if 'ash' in name and (mode & 0o170000) == S_IFLNK:
                        found_symlink = True
                    header_and_name = 110 + namesize
                    pad1 = build_polyglot._cpio_pad4(header_and_name)
                    pad2 = build_polyglot._cpio_pad4(filesize)
                    pos += header_and_name + pad1 + filesize + pad2
                self.assertTrue(found_symlink, "Symlinks must appear as S_IFLNK in cpio output")
            finally:
                os.unlink(out_path)

    def test_initramfs_only_cli(self):
        """--initramfs-only CLI flag must produce valid gzip output."""
        with tempfile.TemporaryDirectory() as rootfs:
            # Minimal rootfs
            with open(os.path.join(rootfs, 'hello'), 'w') as f:
                f.write('hi')
            with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as out:
                out_path = out.name
            try:
                script = os.path.join(SCRIPTS_DIR, 'build_polyglot.py')
                result = subprocess.run(
                    [sys.executable, script, '--initramfs-only', rootfs, out_path],
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0,
                                 f"--initramfs-only failed: {result.stderr.decode()}")
                self.assertTrue(os.path.exists(out_path))
                with open(out_path, 'rb') as f:
                    self.assertEqual(f.read(2), b'\x1f\x8b',
                                     "Output must be gzip-compressed")
            finally:
                os.unlink(out_path)


class TestMarkerPatching(unittest.TestCase):
    """Tests for VM marker patching in build_polyglot.patch_markers()."""

    def test_kernel_markers_patched(self):
        """KERNEL_OFFSET and KERNEL_SIZE sentinels must be replaced."""
        # Build fake loader data containing sentinel values
        sentinel_off  = build_polyglot.KERNEL_OFFSET_MARKER
        sentinel_size = build_polyglot.KERNEL_SIZE_MARKER
        # Also include OCI markers so patch_markers doesn't warn
        fake_data = (
            build_polyglot.OFFSET_MARKER +
            build_polyglot.SIZE_MARKER +
            build_polyglot.PATCHED_MARKER +
            sentinel_off +
            sentinel_size
        )
        patched = build_polyglot.patch_markers(
            fake_data, oci_offset=0x1000, oci_size=0x2000,
            kernel_offset=0xABCD0000, kernel_size=0x500000,
        )
        self.assertNotIn(sentinel_off, patched)
        self.assertNotIn(sentinel_size, patched)
        self.assertIn(struct.pack('<Q', 0xABCD0000), patched)
        self.assertIn(struct.pack('<Q', 0x500000), patched)

    def test_initramfs_markers_patched(self):
        """INITRAMFS_OFFSET and INITRAMFS_SIZE sentinels must be replaced."""
        sentinel_off  = build_polyglot.INITRAMFS_OFFSET_MARKER
        sentinel_size = build_polyglot.INITRAMFS_SIZE_MARKER
        fake_data = (
            build_polyglot.OFFSET_MARKER +
            build_polyglot.SIZE_MARKER +
            build_polyglot.PATCHED_MARKER +
            sentinel_off +
            sentinel_size
        )
        patched = build_polyglot.patch_markers(
            fake_data, oci_offset=0x1000, oci_size=0x2000,
            initramfs_offset=0xDEF00000, initramfs_size=0x100000,
        )
        self.assertNotIn(sentinel_off, patched)
        self.assertNotIn(sentinel_size, patched)
        self.assertIn(struct.pack('<Q', 0xDEF00000), patched)
        self.assertIn(struct.pack('<Q', 0x100000), patched)

    def test_oci_markers_still_patched(self):
        """OCI markers must still be patched when VM markers are present."""
        fake_data = (
            build_polyglot.OFFSET_MARKER +
            build_polyglot.SIZE_MARKER +
            build_polyglot.PATCHED_MARKER
        )
        patched = build_polyglot.patch_markers(
            fake_data, oci_offset=0x4000, oci_size=0x8000,
        )
        self.assertNotIn(build_polyglot.OFFSET_MARKER, patched)
        self.assertNotIn(build_polyglot.SIZE_MARKER, patched)
        self.assertNotIn(build_polyglot.PATCHED_MARKER, patched)
        self.assertIn(struct.pack('<Q', 0x4000), patched)
        self.assertIn(struct.pack('<Q', 0x8000), patched)


if __name__ == '__main__':
    unittest.main()
