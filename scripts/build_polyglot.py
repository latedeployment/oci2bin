#!/usr/bin/env python3
"""
build_polyglot.py - Construct a TAR+ELF polyglot container image.

The output file is simultaneously:
  - A valid POSIX tar archive (docker load compatible)
  - A valid ELF64 executable (runs as rootless container)

How it works:
  TAR puts its magic ("ustar") at byte 257. The first 100 bytes are just a filename.
  ELF puts its magic (7f 45 4c 46) at byte 0. The header is 64 bytes.
  -> The ELF header fits inside the tar's filename field with no overlap.

Layout:
  [0-511]     Tar header #1 / ELF header (bytes 0-63 are ELF, 257+ is ustar)
  [512-N]     Tar entry #1 data: ELF program headers + loader code
  [N+1-...]   Remaining tar entries: manifest.json, config, layers
  [EOF]       Two 512-byte zero blocks
"""

import argparse
import datetime
import gzip
import io
import json
import os
import stat as stat_module
import struct
import subprocess
import sys
import tarfile
import tempfile


# ── ELF64 constants ──────────────────────────────────────────────────────────

ELF_MAGIC = b'\x7fELF'
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ELFOSABI_NONE = 0
ET_EXEC = 2
EM_X86_64 = 0x3e
EM_AARCH64 = 0xb7
PT_LOAD = 1
PF_R = 4
PF_W = 2
PF_X = 1

SUPPORTED_MACHINES = {
    EM_X86_64:  'x86_64',
    EM_AARCH64: 'aarch64',
}

# Virtual address base for our polyglot. We load everything starting here.
VADDR_BASE = 0x400000


def build_elf64_header(entry, phoff, phnum, e_machine=EM_X86_64):
    """Build a 64-byte ELF64 header."""
    e_ident = (
        ELF_MAGIC +
        bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE]) +
        b'\x00' * 8  # padding
    )
    return struct.pack(
        '<16s HHI QQQ I HHHHHH',
        e_ident,
        ET_EXEC,           # e_type
        e_machine,         # e_machine
        EV_CURRENT,        # e_version
        entry,             # e_entry
        phoff,             # e_phoff
        0,                 # e_shoff (no section headers)
        0,                 # e_flags
        64,                # e_ehsize
        56,                # e_phentsize
        phnum,             # e_phnum
        0,                 # e_shentsize
        0,                 # e_shnum
        0,                 # e_shstrndx
    )


def build_program_header(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align):
    """Build a 56-byte ELF64 program header."""
    return struct.pack(
        '<II QQQQ QQ',
        p_type,
        p_flags,
        p_offset,           # offset in file
        p_vaddr,            # virtual address
        p_vaddr,            # physical address (same)
        p_filesz,           # size in file
        p_memsz,            # size in memory
        p_align,
    )


# ── Tar header helpers ───────────────────────────────────────────────────────

def tar_octal(val, width):
    """Encode an integer as a zero-padded, null-terminated octal string."""
    s = format(val, f'0{width - 1}o').encode('ascii')
    return s[:width - 1] + b'\x00'


def tar_checksum(header_bytes):
    """Compute the tar checksum: sum of all bytes, treating chksum field as spaces."""
    total = 0
    for i, b in enumerate(header_bytes):
        if 148 <= i < 156:
            total += ord(' ')
        else:
            total += b
    return total


def build_tar_header(name_bytes, size, mode=0o755, uid=0, gid=0, mtime=0, typeflag=b'0'):
    """
    Build a 512-byte POSIX tar header.
    name_bytes: raw bytes for the name field (up to 100 bytes, will be used as-is).
    """
    header = bytearray(512)

    # name field [0-99]: we write raw bytes (this is where ELF header goes for entry 0)
    name_padded = name_bytes[:100].ljust(100, b'\x00')
    header[0:100] = name_padded

    # mode [100-107]
    header[100:108] = tar_octal(mode, 8)
    # uid [108-115]
    header[108:116] = tar_octal(uid, 8)
    # gid [116-123]
    header[116:124] = tar_octal(gid, 8)
    # size [124-135]
    header[124:136] = tar_octal(size, 12)
    # mtime [136-147]
    header[136:148] = tar_octal(mtime, 12)
    # chksum placeholder [148-155] - filled later
    header[148:156] = b'        '  # 8 spaces
    # typeflag [156]
    header[156:157] = typeflag
    # linkname [157-256] - zeros
    # magic [257-262]
    header[257:263] = b'ustar\x00'
    # version [263-264]
    header[263:265] = b'00'
    # uname [265-296]
    header[265:269] = b'root'
    # gname [297-328]
    header[297:301] = b'root'

    # Compute and insert checksum
    chk = tar_checksum(header)
    header[148:156] = tar_octal(chk, 7) + b' '

    return bytes(header)


def tar_pad(data):
    """Pad data to 512-byte boundary."""
    remainder = len(data) % 512
    if remainder:
        return data + b'\x00' * (512 - remainder)
    return data


# ── Read the compiled loader ELF ─────────────────────────────────────────────

def parse_loader_elf(loader_path):
    """
    Parse the loader ELF to extract:
    - entry point virtual address
    - program headers
    - loadable segment data

    Returns dict with all info needed to reconstruct in the polyglot.
    """
    with open(loader_path, 'rb') as f:
        elf_data = f.read()

    # Verify ELF magic
    if elf_data[:4] != ELF_MAGIC:
        print(f"ERROR: Not an ELF file: {loader_path}", file=sys.stderr)
        sys.exit(1)

    # Parse ELF header
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from('<HHI QQQ I HHHHHH', elf_data, 16)

    if e_machine not in SUPPORTED_MACHINES:
        print(f"ERROR: Unsupported loader architecture: e_machine=0x{e_machine:x}", file=sys.stderr)
        print(f"  Supported: {', '.join(f'{n} (0x{k:x})' for k, n in SUPPORTED_MACHINES.items())}", file=sys.stderr)
        sys.exit(1)

    # Parse program headers
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, p_paddr,
         p_filesz, p_memsz, p_align) = struct.unpack_from('<II QQQQ QQ', elf_data, off)

        seg = {
            'type': p_type, 'flags': p_flags,
            'offset': p_offset, 'vaddr': p_vaddr,
            'filesz': p_filesz, 'memsz': p_memsz,
            'align': p_align,
            'data': elf_data[p_offset:p_offset + p_filesz] if p_filesz > 0 else b'',
        }
        segments.append(seg)

    return {
        'entry': e_entry,
        'segments': segments,
        'raw': elf_data,
        'phnum': e_phnum,
        'e_machine': e_machine,
    }


# ── Marker patching ──────────────────────────────────────────────────────────

OFFSET_MARKER  = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
SIZE_MARKER    = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
PATCHED_MARKER = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)

# VM blob markers — chosen so no two adjacent markers produce an OCI marker
# as a cross-boundary substring. Do NOT use DEAD/BEEF/CAFE/BABE byte patterns.
KERNEL_OFFSET_MARKER     = struct.pack('<Q', 0x7E57AB1E7E57AB1E)
KERNEL_SIZE_MARKER       = struct.pack('<Q', 0xB00BB00BB00BB00B)
KERNEL_PATCHED_MARKER    = struct.pack('<Q', 0x5A5A5A5A5A5A5A5A)
INITRAMFS_OFFSET_MARKER  = struct.pack('<Q', 0xC0FFEE00C0FFEE00)
INITRAMFS_SIZE_MARKER    = struct.pack('<Q', 0xFACEB00CFACEB00C)
INITRAMFS_PATCHED_MARKER = struct.pack('<Q', 0x6B6B6B6B6B6B6B6B)


def patch_markers(data, oci_offset, oci_size,
                  kernel_offset=None, kernel_size=None,
                  initramfs_offset=None, initramfs_size=None):
    """
    Find and replace the OCI_DATA_OFFSET and OCI_DATA_SIZE markers in the
    loader binary.  Optionally also patch KERNEL and INITRAMFS markers when
    those blobs are appended to the polyglot.
    """
    patched = data.replace(OFFSET_MARKER,  struct.pack('<Q', oci_offset))
    patched = patched.replace(SIZE_MARKER, struct.pack('<Q', oci_size))
    patched = patched.replace(PATCHED_MARKER, struct.pack('<Q', 1))

    n_off = data.count(OFFSET_MARKER)
    n_sz  = data.count(SIZE_MARKER)
    print(f"  Patched OCI: offset({n_off}x) size({n_sz}x)", file=sys.stderr)
    if n_off == 0 or n_sz == 0:
        print("WARNING: OCI markers not found in loader binary!", file=sys.stderr)

    if kernel_offset is not None:
        n = patched.count(KERNEL_OFFSET_MARKER)
        patched = patched.replace(KERNEL_OFFSET_MARKER, struct.pack('<Q', kernel_offset))
        patched = patched.replace(KERNEL_SIZE_MARKER,   struct.pack('<Q', kernel_size))
        patched = patched.replace(KERNEL_PATCHED_MARKER, struct.pack('<Q', 1))
        print(f"  Patched KERNEL offset=0x{kernel_offset:x} size=0x{kernel_size:x} ({n}x marker)", file=sys.stderr)
        if n != 1:
            print(f"WARNING: expected 1 KERNEL_OFFSET marker, found {n}", file=sys.stderr)
    if initramfs_offset is not None:
        n = patched.count(INITRAMFS_OFFSET_MARKER)
        patched = patched.replace(INITRAMFS_OFFSET_MARKER, struct.pack('<Q', initramfs_offset))
        patched = patched.replace(INITRAMFS_SIZE_MARKER,   struct.pack('<Q', initramfs_size))
        patched = patched.replace(INITRAMFS_PATCHED_MARKER, struct.pack('<Q', 1))
        print(f"  Patched INITRAMFS offset=0x{initramfs_offset:x} size=0x{initramfs_size:x} ({n}x marker)", file=sys.stderr)
        if n != 1:
            print(f"WARNING: expected 1 INITRAMFS_OFFSET marker, found {n}", file=sys.stderr)

    return patched


# ── cpio initramfs builder ────────────────────────────────────────────────────

def _cpio_newc_header(ino, mode, uid, gid, nlink, mtime, filesize,
                      devmajor, devminor, rdevmajor, rdevminor, namesize):
    """Build a 110-byte cpio newc (070701) header."""
    return (
        b"070701"
        + format(ino,       '08x').encode()
        + format(mode,      '08x').encode()
        + format(uid,       '08x').encode()
        + format(gid,       '08x').encode()
        + format(nlink,     '08x').encode()
        + format(mtime,     '08x').encode()
        + format(filesize,  '08x').encode()
        + format(devmajor,  '08x').encode()
        + format(devminor,  '08x').encode()
        + format(rdevmajor, '08x').encode()
        + format(rdevminor, '08x').encode()
        + format(namesize,  '08x').encode()
        + b"00000000"  # check field — always zero for newc
    )


def _cpio_pad4(n):
    """Return number of NUL bytes needed to pad n to a 4-byte boundary."""
    return (4 - (n % 4)) % 4


def build_initramfs(rootfs_dir, out_path):
    """
    Build a gzip-compressed cpio newc archive from rootfs_dir.
    Pure Python, stdlib only.  Security properties:
    - Strips setuid and setgid bits (mode & 0o1777, then OR file type back in).
    - Normalizes uid/gid to 0 (root) in the guest.
    - Follows no symlinks during the walk (followlinks=False).
    """
    buf = io.BytesIO()
    rootfs_dir = os.path.realpath(rootfs_dir)
    ino_counter = [1]

    def write_entry(name_bytes, st, data=b''):
        ino = ino_counter[0]
        ino_counter[0] += 1
        # Keep the file type bits; strip setuid/setgid from permission bits.
        type_bits = stat_module.S_IFMT(st.st_mode)
        perm_bits = st.st_mode & 0o1777
        mode = type_bits | perm_bits
        uid = 0
        gid = 0
        nlink = max(1, st.st_nlink)
        mtime = max(0, int(st.st_mtime))
        filesize = len(data)
        devmajor = 3
        devminor = 1
        rdevmajor = 0
        rdevminor = 0
        if stat_module.S_ISCHR(st.st_mode) or stat_module.S_ISBLK(st.st_mode):
            rdevmajor = os.major(st.st_rdev)
            rdevminor = os.minor(st.st_rdev)
        name_with_null = name_bytes + b'\x00'
        namesize = len(name_with_null)
        hdr = _cpio_newc_header(ino, mode, uid, gid, nlink, mtime, filesize,
                                devmajor, devminor, rdevmajor, rdevminor, namesize)
        buf.write(hdr)
        buf.write(name_with_null)
        buf.write(b'\x00' * _cpio_pad4(len(hdr) + namesize))
        if data:
            buf.write(data)
            buf.write(b'\x00' * _cpio_pad4(filesize))

    # Root directory "." entry
    write_entry(b'.', os.lstat(rootfs_dir))

    # Walk the tree — no symlink following
    for dirpath, dirs, files in os.walk(rootfs_dir, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            full = os.path.join(dirpath, name)
            rel  = os.path.relpath(full, rootfs_dir)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat_module.S_ISREG(st.st_mode):
                try:
                    with open(full, 'rb') as fh:
                        file_data = fh.read()
                except OSError:
                    file_data = b''
                write_entry(rel.encode(), st, file_data)
            elif stat_module.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(full).encode()
                except OSError:
                    target = b''
                write_entry(rel.encode(), st, target)
            else:
                # Directory, device, FIFO, socket — no data
                write_entry(rel.encode(), st)

    # TRAILER!!! entry
    trailer_name = b'TRAILER!!!\x00'
    hdr = _cpio_newc_header(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer_name))
    buf.write(hdr)
    buf.write(trailer_name)
    buf.write(b'\x00' * _cpio_pad4(len(hdr) + len(trailer_name)))

    with open(out_path, 'wb') as f:
        f.write(gzip.compress(buf.getvalue(), compresslevel=6))


# ── Main polyglot construction ───────────────────────────────────────────────

def get_oci_tar(image_name, output_path):
    """Run docker save to produce the OCI tar."""
    print(f"Saving image '{image_name}' via docker save...")
    result = subprocess.run(
        ['docker', 'save', '-o', output_path, image_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"docker save failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)


META_MAGIC = b'OCI2BIN_META\x00'
OCI2BIN_VERSION = '0.2.0'


def build_meta_block(image_name, digest=None):
    """
    Build the OCI2BIN_META block appended to the end of the output binary.
    Format: uint32_le(total_size) + META_MAGIC + json_bytes + b'\\x00'
    total_size counts from the start of the uint32 field to the end of the block.
    """
    meta = {
        'image':     image_name,
        'timestamp': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'version':   OCI2BIN_VERSION,
    }
    if digest:
        meta['digest'] = digest
    json_bytes = json.dumps(meta).encode() + b'\x00'
    total_size = 4 + len(META_MAGIC) + len(json_bytes)
    return struct.pack('<I', total_size) + META_MAGIC + json_bytes


def build_polyglot(loader_path, image_name, output_path, tar_path=None,
                   digest=None, image_name_for_meta=None,
                   kernel_path=None, initramfs_path=None):
    """Build the TAR+ELF polyglot file.

    If tar_path is given, use it as the pre-saved OCI tar instead of running
    docker save. digest is the content-addressed image digest for the metadata block.
    image_name_for_meta overrides image_name in the embedded metadata block.
    """

    PAGE_SIZE = 4096
    TAR_BLOCK = 512

    # 1. Parse the loader ELF
    print(f"Parsing loader: {loader_path}")
    loader = parse_loader_elf(loader_path)
    arch_name = SUPPORTED_MACHINES[loader['e_machine']]
    print(f"  Architecture: {arch_name}")

    load_segments = [s for s in loader['segments'] if s['type'] == PT_LOAD]
    if not load_segments:
        print("ERROR: No PT_LOAD segments in loader!", file=sys.stderr)
        sys.exit(1)

    loader_raw = loader['raw']
    loader_size = len(loader_raw)

    # 2. Get the OCI tar data
    if tar_path is not None:
        with open(tar_path, 'rb') as f:
            oci_data = f.read()
    else:
        with tempfile.TemporaryDirectory() as tmpdir:
            oci_tar_path = os.path.join(tmpdir, 'image.tar')
            get_oci_tar(image_name, oci_tar_path)

            with open(oci_tar_path, 'rb') as f:
                oci_data = f.read()

    oci_size = len(oci_data)

    # 3. Calculate layout
    #
    # ELF mmap requires: p_offset % PAGE_SIZE == p_vaddr % PAGE_SIZE
    # Original loader has segments at page-aligned file offsets (0, 0xc000, ...).
    # We need to shift them so that alignment is preserved.
    # Solution: pad the first tar entry data so the loader binary starts at
    # file offset PAGE_SIZE (4096). Then shift all segment offsets by PAGE_SIZE.
    #
    # Layout:
    # [0-511]           Tar header #1 (name field = ELF header, ustar at 257)
    # [512-4095]        Tar entry #1 data: 3584 bytes NUL padding (part of tar file content)
    # [4096-4096+L]     Tar entry #1 data continues: the loader binary
    # [4096+L padded]   Tar header #2: "oci.tar"
    # [+512]            Tar entry #2 data: OCI tar
    # [end]             Tar EOF (two zero blocks)
    #
    # The tar entry #1 file size = pre_pad + loader_size

    pre_pad = PAGE_SIZE - TAR_BLOCK  # 3584 bytes before loader in tar data
    tar_entry1_content_size = pre_pad + loader_size
    tar_entry1_padded = ((tar_entry1_content_size + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK

    # OCI entries follow directly after the loader entry (no wrapper).
    # The raw OCI tar bytes already include their own EOF blocks.
    # docker load will see: [ELF entry] [manifest.json] [config] [layers...] [EOF]
    # The loader reads the OCI region as a standalone tar.
    oci_data_file_offset = TAR_BLOCK + tar_entry1_padded

    # 4. Load optional VM blobs (kernel, initramfs)
    kernel_data = b''
    if kernel_path:
        with open(kernel_path, 'rb') as f:
            kernel_data = f.read()
        print(f"  Kernel: {kernel_path} ({len(kernel_data) // 1024} KB)", file=sys.stderr)

    initramfs_data = b''
    if initramfs_path:
        with open(initramfs_path, 'rb') as f:
            initramfs_data = f.read()
        print(f"  Initramfs: {initramfs_path} ({len(initramfs_data) // 1024} KB)", file=sys.stderr)

    # Pre-compute VM blob offsets (after OCI tar, aligned to 4096)
    PAGE_ALIGN = 4096
    kernel_file_offset = None
    initramfs_file_offset = None

    if kernel_data:
        # offset after OCI tar, aligned to PAGE_ALIGN
        base = oci_data_file_offset + oci_size
        pad = (PAGE_ALIGN - (base % PAGE_ALIGN)) % PAGE_ALIGN
        kernel_file_offset = base + pad

    if initramfs_data:
        if kernel_file_offset is not None:
            base = kernel_file_offset + len(kernel_data)
        else:
            base = oci_data_file_offset + oci_size
        pad = (PAGE_ALIGN - (base % PAGE_ALIGN)) % PAGE_ALIGN
        initramfs_file_offset = base + pad

    # 4. Patch the OCI offset/size markers in the loader binary
    patched_loader = patch_markers(
        loader_raw, oci_data_file_offset, oci_size,
        kernel_offset=kernel_file_offset,
        kernel_size=len(kernel_data) if kernel_data else None,
        initramfs_offset=initramfs_file_offset,
        initramfs_size=len(initramfs_data) if initramfs_data else None,
    )

    # 5. Patch program headers in the loader binary.
    # Loader binary will be at file offset PAGE_SIZE in the polyglot.
    # Original segment at file offset X → polyglot file offset X + PAGE_SIZE.
    original_phoff = 64
    phentsize = 56
    patched_loader_ba = bytearray(patched_loader)
    for i, seg in enumerate(loader['segments']):
        ph_file_offset = original_phoff + i * phentsize
        new_offset = seg['offset'] + PAGE_SIZE
        # Patch p_offset at byte +8 in the program header
        struct.pack_into('<Q', patched_loader_ba, ph_file_offset + 8, new_offset)

    patched_loader = bytes(patched_loader_ba)

    # 6. Build the ELF header (goes in tar name field, bytes 0-63)
    # phoff = PAGE_SIZE + 64 (program headers are inside the loader at its byte 64)
    elf_header = build_elf64_header(
        entry=loader['entry'],
        phoff=PAGE_SIZE + original_phoff,
        phnum=loader['phnum'],
        e_machine=loader['e_machine'],
    )
    if len(elf_header) != 64:
        print("ERROR: ELF header length is not 64 bytes", file=sys.stderr)
        sys.exit(1)

    # Verify page alignment of shifted segments
    for i, seg in enumerate(loader['segments']):
        if seg['type'] == PT_LOAD and seg['align'] >= PAGE_SIZE:
            new_off = seg['offset'] + PAGE_SIZE
            if new_off % PAGE_SIZE != seg['vaddr'] % PAGE_SIZE:
                print(f"ERROR: Segment {i} alignment broken: "
                      f"offset=0x{new_off:x} vaddr=0x{seg['vaddr']:x}", file=sys.stderr)
                sys.exit(1)

    # 7. Build tar header #1
    tar_header_1 = build_tar_header(
        name_bytes=elf_header,
        size=tar_entry1_content_size,
        mode=0o755,
        typeflag=b'0',
    )

    # 8. Assemble the polyglot
    polyglot = bytearray()

    # Tar header #1 (bytes 0-511, contains ELF header in name field)
    polyglot += tar_header_1
    if len(polyglot) != TAR_BLOCK:
        print("ERROR: tar header #1 is not exactly 512 bytes", file=sys.stderr)
        sys.exit(1)

    # Pre-padding: 3584 NUL bytes (tar entry data, before loader)
    polyglot += b'\x00' * pre_pad
    if len(polyglot) != PAGE_SIZE:
        print("ERROR: layout error: polyglot not at PAGE_SIZE after pre-padding", file=sys.stderr)
        sys.exit(1)

    # Loader binary (starts at file offset PAGE_SIZE)
    polyglot += patched_loader

    # Pad to 512-byte boundary
    remainder = len(polyglot) % TAR_BLOCK
    if remainder:
        polyglot += b'\x00' * (TAR_BLOCK - remainder)

    if len(polyglot) != TAR_BLOCK + tar_entry1_padded:
        print("ERROR: layout error: loader entry size mismatch", file=sys.stderr)
        sys.exit(1)

    # Verify OCI data offset
    actual_oci_offset = len(polyglot)
    if actual_oci_offset != oci_data_file_offset:
        print(f"ERROR: OCI offset mismatch! expected={oci_data_file_offset} "
              f"actual={actual_oci_offset}", file=sys.stderr)
        sys.exit(1)

    # OCI tar entries (raw from docker save, already includes EOF blocks).
    # docker load sees these as top-level entries: manifest.json, config, layers.
    polyglot += oci_data

    # Append kernel blob (page-aligned) if provided
    if kernel_data:
        pad = (PAGE_ALIGN - (len(polyglot) % PAGE_ALIGN)) % PAGE_ALIGN
        polyglot += b'\x00' * pad
        assert len(polyglot) == kernel_file_offset, \
            f"kernel offset mismatch: {len(polyglot)} != {kernel_file_offset}"
        polyglot += kernel_data

    # Append initramfs blob (page-aligned) if provided
    if initramfs_data:
        pad = (PAGE_ALIGN - (len(polyglot) % PAGE_ALIGN)) % PAGE_ALIGN
        polyglot += b'\x00' * pad
        assert len(polyglot) == initramfs_file_offset, \
            f"initramfs offset mismatch: {len(polyglot)} != {initramfs_file_offset}"
        polyglot += initramfs_data

    # 10. Write output (polyglot + metadata block)
    meta_image = image_name_for_meta if image_name_for_meta else image_name
    meta_block = build_meta_block(meta_image, digest)
    with open(output_path, 'wb') as f:
        f.write(polyglot)
        f.write(meta_block)

    os.chmod(output_path, 0o755)

    # 11. Verify
    print(f"\nPolyglot written to: {output_path}")
    print(f"  Total size: {len(polyglot)} bytes ({len(polyglot) / 1024:.1f} KB)")
    print(f"  Loader at file offset: 0x{PAGE_SIZE:x} ({PAGE_SIZE})")
    print(f"  OCI data offset: 0x{oci_data_file_offset:x} ({oci_data_file_offset})")
    print(f"  OCI data size: {oci_size} bytes ({oci_size / 1024 / 1024:.1f} MB)")
    if kernel_data:
        print(f"  Kernel offset:  0x{kernel_file_offset:x} ({kernel_file_offset})")
        print(f"  Kernel size:    {len(kernel_data)} bytes ({len(kernel_data) / 1024 / 1024:.1f} MB)")
    if initramfs_data:
        print(f"  Initramfs offset: 0x{initramfs_file_offset:x} ({initramfs_file_offset})")
        print(f"  Initramfs size:   {len(initramfs_data)} bytes ({len(initramfs_data) / 1024:.1f} KB)")

    if polyglot[0:4] != ELF_MAGIC:
        print("ERROR: ELF magic missing at byte 0!", file=sys.stderr)
        sys.exit(1)
    if polyglot[257:263] != b'ustar\x00':
        print("ERROR: ustar magic missing at byte 257!", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Byte 0-3:     {polyglot[0:4].hex()} (ELF magic)")
    print(f"  Byte 257-262: {polyglot[257:263]} (tar magic)")
    print(f"\nVerification passed: file is both ELF and TAR!")


def main():
    parser = argparse.ArgumentParser(
        description='Build a TAR+ELF polyglot container image',
    )
    parser.add_argument('--loader', required=False, default=None,
                        help='Path to the compiled loader ELF binary')
    parser.add_argument('--image', required=False, default=None,
                        help='Docker image name (e.g., alpine:latest)')
    parser.add_argument('--output', default='oci2bin.img',
                        help='Output polyglot file path')
    parser.add_argument('--tar', default=None,
                        help='Path to a pre-saved OCI tar (skips docker save)')
    parser.add_argument('--image-name', default=None,
                        help='Image name/tag to embed in metadata block '
                             '(defaults to --image value)')
    parser.add_argument('--digest', default=None,
                        help='Image digest to embed in metadata block '
                             '(e.g. redis@sha256:abc123...)')
    parser.add_argument('--kernel', default=None,
                        help='Path to vmlinux blob to embed (cloud-hypervisor path)')
    parser.add_argument('--initramfs', default=None,
                        help='Path to pre-built initramfs cpio.gz to embed')
    parser.add_argument('--initramfs-only', nargs=2, metavar=('ROOTFSDIR', 'OUTPATH'),
                        help='Build only a cpio.gz initramfs from ROOTFSDIR into OUTPATH and exit')

    args = parser.parse_args()

    # --initramfs-only: standalone cpio build, no polyglot needed
    if args.initramfs_only:
        rootfs_dir, out_path = args.initramfs_only
        if not os.path.isdir(rootfs_dir):
            print(f"initramfs-only: ROOTFSDIR not found: {rootfs_dir}", file=sys.stderr)
            sys.exit(1)
        build_initramfs(rootfs_dir, out_path)
        print(f"Initramfs written to: {out_path} "
              f"({os.path.getsize(out_path) // 1024} KB)", file=sys.stderr)
        sys.exit(0)

    if not args.loader:
        print("error: --loader is required (unless --initramfs-only is used)", file=sys.stderr)
        sys.exit(1)
    if not args.image and not args.tar:
        print("error: --image or --tar is required", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.loader):
        print(f"Loader not found: {args.loader}", file=sys.stderr)
        sys.exit(1)

    if args.tar is not None and not os.path.isfile(args.tar):
        print(f"Tar not found: {args.tar}", file=sys.stderr)
        sys.exit(1)

    if args.kernel is not None and not os.path.isfile(args.kernel):
        print(f"Kernel not found: {args.kernel}", file=sys.stderr)
        sys.exit(1)

    if args.initramfs is not None and not os.path.isfile(args.initramfs):
        print(f"Initramfs not found: {args.initramfs}", file=sys.stderr)
        sys.exit(1)

    image_name_for_meta = args.image_name if args.image_name else (args.image or 'unknown')
    build_polyglot(args.loader, args.image or '', args.output,
                   tar_path=args.tar,
                   digest=args.digest,
                   image_name_for_meta=image_name_for_meta,
                   kernel_path=args.kernel,
                   initramfs_path=args.initramfs)


if __name__ == '__main__':
    main()
