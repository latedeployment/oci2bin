#!/usr/bin/env python3
"""
diff_images.py — compare file contents of two oci2bin polyglot binaries.

Usage:
    diff_images.py <binary1> <binary2>

Extracts the embedded OCI tar from each binary, walks all layer tarballs,
and prints a diff of the filesystem contents:

    + /path/to/added_file       (only in binary2)
    - /path/to/removed_file     (only in binary1)
    M /path/to/modified_file    1234 -> 5678 bytes

Summary line at the end: N added, N removed, N modified

Pure Python, stdlib only.
"""

import gzip
import io
import json
import os
import stat as stat_module
import struct
import sys
import tarfile

# Reuse marker constants from inspect_image.py logic
OFFSET_MARKER  = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
SIZE_MARKER    = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
PATCHED_MARKER = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)


def read_oci_data(binary_path):
    """Extract embedded OCI tar bytes from an oci2bin binary."""
    with open(binary_path, 'rb') as f:
        data = f.read()

    patched_off = data.find(PATCHED_MARKER)
    if patched_off is not None and patched_off != -1:
        print(f"diff: {binary_path}: OCI markers not patched", file=sys.stderr)
        sys.exit(1)

    loader_region = data[:8 * 1024 * 1024]
    file_size = len(data)

    for pos in range(0, len(loader_region) - 16, 8):
        candidate_offset = struct.unpack_from('<Q', loader_region, pos)[0]
        candidate_size   = struct.unpack_from('<Q', loader_region, pos + 8)[0]

        if candidate_offset in (0xDEADBEEFCAFEBABE, 0xCAFEBABEDEADBEEF,
                                 0xAAAAAAAAAAAAAAAA, 0):
            continue
        if candidate_offset >= file_size:
            continue
        if candidate_size == 0 or candidate_size > file_size:
            continue
        if candidate_offset + candidate_size > file_size:
            continue

        tar_region = data[candidate_offset:candidate_offset + 512]
        if len(tar_region) >= 262 and tar_region[257:262] == b'ustar':
            return data[candidate_offset:candidate_offset + candidate_size]

    print(f"diff: could not find embedded OCI tar in {binary_path}", file=sys.stderr)
    sys.exit(1)


def open_layer(layer_data):
    """Open a layer tarball, handling gzip compression transparently."""
    if layer_data[:2] == b'\x1f\x8b':
        return tarfile.open(fileobj=io.BytesIO(gzip.decompress(layer_data)), mode='r:')
    return tarfile.open(fileobj=io.BytesIO(layer_data), mode='r:')


def build_file_dict(oci_bytes):
    """
    Extract all layers from an OCI tar and build a dict:
        path -> ('file', size, sha256_or_none)  for regular files
        path -> ('link', target)                for symlinks
        path -> ('dir', None)                   for directories
    Whiteout entries are processed to mark deletions.
    """
    try:
        outer_tf = tarfile.open(fileobj=io.BytesIO(oci_bytes), mode='r')
    except tarfile.TarError as e:
        print(f"diff: tar error: {e}", file=sys.stderr)
        sys.exit(1)

    # Read manifest to get layer order
    try:
        manifest_member = outer_tf.getmember('manifest.json')
    except KeyError:
        print("diff: manifest.json not found", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(outer_tf.extractfile(manifest_member).read())
    layers = manifest[0].get('Layers', [])

    file_dict = {}

    for layer_name in layers:
        try:
            layer_member = outer_tf.getmember(layer_name)
        except KeyError:
            continue
        layer_data = outer_tf.extractfile(layer_member).read()

        try:
            layer_tf = open_layer(layer_data)
        except Exception:
            continue

        for m in layer_tf.getmembers():
            path = '/' + m.name.lstrip('./')
            # Normalize double slashes
            while '//' in path:
                path = path.replace('//', '/')

            basename = os.path.basename(m.name)

            # Handle whiteout entries (OCI layer deletions)
            if basename.startswith('.wh.'):
                real_name = basename[4:]
                real_path = os.path.join(os.path.dirname(path), real_name)
                real_path = '/' + real_path.lstrip('/')
                file_dict.pop(real_path, None)
                if basename == '.wh..wh..opq':
                    # Opaque whiteout: remove all children of parent dir
                    parent = os.path.dirname(path)
                    to_remove = [k for k in file_dict
                                 if k.startswith(parent + '/')]
                    for k in to_remove:
                        del file_dict[k]
                continue

            if m.issym():
                file_dict[path] = ('link', m.linkname)
            elif m.isdir():
                file_dict[path] = ('dir', None)
            elif m.isfile():
                file_dict[path] = ('file', m.size)

        layer_tf.close()

    outer_tf.close()
    return file_dict


def diff_dicts(d1, d2):
    """Compare two file dicts. Return (added, removed, modified) lists."""
    keys1 = set(d1.keys())
    keys2 = set(d2.keys())

    added    = sorted(keys2 - keys1)
    removed  = sorted(keys1 - keys2)
    modified = []

    for path in sorted(keys1 & keys2):
        v1 = d1[path]
        v2 = d2[path]
        if v1[0] != v2[0]:
            # Type changed (file → dir, etc.)
            modified.append((path, v1, v2))
        elif v1[0] == 'file' and v1[1] != v2[1]:
            modified.append((path, v1, v2))
        elif v1[0] == 'link' and v1[1] != v2[1]:
            modified.append((path, v1, v2))

    return added, removed, modified


def fmt_size(n):
    if n is None:
        return '-'
    if n < 1024:
        return f'{n} B'
    if n < 1024 * 1024:
        return f'{n / 1024:.1f} KB'
    return f'{n / (1024 * 1024):.1f} MB'


def build_file_dict_from_rootfs(rootfs_path):
    """
    Walk a live container rootfs at rootfs_path (e.g. /proc/PID/root)
    and build the same dict format as build_file_dict():
        path -> ('file', size)
        path -> ('link', target)
        path -> ('dir', None)
    Does NOT follow symlinks outside the rootfs.
    """
    import re
    if not re.match(r'^/proc/[0-9]+/root$', rootfs_path):
        print(f"diff: invalid live rootfs path: {rootfs_path}", file=sys.stderr)
        sys.exit(1)

    file_dict = {}
    rootfs_len = len(rootfs_path.rstrip('/'))

    for dirpath, dirnames, filenames, dirfd in os.fwalk(
            rootfs_path, follow_symlinks=False):
        # Compute the path relative to rootfs
        rel = dirpath[rootfs_len:] or '/'
        if not rel.startswith('/'):
            rel = '/' + rel

        # Record directory itself (skip the root)
        if rel != '/':
            file_dict[rel] = ('dir', None)

        for fname in filenames:
            fpath = rel.rstrip('/') + '/' + fname
            try:
                st = os.lstat(os.path.join(dirpath, fname))
            except OSError:
                continue
            if stat_module.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(os.path.join(dirpath, fname))
                except OSError:
                    target = ''
                file_dict[fpath] = ('link', target)
            elif stat_module.S_ISREG(st.st_mode):
                file_dict[fpath] = ('file', st.st_size)

    return file_dict


def print_diff_results(added, removed, modified, d1, d2):
    """Print diff results and return exit code."""
    for path in removed:
        v = d1[path]
        if v[0] == 'file':
            print(f"- {path}  ({fmt_size(v[1])})")
        else:
            print(f"- {path}")

    for path in added:
        v = d2[path]
        if v[0] == 'file':
            print(f"+ {path}  ({fmt_size(v[1])})")
        else:
            print(f"+ {path}")

    for path, v1, v2 in modified:
        if v1[0] == 'file' and v2[0] == 'file':
            print(f"M {path}  ({fmt_size(v1[1])} -> {fmt_size(v2[1])})")
        elif v1[0] == 'link' and v2[0] == 'link':
            print(f"M {path}  (link: {v1[1]!r} -> {v2[1]!r})")
        else:
            print(f"M {path}  ({v1[0]} -> {v2[0]})")

    print()
    print(f"{len(added)} added, {len(removed)} removed, {len(modified)} modified")
    return 1 if (added or removed or modified) else 0


def main():
    # --live PID BINARY mode
    if len(sys.argv) >= 4 and sys.argv[1] == '--live':
        pid_str = sys.argv[2]
        binary  = sys.argv[3]
        if not pid_str.isdigit():
            print("diff: PID must be a positive integer", file=sys.stderr)
            sys.exit(1)
        rootfs = f'/proc/{pid_str}/root'
        if not os.path.isdir(rootfs):
            print(f"diff: {rootfs}: not accessible", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(binary):
            print(f"diff: file not found: {binary}", file=sys.stderr)
            sys.exit(1)
        print(f"Comparing live container PID={pid_str} → {binary}", file=sys.stderr)
        d1 = build_file_dict(read_oci_data(binary))   # reference (image)
        d2 = build_file_dict_from_rootfs(rootfs)      # live state
        added, removed, modified = diff_dicts(d1, d2)
        sys.exit(print_diff_results(added, removed, modified, d1, d2))

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <binary1> <binary2>", file=sys.stderr)
        print(f"       {sys.argv[0]} --live PID BINARY", file=sys.stderr)
        sys.exit(1)

    b1, b2 = sys.argv[1], sys.argv[2]
    for p in (b1, b2):
        if not os.path.isfile(p):
            print(f"diff: file not found: {p}", file=sys.stderr)
            sys.exit(1)

    print(f"Comparing {b1} → {b2}", file=sys.stderr)

    d1 = build_file_dict(read_oci_data(b1))
    d2 = build_file_dict(read_oci_data(b2))

    added, removed, modified = diff_dicts(d1, d2)
    sys.exit(print_diff_results(added, removed, modified, d1, d2))


if __name__ == '__main__':
    main()
