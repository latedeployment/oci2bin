#!/usr/bin/env python3
"""
inspect_image.py — display metadata embedded in an oci2bin polyglot binary.

Usage:
    inspect_image.py <binary>

Reads the ELF binary, finds the embedded OCI tar via the patched marker bytes,
extracts manifest.json and the image config, and prints a human-readable summary.

Also displays the OCI2BIN_META block (image name, digest, build timestamp,
version) if present.

Pure Python, stdlib only.
"""

import io
import json
import os
import struct
import sys
import tarfile

# Marker values (little-endian uint64) used by the polyglot builder
OFFSET_MARKER  = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
SIZE_MARKER    = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
PATCHED_MARKER = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)

# OCI2BIN_META magic prefix (Feature 10)
META_MAGIC = b'OCI2BIN_META\x00'


def find_marker(data, marker):
    """Return offset of first occurrence of marker bytes, or None."""
    idx = data.find(marker)
    return idx if idx != -1 else None


def read_oci_data(binary_path):
    """
    Open the binary, find the patched OCI_DATA_OFFSET and OCI_DATA_SIZE values,
    and return the embedded OCI tar as bytes.
    """
    with open(binary_path, 'rb') as f:
        data = f.read()

    # Check PATCHED flag — if the marker value is still the unpatched sentinel,
    # the binary was not built by oci2bin or the patch failed.
    patched_off = find_marker(data, PATCHED_MARKER)
    if patched_off is not None:
        # Still unpatched (marker value present as literal bytes) → not a valid binary
        print(f"inspect: {binary_path}: OCI markers are not patched "
              "(is this a valid oci2bin binary?)", file=sys.stderr)
        sys.exit(1)

    # The patched binary has the OFFSET and SIZE markers replaced with the
    # actual values. We scan for the 8-byte little-endian values by finding
    # the location where the patch was applied.
    #
    # Strategy: the loader ELF is at the start of the file. We scan the first
    # ~4 MiB for the pattern:
    #   [offset_value:8] ... [size_value:8]
    # where offset_value points into the file and size_value is reasonable.
    #
    # Simpler: build_polyglot replaces the marker bytes in-place, so the offset
    # and size values are stored at the same offsets the markers were at.
    # We just need to find a uint64 that, when used as a file offset, points
    # to a valid tar archive, within the first ~8 MiB of the file.

    loader_region = data[:8 * 1024 * 1024]  # search first 8 MiB (loader region)
    file_size = len(data)

    oci_offset = None
    oci_size = None

    # Scan uint64 values in the loader region looking for a plausible offset
    for pos in range(0, len(loader_region) - 16, 8):
        candidate_offset = struct.unpack_from('<Q', loader_region, pos)[0]
        candidate_size   = struct.unpack_from('<Q', loader_region, pos + 8)[0]

        # Skip sentinel / unpatched values
        if candidate_offset in (0xDEADBEEFCAFEBABE, 0xCAFEBABEDEADBEEF,
                                 0xAAAAAAAAAAAAAAAA, 0):
            continue

        # Sanity checks
        if candidate_offset >= file_size:
            continue
        if candidate_size == 0 or candidate_size > file_size:
            continue
        if candidate_offset + candidate_size > file_size:
            continue

        # Check for tar magic at the candidate offset
        tar_region = data[candidate_offset:candidate_offset + 512]
        if len(tar_region) >= 262 and tar_region[257:262] == b'ustar':
            oci_offset = candidate_offset
            oci_size   = candidate_size
            break

    if oci_offset is None:
        print(f"inspect: could not find embedded OCI tar in {binary_path}",
              file=sys.stderr)
        sys.exit(1)

    return data[oci_offset:oci_offset + oci_size]


def parse_config(oci_bytes):
    """Parse manifest.json and image config from the embedded OCI tar bytes."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(oci_bytes), mode='r')
    except tarfile.TarError as e:
        print(f"inspect: tar error: {e}", file=sys.stderr)
        sys.exit(1)

    manifest_member = None
    try:
        manifest_member = tf.getmember('manifest.json')
    except KeyError:
        print("inspect: manifest.json not found in embedded tar", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(tf.extractfile(manifest_member).read())
    if not manifest:
        print("inspect: empty manifest.json", file=sys.stderr)
        sys.exit(1)

    entry = manifest[0]
    config_name = entry.get('Config', '')
    repo_tags = entry.get('RepoTags', [])
    layers = entry.get('Layers', [])

    config = {}
    try:
        config_member = tf.getmember(config_name)
        config = json.loads(tf.extractfile(config_member).read())
    except (KeyError, Exception):
        pass

    tf.close()
    return repo_tags, layers, config


def read_meta_block(binary_path):
    """
    Scan the binary for the OCI2BIN_META block appended by Feature 10.
    Returns the parsed dict or None if not present.
    """
    with open(binary_path, 'rb') as f:
        data = f.read()

    magic_off = data.rfind(META_MAGIC)
    if magic_off < 4:
        return None

    # 4-byte LE uint32 total size is right before the magic
    total_size = struct.unpack_from('<I', data, magic_off - 4)[0]
    if total_size < len(META_MAGIC) + 1:
        return None

    json_start = magic_off + len(META_MAGIC)
    json_end = magic_off - 4 + total_size
    if json_end > len(data) or json_end <= json_start:
        return None

    json_bytes = data[json_start:json_end].rstrip(b'\x00')
    try:
        return json.loads(json_bytes)
    except json.JSONDecodeError:
        return None


def main():
    import argparse as _argparse
    parser = _argparse.ArgumentParser(
        description='Inspect an oci2bin polyglot binary',
        add_help=True,
    )
    parser.add_argument('binary', help='Path to the oci2bin binary')
    parser.add_argument('--json', action='store_true',
                        help='Output metadata as JSON (for machine parsing)')
    args = parser.parse_args()

    binary_path = args.binary
    if not os.path.isfile(binary_path):
        print(f"inspect: file not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        # JSON mode: return meta block or minimal fallback
        meta = read_meta_block(binary_path)
        file_size = os.path.getsize(binary_path)
        if meta is None:
            meta = {}
        # Fill in image name from OCI tar if not in meta
        if 'image' not in meta:
            try:
                oci_bytes = read_oci_data(binary_path)
                repo_tags, _, _ = parse_config(oci_bytes)
                meta['image'] = repo_tags[0] if repo_tags else 'unknown'
            except SystemExit:
                meta['image'] = 'unknown'
        meta['size'] = file_size
        print(json.dumps(meta))
        return

    oci_bytes = read_oci_data(binary_path)
    repo_tags, layers, config = parse_config(oci_bytes)

    cfg = config.get('config', config)  # docker save puts it under 'config' key

    image_name = repo_tags[0] if repo_tags else '(unknown)'
    arch = config.get('architecture', '(unknown)')
    entrypoint = cfg.get('Entrypoint') or []
    cmd        = cfg.get('Cmd') or []
    workdir    = cfg.get('WorkingDir') or '/'
    env        = cfg.get('Env') or []
    ports      = cfg.get('ExposedPorts') or {}

    print(f"Image:        {image_name}")
    print(f"Architecture: {arch}")
    print(f"Layers:       {len(layers)}")
    print(f"Entrypoint:   {json.dumps(entrypoint)}")
    print(f"Cmd:          {json.dumps(cmd)}")
    print(f"WorkingDir:   {workdir}")

    if env:
        print("Env:")
        for e in env:
            print(f"              {e}")

    if ports:
        print(f"ExposedPorts: {' '.join(ports.keys())}")

    # Display OCI2BIN_META block if present
    meta = read_meta_block(binary_path)
    if meta:
        print()
        print("Build metadata:")
        if 'image' in meta:
            print(f"  Image:     {meta['image']}")
        if 'digest' in meta:
            print(f"  Digest:    {meta['digest']}")
        if 'timestamp' in meta:
            print(f"  Built:     {meta['timestamp']}")
        if 'version' in meta:
            print(f"  oci2bin:   {meta['version']}")


if __name__ == '__main__':
    main()
