#!/usr/bin/env python3
"""
add_files.py — inject files/directories into an OCI image tar at build time.

Usage:
    add_files.py --input INPUT_TAR --output OUTPUT_TAR
                 [--file HOST_PATH:CONTAINER_PATH ...]
                 [--dir  HOST_DIR:CONTAINER_DIR ...]

Creates a new layer containing the injected files, appends it to the image,
and writes a new OCI tar with an updated manifest.json.

Pure Python, stdlib only.
"""

import argparse
import hashlib
import io
import json
import os
import posixpath
import sys
import tarfile
import time


def _validate_container_path(spec: str, container_path: str) -> str:
    """Normalize and validate a user-supplied container path.

    Rules:
      - must be non-empty
      - must not contain NUL bytes or control characters (a tar entry
        name with embedded \\0 / \\n is malformed and ambiguous)
      - posixpath.normpath() is applied so '//' and '.' segments
        collapse cleanly; the input must end up as an absolute path
        (i.e. start with '/'); after normalization there must be no
        '..' segments left (those would mean the user requested
        something outside the rootfs root)

    Returns the cleaned absolute container path. sys.exit(1) on any
    rule violation, with a message naming the original spec.
    """
    if not container_path:
        print(f"add_files: empty container path in {spec!r}",
              file=sys.stderr)
        sys.exit(1)
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in container_path):
        print(f"add_files: control bytes in container path: "
              f"{spec!r}", file=sys.stderr)
        sys.exit(1)
    if "\\" in container_path:
        print(f"add_files: backslash in container path: {spec!r}",
              file=sys.stderr)
        sys.exit(1)
    if not container_path.startswith("/"):
        print(f"add_files: container path must be absolute: "
              f"{spec!r}", file=sys.stderr)
        sys.exit(1)
    norm = posixpath.normpath(container_path)
    if any(p == ".." for p in norm.split("/") if p):
        print(f"add_files: '..' segment in container path: "
              f"{spec!r}", file=sys.stderr)
        sys.exit(1)
    return norm


def build_layer(entries):
    """
    Build a layer tarball from a list of (host_path, tar_name, is_dir) tuples.
    Returns the layer bytes (uncompressed tar).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        for host_path, tar_name, is_dir in entries:
            # Strip leading '/' from tar_name — tar convention
            arc_name = tar_name.lstrip('/')
            if is_dir:
                tf.add(host_path, arcname=arc_name, recursive=True)
            else:
                tf.add(host_path, arcname=arc_name, recursive=False)
    return buf.getvalue()


def collect_entries(files, dirs):
    """
    Build list of (host_path, container_path, is_dir) for all --file/--dir args.
    Validates that host paths exist.
    """
    entries = []
    for spec in files:
        colon = spec.rfind(':')
        if colon < 1:
            print(f"add_files: --file must be HOST:CONTAINER: {spec}",
                  file=sys.stderr)
            sys.exit(1)
        host = spec[:colon]
        ctr  = _validate_container_path(spec, spec[colon + 1:])
        if not os.path.isfile(host):
            print(f"add_files: host file not found: {host}", file=sys.stderr)
            sys.exit(1)
        entries.append((host, ctr, False))

    for spec in dirs:
        colon = spec.rfind(':')
        if colon < 1:
            print(f"add_files: --dir must be HOST:CONTAINER: {spec}",
                  file=sys.stderr)
            sys.exit(1)
        host = spec[:colon]
        ctr  = _validate_container_path(spec, spec[colon + 1:])
        if not os.path.isdir(host):
            print(f"add_files: host directory not found: {host}", file=sys.stderr)
            sys.exit(1)
        entries.append((host, ctr, True))

    return entries


def add_files(input_tar, output_tar, files, dirs):
    entries = collect_entries(files, dirs)
    if not entries:
        print("add_files: no --file or --dir entries; copying input unchanged",
              file=sys.stderr)
        import shutil
        shutil.copy2(input_tar, output_tar)
        return

    layer_bytes = build_layer(entries)
    layer_digest = 'sha256:' + hashlib.sha256(layer_bytes).hexdigest()
    # Use a stable directory name derived from the digest
    layer_dir  = layer_digest[7:71]  # first 64 hex chars of sha256
    layer_name = f'{layer_dir}/layer.tar'

    with tarfile.open(input_tar, 'r') as src_tf:
        members = src_tf.getmembers()

        # Read and parse manifest.json
        manifest_bytes = None
        for m in members:
            if m.name == 'manifest.json':
                f = src_tf.extractfile(m)
                manifest_bytes = f.read() if f else None
                break
        if manifest_bytes is None:
            print("add_files: manifest.json not found", file=sys.stderr)
            sys.exit(1)

        manifest = json.loads(manifest_bytes)

        # Read config to update RootFS.DiffIDs
        config_name = manifest[0]['Config']
        config_bytes = None
        for m in members:
            if m.name == config_name:
                f = src_tf.extractfile(m)
                config_bytes = f.read() if f else None
                break
        if config_bytes is None:
            print(f"add_files: config {config_name} not found", file=sys.stderr)
            sys.exit(1)

        config = json.loads(config_bytes)

        # Append new layer to manifest and config
        manifest[0]['Layers'].append(layer_name)
        if 'rootfs' in config:
            config['rootfs'].setdefault('diff_ids', []).append(layer_digest)

        new_config_bytes = json.dumps(config).encode()
        new_config_sha = hashlib.sha256(new_config_bytes).hexdigest()
        new_config_name = f'blobs/sha256/{new_config_sha}'
        manifest[0]['Config'] = new_config_name
        new_manifest_bytes = json.dumps(manifest).encode()

        with tarfile.open(output_tar, 'w') as out_tf:
            for m in members:
                f = src_tf.extractfile(m) if m.isfile() else None

                if m.name == 'manifest.json':
                    info = tarfile.TarInfo(name='manifest.json')
                    info.size  = len(new_manifest_bytes)
                    info.mode  = m.mode
                    info.mtime = m.mtime
                    out_tf.addfile(info, io.BytesIO(new_manifest_bytes))
                elif m.name == config_name:
                    info = tarfile.TarInfo(name=new_config_name)
                    info.size  = len(new_config_bytes)
                    info.mode  = m.mode
                    info.mtime = m.mtime
                    out_tf.addfile(info, io.BytesIO(new_config_bytes))
                elif f is not None:
                    data = f.read()
                    info = tarfile.TarInfo(name=m.name)
                    info.size  = len(data)
                    info.mode  = m.mode
                    info.mtime = m.mtime
                    out_tf.addfile(info, io.BytesIO(data))
                else:
                    out_tf.addfile(m)

            # Write the new injected layer
            info = tarfile.TarInfo(name=layer_name)
            info.size  = len(layer_bytes)
            info.mode  = 0o644
            info.mtime = int(time.time())
            out_tf.addfile(info, io.BytesIO(layer_bytes))

    n = sum(1 + (len(list(os.walk(h))) > 0) for h, _, is_dir in entries
            if is_dir) + sum(1 for _, _, is_dir in entries if not is_dir)
    print(f"add_files: injected {len(entries)} item(s) as new layer {layer_dir[:12]}")


def main():
    parser = argparse.ArgumentParser(
        description='Inject files/directories into an OCI image tar at build time',
    )
    parser.add_argument('--input',  required=True, help='Input OCI tar')
    parser.add_argument('--output', required=True, help='Output OCI tar')
    parser.add_argument('--file', action='append', default=[],
                        metavar='HOST:CONTAINER',
                        help='File to inject (repeatable)')
    parser.add_argument('--dir', action='append', default=[],
                        metavar='HOST:CONTAINER',
                        help='Directory to inject recursively (repeatable)')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"add_files: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    add_files(args.input, args.output, args.file, args.dir)


if __name__ == '__main__':
    main()
