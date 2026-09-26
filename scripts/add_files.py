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
import os
import posixpath
import sys
import tarfile

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import oci_tar  # noqa: E402  (shared manifest/repack helpers)


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


def _source_date_epoch():
    """SOURCE_DATE_EPOCH as an int, or None when unset/invalid."""
    value = os.environ.get("SOURCE_DATE_EPOCH", "")
    return int(value) if value.isdigit() else None


def _normalize_member(epoch):
    """tarfile filter: drop host identity, clamp mtimes when requested.

    Injected files used to carry the building user's uid/gid/uname, which
    both leaks host details into the image and makes every --add-file build
    differ between machines.  Files are owned by root in the image, as a
    Dockerfile COPY would produce.
    """
    def _filter(info):
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        if epoch is not None and info.mtime > epoch:
            info.mtime = epoch
        return info
    return _filter


def build_layer(entries):
    """
    Build a layer tarball from a list of (host_path, tar_name, is_dir) tuples.
    Returns the layer bytes (uncompressed tar).
    """
    buf = io.BytesIO()
    member_filter = _normalize_member(_source_date_epoch())
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        for host_path, tar_name, is_dir in entries:
            # Strip leading '/' from tar_name — tar convention
            arc_name = tar_name.lstrip('/')
            if is_dir:
                tf.add(host_path, arcname=arc_name, recursive=True,
                       filter=member_filter)
            else:
                # --file names a file: a host symlink is validated with
                # isfile() (which follows it), so store what it points to,
                # not a link that would dangle inside the image.
                tf.add(os.path.realpath(host_path), arcname=arc_name,
                       recursive=False, filter=member_filter)
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

    with open(input_tar, 'rb') as f:
        oci_data = f.read()
    try:
        manifest, config_name, config, _ = oci_tar.read_manifest_and_config(
            oci_data)
    except (KeyError, ValueError, tarfile.TarError) as e:
        print(f"add_files: {e}", file=sys.stderr)
        sys.exit(1)

    # Append the new layer to manifest and config
    manifest[0].setdefault('Layers', []).append(layer_name)
    if 'rootfs' in config:
        config['rootfs'].setdefault('diff_ids', []).append(layer_digest)

    layer_info = oci_tar.make_tar_info(layer_name, len(layer_bytes),
                                       mtime=_source_date_epoch() or 0)
    new_data, _ = oci_tar.rebuild_oci_with_new_config(
        oci_data, manifest, config_name, config,
        extra_entries=[(layer_info, layer_bytes)])
    with open(output_tar, 'wb') as f:
        f.write(new_data)

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
