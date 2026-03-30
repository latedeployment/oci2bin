#!/usr/bin/env python3
"""
strip_image.py — remove docs/man/locale/cache files from a docker-save tar.

Usage:
    strip_image.py --input INPUT_TAR --output OUTPUT_TAR [--strip-prefix PREFIX ...]

--strip-prefix may be repeated.  If given, the supplied prefixes are used
instead of the built-in defaults.  Prefixes must not start with '/' or
contain '..'; leading './' is accepted and normalised.

Reads a docker-save OCI tar, extracts each layer tarball, rewrites each layer
removing entries whose paths start with any of the strip prefixes, then writes
a new image tar with the stripped layers.

Pure Python, stdlib only.
"""

import argparse
import io
import json
import os
import sys
import tarfile

# Path prefixes to strip from each layer (no leading slash — tar entries
# typically start without one, but we strip either form).
STRIP_PREFIXES = (
    'usr/share/doc/',
    'usr/share/man/',
    'usr/share/info/',
    'usr/share/locale/',
    'usr/share/i18n/',
    'var/cache/apt/',
    'var/lib/apt/lists/',
    'tmp/',
)


def validate_prefix(p):
    """Raise ValueError if p is unsafe to use as a strip prefix."""
    if p.startswith('/'):
        raise ValueError(f"strip prefix must not start with '/': {p!r}")
    if '..' in p.split('/'):
        raise ValueError(f"strip prefix must not contain '..': {p!r}")


def should_strip(name, prefixes):
    """Return True if a tar entry name should be removed."""
    # Normalise: remove leading './' or '/'
    n = name.lstrip('./')
    for prefix in prefixes:
        if n == prefix.rstrip('/') or n.startswith(prefix):
            return True
    return False


def strip_layer(layer_bytes, prefixes):
    """
    Read a gzip/raw layer tarball from bytes, strip unwanted entries,
    and return the rewritten layer as bytes.
    """
    src = io.BytesIO(layer_bytes)
    dst = io.BytesIO()

    try:
        mode_r = 'r:gz' if layer_bytes[:2] == b'\x1f\x8b' else 'r:'
        with tarfile.open(fileobj=src, mode=mode_r) as src_tf:
            mode_w = 'w:gz' if layer_bytes[:2] == b'\x1f\x8b' else 'w:'
            with tarfile.open(fileobj=dst, mode=mode_w) as dst_tf:
                for member in src_tf.getmembers():
                    if should_strip(member.name, prefixes):
                        continue
                    if member.isfile():
                        f = src_tf.extractfile(member)
                        if f is None:
                            continue
                        dst_tf.addfile(member, f)
                    else:
                        dst_tf.addfile(member)
    except tarfile.TarError as e:
        print(f"strip_image: warning: layer tar error: {e}", file=sys.stderr)
        # Return original on error
        return layer_bytes

    return dst.getvalue()


def strip_image(input_tar, output_tar, prefixes=None):
    active = tuple(prefixes) if prefixes else STRIP_PREFIXES
    # Ensure each prefix ends with '/' so startswith works correctly for dirs
    active = tuple(p if p.endswith('/') else p + '/' for p in active)
    stripped_total = 0

    with tarfile.open(input_tar, 'r') as src_tf:
        members = src_tf.getmembers()

        # Read manifest.json
        manifest_bytes = None
        for m in members:
            if m.name == 'manifest.json':
                f = src_tf.extractfile(m)
                manifest_bytes = f.read() if f else None
                break
        if manifest_bytes is None:
            print("strip_image: manifest.json not found", file=sys.stderr)
            sys.exit(1)

        manifest = json.loads(manifest_bytes)
        layer_names = set()
        for entry in manifest:
            layer_names.update(entry.get('Layers', []))

        with tarfile.open(output_tar, 'w') as out_tf:
            for member in members:
                f = src_tf.extractfile(member) if member.isfile() else None

                if member.name in layer_names and f is not None:
                    original = f.read()
                    stripped = strip_layer(original, active)
                    saved = len(original) - len(stripped)
                    stripped_total += saved
                    info = tarfile.TarInfo(name=member.name)
                    info.size = len(stripped)
                    info.mode = member.mode
                    info.mtime = member.mtime
                    out_tf.addfile(info, io.BytesIO(stripped))
                elif member.name == 'manifest.json':
                    # Re-write manifest with updated layer info
                    # (digest field is informational; builder reads by offset)
                    info = tarfile.TarInfo(name='manifest.json')
                    info.size = len(manifest_bytes)
                    info.mode = member.mode
                    out_tf.addfile(info, io.BytesIO(manifest_bytes))
                elif f is not None:
                    data = f.read()
                    info = tarfile.TarInfo(name=member.name)
                    info.size = len(data)
                    info.mode = member.mode
                    info.mtime = member.mtime
                    out_tf.addfile(info, io.BytesIO(data))
                else:
                    out_tf.addfile(member)

    print(f"strip_image: stripped ~{stripped_total // 1024} KiB of docs/locale/cache")


def main():
    parser = argparse.ArgumentParser(
        description='Strip docs/man/locale/cache from a docker-save OCI tar',
    )
    parser.add_argument('--input', required=True, help='Input OCI tar')
    parser.add_argument('--output', required=True, help='Output OCI tar')
    parser.add_argument(
        '--strip-prefix', metavar='PREFIX', action='append', dest='prefixes',
        help='Path prefix to strip (repeatable); replaces built-in defaults when given',
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"strip_image: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if args.prefixes:
        for p in args.prefixes:
            try:
                validate_prefix(p)
            except ValueError as e:
                print(f"strip_image: {e}", file=sys.stderr)
                sys.exit(1)

    strip_image(args.input, args.output, prefixes=args.prefixes)


if __name__ == '__main__':
    main()
