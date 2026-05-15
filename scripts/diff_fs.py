#!/usr/bin/env python3
"""
oci2bin diff-fs — walk an overlayfs upperdir and print docker-diff-style
A/D classification for each entry.

Usage:
    oci2bin diff-fs OVERLAY_PATH [--json]

OVERLAY_PATH may be either the upperdir directly OR a parent directory that
contains an `upper/` subdir (the layout produced by --overlay-persist DIR).
The script auto-detects which case applies.

Classification rules (matched to overlayfs on-disk format):
    D <path>   the upperdir entry is a character device with rdev (0,0),
               i.e. an overlayfs whiteout marker — the lower-layer entry
               is hidden ("deleted" from the container's view).
    A <path>   anything else in the upperdir — added or modified relative
               to the image. Without comparing against the original
               lowerdir we cannot distinguish "added" from "changed", so
               both collapse to A. This matches what a self-host operator
               needs ("what should I -v mount on the next run?").

Opaque directories (trusted.overlay.opaque=y xattr) are marked with
trailing "(opaque)" — the directory replaces, rather than merges with,
the lower version.

Exit codes:
    0   success (zero or more entries reported)
    1   OVERLAY_PATH does not exist or is not a directory
    2   I/O error while walking
"""

import argparse
import json
import os
import stat
import sys


def _is_whiteout(st):
    """Return True if st describes an overlayfs whiteout char device."""
    return (stat.S_ISCHR(st.st_mode)
            and os.major(st.st_rdev) == 0
            and os.minor(st.st_rdev) == 0)


def _is_opaque(path):
    """Return True if the directory has the trusted.overlay.opaque=y xattr."""
    try:
        val = os.getxattr(path, b'trusted.overlay.opaque')
    except (OSError, AttributeError):
        return False
    return val in (b'y', b'Y')


def _resolve_upper(arg):
    """If arg/upper exists and is a directory, return arg/upper; else arg."""
    if not os.path.isdir(arg):
        print(f"oci2bin diff-fs: not a directory: {arg}", file=sys.stderr)
        sys.exit(1)
    candidate = os.path.join(arg, 'upper')
    if os.path.isdir(candidate):
        return candidate
    return arg


def walk_upper(upper_root):
    """
    Yield (op, rel_path, extra) tuples in deterministic sort order.

    op       'A' or 'D'
    rel_path path relative to upper_root with a leading '/'
    extra    None, or 'opaque' for directories with the opaque xattr
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(upper_root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, upper_root)
        if rel_dir == '.':
            rel_dir = ''
        # Emit the directory itself, except the root.
        if rel_dir:
            full = os.path.join(upper_root, rel_dir)
            extra = 'opaque' if _is_opaque(full) else None
            entries.append(('A', '/' + rel_dir, extra))
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            try:
                st = os.lstat(full)
            except OSError as exc:
                print(f"oci2bin diff-fs: lstat({full}): {exc}",
                      file=sys.stderr)
                sys.exit(2)
            op = 'D' if _is_whiteout(st) else 'A'
            entries.append((op, '/' + rel, None))
    entries.sort(key=lambda t: t[1])
    return entries


def main():
    ap = argparse.ArgumentParser(prog='oci2bin diff-fs')
    ap.add_argument('overlay_path',
                    help='Overlay directory (or parent containing upper/)')
    ap.add_argument('--json', action='store_true',
                    help='Emit JSON list of {"op","path","opaque"} objects')
    args = ap.parse_args()

    upper = _resolve_upper(args.overlay_path)
    entries = walk_upper(upper)

    if args.json:
        out = [{'op': op, 'path': p,
                **({'opaque': True} if extra == 'opaque' else {})}
               for (op, p, extra) in entries]
        json.dump(out, sys.stdout, indent=2)
        print()
    else:
        for op, p, extra in entries:
            suffix = '  (opaque)' if extra == 'opaque' else ''
            print(f"{op} {p}{suffix}")


if __name__ == '__main__':
    main()
