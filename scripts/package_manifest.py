#!/usr/bin/env python3
"""Install and sync packaged oci2bin helper scripts from one manifest."""

import argparse
import os
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "packaging" / "oci2bin-scripts.txt"


def read_manifest(manifest=DEFAULT_MANIFEST):
    """Return repository-relative helper paths from *manifest*."""
    manifest = Path(manifest)
    entries = []
    seen = set()
    lines = manifest.read_text(encoding="utf-8").splitlines()
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        rel = Path(line)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"{manifest}:{lineno}: unsafe path {line!r}")
        if len(rel.parts) != 2 or rel.parts[0] != "scripts":
            raise ValueError(f"{manifest}:{lineno}: expected scripts/*.py")
        if rel.suffix != ".py":
            raise ValueError(f"{manifest}:{lineno}: expected a Python helper")
        rel_text = rel.as_posix()
        if rel_text in seen:
            raise ValueError(f"{manifest}:{lineno}: duplicate {rel_text}")
        seen.add(rel_text)
        entries.append(rel_text)
    if not entries:
        raise ValueError(f"{manifest}: empty helper manifest")
    return entries


def script_sources(root=ROOT, manifest=DEFAULT_MANIFEST):
    """Return absolute source paths for manifest helpers."""
    root = Path(root)
    return [root / rel for rel in read_manifest(manifest)]


def _copy_file(src, dst, mode=0o644):
    src = Path(src)
    dst = Path(dst)
    if not src.is_file():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        try:
            same_file = os.path.samefile(src, dst)
        except OSError:
            same_file = False
        if same_file and not dst.is_symlink():
            os.chmod(dst, mode)
            return
        if dst.is_symlink():
            dst.unlink()
    shutil.copy2(src, dst)
    os.chmod(dst, mode)


def _symlink_file(src, dst):
    src = Path(src)
    dst = Path(dst)
    if not src.is_file():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    rel_src = os.path.relpath(src, dst.parent)
    if dst.is_symlink() and os.readlink(dst) == rel_src:
        return
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    dst.symlink_to(rel_src)


def install_scripts(dest, root=ROOT, manifest=DEFAULT_MANIFEST):
    """Install manifest helpers into *dest*."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    installed = []
    for src in script_sources(root, manifest):
        dst = dest / src.name
        _copy_file(src, dst)
        installed.append(dst)
    return installed


def sync_package_scripts(root=ROOT, manifest=DEFAULT_MANIFEST):
    """Refresh oci2bin_pkg/scripts links from the manifest."""
    root = Path(root)
    pkg_scripts = root / "oci2bin_pkg" / "scripts"
    expected = {Path(rel).name for rel in read_manifest(manifest)}
    pkg_scripts.mkdir(parents=True, exist_ok=True)
    for existing in pkg_scripts.glob("*.py"):
        if existing.name not in expected:
            existing.unlink()
    synced = []
    for src in script_sources(root, manifest):
        dst = pkg_scripts / src.name
        _symlink_file(src, dst)
        synced.append(dst)
    return synced


def check_sources_exist(root=ROOT, manifest=DEFAULT_MANIFEST):
    """Return missing manifest sources."""
    return [src for src in script_sources(root, manifest) if not src.is_file()]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Install/sync oci2bin packaged helper scripts")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                        help="helper manifest path")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="print manifest entries")

    install = sub.add_parser("install-scripts",
                             help="copy helper scripts to a destination")
    install.add_argument("--dest", required=True,
                         help="destination scripts directory")

    sub.add_parser("sync-package",
                   help="refresh oci2bin_pkg/scripts from the manifest")

    sub.add_parser("check", help="verify every manifest source exists")

    args = parser.parse_args(argv)
    manifest = Path(args.manifest)
    try:
        if args.cmd == "list":
            for rel in read_manifest(manifest):
                print(rel)
        elif args.cmd == "install-scripts":
            install_scripts(args.dest, ROOT, manifest)
        elif args.cmd == "sync-package":
            sync_package_scripts(ROOT, manifest)
        elif args.cmd == "check":
            missing = check_sources_exist(ROOT, manifest)
            if missing:
                for path in missing:
                    print(f"missing: {path}", file=sys.stderr)
                return 1
    except (OSError, ValueError) as exc:
        print(f"package_manifest: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
