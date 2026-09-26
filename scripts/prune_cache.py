#!/usr/bin/env python3
"""Prune oci2bin caches.

Two caches live under ~/.cache/oci2bin:

* build outputs (``<image>_<tag>_<digest>/output``), written by
  ``oci2bin --cache``: prune keeps the newest entry per image and removes
  the superseded digests;
* extracted rootfs trees (``rootfs/<sha256>/``), written by the loader on
  first launch so later launches skip layer extraction: prune evicts
  entries by age and, optionally, by total size, oldest-used first, and
  never touches an entry a running container holds a shared lock on.

Only stdlib is used; the wrapper calls ``main()`` from ``oci2bin prune``.
"""

import argparse
import fcntl
import os
import re
import shutil
import sys
import time


KEY_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_SUFFIX_RE = re.compile(r"_[0-9a-f]{12,}$")
META_MAGIC = "oci2bin-rootfs-cache 1"
STALE_SCRATCH_SECONDS = 24 * 3600


def cache_home():
    """$XDG_CACHE_HOME or ~/.cache, the base both caches hang off."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg and os.path.isabs(xdg):
        return xdg
    return os.path.join(os.path.expanduser("~"), ".cache")


def rootfs_cache_root(base=None):
    """The loader's rootfs cache directory (mirrors rootfs_cache_root() in
    src/loader.c)."""
    return os.path.join(base or cache_home(), "oci2bin", "rootfs")


def parse_size(text):
    """Parse ``10G`` / ``512M`` / ``1.5g`` / ``1024`` into bytes."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*", text,
                         re.IGNORECASE)
    if not match:
        raise ValueError(f"invalid size: {text!r}")
    number, unit = match.groups()
    factor = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3,
              "t": 1024 ** 4}[unit.lower()]
    return int(float(number) * factor)


def human_size(size):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def dir_size(path):
    """Bytes used below *path*, counting each hardlinked inode once."""
    total = 0
    seen = set()
    for dirpath, dirnames, filenames in os.walk(path, onerror=lambda e: None):
        for name in dirnames + filenames:
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            if st.st_nlink > 1:
                ident = (st.st_dev, st.st_ino)
                if ident in seen:
                    continue
                seen.add(ident)
            total += st.st_size
    return total


def read_meta(entry_dir):
    """Parse ``<entry>/meta`` into a dict, or return None if absent/invalid."""
    try:
        with open(os.path.join(entry_dir, "meta"), encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    if not lines or lines[0] != META_MAGIC:
        return None
    fields = {}
    for line in lines[1:]:
        key, _, value = line.partition(" ")
        if key and value:
            fields[key] = value
    return fields


def entry_in_use(root, key):
    """True when a loader holds the entry's shared lock (a container is
    running from it) or the lock cannot be probed."""
    lock_path = os.path.join(root, key + ".lock")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True    # EWOULDBLOCK: a loader holds LOCK_SH; else unknown
    finally:
        os.close(fd)   # releases the probe lock
    return False


def list_rootfs_entries(root, now=None):
    """Return (entries, scratch) for the rootfs cache.

    entries: dicts with key, path, size, last_used, created, valid.
    scratch: leftover ``.build-*`` / ``.trash-*`` directories older than a
    day, i.e. abandoned by a crashed loader.
    """
    now = time.time() if now is None else now
    entries = []
    scratch = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return entries, scratch
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        if name.startswith((".build-", ".trash-")):
            try:
                age = now - os.lstat(path).st_mtime
            except OSError:
                continue
            if age > STALE_SCRATCH_SECONDS:
                scratch.append(path)
            continue
        if not KEY_RE.match(name):
            continue
        meta = read_meta(path)
        try:
            last_used = os.stat(os.path.join(path, "meta")).st_mtime
        except OSError:
            last_used = os.lstat(path).st_mtime
        created = None
        if meta and meta.get("created", "").isdigit():
            created = int(meta["created"])
        entries.append({
            "key": name,
            "path": path,
            "size": dir_size(path),
            "last_used": last_used,
            "created": created,
            "valid": meta is not None and meta.get("key") == name,
        })
    return entries, scratch


def _remove_tree(path, dry_run, out, why):
    if dry_run:
        out(f"[dry-run] would remove {path}  ({why})")
        return
    out(f"removing {path}  ({why})")
    shutil.rmtree(path, ignore_errors=True)


def prune_rootfs(root, dry_run=False, max_age_days=30, max_bytes=None,
                 remove_all=False, now=None, out=print):
    """Evict rootfs cache entries.

    Order: everything when *remove_all*; otherwise entries without a valid
    marker, then entries last used more than *max_age_days* ago, then the
    least recently used until the cache fits in *max_bytes*.  Entries in use
    are always skipped.  Returns (removed, freed_bytes, skipped_in_use).
    """
    now = time.time() if now is None else now
    entries, scratch = list_rootfs_entries(root, now)
    total = sum(e["size"] for e in entries)
    if not entries and not scratch:
        out(f"rootfs cache: empty ({root})")
        return 0, 0, 0
    out(f"rootfs cache: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'},"
        f" {human_size(total)} in {root}")

    removed = 0
    freed = 0
    skipped = 0
    for path in scratch:
        # ".build-<key>-XXXXXX": a loader that could not publish its build
        # runs from it and keeps the key's shared lock while it does.
        match = re.match(r"^\.(?:build|trash)-([0-9a-f]{64})-", os.path.basename(path))
        if match and entry_in_use(root, match.group(1)):
            out(f"skipping {path}: in use by a running container")
            skipped += 1
            continue
        _remove_tree(path, dry_run, out, "abandoned build scratch")
        removed += 1

    victims = []   # (entry, reason)
    remaining = []
    for entry in sorted(entries, key=lambda e: e["last_used"]):
        age_days = (now - entry["last_used"]) / 86400.0
        if remove_all:
            victims.append((entry, "--all"))
        elif not entry["valid"]:
            victims.append((entry, "no valid marker"))
        elif max_age_days is not None and age_days > max_age_days:
            victims.append((entry, f"last used {age_days:.0f} days ago"))
        else:
            remaining.append(entry)
    if max_bytes is not None:
        kept = sum(e["size"] for e in remaining)
        for entry in list(remaining):    # oldest-used first
            if kept <= max_bytes:
                break
            remaining.remove(entry)
            kept -= entry["size"]
            victims.append((entry, f"over --max-size ({human_size(max_bytes)})"))

    for entry, reason in victims:
        if entry_in_use(root, entry["key"]):
            out(f"skipping {entry['path']}: in use by a running container")
            skipped += 1
            continue
        _remove_tree(entry["path"], dry_run, out,
                     f"{human_size(entry['size'])}, {reason}")
        if not dry_run:
            try:
                os.unlink(os.path.join(root, entry["key"] + ".lock"))
            except OSError:
                pass
        removed += 1
        freed += entry["size"]

    # Lock files whose entry is gone are harmless but pointless.
    if not dry_run:
        live = {e["key"] for e in entries} - {e["key"] for e, _ in victims}
        try:
            for name in os.listdir(root):
                if name.endswith(".lock") and name[:-5] not in live \
                        and KEY_RE.match(name[:-5]) \
                        and not os.path.isdir(os.path.join(root, name[:-5])):
                    os.unlink(os.path.join(root, name))
        except OSError:
            pass
    return removed, freed, skipped


def prune_build_outputs(cache_root, dry_run=False, out=print):
    """Keep only the newest ``--cache`` build output per image."""
    groups = {}
    try:
        names = os.listdir(cache_root)
    except OSError:
        return 0, 0
    for name in names:
        output = os.path.join(cache_root, name, "output")
        if not os.path.isfile(output):
            continue
        key = DIGEST_SUFFIX_RE.sub("", name)
        groups.setdefault(key, []).append(
            (os.path.getmtime(output), os.path.getsize(output),
             os.path.join(cache_root, name)))
    deleted = 0
    freed = 0
    for key, items in sorted(groups.items()):
        if len(items) <= 1:
            continue
        items.sort(key=lambda item: item[0], reverse=True)
        for _mtime, size, path in items[1:]:
            _remove_tree(path, dry_run, out, human_size(size))
            deleted += 1
            freed += size
    return deleted, freed


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="oci2bin prune",
        description="remove superseded build outputs and evict cached rootfs "
                    "trees")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be removed, remove nothing")
    parser.add_argument("--max-age", type=float, default=30, metavar="DAYS",
                        help="evict cached rootfs trees not used for DAYS "
                             "(default: 30; 0 evicts all unused ones)")
    parser.add_argument("--max-size", type=parse_size, default=None,
                        metavar="SIZE",
                        help="then evict least recently used rootfs trees "
                             "until the cache fits in SIZE (e.g. 10G, 512M)")
    parser.add_argument("--all", action="store_true",
                        help="evict every cached rootfs tree not in use")
    parser.add_argument("--build-root", default=None,
                        help=argparse.SUPPRESS)   # set by the wrapper
    parser.add_argument("--rootfs-root", default=None,
                        help=argparse.SUPPRESS)   # tests
    args = parser.parse_args(argv)

    build_root = args.build_root or os.path.join(
        os.path.expanduser("~"), ".cache", "oci2bin")
    rootfs_root = args.rootfs_root or rootfs_cache_root()

    deleted, freed = prune_build_outputs(build_root, args.dry_run)
    if deleted == 0:
        print("oci2bin prune: no superseded build outputs")
    else:
        verb = "would free" if args.dry_run else "freed"
        print(f"oci2bin prune: {deleted} build output"
              f"{'' if deleted == 1 else 's'} removed, {verb} "
              f"{human_size(freed)}")

    removed, freed, skipped = prune_rootfs(
        rootfs_root, dry_run=args.dry_run, max_age_days=args.max_age,
        max_bytes=args.max_size, remove_all=args.all)
    verb = "would free" if args.dry_run else "freed"
    tail = f", {skipped} in use" if skipped else ""
    print(f"oci2bin prune: {removed} rootfs cache entr"
          f"{'y' if removed == 1 else 'ies'} removed, {verb} "
          f"{human_size(freed)}{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
