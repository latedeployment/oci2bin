#!/usr/bin/env python3
"""
from_chroot.py — Build an OCI image layout from a chroot directory.

Usage:
  from_chroot.py <chroot_dir> <out_dir>
                 [--entrypoint CMD [ARGS...]] [--cmd CMD [ARGS...]]
                 [--env KEY=VAL ...] [--workdir PATH]
                 [--arch amd64|arm64] [--user UID] [--label KEY=VAL ...]
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import stat
import sys
import tarfile

# Pseudo-filesystems present in live chroot dirs that must not be included.
_SKIP_TOPS = frozenset(["proc", "sys", "dev"])


def _sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_blob(blobs_dir: str, data: bytes) -> tuple:
    """Write *data* to blobs_dir/<sha256> and return (digest-str, size)."""
    h = _sha256hex(data)
    path = os.path.join(blobs_dir, h)
    with open(path, "wb") as f:
        f.write(data)
    return f"sha256:{h}", len(data)


def _add_entry(tf: tarfile.TarFile, host_path: str, arc_name: str,
               inode_map: dict) -> None:
    """Add a single filesystem entry to an open TarFile."""
    try:
        st = os.lstat(host_path)
    except OSError:
        return
    mode = st.st_mode
    ti = tarfile.TarInfo(name=arc_name)
    ti.mtime = 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""

    if stat.S_ISLNK(mode):
        ti.type = tarfile.SYMTYPE
        ti.linkname = os.readlink(host_path)
        tf.addfile(ti)
    elif stat.S_ISREG(mode):
        key = (st.st_dev, st.st_ino)
        if st.st_nlink > 1 and key in inode_map:
            ti.type = tarfile.LNKTYPE
            ti.linkname = inode_map[key]
            tf.addfile(ti)
        else:
            ti.type = tarfile.REGTYPE
            ti.mode = mode & 0o1777
            ti.size = st.st_size
            if st.st_nlink > 1:
                inode_map[key] = arc_name
            with open(host_path, "rb") as f:
                tf.addfile(ti, f)
    elif stat.S_ISCHR(mode):
        ti.type = tarfile.CHRTYPE
        ti.mode = mode & 0o777
        ti.devmajor = os.major(st.st_rdev)
        ti.devminor = os.minor(st.st_rdev)
        tf.addfile(ti)
    elif stat.S_ISBLK(mode):
        ti.type = tarfile.BLKTYPE
        ti.mode = mode & 0o777
        ti.devmajor = os.major(st.st_rdev)
        ti.devminor = os.minor(st.st_rdev)
        tf.addfile(ti)
    elif stat.S_ISFIFO(mode):
        ti.type = tarfile.FIFOTYPE
        ti.mode = mode & 0o777
        tf.addfile(ti)
    # Sockets are intentionally skipped — not usable across namespaces.


def build_layer(chroot_dir: str) -> tuple:
    """
    Walk *chroot_dir* and produce a gzip-compressed OCI layer tarball.

    Returns (compressed_bytes, uncompressed_sha256_hex).
    Strips setuid/setgid bits and skips proc/sys/dev at the root level.
    mtime is forced to 0 for reproducible output.
    """
    raw = io.BytesIO()
    inode_map: dict = {}
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for dirpath, dirnames, filenames in os.walk(
                chroot_dir, followlinks=False):
            rel = os.path.relpath(dirpath, chroot_dir)
            if rel == ".":
                rel = ""
                dirnames[:] = sorted(d for d in dirnames
                                     if d not in _SKIP_TOPS)
            else:
                dirnames.sort()

            if rel:
                try:
                    dstat = os.lstat(dirpath)
                except OSError:
                    continue
                ti = tarfile.TarInfo(name=rel + "/")
                ti.type = tarfile.DIRTYPE
                ti.mode = dstat.st_mode & 0o1777
                ti.mtime = 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                tf.addfile(ti)

            for fname in sorted(filenames):
                arc = os.path.join(rel, fname) if rel else fname
                _add_entry(tf, os.path.join(dirpath, fname), arc, inode_map)

    raw_bytes = raw.getvalue()
    diff_id = _sha256hex(raw_bytes)

    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as gf:
        gf.write(raw_bytes)
    return gz.getvalue(), diff_id


def build_oci_layout(chroot_dir: str, out_dir: str, *,
                     entrypoint=None, cmd=None, env=None,
                     workdir="/", arch="amd64", user="",
                     labels=None) -> None:
    """
    Build a complete OCI image layout in *out_dir* from *chroot_dir*.

    The layout can be passed directly to ``oci2bin --oci-dir <out_dir>``.
    """
    blobs_dir = os.path.join(out_dir, "blobs", "sha256")
    os.makedirs(blobs_dir, exist_ok=True)

    with open(os.path.join(out_dir, "oci-layout"), "w") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)

    print("oci2bin: building layer from chroot...", file=sys.stderr)
    layer_gz, diff_id = build_layer(chroot_dir)
    layer_digest, layer_size = _write_blob(blobs_dir, layer_gz)
    print(f"oci2bin: layer {layer_digest} ({layer_size} bytes compressed)",
          file=sys.stderr)

    default_env = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ]
    cfg: dict = {
        "architecture": arch,
        "os": "linux",
        "config": {
            "Entrypoint": entrypoint,
            "Cmd": cmd if cmd is not None else ["/bin/sh"],
            "Env": env if env is not None else default_env,
            "WorkingDir": workdir,
            "Labels": labels or {},
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{diff_id}"],
        },
        "history": [],
    }
    if user:
        cfg["config"]["User"] = user

    cfg_bytes = json.dumps(cfg, sort_keys=True).encode()
    cfg_digest, cfg_size = _write_blob(blobs_dir, cfg_bytes)

    manifest: dict = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": cfg_digest,
            "size": cfg_size,
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": layer_digest,
            "size": layer_size,
        }],
    }
    mfst_bytes = json.dumps(manifest, sort_keys=True).encode()
    mfst_digest, mfst_size = _write_blob(blobs_dir, mfst_bytes)

    index: dict = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": mfst_digest,
            "size": mfst_size,
        }],
    }
    with open(os.path.join(out_dir, "index.json"), "w") as f:
        json.dump(index, f)

    print(f"oci2bin: OCI layout → {out_dir}", file=sys.stderr)
    print(f"  manifest {mfst_digest}", file=sys.stderr)
    print(f"  config   {cfg_digest}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Build an OCI image layout from a chroot directory")
    p.add_argument("chroot_dir", help="Source chroot root")
    p.add_argument("out_dir", help="Destination OCI layout directory")
    p.add_argument("--entrypoint", nargs="+", metavar="ARG",
                   help="Container entrypoint (overrides default /bin/sh)")
    p.add_argument("--cmd", nargs="+", metavar="ARG",
                   help="Default command arguments")
    p.add_argument("--env", action="append", default=[], metavar="KEY=VAL",
                   help="Environment variable (repeatable)")
    p.add_argument("--workdir", default="/", metavar="PATH",
                   help="Working directory inside the container")
    p.add_argument("--arch", choices=["amd64", "arm64"], default="amd64",
                   help="Target CPU architecture")
    p.add_argument("--user", default="", metavar="UID[:GID]",
                   help="Default user to run as")
    p.add_argument("--label", action="append", default=[], metavar="KEY=VAL",
                   help="Image label (repeatable)")
    args = p.parse_args()

    chroot_dir = os.path.abspath(args.chroot_dir)
    if not os.path.isdir(chroot_dir):
        print(f"error: not a directory: {chroot_dir}", file=sys.stderr)
        sys.exit(1)

    labels: dict = {}
    for kv in args.label:
        if "=" not in kv:
            print(f"error: --label must be KEY=VAL, got: {kv!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = kv.split("=", 1)
        labels[k] = v

    env = args.env if args.env else None

    build_oci_layout(
        chroot_dir,
        args.out_dir,
        entrypoint=args.entrypoint,
        cmd=args.cmd,
        env=env,
        workdir=args.workdir,
        arch=args.arch,
        user=args.user,
        labels=labels,
    )


if __name__ == "__main__":
    main()
