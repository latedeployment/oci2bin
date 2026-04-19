#!/usr/bin/env python3
"""
dockerfile_build.py — Build an OCI image layout from a simple Dockerfile.

Supported instructions:
  FROM scratch | <oci-layout-dir> | <docker-image>
  COPY <src...> <dst>
  ADD  <src>    <dst>     (local files only, same as COPY)
  RUN  <cmd>              (requires unshare + /bin/sh in the rootfs)
  ENV  KEY=VAL | KEY VAL
  ENTRYPOINT ["cmd","arg"] | cmd arg
  CMD        ["cmd","arg"] | cmd arg
  WORKDIR    /path
  LABEL      key=value
  USER       uid[:gid]
  EXPOSE     port[/proto]  (informational)
  ARG        NAME[=default]

Usage:
  dockerfile_build.py [Dockerfile] <out_oci_dir>
                      [--context DIR] [--build-arg KEY=VAL ...]
                      [--arch amd64|arm64]
"""

import argparse
import fnmatch
import glob as _glob
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

# Import the OCI layout builder from the sibling script.
sys.path.insert(0, os.path.dirname(__file__))
import from_chroot  # noqa: E402


# ── Dockerfile parser ────────────────────────────────────────────────────────

def _parse_dockerfile(path: str) -> list:
    """Return list of (INSTRUCTION, raw_args_str) from *path*."""
    instructions = []
    with open(path, encoding="utf-8") as f:
        raw_lines = f.readlines()

    i = 0
    while i < len(raw_lines):
        line = raw_lines[i].rstrip("\n")
        i += 1
        # Continuation lines
        while line.endswith("\\"):
            line = line[:-1]
            if i < len(raw_lines):
                line += raw_lines[i].lstrip().rstrip("\n")
                i += 1
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        instructions.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return instructions


def _parse_json_or_shell(s: str):
    """Parse ENTRYPOINT/CMD: JSON array or shell-form string."""
    s = s.strip()
    if s.startswith("["):
        try:
            val = json.loads(s)
            if isinstance(val, list) and all(isinstance(x, str) for x in val):
                return val
        except json.JSONDecodeError:
            pass
    return ["/bin/sh", "-c", s] if s else None


# ── Layer extraction helpers ─────────────────────────────────────────────────

def _extract_layer_tar(tf: tarfile.TarFile, rootfs: str) -> None:
    """Apply one OCI/docker layer tarball to *rootfs*, handling whiteouts."""
    for member in tf.getmembers():
        # Normalise path: strip leading ./ and /
        name = member.name
        while name.startswith("./") or name.startswith("/"):
            name = name[2:] if name.startswith("./") else name[1:]
        if not name:
            continue

        # Reject path traversal
        if any(p == ".." for p in name.split("/")):
            print(f"  warning: skipping unsafe tar path: {member.name!r}",
                  file=sys.stderr)
            continue

        basename = os.path.basename(name)

        # Opaque whiteout: clear parent directory contents
        if basename == ".wh..wh..opq":
            parent = os.path.join(rootfs, os.path.dirname(name))
            if os.path.isdir(parent):
                for entry in os.listdir(parent):
                    ep = os.path.join(parent, entry)
                    if os.path.islink(ep) or not os.path.isdir(ep):
                        os.unlink(ep)
                    else:
                        shutil.rmtree(ep, ignore_errors=True)
            continue

        # Regular whiteout: delete the named file
        if basename.startswith(".wh."):
            target_name = os.path.join(
                os.path.dirname(name), basename[len(".wh."):])
            target = os.path.join(rootfs, target_name)
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
            elif os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            continue

        dest = os.path.join(rootfs, name)
        # Strip setuid/setgid
        member.mode = member.mode & 0o1777

        try:
            if member.isdir():
                os.makedirs(dest, exist_ok=True)
                os.chmod(dest, member.mode)
            elif member.issym():
                if os.path.lexists(dest):
                    os.unlink(dest)
                os.symlink(member.linkname, dest)
            elif member.islnk():
                # Hardlink — resolve relative to rootfs
                link_src_rel = member.linkname
                while link_src_rel.startswith("./") or \
                        link_src_rel.startswith("/"):
                    link_src_rel = (link_src_rel[2:]
                                    if link_src_rel.startswith("./")
                                    else link_src_rel[1:])
                link_src = os.path.join(rootfs, link_src_rel)
                if os.path.lexists(dest):
                    os.unlink(dest)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if os.path.exists(link_src):
                    os.link(link_src, dest)
            elif member.isfile():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj:
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(fobj, out)
                    os.chmod(dest, member.mode)
        except OSError as exc:
            print(f"  warning: {name}: {exc}", file=sys.stderr)


def _extract_oci_to_rootfs(oci_dir: str, rootfs: str) -> dict:
    """
    Extract all layers from an OCI layout directory into *rootfs*.
    Returns the config object for ENV/ENTRYPOINT/CMD inheritance.
    """
    with open(os.path.join(oci_dir, "index.json")) as f:
        index = json.load(f)

    mfst_desc = index["manifests"][0]
    alg, hex_val = mfst_desc["digest"].split(":", 1)
    if alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", hex_val):
        print("error: invalid manifest digest in index.json", file=sys.stderr)
        sys.exit(1)

    with open(os.path.join(oci_dir, "blobs", alg, hex_val)) as f:
        manifest = json.load(f)

    cfg_desc = manifest["config"]
    cfg_alg, cfg_hex = cfg_desc["digest"].split(":", 1)
    if cfg_alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", cfg_hex):
        print("error: invalid config digest in manifest", file=sys.stderr)
        sys.exit(1)
    with open(os.path.join(oci_dir, "blobs", cfg_alg, cfg_hex)) as f:
        cfg = json.load(f)

    for layer_desc in manifest["layers"]:
        l_alg, l_hex = layer_desc["digest"].split(":", 1)
        if l_alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", l_hex):
            print("error: invalid layer digest", file=sys.stderr)
            sys.exit(1)
        layer_path = os.path.join(oci_dir, "blobs", l_alg, l_hex)
        print(f"  extracting layer sha256:{l_hex[:12]}...", file=sys.stderr)
        with tarfile.open(layer_path, mode="r:*") as tf:
            _extract_layer_tar(tf, rootfs)

    return cfg


def _extract_docker_save_to_rootfs(tar_path: str, rootfs: str) -> dict:
    """Extract a docker-save tar into *rootfs*, return parsed config."""
    with tarfile.open(tar_path, mode="r:*") as outer:
        mf_obj = outer.extractfile("manifest.json")
        if not mf_obj:
            print("error: manifest.json not found in docker-save tar",
                  file=sys.stderr)
            sys.exit(1)
        manifest_list = json.load(mf_obj)
        entry = manifest_list[0]

        cfg_obj = outer.extractfile(entry["Config"])
        cfg = json.load(cfg_obj) if cfg_obj else {}

        for layer_rel in entry["Layers"]:
            layer_member = outer.getmember(layer_rel)
            layer_f = outer.extractfile(layer_member)
            if not layer_f:
                continue
            layer_data = io.BytesIO(layer_f.read())
            short = layer_rel.split("/")[0][:12]
            print(f"  extracting layer {short}...", file=sys.stderr)
            with tarfile.open(fileobj=layer_data, mode="r:*") as inner:
                _extract_layer_tar(inner, rootfs)

    return cfg


# ── Build-state ──────────────────────────────────────────────────────────────

class _State:
    """Mutable build state accumulated across Dockerfile instructions."""

    def __init__(self, context_dir: str, build_args: dict, arch: str):
        self.context_dir = os.path.abspath(context_dir)
        self.build_args = dict(build_args)
        self.arch = arch
        self.rootfs: str = ""       # set by FROM
        self.env: list = []
        self.entrypoint = None
        self.cmd = None
        self.workdir = "/"
        self.labels: dict = {}
        self.user = ""
        self.exposed: list = []


# ── Instruction handlers ─────────────────────────────────────────────────────

def _do_from(state: _State, args: str, tmpdir: str) -> None:
    # FROM <image> [AS <name>] — we ignore the alias
    image = args.split()[0]

    # Remove any previous rootfs (multi-stage is simplified to last FROM)
    if state.rootfs and os.path.isdir(state.rootfs):
        shutil.rmtree(state.rootfs)
    state.rootfs = tempfile.mkdtemp(dir=tmpdir, prefix="rootfs_")
    state.env = []
    state.entrypoint = None
    state.cmd = None
    state.workdir = "/"
    state.labels = {}
    state.user = ""

    if image.lower() == "scratch":
        print("oci2bin: FROM scratch — empty rootfs", file=sys.stderr)
        return

    # Local OCI layout directory?
    if os.path.isdir(image) and os.path.exists(
            os.path.join(image, "oci-layout")):
        print(f"oci2bin: FROM {image} (local OCI layout)", file=sys.stderr)
        cfg = _extract_oci_to_rootfs(image, state.rootfs)
        _inherit_config(state, cfg)
        return

    # Try docker
    if shutil.which("docker"):
        print(f"oci2bin: FROM {image} (docker pull)", file=sys.stderr)
        subprocess.run(["docker", "pull", image], check=True)
        docker_tar = os.path.join(tmpdir, "base.tar")
        subprocess.run(["docker", "save", "-o", docker_tar, image], check=True)
        cfg = _extract_docker_save_to_rootfs(docker_tar, state.rootfs)
        os.unlink(docker_tar)
        _inherit_config(state, cfg)
        return

    print(f"error: FROM {image!r}: not a local OCI dir and docker not found",
          file=sys.stderr)
    sys.exit(1)


def _inherit_config(state: _State, cfg: dict) -> None:
    """Pull ENV/ENTRYPOINT/CMD/WorkingDir from an extracted image config."""
    c = cfg.get("config", {})
    if c.get("Env"):
        state.env = list(c["Env"])
    if c.get("Entrypoint"):
        state.entrypoint = list(c["Entrypoint"])
    if c.get("Cmd"):
        state.cmd = list(c["Cmd"])
    if c.get("WorkingDir"):
        state.workdir = c["WorkingDir"]
    if c.get("Labels"):
        state.labels.update(c["Labels"])
    if c.get("User"):
        state.user = c["User"]


def _do_copy(state: _State, args: str) -> None:
    """COPY [--chown=...] <src...> <dst>"""
    # Strip --chown flag (not enforced at build time)
    parts = shlex.split(args)
    parts = [p for p in parts if not p.startswith("--chown=")]

    if len(parts) < 2:
        print(f"error: COPY requires at least src and dst: {args!r}",
              file=sys.stderr)
        sys.exit(1)

    srcs, dst_rel = parts[:-1], parts[-1]
    dst_container = dst_rel if os.path.isabs(dst_rel) else \
        os.path.join(state.workdir, dst_rel)
    dst_host = os.path.join(state.rootfs, dst_container.lstrip("/"))
    dst_is_dir = dst_rel.endswith("/") or (
        os.path.isdir(dst_host) and not os.path.islink(dst_host))

    resolved_srcs: list = []
    for src in srcs:
        if any(c in src for c in ("*", "?", "[")):
            matched = _glob.glob(
                os.path.join(state.context_dir, src), recursive=True)
            resolved_srcs.extend(sorted(matched))
        else:
            resolved_srcs.append(os.path.join(state.context_dir, src))

    if not resolved_srcs:
        print(f"error: COPY: no files matched: {srcs}", file=sys.stderr)
        sys.exit(1)

    for src_path in resolved_srcs:
        src_path = os.path.normpath(src_path)
        # Ensure source stays within build context
        if not src_path.startswith(state.context_dir + os.sep) and \
                src_path != state.context_dir:
            print(f"error: COPY source escapes build context: {src_path}",
                  file=sys.stderr)
            sys.exit(1)
        if not os.path.lexists(src_path):
            print(f"error: COPY source not found: {src_path}", file=sys.stderr)
            sys.exit(1)

        if os.path.isdir(src_path) and not os.path.islink(src_path):
            dest = dst_host if dst_is_dir else dst_host
            os.makedirs(dest, exist_ok=True)
            shutil.copytree(src_path, dest, symlinks=True,
                            dirs_exist_ok=True)
        else:
            if dst_is_dir or len(resolved_srcs) > 1:
                os.makedirs(dst_host, exist_ok=True)
                dest = os.path.join(dst_host, os.path.basename(src_path))
            else:
                os.makedirs(os.path.dirname(dst_host), exist_ok=True)
                dest = dst_host
            if os.path.islink(src_path):
                if os.path.lexists(dest):
                    os.unlink(dest)
                os.symlink(os.readlink(src_path), dest)
            else:
                shutil.copy2(src_path, dest)


def _do_run(state: _State, args: str) -> None:
    """RUN <cmd> — execute in rootfs via unshare + chroot."""
    sh = os.path.join(state.rootfs, "bin", "sh")
    if not os.path.exists(sh):
        print(f"error: RUN requires /bin/sh in the rootfs; got FROM scratch?",
              file=sys.stderr)
        sys.exit(1)

    proc_dir = os.path.join(state.rootfs, "proc")
    os.makedirs(proc_dir, exist_ok=True)

    # Build environment for the RUN step (image env + build-time ARGs as env)
    run_env = dict(os.environ)
    for kv in state.env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            run_env[k] = v

    # Write the command to a temp script so we can exec it cleanly
    with tempfile.NamedTemporaryFile(
            dir=state.rootfs, prefix=".oci2bin_run_", suffix=".sh",
            mode="w", delete=False) as tmp:
        tmp.write(f"#!/bin/sh\nset -e\n{args}\n")
        tmp_path = tmp.name
        tmp_arc = "/" + os.path.relpath(tmp_path, state.rootfs)

    try:
        os.chmod(tmp_path, 0o700)
        # Mount proc inside rootfs, then chroot and exec the script.
        # unshare --user --map-root-user gives us a private user namespace
        # so chroot works without real root.
        inner = (
            f"mount -t proc proc {shlex.quote(proc_dir)} 2>/dev/null; "
            f"chroot {shlex.quote(state.rootfs)} /bin/sh -e "
            f"{shlex.quote(tmp_arc)}"
        )
        subprocess.run(
            ["unshare", "--user", "--map-root-user",
             "--mount", "--pid", "--fork",
             "sh", "-ec", inner],
            check=True,
            env=run_env,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _do_env(state: _State, args: str) -> None:
    """ENV KEY=VAL ... or ENV KEY VAL (legacy form)."""
    # Try to parse as KEY=VAL pairs; fall back to legacy "KEY VAL" form
    if "=" in args.split()[0]:
        # One or more KEY=VAL pairs (possibly with quoted values)
        pairs = shlex.split(args)
        for pair in pairs:
            if "=" not in pair:
                print(f"error: ENV: malformed pair: {pair!r}", file=sys.stderr)
                sys.exit(1)
            k, v = pair.split("=", 1)
            # Replace existing or append
            new_env = [e for e in state.env if not e.startswith(k + "=")]
            new_env.append(f"{k}={v}")
            state.env = new_env
    else:
        # Legacy: ENV KEY VALUE
        parts = args.split(None, 1)
        if len(parts) != 2:
            print(f"error: ENV: expected KEY VALUE, got: {args!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = parts
        new_env = [e for e in state.env if not e.startswith(k + "=")]
        new_env.append(f"{k}={v}")
        state.env = new_env


def _do_workdir(state: _State, args: str) -> None:
    wd = args.strip()
    if not os.path.isabs(wd):
        wd = os.path.join(state.workdir, wd)
    state.workdir = os.path.normpath(wd)
    host_wd = os.path.join(state.rootfs, state.workdir.lstrip("/"))
    os.makedirs(host_wd, exist_ok=True)


# ── Main build loop ──────────────────────────────────────────────────────────

def build_from_dockerfile(dockerfile: str, out_dir: str, *,
                          context_dir: str,
                          build_args: dict,
                          arch: str) -> None:
    instructions = _parse_dockerfile(dockerfile)
    if not instructions:
        print("error: Dockerfile is empty", file=sys.stderr)
        sys.exit(1)
    if instructions[0][0] != "FROM":
        print("error: Dockerfile must begin with FROM", file=sys.stderr)
        sys.exit(1)

    state = _State(context_dir, build_args, arch)
    tmpdir = tempfile.mkdtemp(prefix="oci2bin_build_")
    try:
        for instr, args in instructions:
            # Expand ARG references in args
            for k, v in state.build_args.items():
                args = args.replace(f"${k}", v).replace(f"${{{k}}}", v)

            print(f"oci2bin: {instr} {args[:60]}", file=sys.stderr)

            if instr == "FROM":
                _do_from(state, args, tmpdir)
            elif instr in ("COPY", "ADD"):
                _do_copy(state, args)
            elif instr == "RUN":
                _do_run(state, args)
            elif instr == "ENV":
                _do_env(state, args)
            elif instr == "ENTRYPOINT":
                state.entrypoint = _parse_json_or_shell(args)
            elif instr == "CMD":
                state.cmd = _parse_json_or_shell(args)
            elif instr == "WORKDIR":
                _do_workdir(state, args)
            elif instr == "LABEL":
                for pair in shlex.split(args):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        state.labels[k] = v
            elif instr == "USER":
                state.user = args.strip()
            elif instr == "EXPOSE":
                state.exposed.append(args.strip())
            elif instr == "ARG":
                # ARG NAME[=default] — register with default if not in build_args
                name_default = args.strip().split("=", 1)
                name = name_default[0]
                if name not in state.build_args and len(name_default) == 2:
                    state.build_args[name] = name_default[1]
            elif instr in ("MAINTAINER", "STOPSIGNAL", "HEALTHCHECK",
                           "SHELL", "ONBUILD", "VOLUME"):
                pass  # accepted but not acted upon
            else:
                print(f"warning: unsupported instruction: {instr}",
                      file=sys.stderr)

        if not state.rootfs:
            print("error: Dockerfile has no FROM instruction", file=sys.stderr)
            sys.exit(1)

        from_chroot.build_oci_layout(
            state.rootfs,
            out_dir,
            entrypoint=state.entrypoint,
            cmd=state.cmd,
            env=state.env or None,
            workdir=state.workdir,
            arch=arch,
            user=state.user,
            labels=state.labels,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Build an OCI image layout from a Dockerfile")
    p.add_argument("dockerfile", nargs="?", default="Dockerfile",
                   help="Path to Dockerfile (default: ./Dockerfile)")
    p.add_argument("out_dir",
                   help="Output OCI layout directory")
    p.add_argument("--context", default=".", metavar="DIR",
                   help="Build context directory (default: current dir)")
    p.add_argument("--build-arg", action="append", default=[],
                   metavar="KEY=VAL",
                   help="Build-time variable (repeatable)")
    p.add_argument("--arch", choices=["amd64", "arm64"], default="amd64",
                   help="Target CPU architecture")
    args = p.parse_args()

    dockerfile = os.path.abspath(args.dockerfile)
    if not os.path.isfile(dockerfile):
        print(f"error: Dockerfile not found: {dockerfile}", file=sys.stderr)
        sys.exit(1)

    build_args: dict = {}
    for kv in args.build_arg:
        if "=" not in kv:
            print(f"error: --build-arg must be KEY=VAL, got: {kv!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = kv.split("=", 1)
        build_args[k] = v

    build_from_dockerfile(
        dockerfile,
        args.out_dir,
        context_dir=args.context,
        build_args=build_args,
        arch=args.arch,
    )


if __name__ == "__main__":
    main()
