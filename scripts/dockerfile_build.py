#!/usr/bin/env python3
"""
dockerfile_build.py — Build an OCI image layout from a Dockerfile.

Supported instructions:
  FROM scratch | <oci-layout-dir> | <docker-image>
  COPY [--chown=] <src...> <dst>
  ADD  <src> <dst>         (local files only, same as COPY)
  RUN  [--mount=...] <cmd>
  ENV  KEY=VAL | KEY VAL
  ENTRYPOINT ["cmd","arg"] | cmd arg
  CMD        ["cmd","arg"] | cmd arg
  WORKDIR    /path
  LABEL      key=value
  USER       uid[:gid]
  EXPOSE     port[/proto]  (informational)
  ARG        NAME[=default]

RUN --mount types (BuildKit-compatible):
  --mount=type=bind,source=<src>,target=<dst>[,ro]
      Bind-mount from the build context (read-only by default).
  --mount=type=secret,id=<id>[,target=<path>][,required]
      Secret file provided via --build-secret id=<id>,src=<path>.
      NOT included in the image layer.
  --mount=type=ssh[,id=<id>][,target=<path>][,required]
      SSH agent socket forwarded from $SSH_AUTH_SOCK.
      NOT included in the image layer.
  --mount=type=cache,target=<path>[,id=<id>][,sharing=locked|shared|private]
      Persistent cache directory at ~/.cache/oci2bin/build-cache/<id>.
      NOT included in the image layer.
  --mount=type=tmpfs,target=<path>[,size=<bytes>]
      Temporary in-memory filesystem for the RUN step only.

Usage:
  dockerfile_build.py [Dockerfile] <out_oci_dir>
                      [--context DIR]
                      [--build-arg KEY=VAL ...]
                      [--build-secret id=<id>,src=<path> ...]
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


def _parse_kvs(spec: str) -> dict:
    """Parse 'key=val,key2=val2' into a dict. Bare keys get value True."""
    result: dict = {}
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            k, v = token.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[token] = True
    return result


def _parse_run_line(args: str) -> tuple:
    """
    Split RUN [--mount=...] [--network=...] CMD into (cmd_str, [mount_dicts]).

    Handles both '--mount=type=...' and '--mount type=...' forms.
    Unrecognised leading flags (--network, --security) are silently ignored.
    """
    mounts = []
    try:
        parts = shlex.split(args)
    except ValueError:
        return args, []

    i = 0
    while i < len(parts):
        part = parts[i]
        if part.startswith("--mount="):
            mounts.append(_parse_kvs(part[len("--mount="):]))
            i += 1
        elif part == "--mount" and i + 1 < len(parts):
            mounts.append(_parse_kvs(parts[i + 1]))
            i += 2
        elif part in ("--network", "--security") and i + 1 < len(parts):
            i += 2  # skip value
        elif part.startswith("--network=") or part.startswith("--security="):
            i += 1  # skip
        else:
            break

    # Reconstruct command preserving original quoting for /bin/sh -c
    cmd = " ".join(shlex.quote(p) for p in parts[i:])
    return cmd, mounts


# ── Layer extraction helpers ─────────────────────────────────────────────────

def _extract_layer_tar(tf: tarfile.TarFile, rootfs: str) -> None:
    """Apply one OCI/docker layer tarball to *rootfs*, handling whiteouts."""
    for member in tf.getmembers():
        name = member.name
        while name.startswith("./") or name.startswith("/"):
            name = name[2:] if name.startswith("./") else name[1:]
        if not name:
            continue
        if any(p == ".." for p in name.split("/")):
            print(f"  warning: skipping unsafe tar path: {member.name!r}",
                  file=sys.stderr)
            continue

        basename = os.path.basename(name)

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

        if basename.startswith(".wh."):
            target = os.path.join(rootfs,
                                  os.path.dirname(name), basename[len(".wh."):])
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
            elif os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            continue

        dest = os.path.join(rootfs, name)
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
                link_rel = member.linkname
                while link_rel.startswith("./") or link_rel.startswith("/"):
                    link_rel = (link_rel[2:] if link_rel.startswith("./")
                                else link_rel[1:])
                link_src = os.path.join(rootfs, link_rel)
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
    """Extract all layers from an OCI layout directory into *rootfs*."""
    with open(os.path.join(oci_dir, "index.json")) as f:
        index = json.load(f)

    mfst_desc = index["manifests"][0]
    alg, hex_val = mfst_desc["digest"].split(":", 1)
    if alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", hex_val):
        print("error: invalid manifest digest in index.json", file=sys.stderr)
        sys.exit(1)
    with open(os.path.join(oci_dir, "blobs", alg, hex_val)) as f:
        manifest = json.load(f)

    cfg_alg, cfg_hex = manifest["config"]["digest"].split(":", 1)
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
    def __init__(self, context_dir: str, build_args: dict,
                 build_secrets: dict, arch: str):
        self.context_dir = os.path.abspath(context_dir)
        self.build_args = dict(build_args)
        self.build_secrets = dict(build_secrets)  # id -> host path
        self.arch = arch
        self.rootfs: str = ""
        self.env: list = []
        self.entrypoint = None
        self.cmd = None
        self.workdir = "/"
        self.labels: dict = {}
        self.user = ""
        self.exposed: list = []


# ── RUN --mount helpers ──────────────────────────────────────────────────────

def _mount_bind(m: dict, state: _State) -> tuple:
    """
    --mount=type=bind,source=<src>,target=<dst>[,ro]

    Bind-mounts a path from the build context into the rootfs for the
    duration of the RUN step.  Default is read-only; pass rw to allow writes
    (changes are NOT captured into the layer).
    Returns (shell_cmd, host_cleanup_path_or_None).
    """
    src_rel = m.get("source") or m.get("src") or m.get("from") or "."
    dst = m.get("target") or m.get("dst")
    if not dst:
        print("error: --mount=type=bind requires target=", file=sys.stderr)
        sys.exit(1)

    src = os.path.normpath(os.path.join(state.context_dir, src_rel))
    if not src.startswith(state.context_dir):
        print(f"error: --mount=type=bind source escapes build context: {src_rel}",
              file=sys.stderr)
        sys.exit(1)

    dst_in_rootfs = os.path.join(state.rootfs, dst.lstrip("/"))
    is_dir = os.path.isdir(src)
    if is_dir:
        os.makedirs(dst_in_rootfs, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
        if not os.path.exists(dst_in_rootfs):
            with open(dst_in_rootfs, "w"):
                pass

    ro = "rw" not in m
    remount = (
        f"; mount -o remount,bind,ro {shlex.quote(dst_in_rootfs)}"
        if ro else ""
    )
    cmd = (
        f"mount --bind {shlex.quote(src)} {shlex.quote(dst_in_rootfs)}"
        + remount
    )
    # Bind mounts from context: don't delete the target, it may be a
    # real directory in the rootfs.  We just leave the empty placeholder.
    return cmd, None


def _mount_secret(m: dict, state: _State) -> tuple:
    """
    --mount=type=secret,id=<id>[,target=<path>][,required]

    Mounts a secret file provided via --build-secret id=<id>,src=<host-path>
    into the container for this RUN step only.  The file is NOT written into
    the image layer — only the empty mount-target placeholder is, which is
    also cleaned up after the step.
    """
    secret_id = m.get("id", "")
    if not secret_id:
        print("error: --mount=type=secret requires id=", file=sys.stderr)
        sys.exit(1)

    src = state.build_secrets.get(secret_id)
    if not src:
        if m.get("required") is True or m.get("required") == "true":
            print(f"error: --mount=type=secret,id={secret_id}: "
                  f"secret not provided (use --build-secret id={secret_id},src=<path>)",
                  file=sys.stderr)
            sys.exit(1)
        print(f"  warning: secret id={secret_id!r} not provided, skipping mount",
              file=sys.stderr)
        return "", None

    if not os.path.exists(src):
        print(f"error: --build-secret id={secret_id}: file not found: {src}",
              file=sys.stderr)
        sys.exit(1)

    target = m.get("target") or m.get("dst") or f"/run/secrets/{secret_id}"
    dst_in_rootfs = os.path.join(state.rootfs, target.lstrip("/"))
    os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
    # Create empty placeholder; will be cleaned up after RUN completes.
    if not os.path.exists(dst_in_rootfs):
        with open(dst_in_rootfs, "w"):
            pass

    cmd = (
        f"mount --bind {shlex.quote(src)} {shlex.quote(dst_in_rootfs)}"
        f"; mount -o remount,bind,ro {shlex.quote(dst_in_rootfs)}"
    )
    # Remove the placeholder after the step so it's not in the layer.
    return cmd, dst_in_rootfs


def _mount_ssh(m: dict, state: _State) -> tuple:
    """
    --mount=type=ssh[,id=<id>][,target=<path>][,required]

    Forwards the host SSH agent socket ($SSH_AUTH_SOCK) into the build
    container.  Sets SSH_AUTH_SOCK inside the container to the target path.

    The socket directory is bind-mounted read-only; the mount and the
    placeholder file are removed after the RUN step.
    """
    ssh_sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not ssh_sock or not os.path.exists(ssh_sock):
        required = m.get("required") is True or m.get("required") == "true"
        msg = ("error" if required else "warning")
        print(f"  {msg}: --mount=type=ssh: SSH_AUTH_SOCK not set or missing",
              file=sys.stderr)
        if required:
            sys.exit(1)
        return "", None

    target = (m.get("target") or m.get("dst")
              or "/run/buildkit/ssh_agent.0")
    dst_in_rootfs = os.path.join(state.rootfs, target.lstrip("/"))
    os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
    # Create a regular-file placeholder for the socket bind-mount.
    if not os.path.lexists(dst_in_rootfs):
        with open(dst_in_rootfs, "w"):
            pass

    # Bind-mount the socket file.  The mount namespace is discarded when
    # the RUN step exits so this never leaks outside the build step.
    cmd = f"mount --bind {shlex.quote(ssh_sock)} {shlex.quote(dst_in_rootfs)}"

    # Expose SSH_AUTH_SOCK inside the container via the temp script env.
    # We patch state.env temporarily in _do_run.
    m["_resolved_target"] = target  # pass back the in-container path

    return cmd, dst_in_rootfs


def _mount_cache(m: dict, state: _State) -> tuple:
    """
    --mount=type=cache,target=<path>[,id=<id>][,sharing=locked|shared|private]

    Persistent cache directory stored at ~/.cache/oci2bin/build-cache/<id>.
    Contents survive across builds but are NOT included in the image layer.
    """
    target = m.get("target") or m.get("dst")
    if not target:
        print("error: --mount=type=cache requires target=", file=sys.stderr)
        sys.exit(1)

    cache_id = m.get("id") or target.replace("/", "_").strip("_")
    # Sanitise cache_id: only allow safe characters.
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", cache_id)
    cache_dir = os.path.expanduser(
        os.path.join("~", ".cache", "oci2bin", "build-cache", safe_id))
    os.makedirs(cache_dir, exist_ok=True)

    dst_in_rootfs = os.path.join(state.rootfs, target.lstrip("/"))
    os.makedirs(dst_in_rootfs, exist_ok=True)

    cmd = f"mount --bind {shlex.quote(cache_dir)} {shlex.quote(dst_in_rootfs)}"
    # Do NOT clean up dst_in_rootfs — it's a real directory we created and
    # the layer should contain it (empty).  Only the cache contents are transient.
    return cmd, None


def _mount_tmpfs(m: dict, state: _State) -> tuple:
    """
    --mount=type=tmpfs,target=<path>[,size=<bytes>]

    In-memory filesystem for the RUN step only; discarded on exit.
    """
    target = m.get("target") or m.get("dst")
    if not target:
        print("error: --mount=type=tmpfs requires target=", file=sys.stderr)
        sys.exit(1)

    dst_in_rootfs = os.path.join(state.rootfs, target.lstrip("/"))
    os.makedirs(dst_in_rootfs, exist_ok=True)

    opts = ""
    if "size" in m:
        # Validate: must be a plain integer (bytes)
        if not re.fullmatch(r"[0-9]+", str(m["size"])):
            print(f"error: --mount=type=tmpfs,size= must be an integer",
                  file=sys.stderr)
            sys.exit(1)
        opts = f",size={m['size']}"

    cmd = f"mount -t tmpfs tmpfs{opts} {shlex.quote(dst_in_rootfs)}"
    return cmd, None


def _build_mount_cmds(mounts: list, state: _State) -> tuple:
    """
    Translate a list of mount spec dicts into (shell_cmd_list, cleanup_paths).

    shell_cmd_list — commands to run inside the unshare namespace before chroot
    cleanup_paths  — host paths to remove from rootfs after the RUN step
    """
    cmds: list = []
    cleanup: list = []
    ssh_targets: list = []

    handlers = {
        "bind":  _mount_bind,
        "secret": _mount_secret,
        "ssh":   _mount_ssh,
        "cache": _mount_cache,
        "tmpfs": _mount_tmpfs,
    }

    for m in mounts:
        mtype = m.get("type", "bind")
        handler = handlers.get(mtype)
        if handler is None:
            print(f"  warning: unsupported mount type: {mtype!r}",
                  file=sys.stderr)
            continue
        cmd, cleanup_path = handler(m, state)
        if cmd:
            cmds.append(cmd)
        if cleanup_path:
            cleanup.append(cleanup_path)
        if mtype == "ssh" and "_resolved_target" in m:
            ssh_targets.append(m["_resolved_target"])

    return cmds, cleanup, ssh_targets


# ── Instruction handlers ─────────────────────────────────────────────────────

def _do_from(state: _State, args: str, tmpdir: str) -> None:
    image = args.split()[0]

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

    if os.path.isdir(image) and os.path.exists(
            os.path.join(image, "oci-layout")):
        print(f"oci2bin: FROM {image} (local OCI layout)", file=sys.stderr)
        cfg = _extract_oci_to_rootfs(image, state.rootfs)
        _inherit_config(state, cfg)
        return

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

    resolved: list = []
    for src in srcs:
        if any(c in src for c in ("*", "?", "[")):
            matched = _glob.glob(
                os.path.join(state.context_dir, src), recursive=True)
            resolved.extend(sorted(matched))
        else:
            resolved.append(os.path.join(state.context_dir, src))

    if not resolved:
        print(f"error: COPY: no files matched: {srcs}", file=sys.stderr)
        sys.exit(1)

    for src_path in resolved:
        src_path = os.path.normpath(src_path)
        if not src_path.startswith(state.context_dir + os.sep) and \
                src_path != state.context_dir:
            print(f"error: COPY source escapes build context: {src_path}",
                  file=sys.stderr)
            sys.exit(1)
        if not os.path.lexists(src_path):
            print(f"error: COPY source not found: {src_path}", file=sys.stderr)
            sys.exit(1)
        if os.path.isdir(src_path) and not os.path.islink(src_path):
            os.makedirs(dst_host, exist_ok=True)
            shutil.copytree(src_path, dst_host, symlinks=True,
                            dirs_exist_ok=True)
        else:
            if dst_is_dir or len(resolved) > 1:
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
    """
    RUN [--mount=type=bind|secret|ssh|cache|tmpfs,...] <cmd>

    Executes <cmd> inside the rootfs using unshare --user --map-root-user
    so no real root privilege is required.  All --mount options are set up
    inside the new mount namespace and torn down automatically on exit;
    secret/ssh mounts leave no trace in the image layer.
    """
    cmd, mounts = _parse_run_line(args)

    sh = os.path.join(state.rootfs, "bin", "sh")
    if not os.path.exists(sh):
        print("error: RUN requires /bin/sh in the rootfs "
              "(FROM scratch cannot execute RUN)", file=sys.stderr)
        sys.exit(1)

    proc_dir = os.path.join(state.rootfs, "proc")
    os.makedirs(proc_dir, exist_ok=True)

    # Translate --mount options into shell commands + cleanup list.
    mount_cmds, cleanup_paths, ssh_targets = _build_mount_cmds(mounts, state)

    # Propagate image env + SSH_AUTH_SOCK for ssh mounts.
    run_env = dict(os.environ)
    for kv in state.env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            run_env[k] = v
    if ssh_targets:
        # Point SSH_AUTH_SOCK at the first ssh mount target inside the container.
        run_env["SSH_AUTH_SOCK"] = ssh_targets[0]

    # Write the command to a temp script inside rootfs so we can exec it.
    with tempfile.NamedTemporaryFile(
            dir=state.rootfs, prefix=".oci2bin_run_", suffix=".sh",
            mode="w", delete=False) as tmp:
        tmp.write(f"#!/bin/sh\nset -e\n{cmd}\n")
        tmp_path = tmp.name
        tmp_arc = "/" + os.path.relpath(tmp_path, state.rootfs)

    try:
        os.chmod(tmp_path, 0o700)

        # Build the inner shell script that runs inside the unshare namespace:
        #   1. Mount proc (best-effort)
        #   2. Apply RUN --mount bind-mounts (inside the new namespace only)
        #   3. chroot into rootfs and exec the script
        steps = [f"mount -t proc proc {shlex.quote(proc_dir)} 2>/dev/null"]
        steps.extend(mount_cmds)
        steps.append(
            f"chroot {shlex.quote(state.rootfs)} /bin/sh -e "
            f"{shlex.quote(tmp_arc)}"
        )
        inner = "; ".join(steps)

        subprocess.run(
            ["unshare", "--user", "--map-root-user",
             "--mount", "--pid", "--fork",
             "sh", "-ec", inner],
            check=True,
            env=run_env,
        )
    finally:
        # Remove the temp script — it must not appear in the image layer.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        # Remove secret/ssh placeholder files left as mount targets.
        for path in cleanup_paths:
            try:
                if os.path.islink(path) or os.path.isfile(path):
                    os.unlink(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass


def _do_env(state: _State, args: str) -> None:
    if "=" in args.split()[0]:
        for pair in shlex.split(args):
            if "=" not in pair:
                print(f"error: ENV: malformed pair: {pair!r}", file=sys.stderr)
                sys.exit(1)
            k, v = pair.split("=", 1)
            state.env = [e for e in state.env if not e.startswith(k + "=")]
            state.env.append(f"{k}={v}")
    else:
        parts = args.split(None, 1)
        if len(parts) != 2:
            print(f"error: ENV: expected KEY VALUE, got: {args!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = parts
        state.env = [e for e in state.env if not e.startswith(k + "=")]
        state.env.append(f"{k}={v}")


def _do_workdir(state: _State, args: str) -> None:
    wd = args.strip()
    if not os.path.isabs(wd):
        wd = os.path.join(state.workdir, wd)
    state.workdir = os.path.normpath(wd)
    os.makedirs(os.path.join(state.rootfs, state.workdir.lstrip("/")),
                exist_ok=True)


# ── Main build loop ──────────────────────────────────────────────────────────

def build_from_dockerfile(dockerfile: str, out_dir: str, *,
                          context_dir: str,
                          build_args: dict,
                          build_secrets: dict,
                          arch: str) -> None:
    instructions = _parse_dockerfile(dockerfile)
    if not instructions:
        print("error: Dockerfile is empty", file=sys.stderr)
        sys.exit(1)
    if instructions[0][0] != "FROM":
        print("error: Dockerfile must begin with FROM", file=sys.stderr)
        sys.exit(1)

    state = _State(context_dir, build_args, build_secrets, arch)
    tmpdir = tempfile.mkdtemp(prefix="oci2bin_build_")
    try:
        for instr, args in instructions:
            for k, v in state.build_args.items():
                args = args.replace(f"${k}", v).replace(f"${{{k}}}", v)

            # Summarise: truncate long args for readability
            summary = args[:72].replace("\n", " ")
            print(f"oci2bin: {instr} {summary}", file=sys.stderr)

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
                name_default = args.strip().split("=", 1)
                name = name_default[0]
                if name not in state.build_args and len(name_default) == 2:
                    state.build_args[name] = name_default[1]
            elif instr in ("MAINTAINER", "STOPSIGNAL", "HEALTHCHECK",
                           "SHELL", "ONBUILD", "VOLUME"):
                pass
            else:
                print(f"  warning: unsupported instruction: {instr}",
                      file=sys.stderr)

        if not state.rootfs:
            print("error: Dockerfile has no FROM instruction", file=sys.stderr)
            sys.exit(1)

        from_chroot.build_oci_layout(
            state.rootfs, out_dir,
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

def _parse_build_secret(s: str) -> tuple:
    """Parse 'id=<id>,src=<path>' → (id, path)."""
    kv = _parse_kvs(s)
    sid = kv.get("id", "")
    src = kv.get("src") or kv.get("source") or kv.get("from") or ""
    if not sid or not src:
        print(f"error: --build-secret must be id=<id>,src=<path>, got: {s!r}",
              file=sys.stderr)
        sys.exit(1)
    src = os.path.abspath(src)
    if not os.path.exists(src):
        print(f"error: --build-secret src not found: {src}", file=sys.stderr)
        sys.exit(1)
    return sid, src


def main() -> None:
    p = argparse.ArgumentParser(
        description="Build an OCI image layout from a Dockerfile")
    p.add_argument("dockerfile", nargs="?", default="Dockerfile",
                   help="Path to Dockerfile (default: ./Dockerfile)")
    p.add_argument("out_dir", help="Output OCI layout directory")
    p.add_argument("--context", default=".", metavar="DIR",
                   help="Build context directory (default: .)")
    p.add_argument("--build-arg", action="append", default=[],
                   metavar="KEY=VAL",
                   help="Build-time variable (repeatable)")
    p.add_argument("--build-secret", action="append", default=[],
                   metavar="id=<id>,src=<path>",
                   help="Secret file available to RUN --mount=type=secret "
                        "(repeatable)")
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

    build_secrets: dict = {}
    for spec in args.build_secret:
        sid, src = _parse_build_secret(spec)
        build_secrets[sid] = src

    build_from_dockerfile(
        dockerfile, args.out_dir,
        context_dir=args.context,
        build_args=build_args,
        build_secrets=build_secrets,
        arch=args.arch,
    )


if __name__ == "__main__":
    main()
