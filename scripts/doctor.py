#!/usr/bin/env python3
"""
doctor.py — `oci2bin doctor`: probe the host for the toolchain and
kernel features oci2bin uses, and print exact fix commands for each
missing piece.

Output:
  - Default: human-readable table to stdout. Exit 0 if everything is
    OK or only DEGRADED, exit 1 if any required check is MISSING.
  - --json: machine-readable list of check results.

A check yields one of:
  OK        feature is present and works
  DEGRADED  present but limited (e.g. cgroup v1 only, missing optional)
  MISSING   absent and required for at least one oci2bin code path

Pure stdlib. No external deps.
"""

import argparse
import ctypes
import errno
import json
import os
import shutil
import subprocess
import sys


# ── Result helpers ───────────────────────────────────────────────────────────

OK, DEGRADED, MISSING = "OK", "DEGRADED", "MISSING"


def _result(name, status, detail="", fix=""):
    return {"name": name, "status": status,
            "detail": detail, "fix": fix}


def _which(prog):
    return shutil.which(prog)


def _run(argv, timeout=5):
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


# ── Individual checks ────────────────────────────────────────────────────────

def _check_gcc():
    if _which("gcc") is None:
        return _result(
            "gcc", MISSING,
            "no gcc in PATH",
            "apt install build-essential / dnf install gcc / "
            "pacman -S base-devel")
    rc, out, _ = _run(["gcc", "--version"])
    ver = out.splitlines()[0] if out else ""
    return _result("gcc", OK, ver)


def _check_static_libc():
    if _which("musl-gcc") is not None:
        return _result(
            "static libc", OK, "musl-gcc available")
    # Try a tiny -static link test with the system gcc.
    if _which("gcc") is None:
        return _result(
            "static libc", MISSING, "no gcc",
            "see gcc check above")
    src = b"int main(void){return 0;}\n"
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cf = os.path.join(td, "t.c")
            of = os.path.join(td, "t")
            with open(cf, "wb") as f:
                f.write(src)
            rc, _, err = _run(["gcc", "-static", "-o", of, cf])
            if rc == 0 and os.path.isfile(of):
                return _result(
                    "static libc", OK, "gcc -static works")
            return _result(
                "static libc", DEGRADED,
                "gcc -static failed (no static libc shipped)",
                "apt install glibc-static / dnf install glibc-static "
                "(or install musl-gcc)")
    except Exception as e:
        return _result("static libc", DEGRADED, str(e), "")


def _check_docker_or_podman():
    for tool in ("docker", "podman"):
        if _which(tool) is not None:
            rc, out, _ = _run([tool, "--version"])
            return _result(
                f"{tool}", OK,
                out.strip() or "present")
    return _result(
        "docker/podman", MISSING,
        "neither docker nor podman in PATH",
        "install Docker (https://docs.docker.com/engine/install/) "
        "or Podman (apt install podman / dnf install podman)")


def _check_newuidmap():
    if _which("newuidmap") is None or _which("newgidmap") is None:
        return _result(
            "newuidmap/newgidmap", DEGRADED,
            "missing — falls back to single-ID userns",
            "apt install uidmap / dnf install shadow-utils")
    return _result("newuidmap/newgidmap", OK, "present")


def _check_subid():
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    missing = []
    for path in ("/etc/subuid", "/etc/subgid"):
        if not os.path.isfile(path):
            missing.append(path)
            continue
        if user:
            try:
                with open(path) as f:
                    if not any(line.startswith(user + ":")
                               for line in f):
                        missing.append(f"{path} (no entry for {user})")
            except OSError:
                missing.append(path)
    if missing:
        return _result(
            "/etc/subuid /etc/subgid", DEGRADED,
            "; ".join(missing),
            "usermod --add-subuids 100000-165535 "
            "--add-subgids 100000-165535 $USER")
    return _result(
        "/etc/subuid /etc/subgid", OK,
        f"{user} entries present")


def _check_seccomp():
    path = "/proc/sys/kernel/seccomp/actions_avail"
    if not os.path.isfile(path):
        return _result(
            "seccomp", DEGRADED,
            "kernel built without CONFIG_SECCOMP",
            "rebuild kernel with CONFIG_SECCOMP=y "
            "(rare on modern distros)")
    try:
        with open(path) as f:
            actions = f.read().split()
        return _result(
            "seccomp", OK,
            f"actions: {', '.join(actions)}")
    except OSError as e:
        return _result("seccomp", DEGRADED, str(e), "")


def _check_landlock():
    # syscall numbers from the kernel: x86_64 = 444, aarch64 = 444.
    SYS_landlock_create_ruleset = 444
    libc = None
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return _result(
            "landlock", DEGRADED, "libc not loadable",
            "Landlock probe needs libc.so.6")
    # Calling with NULL,0,1 returns ABI version. ENOSYS → kernel
    # too old; EOPNOTSUPP → compiled out; other negatives → unknown.
    rc = libc.syscall(SYS_landlock_create_ruleset, 0, 0, 1)
    if rc < 0:
        e = ctypes.get_errno()
        if e == errno.ENOSYS:
            return _result(
                "landlock", DEGRADED,
                "kernel < 5.13 — landlock disabled",
                "upgrade to a Linux 5.13+ kernel")
        if e == errno.EOPNOTSUPP:
            return _result(
                "landlock", DEGRADED,
                "kernel built without CONFIG_SECURITY_LANDLOCK",
                "rebuild kernel with CONFIG_SECURITY_LANDLOCK=y")
        return _result(
            "landlock", DEGRADED,
            f"probe returned errno {e}", "")
    return _result(
        "landlock", OK, f"ABI v{rc}")


def _check_cgroup_v2():
    # cgroup v2 unified hierarchy presents controllers at
    # /sys/fs/cgroup/cgroup.controllers
    path = "/sys/fs/cgroup/cgroup.controllers"
    if os.path.isfile(path):
        try:
            with open(path) as f:
                ctrls = f.read().strip()
            return _result("cgroup v2", OK, ctrls)
        except OSError as e:
            return _result("cgroup v2", DEGRADED, str(e), "")
    if os.path.isdir("/sys/fs/cgroup/memory"):
        return _result(
            "cgroup v2", DEGRADED,
            "running on cgroup v1 — resource limits are best-effort",
            "boot with systemd.unified_cgroup_hierarchy=1 (or update "
            "to a distro that defaults to cgroup v2)")
    return _result(
        "cgroup v2", MISSING,
        "no /sys/fs/cgroup hierarchy detected",
        "mount -t cgroup2 cgroup2 /sys/fs/cgroup")


def _check_userns_unprivileged():
    path = "/proc/sys/kernel/unprivileged_userns_clone"
    if os.path.isfile(path):
        try:
            with open(path) as f:
                v = f.read().strip()
            if v == "1":
                return _result(
                    "unprivileged user namespaces", OK,
                    "enabled")
            return _result(
                "unprivileged user namespaces", MISSING,
                "kernel.unprivileged_userns_clone=0",
                "sysctl kernel.unprivileged_userns_clone=1 "
                "(persist via /etc/sysctl.d/)")
        except OSError as e:
            return _result(
                "unprivileged user namespaces", DEGRADED, str(e), "")
    # No knob — userns is probably enabled by default on this kernel.
    return _result(
        "unprivileged user namespaces", OK,
        "no kernel knob present (default-on)")


def _check_slirp_or_pasta():
    found = []
    for tool in ("slirp4netns", "pasta"):
        if _which(tool) is not None:
            found.append(tool)
    if found:
        return _result(
            "slirp4netns / pasta", OK,
            ", ".join(found))
    return _result(
        "slirp4netns / pasta", DEGRADED,
        "missing — only --net none / host available",
        "apt install slirp4netns passt / "
        "dnf install slirp4netns passt")


def _check_kvm_libkrun():
    notes = []
    if os.path.exists("/dev/kvm"):
        try:
            os.access("/dev/kvm", os.W_OK)
            notes.append("/dev/kvm present")
        except OSError:
            notes.append("/dev/kvm exists but not writable")
    else:
        notes.append("/dev/kvm absent")
    libkrun = None
    for cand in ("/usr/lib/libkrun.so", "/usr/lib/libkrun.so.1",
                 "/usr/lib64/libkrun.so", "/usr/lib64/libkrun.so.1"):
        if os.path.isfile(cand):
            libkrun = cand
            break
    if libkrun:
        notes.append(f"libkrun: {libkrun}")
    if "/dev/kvm absent" in notes and not libkrun:
        return _result(
            "VM backend (KVM / libkrun)", DEGRADED,
            "; ".join(notes),
            "install KVM (apt install qemu-kvm) and add user to "
            "kvm group, or `make LIBKRUN=1` with libkrun-devel")
    return _result(
        "VM backend (KVM / libkrun)", OK, "; ".join(notes))


def _check_openssl_cosign():
    parts = []
    status = OK
    fix = ""
    if _which("openssl") is None:
        status = DEGRADED
        parts.append("openssl missing — signing flows unavailable")
        fix = "apt install openssl"
    else:
        parts.append("openssl")
    if _which("cosign") is None:
        parts.append("cosign optional, missing — --verify-cosign disabled")
    else:
        parts.append("cosign")
    return _result("signing tooling", status,
                   ", ".join(parts), fix)


def _check_tar_gzip_zstd():
    parts = []
    status = OK
    fix = ""
    for needed in ("tar", "gzip"):
        if _which(needed) is None:
            status = MISSING
            fix = f"apt install {needed}"
            parts.append(f"{needed} missing")
        else:
            parts.append(needed)
    if _which("zstd") is None:
        parts.append("zstd optional, missing — --compress zstd disabled")
    else:
        parts.append("zstd")
    return _result("tar/gzip/zstd", status,
                   ", ".join(parts), fix)


# ── Driver ──────────────────────────────────────────────────────────────────

CHECKS = [
    _check_gcc,
    _check_static_libc,
    _check_docker_or_podman,
    _check_newuidmap,
    _check_subid,
    _check_seccomp,
    _check_landlock,
    _check_cgroup_v2,
    _check_userns_unprivileged,
    _check_slirp_or_pasta,
    _check_kvm_libkrun,
    _check_openssl_cosign,
    _check_tar_gzip_zstd,
]


def _print_table(results):
    name_w = max(len(r["name"]) for r in results) + 2
    status_w = max(len(r["status"]) for r in results) + 2
    print(f"{'check'.ljust(name_w)}{'status'.ljust(status_w)}detail / fix")
    print("-" * (name_w + status_w + 60))
    for r in results:
        print(f"{r['name'].ljust(name_w)}"
              f"{r['status'].ljust(status_w)}{r['detail']}")
        if r["status"] != OK and r["fix"]:
            print(f"{''.ljust(name_w + status_w)}fix: {r['fix']}")


def main():
    p = argparse.ArgumentParser(
        prog="oci2bin doctor",
        description="probe the host for oci2bin's required toolchain "
                    "and kernel features")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    args = p.parse_args()
    results = [c() for c in CHECKS]
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(results)
    # Exit non-zero only on hard MISSING; DEGRADED is informational.
    if any(r["status"] == MISSING for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
