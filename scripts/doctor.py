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
                "apt install libc6-dev / dnf install glibc-static "
                "(or install musl-gcc)")
    except Exception as e:
        return _result("static libc", DEGRADED, str(e), "")


def _check_docker_or_podman():
    # The default build path pulls and `save`s the image with a container
    # engine. podman is CLI-compatible with the docker subcommands oci2bin
    # uses, so it works as a drop-in fallback. This is NOT a hard requirement:
    # the loader/runtime never needs it, and an image can be built without any
    # engine via --oci-dir (an OCI layout from skopeo/crane/buildah), the
    # `from-chroot` subcommand, or `build-dockerfile`. Hence DEGRADED, not
    # MISSING, when neither is present.
    for tool in ("docker", "podman"):
        if _which(tool) is not None:
            rc, out, _ = _run([tool, "--version"])
            return _result(
                f"{tool}", OK,
                (out.strip() or "present") + " — default build engine")
    # skopeo is a fully daemonless pull backend: `oci2bin IMAGE` works through
    # it (skopeo copy docker://… → OCI layout) with no docker/podman at all.
    if _which("skopeo") is not None:
        rc, out, _ = _run(["skopeo", "--version"])
        return _result(
            "skopeo", OK,
            (out.strip() or "present")
            + " — daemonless pull backend (no engine needed)")
    return _result(
        "docker/podman", DEGRADED,
        "no pull backend in PATH — the default build is unavailable; install "
        "skopeo for a daemonless pull, or build via --oci-dir, from-chroot, "
        "or build-dockerfile instead",
        "optional: install skopeo (apt/dnf install skopeo), Docker "
        "(https://docs.docker.com/engine/install/), or Podman "
        "(apt/dnf install podman)")


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


def _read_sysctl_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _check_userns_unprivileged():
    # Ubuntu 23.10+ keeps unprivileged userns creation enabled but has AppArmor
    # strip the new namespace's capabilities unless the binary has a profile.
    # The follow-up unshare(NEWNS|NEWPID|NEWUTS) then fails with EPERM, so this
    # knob is the real gate on those distros even when the clone knob is 1.
    apparmor = _read_sysctl_file(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if apparmor == "1":
        return _result(
            "unprivileged user namespaces", DEGRADED,
            "kernel.apparmor_restrict_unprivileged_userns=1 "
            "(AppArmor strips userns capabilities)",
            "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 "
            "(persist via /etc/sysctl.d/), or run with --vm")

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


def _check_squashfs():
    tools = ("mksquashfs", "squashfuse", "fuse-overlayfs")
    present = [tool for tool in tools if _which(tool)]
    missing = [tool for tool in tools if not _which(tool)]
    if not missing:
        return _result(
            "SquashFS lazy rootfs", OK,
            "mksquashfs (build), squashfuse + fuse-overlayfs (runtime)")
    return _result(
        "SquashFS lazy rootfs", DEGRADED,
        "present: " + (", ".join(present) or "none")
        + "; missing (optional): " + ", ".join(missing),
        "apt install squashfs-tools squashfuse fuse-overlayfs / "
        "dnf install squashfs-tools squashfuse fuse-overlayfs")


def _check_kvm_libkrun():
    notes = []
    if os.path.exists("/dev/kvm"):
        # os.access() reports through its return value; it does not raise.
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            notes.append("/dev/kvm present")
        else:
            notes.append("/dev/kvm exists but not accessible "
                         "(add yourself to the kvm group)")
    else:
        notes.append("/dev/kvm absent")
    libkrun = None
    for cand in ("/usr/lib/libkrun.so", "/usr/lib/libkrun.so.1",
                 "/usr/lib64/libkrun.so", "/usr/lib64/libkrun.so.1"):
        if os.path.isfile(cand):
            libkrun = cand
            break
    notes.append("libkrun: " + (libkrun if libkrun else "absent"))
    # cloud-hypervisor backend: needs the VMM binary; virtiofsd for -v.
    notes.append("cloud-hypervisor: "
                 + ("present" if _which("cloud-hypervisor") else "absent"))
    # The loader also looks in libexec, where Fedora/Debian install it.
    have_vfsd = _which("virtiofsd") or any(
        os.access(p, os.X_OK) for p in ("/usr/libexec/virtiofsd",
                                        "/usr/lib/virtiofsd",
                                        "/usr/lib/qemu/virtiofsd"))
    notes.append("virtiofsd: " + ("present" if have_vfsd else "absent"))
    notes.append("mkfs.ext2 (--overlay-persist): "
                 + ("present" if _which("mkfs.ext2") else "absent"))
    have_backend = bool(libkrun) or _which("cloud-hypervisor")
    if "/dev/kvm absent" in notes or not have_backend:
        return _result(
            "VM backend (KVM / libkrun / cloud-hypervisor)", DEGRADED,
            "; ".join(notes),
            "install KVM (apt install qemu-kvm) and add user to the kvm "
            "group; install libkrun, or cloud-hypervisor + virtiofsd")
    return _result(
        "VM backend (KVM / libkrun / cloud-hypervisor)", OK,
        "; ".join(notes))


def _find_openssl():
    """Resolve openssl the way the loader and sign_binary.py do.

    Both refuse to take `openssl` from PATH — it is the trust decision in
    every verification path — so doctor must report on the same fixed
    directories rather than on shutil.which().
    """
    for directory in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        candidate = os.path.join(directory, "openssl")
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _check_openssl_cosign():
    parts = []
    status = OK
    fix = ""
    if _find_openssl() is None:
        status = DEGRADED
        if _which("openssl") is not None:
            parts.append("openssl found only via PATH — signature "
                         "verification requires it in /usr/bin, /bin, "
                         "/usr/sbin or /sbin")
        else:
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


def _check_age():
    if _which("age") is None:
        return _result(
            "age (image encryption)", DEGRADED,
            "missing — --encrypt/--passphrase builds and encrypted binaries "
            "cannot run",
            "apt install age / dnf install age / pacman -S age")
    return _result("age (image encryption)", OK, "present")


def _check_nftables():
    if _which("nft") is None:
        return _result(
            "nftables (--allow-egress)", DEGRADED,
            "missing — default-deny egress allowlist unavailable",
            "apt install nftables / dnf install nftables")
    return _result("nftables (--allow-egress)", OK, "present")


def _check_rekor():
    if _which("rekor-cli") is None:
        return _result(
            "rekor-cli (transparency log)", DEGRADED,
            "missing — sign/verify --rekor unavailable",
            "see https://docs.sigstore.dev/rekor/installation/")
    return _result("rekor-cli (transparency log)", OK, "present")


# Kept in sync with CREDSTORE_DIRS in src/loader.c.
_CREDSTORE_DIRS = (
    "/etc/credstore.encrypted",
    "/run/credstore.encrypted",
    "/var/lib/credstore.encrypted",
    "/etc/credstore",
    "/run/credstore",
    "/var/lib/credstore",
)


def _check_tpm2_credstore():
    # --secret tpm2:NAME needs systemd-creds, a credential store to read the
    # sealed blob from, and (for TPM2-bound credentials) a working TPM2.
    if _which("systemd-creds") is None:
        return _result(
            "TPM2 secrets (--secret tpm2:)", DEGRADED,
            "systemd-creds missing — --secret tpm2: unavailable",
            "install the systemd package")

    stores = [d for d in _CREDSTORE_DIRS if os.path.isdir(d)]
    has_tpm2 = os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")

    if not stores:
        return _result(
            "TPM2 secrets (--secret tpm2:)", DEGRADED,
            "systemd-creds present, but no credential store exists",
            "create one: sudo mkdir -p -m 0700 /etc/credstore.encrypted")
    if not has_tpm2:
        return _result(
            "TPM2 secrets (--secret tpm2:)", DEGRADED,
            "credential stores: " + ", ".join(stores)
            + "; no TPM2 device (/dev/tpmrm0) — only host-key credentials "
              "can be decrypted",
            "check with: systemd-analyze has-tpm2")
    return _result(
        "TPM2 secrets (--secret tpm2:)", OK,
        "systemd-creds + /dev/tpmrm0; stores: " + ", ".join(stores))


def _check_runtime_helpers():
    # Per-feature optional runtime helpers the loader/subcommands exec.
    tools = [
        ("nsenter", "oci2bin exec / freeze / thaw"),
        ("sqlite3", "freeze / thaw snapshots"),
        ("systemd-creds", "--secret tpm2:"),
        ("gdb", "--gdb"),
        ("curl", "--notify"),
    ]
    present = [t for t, _ in tools if _which(t)]
    absent = [t for t, _ in tools if not _which(t)]
    if not absent:
        return _result("runtime helpers", OK, ", ".join(present))
    return _result(
        "runtime helpers", DEGRADED,
        "present: " + (", ".join(present) or "none")
        + "; missing (optional): " + ", ".join(absent),
        "install as needed: util-linux (nsenter), sqlite3, "
        "systemd (systemd-creds), gdb, curl")


def _check_cross_toolchain():
    # The native arch builds with plain gcc; the "other" arch needs a cross
    # compiler. Pick the target opposite the host so `--arch` (the non-native
    # direction) is what we probe — x86_64 host -> aarch64, aarch64 -> x86_64.
    machine = os.uname().machine
    if machine in ("aarch64", "arm64"):
        target = "x86_64"
        cands = ("x86_64-linux-gnu-gcc", "x86_64-redhat-linux-gcc")
        pkg = "gcc-x86_64-linux-gnu / dnf install gcc-x86_64-linux-gnu"
    else:
        target = "aarch64"
        cands = ("aarch64-linux-gnu-gcc", "aarch64-redhat-linux-gcc")
        pkg = "gcc-aarch64-linux-gnu / dnf install gcc-aarch64-linux-gnu"
    name = f"cross-compiler (-> {target})"
    cc = None
    for c in cands:
        if _which(c):
            cc = _which(c)
            break
    if cc is None:
        return _result(
            name, DEGRADED,
            f"missing — cross-building for {target} (--arch) unavailable",
            f"apt install {pkg}")
    return _result(name, OK, cc)


def _tar_version_note():
    """Flag a tar that cannot safely take --keep-directory-symlink.

    The loader passes that flag only to GNU tar >= 1.32, which refuses to
    traverse a symlink it created earlier in the same run. Older or non-GNU
    tar still works — the loader drops the flag — but a symlinked directory
    in a layer is then replaced by a real one rather than followed, so it is
    worth surfacing.
    """
    rc, out, _ = _run(["tar", "--version"])
    if rc != 0 or "(GNU tar) " not in out:
        return " (not GNU tar — --keep-directory-symlink disabled)"
    version = out.split("(GNU tar) ", 1)[1].split()[0]
    parts = version.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return " (unparseable version — --keep-directory-symlink disabled)"
    if (major, minor) < (1, 32):
        return f" {version} (< 1.32 — --keep-directory-symlink disabled)"
    return f" {version}"


def _check_tar_gzip_zstd():
    parts = []
    status = OK
    fix = ""
    for needed in ("tar", "gzip"):
        if _which(needed) is None:
            status = MISSING
            fix = f"apt install {needed}"
            parts.append(f"{needed} missing")
        elif needed == "tar":
            parts.append(f"tar{_tar_version_note()}")
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
    _check_cross_toolchain,
    _check_docker_or_podman,
    _check_newuidmap,
    _check_subid,
    _check_seccomp,
    _check_landlock,
    _check_cgroup_v2,
    _check_userns_unprivileged,
    _check_slirp_or_pasta,
    _check_squashfs,
    _check_nftables,
    _check_kvm_libkrun,
    _check_openssl_cosign,
    _check_rekor,
    _check_tar_gzip_zstd,
    _check_age,
    _check_tpm2_credstore,
    _check_runtime_helpers,
]


# ── distro detection + per-distro package summary ─────────────────────────────

def _detect_pkgmgr():
    """Return (pkgmgr, install_cmd, pretty_name) from /etc/os-release, or
    (None, None, name). pkgmgr is one of apt/dnf/pacman/zypper."""
    osr = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    osr[k] = v.strip().strip('"')
    except OSError:
        pass
    ident = (osr.get("ID", "") + " " + osr.get("ID_LIKE", "")).lower()
    pretty = osr.get("PRETTY_NAME") or osr.get("NAME") or "this system"
    if any(d in ident for d in ("debian", "ubuntu")):
        return "apt", "sudo apt install", pretty
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return "dnf", "sudo dnf install", pretty
    if any(d in ident for d in ("arch", "manjaro")):
        return "pacman", "sudo pacman -S", pretty
    if any(d in ident for d in ("suse", "opensuse")):
        return "zypper", "sudo zypper install", pretty
    return None, None, pretty


# Per-check packages by package manager. The native arch never needs a cross
# compiler; the cross-compiler entry is resolved dynamically (see _packages).
# Items absent from a manager's list are not cleanly packaged there and are
# reported under "install manually".
_PKGS = {
    "gcc":              {"apt": ["build-essential"], "dnf": ["gcc"],
                         "pacman": ["base-devel"], "zypper": ["gcc"]},
    "static libc":      {"apt": ["musl-tools"], "dnf": ["glibc-static"],
                         "pacman": ["musl"], "zypper": ["glibc-devel-static"]},
    "newuidmap/newgidmap": {"apt": ["uidmap"], "dnf": ["shadow-utils"],
                            "pacman": [], "zypper": ["shadow"]},
    "slirp4netns / pasta": {"apt": ["slirp4netns", "passt"],
                            "dnf": ["slirp4netns", "passt"],
                            "pacman": ["slirp4netns", "passt"],
                            "zypper": ["slirp4netns", "passt"]},
    "SquashFS lazy rootfs": {
        "apt": ["squashfs-tools", "squashfuse", "fuse-overlayfs"],
        "dnf": ["squashfs-tools", "squashfuse", "fuse-overlayfs"],
        "pacman": ["squashfs-tools", "squashfuse", "fuse-overlayfs"],
        "zypper": ["squashfs", "squashfuse", "fuse-overlayfs"]},
    "nftables (--allow-egress)": {"apt": ["nftables"], "dnf": ["nftables"],
                                  "pacman": ["nftables"], "zypper": ["nftables"]},
    "age (image encryption)": {"apt": ["age"], "dnf": ["age"],
                               "pacman": ["age"], "zypper": ["age"]},
    "tar/gzip/zstd":    {"apt": ["tar", "gzip", "zstd"],
                         "dnf": ["tar", "gzip", "zstd"],
                         "pacman": ["tar", "gzip", "zstd"],
                         "zypper": ["tar", "gzip", "zstd"]},
    "signing tooling":  {"apt": ["openssl"], "dnf": ["openssl"],
                         "pacman": ["openssl"], "zypper": ["openssl"]},
    "runtime helpers":  {"apt": ["util-linux", "sqlite3", "systemd", "gdb",
                                 "curl"],
                         "dnf": ["util-linux", "sqlite", "systemd", "gdb",
                                 "curl"],
                         "pacman": ["util-linux", "sqlite", "systemd", "gdb",
                                    "curl"],
                         "zypper": ["util-linux", "sqlite3", "systemd", "gdb",
                                    "curl"]},
    "docker/podman":    {"apt": ["skopeo"], "dnf": ["skopeo"],
                         "pacman": ["skopeo"], "zypper": ["skopeo"]},
}

# Cross-compiler package names differ per distro AND per target arch. Note the
# Debian/Ubuntu x86_64 package uses a hyphen ("x86-64"), unlike Fedora.
_CROSS_PKGS = {
    "aarch64": {"apt": ["gcc-aarch64-linux-gnu"],
                "dnf": ["gcc-aarch64-linux-gnu",
                        "sysroot-aarch64-fc{fedora}-glibc"],
                "pacman": ["aarch64-linux-gnu-gcc"], "zypper": []},
    "x86_64":  {"apt": ["gcc-x86-64-linux-gnu"],
                "dnf": ["gcc-x86_64-linux-gnu",
                        "sysroot-x86_64-fc{fedora}-glibc"],
                "pacman": [], "zypper": []},
}

# Deps that are not cleanly packaged on most distros — point at upstream.
_MANUAL = {
    "signing tooling": "cosign (https://docs.sigstore.dev/cosign/installation/)",
    "rekor-cli (transparency log)":
        "rekor-cli (https://docs.sigstore.dev/rekor/installation/)",
    "VM backend (KVM / libkrun / cloud-hypervisor)":
        "libkrun or cloud-hypervisor + virtiofsd (see your distro / upstream)",
}


def _packages(result, pkgmgr):
    """Packages to install for one non-OK check on this pkgmgr. Returns
    (apt_packages_list, manual_note_or_None)."""
    name = result["name"]
    if name.startswith("cross-compiler"):
        arch = "x86_64" if "x86_64" in name else "aarch64"
        pkgs = list(_CROSS_PKGS.get(arch, {}).get(pkgmgr, []))
        if pkgmgr == "dnf":
            try:
                with open("/etc/os-release", encoding="utf-8") as f:
                    fields = dict(
                        line.rstrip().split("=", 1)
                        for line in f
                        if "=" in line
                    )
                release = fields.get("VERSION_ID", "").strip("\"'")
            except OSError:
                release = ""
            if release:
                pkgs = [p.format(fedora=release) for p in pkgs]
            else:
                pkgs = [p.replace("{fedora}", "NN") for p in pkgs]
        return pkgs, None
    pkgs = _PKGS.get(name, {}).get(pkgmgr, [])
    return pkgs, _MANUAL.get(name)


def _install_summary(results, pkgmgr, install_cmd, pretty):
    """Build the OS-aware install summary lines for non-OK checks."""
    if pkgmgr is None:
        return ["Install summary: unrecognized distro — see the per-check "
                "fix: lines above."]
    pkgs = []
    manual = []
    for r in results:
        if r["status"] == OK:
            continue
        p, m = _packages(r, pkgmgr)
        pkgs.extend(p)
        if m:
            manual.append(m)
    # De-dup, preserve order.
    seen = set()
    pkgs = [x for x in pkgs if not (x in seen or seen.add(x))]
    manual = sorted(set(manual))
    lines = [f"Install summary for {pretty}:"]
    if pkgs:
        lines.append(f"  {install_cmd} {' '.join(pkgs)}")
    if manual:
        lines.append("  install manually: " + "; ".join(manual))
    if not pkgs and not manual:
        lines.append("  nothing to install — all checks OK or kernel-only.")
    # Fedora sysroot package names embed the release. A missing VERSION_ID is
    # unusual, but make the placeholder explicit instead of printing a bogus
    # package name.
    if pkgmgr == "dnf" and any("sysroot-" in x for x in pkgs):
        if any("fcNN-" in x for x in pkgs):
            lines.append("  (replace NN in the sysroot package name with the "
                         "Fedora release)")
    return lines


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
    pkgmgr, install_cmd, pretty = _detect_pkgmgr()
    if args.json:
        # Stable shape: a list of check results (consumers depend on this).
        json.dump(results, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(results)
        print()
        for line in _install_summary(results, pkgmgr, install_cmd, pretty):
            print(line)
    # Exit non-zero only on hard MISSING; DEGRADED is informational.
    if any(r["status"] == MISSING for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
