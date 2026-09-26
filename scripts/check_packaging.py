#!/usr/bin/env python3
"""
check_packaging.py — `make check-packaging`: stage `make install` under a
temporary DESTDIR and exercise the result the way a package would be used.

What a packager gets wrong is rarely the code: it is a helper script missing
from the manifest, a symlink that points back into the build tree, a wrapper
that still looks for its helpers next to itself, or an entry point that
cannot find bash.  So this stages the install, checks the tree file by file,
then runs the installed `oci2bin --help`, `oci2vm --help` and
`oci2bin doctor --json` out of the staged prefix.  With --wheel it also
builds the wheel, installs it into a scratch target and runs the console
script out of that.

Exit 0 when every check passes; 1 with one line per problem otherwise.
Pure stdlib; `make`, `python3`, `bash` and (for --wheel) pip + setuptools
must be present.
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _manifest_scripts():
    """Names of the helper scripts the manifest ships (package_manifest.py
    is the single source of truth; this never keeps its own list)."""
    spec = importlib.util.spec_from_file_location(
        "package_manifest", ROOT / "scripts" / "package_manifest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [Path(rel).name for rel in mod.read_manifest()]


def _run(argv, env=None, cwd=None, timeout=600):
    return subprocess.run(argv, capture_output=True, text=True, env=env,
                          cwd=cwd, timeout=timeout)


def host_arch():
    return os.uname().machine


def stage_install(destdir, prefix, root=ROOT):
    """`make install DESTDIR=... PREFIX=...`; returns the problems (0 or 1)."""
    r = _run(["make", "-s", "-C", str(root), "install",
              f"DESTDIR={destdir}", f"PREFIX={prefix}"])
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip().splitlines()[-15:]
        return [f"make install failed (exit {r.returncode}):\n  "
                + "\n  ".join(tail)]
    return []


def expected_layout(prefix_root, scripts, arch):
    """(path, kind) for everything `make install` must have produced under
    DESTDIR/PREFIX.  kind: 'exec', 'file', 'symlink'."""
    share = prefix_root / "share" / "oci2bin"
    items = [
        (prefix_root / "bin" / "oci2bin", "exec"),
        (prefix_root / "bin" / "oci2vm", "symlink"),
        (share / "src" / "loader.c", "file"),
        (share / "build" / f"loader-{arch}", "exec"),
        (prefix_root / "share" / "man" / "man1" / "oci2bin.1", "file"),
    ]
    items += [(share / "scripts" / name, "file") for name in scripts]
    return items


def check_tree(destdir, prefix, scripts, arch):
    """Problems with the staged tree; [] when it is what a package needs."""
    destdir = Path(destdir)
    prefix_root = destdir / prefix.lstrip("/")
    problems = []
    for path, kind in expected_layout(prefix_root, scripts, arch):
        rel = path.relative_to(destdir)
        if kind == "symlink":
            if not path.is_symlink():
                problems.append(f"{rel}: expected a symlink")
            elif os.readlink(path) != "oci2bin":
                problems.append(f"{rel}: symlink points at "
                                f"{os.readlink(path)!r}, not 'oci2bin'")
            continue
        if not path.is_file():
            problems.append(f"{rel}: missing")
            continue
        if kind == "exec" and not os.access(path, os.X_OK):
            problems.append(f"{rel}: not executable")
    # Nothing in the staged tree may reach outside it: an absolute symlink,
    # or a relative one that escapes DESTDIR, breaks the moment the tree is
    # packed into an archive or a buildroot.
    for dirpath, dirnames, filenames in os.walk(destdir):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            target = os.readlink(p)
            resolved = (p.parent / target).resolve() if not os.path.isabs(
                target) else Path(target)
            if os.path.isabs(target) or not str(resolved).startswith(
                    str(destdir.resolve()) + os.sep):
                problems.append(f"{p.relative_to(destdir)}: symlink escapes"
                                f" the staged tree ({target})")
    # The installed wrapper must look for its helpers in PREFIX, never next
    # to itself: that sed is the one thing `make install` edits.
    wrapper = prefix_root / "bin" / "oci2bin"
    if wrapper.is_file():
        text = wrapper.read_text(encoding="utf-8", errors="replace")
        baked = f"OCI2BIN_HOME:-{prefix}/share/oci2bin"
        if baked not in text:
            problems.append(f"bin/oci2bin: OCI2BIN_HOME default is not"
                            f" {prefix}/share/oci2bin")
        if "OCI2BIN_HOME:-$SCRIPT_DIR" in text:
            problems.append("bin/oci2bin: still defaults OCI2BIN_HOME to the"
                            " script directory")
    # Every helper must at least compile: a truncated or partial copy would
    # only show up on the first use of that subcommand.
    for name in scripts:
        p = prefix_root / "share" / "oci2bin" / "scripts" / name
        if p.is_file():
            try:
                compile(p.read_bytes(), str(p), "exec")
            except (SyntaxError, ValueError) as exc:
                problems.append(f"share/oci2bin/scripts/{name}: does not"
                                f" compile: {exc}")
    return problems


def run_installed(destdir, prefix, home):
    """Run the staged binaries the way a user would; problems or []."""
    destdir = Path(destdir)
    prefix_root = destdir / prefix.lstrip("/")
    # PREFIX is not real on this machine, so point the wrapper at the staged
    # share dir explicitly; the sed above is checked separately.
    env = dict(os.environ, OCI2BIN_HOME=str(prefix_root / "share" / "oci2bin"),
               HOME=str(home), XDG_CACHE_HOME=str(Path(home) / ".cache"))
    problems = []
    for name in ("oci2bin", "oci2vm"):
        exe = prefix_root / "bin" / name
        r = _run([str(exe), "--help"], env=env)
        # usage() prints the header block and exits 1 by design; what must
        # hold is that the header came out and bash raised no error.
        if "Usage:" not in r.stdout or not r.stdout.startswith("oci2bin"):
            problems.append(f"{name} --help: no usage text (exit"
                            f" {r.returncode}): {(r.stderr or r.stdout).strip()[:200]}")
        if r.stderr.strip():
            problems.append(f"{name} --help: wrote to stderr:"
                            f" {r.stderr.strip()[:200]}")
    # A subcommand that dispatches to a helper proves the staged wrapper
    # finds its scripts; doctor's exit status depends on the host, its
    # output shape does not.
    r = _run([str(prefix_root / "bin" / "oci2bin"), "doctor", "--json"],
             env=env, timeout=120)
    try:
        data = json.loads(r.stdout)
        ok = isinstance(data, list) and data and all(
            "name" in d and "status" in d for d in data)
    except ValueError:
        ok = False
    if not ok:
        problems.append("oci2bin doctor --json: no JSON check list from the"
                        f" staged install: {(r.stderr or r.stdout).strip()[:200]}")
    return problems


def check_wheel(workdir, scripts, root=ROOT):
    """Build the wheel, check its contents, install it into a scratch
    target and run the console scripts out of it.  Problems or []."""
    workdir = Path(workdir)
    wheel_dir = workdir / "wheel"
    wheel_dir.mkdir()
    # pyproject.toml pins setuptools>=77 (PEP 639 license field); pip's
    # default isolated build fetches it, which needs index access.  With
    # OCI2BIN_WHEEL_NO_ISOLATION=1 the host's setuptools is used instead.
    argv = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q",
            "-w", str(wheel_dir), str(root)]
    if os.environ.get("OCI2BIN_WHEEL_NO_ISOLATION") == "1":
        argv.insert(4, "--no-build-isolation")
    r = _run(argv, timeout=900)
    if r.returncode != 0:
        return ["pip wheel failed (an isolated build needs index access for"
                " setuptools>=77; set OCI2BIN_WHEEL_NO_ISOLATION=1 to use the"
                " host's setuptools):\n  "
                + "\n  ".join((r.stderr or r.stdout).strip().splitlines()[-15:])]
    wheels = sorted(wheel_dir.glob("oci2bin-*.whl"))
    if len(wheels) != 1:
        return [f"expected one oci2bin wheel, found {len(wheels)}"]
    whl = wheels[0]
    problems = []
    with zipfile.ZipFile(whl) as zf:
        names = set(zf.namelist())
    for needed in (["oci2bin_pkg/oci2bin.bash", "oci2bin_pkg/src/loader.c",
                    "oci2bin_pkg/_entry.py"]
                   + [f"oci2bin_pkg/scripts/{s}" for s in scripts]):
        if needed not in names:
            problems.append(f"{whl.name}: missing {needed}")
    if problems:
        return problems
    target = workdir / "site"
    r = _run([sys.executable, "-m", "pip", "install", "--no-deps", "-q",
              "--target", str(target), str(whl)], timeout=600)
    if r.returncode != 0:
        return ["pip install --target failed:\n  "
                + "\n  ".join((r.stderr or r.stdout).strip().splitlines()[-15:])]
    env = dict(os.environ, PYTHONPATH=str(target),
               HOME=str(workdir / "home"))
    (workdir / "home").mkdir(exist_ok=True)
    for name in ("oci2bin", "oci2vm"):
        exe = target / "bin" / name
        if not exe.is_file():
            problems.append(f"wheel: console script {name} not installed")
            continue
        r = _run([sys.executable, str(exe), "--help"], env=env)
        if "Usage:" not in r.stdout or not r.stdout.startswith("oci2bin"):
            problems.append(f"wheel {name} --help: no usage text (exit"
                            f" {r.returncode}): {(r.stderr or r.stdout).strip()[:200]}")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="check_packaging.py",
        description="stage `make install` under a temporary DESTDIR and"
                    " exercise the result")
    p.add_argument("--prefix", default="/usr",
                   help="PREFIX to stage under (default /usr, as packages do)")
    p.add_argument("--wheel", action="store_true",
                   help="also build the wheel and run its console scripts")
    p.add_argument("--keep", action="store_true",
                   help="leave the staging directory behind and print it")
    args = p.parse_args(argv)

    for tool in ("make", "bash"):
        if shutil.which(tool) is None:
            print(f"check-packaging: {tool} not in PATH", file=sys.stderr)
            return 1
    scripts = _manifest_scripts()
    arch = host_arch()
    problems = []
    tmp = tempfile.mkdtemp(prefix="oci2bin-pkgcheck-")
    try:
        destdir = Path(tmp) / "destdir"
        home = Path(tmp) / "home"
        home.mkdir()
        print(f"check-packaging: staging make install DESTDIR={destdir}"
              f" PREFIX={args.prefix}")
        problems += stage_install(destdir, args.prefix)
        if not problems:
            problems += check_tree(destdir, args.prefix, scripts, arch)
            print(f"check-packaging: tree checked ({len(scripts)} helper"
                  f" scripts, loader-{arch}, man page, oci2vm link)")
            problems += run_installed(destdir, args.prefix, home)
            print("check-packaging: installed oci2bin --help, oci2vm --help"
                  " and doctor --json ran")
        if args.wheel and not problems:
            work = Path(tmp) / "wheel-work"
            work.mkdir()
            problems += check_wheel(work, scripts)
            if not problems:
                print("check-packaging: wheel built, inspected and its"
                      " console scripts ran")
    finally:
        if args.keep:
            print(f"check-packaging: kept {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    if problems:
        print("check-packaging: FAILED", file=sys.stderr)
        for line in problems:
            print("  - " + line, file=sys.stderr)
        return 1
    print("check-packaging: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
