#!/usr/bin/env python3
"""
explain.py — `oci2bin explain BINARY`: human-readable report of what
a polyglot binary contains and what the host needs to run it.

Combines:
  - inspect_image.py    image config, embedded build metadata
  - doctor.py           host capability probes
  - signature scan      OCI2BIN_SIG / OCI2BIN_SIG_END trailer presence
  - SBOM scan           heuristic check for an embedded SPDX/CycloneDX

Exit code is non-zero only when at least one host feature the binary
*depends on* is reported MISSING by the doctor checks. DEGRADED is
informational, identical to `oci2bin doctor`.
"""

import importlib.util
import json
import os
import pathlib
import sys


_HERE = pathlib.Path(__file__).resolve().parent

# Lazy-load sibling modules by file path so this script works whether
# invoked from the source tree or after `make install`.
def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inspect_image = _load("inspect_image")
doctor = _load("doctor")


SIG_MAGIC = b"OCI2BIN_SIG\x00"
SIG_TRAILER = b"OCI2BIN_SIG_END\x00"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _has_signature(binary_path: str) -> bool:
    """Look for the OCI2BIN_SIG block trailer at any offset."""
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    return SIG_TRAILER in data and SIG_MAGIC in data


def _has_sbom(binary_path: str) -> bool:
    """Heuristic: SBOM blocks are typically appended with a JSON
    document containing 'spdxVersion' or 'bomFormat'."""
    try:
        with open(binary_path, "rb") as f:
            tail = f.read()[-262144:]
    except OSError:
        return False
    return b"spdxVersion" in tail or b"bomFormat" in tail


def _redact_env(env_list):
    """Hide secret-shaped env values (KEY/TOKEN/SECRET/PASSWORD), keep keys."""
    out = []
    for kv in env_list or []:
        if "=" not in kv:
            out.append(kv)
            continue
        k, v = kv.split("=", 1)
        if any(s in k.upper() for s in
               ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD")):
            out.append(f"{k}=<redacted>")
        else:
            out.append(f"{k}={v}")
    return out


def _required_doctor_checks(meta, cfg):
    """
    Return the list of doctor check function names this binary will
    care about based on what its metadata advertises. The full doctor
    output is shown regardless; this set is used only to decide the
    explain exit code.
    """
    needed = {"_check_tar_gzip_zstd"}
    # If the binary embeds a kernel for VM mode, KVM/libkrun is needed.
    if meta.get("kernel_embedded") or meta.get("vm"):
        needed.add("_check_kvm_libkrun")
    # Userns ID remap is needed when running rootless (the default).
    needed.add("_check_subid")
    needed.add("_check_newuidmap")
    needed.add("_check_userns_unprivileged")
    return needed


# ── Driver ──────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        prog="oci2bin explain",
        description="explain what an oci2bin binary contains and "
                    "what the host needs to run it")
    p.add_argument("binary", help="path to an oci2bin polyglot binary")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    args = p.parse_args()

    binary = args.binary
    if not os.path.isfile(binary):
        print(f"explain: file not found: {binary}", file=sys.stderr)
        sys.exit(1)

    # Image config + metadata. Catch broadly: the embedded tar can be
    # truncated, encrypted, or use unusual layouts that tarfile can't
    # parse — explain still wants to show what it does know.
    try:
        oci_bytes = inspect_image.read_oci_data(binary)
        repo_tags, layers, config = inspect_image.parse_config(oci_bytes)
    except SystemExit:
        repo_tags, layers, config = [], [], {}
    except Exception as e:
        print(f"explain: image config unavailable ({type(e).__name__}: {e})",
              file=sys.stderr)
        repo_tags, layers, config = [], [], {}
    cfg = config.get("config", config)
    meta = inspect_image.read_meta_block(binary) or {}

    image_name = repo_tags[0] if repo_tags else "(unknown)"
    arch = config.get("architecture", "(unknown)")
    entrypoint = cfg.get("Entrypoint") or []
    cmd = cfg.get("Cmd") or []
    workdir = cfg.get("WorkingDir") or "/"
    env = cfg.get("Env") or []
    ports = list((cfg.get("ExposedPorts") or {}).keys())
    healthcheck = cfg.get("Healthcheck") or {}
    user = cfg.get("User") or "0"
    volumes = list((cfg.get("Volumes") or {}).keys())
    labels = cfg.get("Labels") or {}

    file_size = os.path.getsize(binary)

    # Host probes
    host_results = [c() for c in doctor.CHECKS]
    needed = _required_doctor_checks(meta, cfg)

    # Compute exit code from required checks
    failing = []
    for check_func, result in zip(doctor.CHECKS, host_results):
        if check_func.__name__ in needed and result["status"] == doctor.MISSING:
            failing.append(result["name"])

    sig_present = _has_signature(binary)
    sbom_present = _has_sbom(binary)

    if args.json:
        report = {
            "binary": os.path.abspath(binary),
            "size": file_size,
            "image": {
                "name": image_name,
                "architecture": arch,
                "layers": len(layers),
                "entrypoint": entrypoint,
                "cmd": cmd,
                "workdir": workdir,
                "user": user,
                "env": _redact_env(env),
                "exposed_ports": ports,
                "healthcheck": healthcheck,
                "volumes": volumes,
                "labels": labels,
            },
            "build_metadata": meta,
            "trust": {
                "signature_present": sig_present,
                "sbom_present": sbom_present,
            },
            "host_checks": host_results,
            "missing_required": failing,
        }
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"Binary:       {binary}")
        print(f"Size:         {file_size} bytes "
              f"({file_size / (1024 * 1024):.1f} MiB)")
        print()
        print(f"Image:        {image_name}")
        print(f"Architecture: {arch}")
        print(f"Layers:       {len(layers)}")
        print(f"Entrypoint:   {json.dumps(entrypoint)}")
        print(f"Cmd:          {json.dumps(cmd)}")
        print(f"WorkingDir:   {workdir}")
        print(f"User:         {user}")
        if env:
            print("Env:")
            for e in _redact_env(env):
                print(f"              {e}")
        if ports:
            print(f"ExposedPorts: {' '.join(ports)}")
        if healthcheck:
            print(f"Healthcheck:  "
                  f"{json.dumps(healthcheck.get('Test') or healthcheck)}")
        if volumes:
            print(f"Volumes:      {' '.join(volumes)}")
        if labels:
            print("Labels:")
            for k, v in labels.items():
                print(f"              {k}={v}")
        print()
        print("Build metadata:")
        if meta:
            for k in ("image", "digest", "timestamp", "version"):
                if k in meta:
                    print(f"  {k:<12}{meta[k]}")
        else:
            print("  (no OCI2BIN_META block — older builder)")
        print()
        print(f"Signature:    {'present' if sig_present else 'absent'}")
        print(f"SBOM:         {'embedded' if sbom_present else 'absent'}")
        print()
        print("Host capabilities:")
        for r in host_results:
            mark = " " if r["status"] == doctor.OK else "!"
            print(f"  [{r['status']:<8}]{mark} {r['name']}: {r['detail']}")
            if r["status"] != doctor.OK and r["fix"]:
                print(f"             fix: {r['fix']}")
        if failing:
            print()
            print(f"FAIL: {len(failing)} required host check(s) MISSING: "
                  f"{', '.join(failing)}")

    sys.exit(1 if failing else 0)


if __name__ == "__main__":
    main()
