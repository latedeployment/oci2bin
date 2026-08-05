#!/usr/bin/env python3
"""
check_version.py — assert every place the project version is written agrees.

The version is duplicated across the Python package, the polyglot builder, the
loader, and distro packaging files. They have drifted apart before. This is
the cheap guard: it does not generate anything, it just fails when they
disagree.

`pyproject.toml` is the canonical source. Run via `make check-version`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, path, regex with one capture group holding the version)
SOURCES = [
    ("pyproject.toml", "pyproject.toml",
     r'(?m)^version\s*=\s*"([^"]+)"'),
    ("scripts/build_polyglot.py", "scripts/build_polyglot.py",
     r"(?m)^OCI2BIN_VERSION\s*=\s*'([^']+)'"),
    ("src/loader.c", "src/loader.c",
     r'(?m)^#define\s+OCI2BIN_VERSION\s+"([^"]+)"'),
    ("packaging/rpm/oci2bin.spec", "packaging/rpm/oci2bin.spec",
     r"(?m)^Version:\s*(\S+)"),
    ("flake.nix", "flake.nix",
     r'(?m)^\s*version\s*=\s*"([^"]+)"\s*;'),
]

CANONICAL = "pyproject.toml"


def main():
    found = {}
    missing = []

    for label, rel, pattern in SOURCES:
        path = ROOT / rel
        if not path.exists():
            missing.append(f"{label}: file not found")
            continue
        match = re.search(pattern, path.read_text())
        if not match:
            missing.append(f"{label}: no version match for {pattern!r}")
            continue
        found[label] = match.group(1)

    if missing:
        for problem in missing:
            print(f"check-version: {problem}", file=sys.stderr)
        return 1

    canonical = found[CANONICAL]
    mismatched = {k: v for k, v in found.items() if v != canonical}

    width = max(len(k) for k in found)
    for rel, version in found.items():
        flag = "" if version == canonical else "   <-- mismatch"
        print(f"  {rel:<{width}}  {version}{flag}")

    if mismatched:
        print(
            f"\ncheck-version: {len(mismatched)} file(s) disagree with"
            f" {CANONICAL} ({canonical})",
            file=sys.stderr)
        return 1

    print(f"\ncheck-version: OK — all {len(found)} sources at {canonical}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
