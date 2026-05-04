#!/usr/bin/env python3
"""
sbom_generate.py — generate a Software Bill of Materials from an oci2bin binary.

Usage:
    sbom_generate.py BINARY [--format spdx|cyclonedx]

Extracts the embedded OCI rootfs, reads package databases, and outputs an SBOM
in SPDX 2.3 JSON or CycloneDX 1.4 JSON format to stdout.

Supported package managers:
    - dpkg  (/var/lib/dpkg/status)
    - apk   (/lib/apk/db/installed)
    - rpm   (/var/lib/rpm/rpmdb.sqlite)

Pure Python, stdlib only.
"""

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import sqlite3
import struct
import sys
import tarfile
import tempfile

# Reuse OCI data reading logic from diff_images.py
OFFSET_MARKER  = struct.pack('<Q', 0xDEADBEEFCAFEBABE)
SIZE_MARKER    = struct.pack('<Q', 0xCAFEBABEDEADBEEF)
PATCHED_MARKER = struct.pack('<Q', 0xAAAAAAAAAAAAAAAA)


def read_oci_data(binary_path):
    """Extract embedded OCI tar bytes from an oci2bin binary."""
    with open(binary_path, 'rb') as f:
        data = f.read()

    patched_off = data.find(PATCHED_MARKER)
    if patched_off is not None and patched_off != -1:
        print(f"sbom: {binary_path}: OCI markers not patched", file=sys.stderr)
        sys.exit(1)

    loader_region = data[:8 * 1024 * 1024]
    file_size = len(data)

    for pos in range(0, len(loader_region) - 16, 8):
        candidate_offset = struct.unpack_from('<Q', loader_region, pos)[0]
        candidate_size   = struct.unpack_from('<Q', loader_region, pos + 8)[0]

        if candidate_offset in (0xDEADBEEFCAFEBABE, 0xCAFEBABEDEADBEEF,
                                 0xAAAAAAAAAAAAAAAA, 0):
            continue
        if candidate_offset >= file_size:
            continue
        if candidate_size == 0 or candidate_size > file_size:
            continue
        if candidate_offset + candidate_size > file_size:
            continue

        tar_region = data[candidate_offset:candidate_offset + 512]
        if len(tar_region) >= 262 and tar_region[257:262] == b'ustar':
            return data[candidate_offset:candidate_offset + candidate_size]

    print(f"sbom: could not find embedded OCI tar in {binary_path}",
          file=sys.stderr)
    sys.exit(1)


def extract_rootfs_to_tmpdir(oci_bytes, tmpdir):
    """Extract all OCI layers into tmpdir/rootfs. Returns rootfs path."""
    rootfs = os.path.join(tmpdir, 'rootfs')
    os.makedirs(rootfs, exist_ok=True)

    try:
        outer_tf = tarfile.open(fileobj=io.BytesIO(oci_bytes), mode='r')
    except tarfile.TarError as e:
        print(f"sbom: tar error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        manifest_member = outer_tf.getmember('manifest.json')
    except KeyError:
        print("sbom: manifest.json not found", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(outer_tf.extractfile(manifest_member).read())
    layers = manifest[0].get('Layers', [])

    for layer_name in layers:
        try:
            layer_member = outer_tf.getmember(layer_name)
        except KeyError:
            continue
        layer_data = outer_tf.extractfile(layer_member).read()

        if layer_data[:2] == b'\x1f\x8b':
            layer_data = gzip.decompress(layer_data)

        try:
            layer_tf = tarfile.open(fileobj=io.BytesIO(layer_data), mode='r:')
        except tarfile.TarError:
            continue

        for member in layer_tf.getmembers():
            # Skip whiteout files
            if os.path.basename(member.name).startswith('.wh.'):
                continue
            # Safety: skip absolute paths and .. components
            name = member.name
            while name.startswith('./') or name.startswith('/'):
                name = name[2:] if name.startswith('./') else name[1:]
            if '..' in name.split('/'):
                continue
            # Refuse to traverse through any existing symlink in the path:
            # a malicious earlier layer could drop a symlink (e.g. etc -> /tmp)
            # that would redirect a later file write outside the rootfs.
            parts = name.split('/')
            cur = rootfs
            traversed_symlink = False
            for p in parts[:-1]:
                if not p or p == '.':
                    continue
                cur = os.path.join(cur, p)
                if os.path.islink(cur):
                    traversed_symlink = True
                    break
            if traversed_symlink:
                continue
            dest = os.path.join(rootfs, name)
            if member.isdir():
                os.makedirs(dest, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    f = layer_tf.extractfile(member)
                    if f:
                        with open(dest, 'wb') as out:
                            out.write(f.read())
                except OSError:
                    pass
            elif member.issym():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                # Validate symlink target does not escape rootfs
                if os.path.isabs(member.linkname):
                    resolved = os.path.normpath(
                        os.path.join(rootfs, member.linkname.lstrip('/')))
                else:
                    resolved = os.path.normpath(
                        os.path.join(os.path.dirname(dest), member.linkname))
                if not resolved.startswith(rootfs + '/') and resolved != rootfs:
                    continue
                try:
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.symlink(member.linkname, dest)
                except OSError:
                    pass
        layer_tf.close()

    outer_tf.close()
    return rootfs


def parse_dpkg_status(status_path):
    """Parse /var/lib/dpkg/status into a list of package dicts."""
    packages = []
    try:
        with open(status_path, 'r', errors='replace') as f:
            content = f.read()
    except OSError:
        return packages

    for stanza in content.split('\n\n'):
        pkg = {}
        for line in stanza.splitlines():
            if ': ' in line and not line.startswith(' '):
                key, _, val = line.partition(': ')
                pkg[key.strip()] = val.strip()
        if 'Package' in pkg and 'Version' in pkg:
            if 'installed' in pkg.get('Status', ''):
                packages.append({
                    'name':    pkg['Package'],
                    'version': pkg['Version'],
                    'arch':    pkg.get('Architecture', ''),
                    'desc':    pkg.get('Description', '').split('\n')[0],
                    'type':    'dpkg',
                })
    return packages


def parse_apk_installed(installed_path):
    """Parse /lib/apk/db/installed into a list of package dicts."""
    packages = []
    try:
        with open(installed_path, 'r', errors='replace') as f:
            content = f.read()
    except OSError:
        return packages

    for stanza in content.split('\n\n'):
        pkg = {}
        for line in stanza.splitlines():
            if len(line) >= 2 and line[1] == ':':
                key = line[0]
                val = line[2:].strip()
                pkg[key] = val
        if 'P' in pkg and 'V' in pkg:
            packages.append({
                'name':    pkg['P'],
                'version': pkg['V'],
                'arch':    pkg.get('A', ''),
                'desc':    pkg.get('T', ''),
                'type':    'apk',
            })
    return packages


def parse_rpm_sqlite(db_path):
    """Parse /var/lib/rpm/rpmdb.sqlite into a list of package dicts."""
    packages = []
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT name, version, release, arch, summary "
                "FROM Packages LIMIT 10000"
            )
            for row in cur.fetchall():
                name, version, release, arch, summary = row
                packages.append({
                    'name':    name or '',
                    'version': f"{version}-{release}" if release else (version or ''),
                    'arch':    arch or '',
                    'desc':    summary or '',
                    'type':    'rpm',
                })
        except sqlite3.OperationalError:
            pass
        conn.close()
    except (sqlite3.Error, OSError):
        pass
    return packages


def collect_packages(rootfs):
    """Collect packages from all supported package managers."""
    packages = []

    # dpkg
    dpkg_path = os.path.join(rootfs, 'var', 'lib', 'dpkg', 'status')
    packages.extend(parse_dpkg_status(dpkg_path))

    # apk (prefer dpkg if found)
    if not packages:
        apk_path = os.path.join(rootfs, 'lib', 'apk', 'db', 'installed')
        packages.extend(parse_apk_installed(apk_path))

    # rpm
    if not packages:
        rpm_path = os.path.join(rootfs, 'var', 'lib', 'rpm', 'rpmdb.sqlite')
        packages.extend(parse_rpm_sqlite(rpm_path))

    return packages


def make_spdx_id(name, version):
    h = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:8]
    safe = ''.join(c if c.isalnum() else '-' for c in name)
    return f"SPDXRef-{safe}-{h}"


def output_spdx(packages, binary_path):
    now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": os.path.basename(binary_path),
        "documentNamespace": (
            f"https://oci2bin.local/sbom/"
            f"{os.path.basename(binary_path)}-{now}"
        ),
        "creationInfo": {
            "created": now,
            "creators": ["Tool: oci2bin-sbom"],
        },
        "packages": [],
    }

    for pkg in packages:
        doc["packages"].append({
            "SPDXID":           make_spdx_id(pkg['name'], pkg['version']),
            "name":             pkg['name'],
            "versionInfo":      pkg['version'],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed":    False,
            "comment":          pkg.get('desc', ''),
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType":     pkg['type'],
                "referenceLocator":  (
                    f"{pkg['name']}@{pkg['version']}"
                ),
            }],
        })

    print(json.dumps(doc, indent=2))


def output_cyclonedx(packages, binary_path):
    now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    doc = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "version":     1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "oci2bin-sbom", "version": "1.0"}],
            "component": {
                "type":    "container",
                "name":    os.path.basename(binary_path),
                "version": "unknown",
            },
        },
        "components": [],
    }

    for pkg in packages:
        purl = (
            f"pkg:{pkg['type']}/{pkg['name']}@{pkg['version']}"
            + (f"?arch={pkg['arch']}" if pkg.get('arch') else "")
        )
        doc["components"].append({
            "type":        "library",
            "name":        pkg['name'],
            "version":     pkg['version'],
            "description": pkg.get('desc', ''),
            "purl":        purl,
        })

    print(json.dumps(doc, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Generate SBOM from an oci2bin binary')
    parser.add_argument('binary', help='Path to oci2bin polyglot binary')
    parser.add_argument('--format', choices=['spdx', 'cyclonedx'],
                        default='spdx', help='Output format (default: spdx)')
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"sbom: file not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    print(f"sbom: extracting OCI rootfs from {args.binary}...",
          file=sys.stderr)
    oci_bytes = read_oci_data(args.binary)

    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = extract_rootfs_to_tmpdir(oci_bytes, tmpdir)
        packages = collect_packages(rootfs)

    if not packages:
        print("sbom: no packages found (unsupported package manager?)",
              file=sys.stderr)
        sys.exit(1)

    print(f"sbom: found {len(packages)} packages", file=sys.stderr)

    if args.format == 'cyclonedx':
        output_cyclonedx(packages, args.binary)
    else:
        output_spdx(packages, args.binary)


if __name__ == '__main__':
    main()
