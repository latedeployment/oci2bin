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
import importlib.util
import io
import json
import os
import sqlite3
import struct
import sys
import tarfile
import tempfile
import urllib.parse

# The embedded-OCI locator lives in inspect_image.py; a private copy here
# missed the span validation added there and misread truncated binaries.
_inspect_spec = importlib.util.spec_from_file_location(
    'oci2bin_inspect_image',
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'inspect_image.py'))
_inspect = importlib.util.module_from_spec(_inspect_spec)
_inspect_spec.loader.exec_module(_inspect)


def read_oci_data(binary_path):
    """Extract embedded OCI tar bytes from an oci2bin binary."""
    return _inspect.read_oci_data(binary_path)


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


# RPM header tags / types (rpmtag.h) used below.
_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE = 1000, 1001, 1002
_RPMTAG_EPOCH, _RPMTAG_SUMMARY, _RPMTAG_ARCH = 1003, 1004, 1022
_RPM_INT32, _RPM_STRING, _RPM_STRING_ARRAY, _RPM_I18NSTRING = 4, 6, 8, 9
_RPM_WANTED = {_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE,
               _RPMTAG_EPOCH, _RPMTAG_SUMMARY, _RPMTAG_ARCH}


def parse_rpm_header_blob(blob):
    """Decode the tags we need from one rpmdb header blob.

    rpm's sqlite backend stores each package as an opaque header blob in
    Packages(hnum, blob) — there are no name/version columns to SELECT,
    which is why every RHEL/Fedora/UBI image used to report "no packages".
    Layout (headerExport): BE32 index count, BE32 data length, then
    16-byte index entries (tag, type, offset, count) and the data store.
    Returns {tag: value} or None for a malformed blob.
    """
    if len(blob) < 8:
        return None
    il, dl = struct.unpack_from('>II', blob, 0)
    data_start = 8 + 16 * il
    if il > 100000 or data_start + dl > len(blob):
        return None
    data = blob[data_start:data_start + dl]
    out = {}
    for i in range(il):
        tag, typ, off, count = struct.unpack_from('>iIiI', blob, 8 + 16 * i)
        if tag not in _RPM_WANTED or off < 0 or off >= dl:
            continue
        if typ == _RPM_INT32 and off + 4 <= dl:
            out[tag] = struct.unpack_from('>i', data, off)[0]
        elif typ in (_RPM_STRING, _RPM_I18NSTRING, _RPM_STRING_ARRAY):
            end = data.find(b'\x00', off)
            if end < 0:
                continue
            out[tag] = data[off:end].decode('utf-8', errors='replace')
    return out


def parse_rpm_sqlite(db_path):
    """Parse an rpmdb.sqlite into a list of package dicts."""
    packages = []
    try:
        conn = sqlite3.connect(
            f"file:{urllib.parse.quote(db_path)}?mode=ro", uri=True)
    except (sqlite3.Error, OSError):
        return packages
    try:
        rows = conn.execute("SELECT blob FROM Packages").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    for (blob,) in rows:
        hdr = parse_rpm_header_blob(bytes(blob or b''))
        if not hdr or _RPMTAG_NAME not in hdr:
            continue
        name = hdr[_RPMTAG_NAME]
        if name == 'gpg-pubkey':
            continue  # imported signing keys, not software
        version = hdr.get(_RPMTAG_VERSION, '')
        release = hdr.get(_RPMTAG_RELEASE, '')
        packages.append({
            'name':    name,
            'version': f"{version}-{release}" if release else version,
            'epoch':   hdr.get(_RPMTAG_EPOCH),
            'arch':    hdr.get(_RPMTAG_ARCH, ''),
            'desc':    hdr.get(_RPMTAG_SUMMARY, ''),
            'type':    'rpm',
        })
    return packages


def read_os_release_id(rootfs):
    """The distro ID from /etc/os-release (purl namespace), or ''."""
    for rel in ('etc/os-release', 'usr/lib/os-release'):
        try:
            with open(os.path.join(rootfs, rel), errors='replace') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line[3:].strip().strip('"\'').lower()
        except OSError:
            continue
    return ''


# Package-manager database type -> purl type (purl-spec).
_PURL_TYPE = {'dpkg': 'deb', 'apk': 'apk', 'rpm': 'rpm'}


def make_purl(pkg, distro):
    """Canonical purl, e.g. pkg:deb/debian/bash@5.2-15?arch=amd64.  The old
    `pkg:dpkg/...` is not a registered purl type, so scanners (Grype,
    Trivy) ignored every component."""
    ptype = _PURL_TYPE.get(pkg['type'], pkg['type'])
    namespace = distro or ('alpine' if ptype == 'apk' else '')
    q = urllib.parse.quote
    purl = f"pkg:{ptype}/"
    if namespace:
        purl += q(namespace, safe='') + '/'
    purl += f"{q(pkg['name'], safe='')}@{q(pkg['version'], safe='')}"
    quals = []
    if pkg.get('arch'):
        quals.append(f"arch={q(pkg['arch'], safe='')}")
    if pkg.get('epoch'):
        quals.append(f"epoch={pkg['epoch']}")
    if distro:
        quals.append(f"distro={q(distro, safe='')}")
    if quals:
        purl += '?' + '&'.join(quals)
    return purl


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

    # rpm — /usr/lib/sysimage/rpm on Fedora 36+/RHEL 10, /var/lib/rpm before
    if not packages:
        for rel in (('usr', 'lib', 'sysimage', 'rpm', 'rpmdb.sqlite'),
                    ('var', 'lib', 'rpm', 'rpmdb.sqlite')):
            rpm_path = os.path.join(rootfs, *rel)
            # The rootfs comes from the image: never follow a symlink in
            # it out to a host database.
            real_root = os.path.realpath(rootfs)
            if not os.path.realpath(rpm_path).startswith(real_root + os.sep):
                continue
            if os.path.isfile(rpm_path):
                packages.extend(parse_rpm_sqlite(rpm_path))
                break

    distro = read_os_release_id(rootfs)
    for pkg in packages:
        pkg['purl'] = make_purl(pkg, distro)
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
                "referenceType":     "purl",
                "referenceLocator":  pkg['purl'],
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
        purl = pkg['purl']
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
