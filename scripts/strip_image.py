#!/usr/bin/env python3
"""
strip_image.py — remove docs/man/locale/cache files from a docker-save tar.

Usage:
    strip_image.py --input INPUT_TAR --output OUTPUT_TAR
                   [--strip-prefix PREFIX ...]
                   [--no-autodetect]

--strip-prefix may be repeated.  When given, the supplied prefixes replace
the built-in defaults.  Prefixes must not start with '/' or contain '..'.

With --autodetect, the image is pre-scanned to detect installed package
managers (apt, apk, pip, npm, dnf/yum, gem, Go, Cargo) and their cache paths
are added automatically on top of the active prefix set.

Pure Python, stdlib only.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile

# ── built-in defaults ────────────────────────────────────────────────────────

STRIP_PREFIXES = (
    'usr/share/doc/',
    'usr/share/man/',
    'usr/share/info/',
    'usr/share/locale/',
    'usr/share/i18n/',
    'var/cache/apt/',
    'var/lib/apt/lists/',
    'tmp/',
)

# ── package-manager auto-detection tables ────────────────────────────────────

# One marker path is enough to declare a PM present.
# Paths are normalised (no leading './' or '/').
_PM_MARKERS = {
    'apt':   ('var/lib/dpkg/status', 'usr/bin/apt-get', 'usr/bin/dpkg'),
    'apk':   ('sbin/apk', 'lib/apk/db/installed'),
    'pip':   ('usr/bin/pip3', 'usr/bin/pip', 'usr/local/bin/pip3',
               'usr/local/bin/pip'),
    'npm':   ('usr/bin/npm', 'usr/lib/node_modules/npm'),
    'dnf':   ('usr/bin/dnf', 'var/lib/rpm/Packages',
               'var/lib/rpm/rpmdb.sqlite'),
    'yum':   ('usr/bin/yum',),
    'gem':   ('usr/bin/gem',),
    'go':    ('usr/local/go/bin/go', 'usr/bin/go'),
    'cargo': ('usr/local/cargo/bin/cargo', 'root/.cargo/bin/cargo'),
}

# Extra prefixes added when the corresponding PM is detected.
_PM_EXTRA_PREFIXES = {
    'apt':   ('var/cache/apt/', 'var/lib/apt/lists/'),
    'apk':   ('var/cache/apk/', 'etc/apk/cache/'),
    'pip':   ('root/.cache/pip/', 'home/app/.cache/pip/'),
    'npm':   ('root/.npm/_cacache/', 'usr/lib/node_modules/.cache/',
               'home/node/.npm/_cacache/'),
    'dnf':   ('var/cache/dnf/', 'var/cache/yum/'),
    'yum':   ('var/cache/yum/',),
    'gem':   ('root/.gem/cache/', 'var/cache/rubygems/'),
    'go':    ('root/go/pkg/mod/cache/', 'home/go/pkg/mod/cache/'),
    'cargo': ('root/.cargo/registry/cache/',
               'usr/local/cargo/registry/cache/'),
}

# Matches usr/lib/python3.X/ and usr/local/lib/python3.X/ directory entries.
_PYTHON_LIB_RE = re.compile(
    r'^(usr/(?:local/)?lib/python3\.\d+)/'
)

# Sub-directories inside each Python lib dir that are safe to strip.
_PYTHON_STRIP_SUBDIRS = (
    'test/',
    'tests/',
    'unittest/',
    'turtledemo/',
    'idlelib/',
    'tkinter/',
    '__pycache__/',
)


# ── helpers ──────────────────────────────────────────────────────────────────

def validate_prefix(p):
    """Raise ValueError if p is unsafe as a strip prefix."""
    if p.startswith('/'):
        raise ValueError(f"strip prefix must not start with '/': {p!r}")
    if '..' in p.split('/'):
        raise ValueError(f"strip prefix must not contain '..': {p!r}")


def _norm(name):
    """Normalise a tar member name: strip leading './' and '/'."""
    normalized = name.removeprefix('./').lstrip('/')
    return '' if normalized == '.' else normalized


def should_strip(name, prefixes):
    """Return True if a tar member name matches any active prefix."""
    n = _norm(name)
    for prefix in prefixes:
        if n == prefix.rstrip('/') or n.startswith(prefix):
            return True
    return False


def _iter_layer_names(input_tar):
    """
    Yield normalised member names from every layer in an image tar.
    Silently skips layers that cannot be read.
    """
    try:
        with tarfile.open(input_tar, 'r') as img_tf:
            for member in img_tf.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if not (name == 'layer.tar' or name.endswith('/layer.tar') or
                        (name.endswith('.tar') and '/' in name)):
                    continue
                f = img_tf.extractfile(member)
                if f is None:
                    continue
                layer_bytes = f.read()
                try:
                    mode_r = 'r:gz' if layer_bytes[:2] == b'\x1f\x8b' else 'r:'
                    with tarfile.open(
                            fileobj=io.BytesIO(layer_bytes),
                            mode=mode_r) as layer_tf:
                        for lm in layer_tf.getmembers():
                            yield _norm(lm.name)
                except tarfile.TarError:
                    pass
    except tarfile.TarError as e:
        print(f"strip_image: warning: scan pass error: {e}", file=sys.stderr)


def autodetect_extra_prefixes(input_tar):
    """
    Pre-scan the image to detect installed package managers.
    Returns a (possibly empty) list of extra prefix strings to strip.
    """
    detected_pms = set()
    python_lib_dirs = set()

    for n in _iter_layer_names(input_tar):
        for pm, markers in _PM_MARKERS.items():
            if pm not in detected_pms:
                for marker in markers:
                    if n == marker or n.startswith(marker + '/'):
                        detected_pms.add(pm)
                        break
        m = _PYTHON_LIB_RE.match(n)
        if m:
            python_lib_dirs.add(m.group(1) + '/')

    if not detected_pms and not python_lib_dirs:
        return []

    extra = []
    seen = set()

    def _add(p):
        p = p if p.endswith('/') else p + '/'
        if p not in seen:
            seen.add(p)
            extra.append(p)

    for pm in sorted(detected_pms):
        for p in _PM_EXTRA_PREFIXES.get(pm, ()):
            _add(p)

    for pydir in sorted(python_lib_dirs):
        for sub in _PYTHON_STRIP_SUBDIRS:
            _add(pydir + sub)

    if detected_pms or python_lib_dirs:
        labels = sorted(detected_pms)
        if python_lib_dirs:
            labels.append('python(' + ', '.join(sorted(python_lib_dirs)) + ')')
        print(f"strip_image: autodetected: {', '.join(labels)}", file=sys.stderr)

    return extra


# ── layer stripping ──────────────────────────────────────────────────────────

def strip_layer(layer_bytes, prefixes):
    """
    Rewrite a gzip/raw layer tarball, omitting entries that match prefixes.
    Returns the rewritten bytes, or the original bytes on tar error.
    """
    src = io.BytesIO(layer_bytes)
    dst = io.BytesIO()
    try:
        mode_r = 'r:gz' if layer_bytes[:2] == b'\x1f\x8b' else 'r:'
        with tarfile.open(fileobj=src, mode=mode_r) as src_tf:
            mode_w = 'w:gz' if layer_bytes[:2] == b'\x1f\x8b' else 'w:'
            with tarfile.open(fileobj=dst, mode=mode_w) as dst_tf:
                for member in src_tf.getmembers():
                    if should_strip(member.name, prefixes):
                        continue
                    if member.isfile():
                        f = src_tf.extractfile(member)
                        if f is None:
                            continue
                        dst_tf.addfile(member, f)
                    else:
                        dst_tf.addfile(member)
    except tarfile.TarError as e:
        print(f"strip_image: warning: layer tar error: {e}", file=sys.stderr)
        return layer_bytes
    return dst.getvalue()


_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _is_oci_blob_path(name):
    parts = name.split('/')
    return len(parts) == 3 and parts[0] == 'blobs' and \
        parts[1] == 'sha256' and _SHA256_RE.fullmatch(parts[2]) is not None


def _config_name_for_digest(old_name, config_bytes):
    digest = _sha256(config_bytes)
    base = os.path.basename(old_name)
    if _is_oci_blob_path(old_name):
        return f'blobs/sha256/{digest}'
    if '/' not in old_name and base.endswith('.json') and \
            _SHA256_RE.fullmatch(base[:-5]):
        return f'{digest}.json'
    return old_name


def _layer_name_for_digest(old_name, layer_bytes):
    if _is_oci_blob_path(old_name):
        return f'blobs/sha256/{_sha256(layer_bytes)}'
    return old_name


def _layer_diff_id(layer_bytes):
    raw = gzip.decompress(layer_bytes) if layer_bytes[:2] == b'\x1f\x8b' \
        else layer_bytes
    return f'sha256:{_sha256(raw)}'


def _copy_member_info(member, name=None, size=None):
    info = tarfile.TarInfo(name=name or member.name)
    info.size = member.size if size is None else size
    info.mode = member.mode
    info.uid = member.uid
    info.gid = member.gid
    info.uname = member.uname
    info.gname = member.gname
    info.mtime = member.mtime
    info.type = member.type
    return info


# ── main entry point ─────────────────────────────────────────────────────────

def strip_image(input_tar, output_tar, prefixes=None, autodetect=False):
    # Base prefix set: user-supplied or built-in defaults
    base = tuple(prefixes) if prefixes else STRIP_PREFIXES
    base = tuple(p if p.endswith('/') else p + '/' for p in base)

    if autodetect:
        extra = autodetect_extra_prefixes(input_tar)
        seen = set(base)
        active = list(base)
        for p in extra:
            if p not in seen:
                seen.add(p)
                active.append(p)
        active = tuple(active)
    else:
        active = base

    stripped_total = 0

    with tarfile.open(input_tar, 'r') as src_tf:
        members = src_tf.getmembers()

        manifest_bytes = None
        for m in members:
            if m.name == 'manifest.json':
                f = src_tf.extractfile(m)
                manifest_bytes = f.read() if f else None
                break
        if manifest_bytes is None:
            print("strip_image: manifest.json not found", file=sys.stderr)
            sys.exit(1)

        manifest = json.loads(manifest_bytes)
        layer_names = []
        for entry in manifest:
            layer_names.extend(entry.get('Layers', []))

        layer_records = {}
        for layer_name in dict.fromkeys(layer_names):
            try:
                member = src_tf.getmember(layer_name)
            except KeyError:
                print(f"strip_image: layer not found: {layer_name}",
                      file=sys.stderr)
                sys.exit(1)
            f = src_tf.extractfile(member)
            if f is None:
                print(f"strip_image: cannot read layer: {layer_name}",
                      file=sys.stderr)
                sys.exit(1)
            original = f.read()
            stripped = strip_layer(original, active)
            stripped_total += len(original) - len(stripped)
            layer_records[layer_name] = {
                'member': member,
                'bytes': stripped,
                'name': _layer_name_for_digest(layer_name, stripped),
                'diff_id': _layer_diff_id(stripped),
            }

        config_records = {}
        rewritten_manifest = []
        for entry in manifest:
            new_entry = dict(entry)
            old_layers = entry.get('Layers', [])
            new_layers = [layer_records[name]['name'] for name in old_layers]
            new_entry['Layers'] = new_layers

            config_name = entry.get('Config')
            if not config_name:
                print("strip_image: manifest entry missing Config",
                      file=sys.stderr)
                sys.exit(1)
            try:
                config_member = src_tf.getmember(config_name)
            except KeyError:
                print(f"strip_image: config not found: {config_name}",
                      file=sys.stderr)
                sys.exit(1)
            config_f = src_tf.extractfile(config_member)
            if config_f is None:
                print(f"strip_image: cannot read config: {config_name}",
                      file=sys.stderr)
                sys.exit(1)
            config = json.loads(config_f.read())
            rootfs = config.setdefault('rootfs', {})
            rootfs['type'] = rootfs.get('type', 'layers')
            rootfs['diff_ids'] = [
                layer_records[name]['diff_id'] for name in old_layers
            ]
            config_bytes = json.dumps(
                config, separators=(',', ':')).encode()
            new_config_name = _config_name_for_digest(config_name,
                                                      config_bytes)
            config_records[config_name] = {
                'member': config_member,
                'bytes': config_bytes,
                'name': new_config_name,
            }
            new_entry['Config'] = new_config_name
            rewritten_manifest.append(new_entry)

        rewritten_manifest_bytes = json.dumps(
            rewritten_manifest, separators=(',', ':')).encode()
        layer_name_set = set(layer_records)
        config_name_set = set(config_records)
        written_names = set()

        with tarfile.open(output_tar, 'w') as out_tf:
            for member in members:
                f = src_tf.extractfile(member) if member.isfile() else None

                if member.name in layer_name_set:
                    rec = layer_records[member.name]
                    if rec['name'] in written_names:
                        continue
                    info = _copy_member_info(
                        rec['member'], name=rec['name'],
                        size=len(rec['bytes']))
                    out_tf.addfile(info, io.BytesIO(rec['bytes']))
                    written_names.add(rec['name'])
                elif member.name in config_name_set:
                    rec = config_records[member.name]
                    if rec['name'] in written_names:
                        continue
                    info = _copy_member_info(
                        rec['member'], name=rec['name'],
                        size=len(rec['bytes']))
                    out_tf.addfile(info, io.BytesIO(rec['bytes']))
                    written_names.add(rec['name'])
                elif member.name == 'manifest.json':
                    info = tarfile.TarInfo(name='manifest.json')
                    info.size = len(rewritten_manifest_bytes)
                    info.mode = member.mode
                    info.mtime = member.mtime
                    out_tf.addfile(info, io.BytesIO(rewritten_manifest_bytes))
                elif f is not None:
                    data = f.read()
                    if member.name in written_names:
                        continue
                    info = _copy_member_info(member, size=len(data))
                    out_tf.addfile(info, io.BytesIO(data))
                    written_names.add(member.name)
                else:
                    if member.name not in written_names:
                        out_tf.addfile(member)
                        written_names.add(member.name)

    print(f"strip_image: stripped ~{stripped_total // 1024} KiB")


def main():
    parser = argparse.ArgumentParser(
        description='Strip docs/man/locale/cache from a docker-save OCI tar',
    )
    parser.add_argument('--input', required=True, help='Input OCI tar')
    parser.add_argument('--output', required=True, help='Output OCI tar')
    parser.add_argument(
        '--strip-prefix', metavar='PREFIX', action='append', dest='prefixes',
        help='Path prefix to strip (repeatable); replaces built-in defaults',
    )
    parser.add_argument(
        '--autodetect', action='store_true',
        help='Scan layers to detect package managers and add their cache paths',
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"strip_image: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if args.prefixes:
        for p in args.prefixes:
            try:
                validate_prefix(p)
            except ValueError as e:
                print(f"strip_image: {e}", file=sys.stderr)
                sys.exit(1)

    strip_image(args.input, args.output,
                prefixes=args.prefixes,
                autodetect=args.autodetect)


if __name__ == '__main__':
    main()
