#!/usr/bin/env python3
"""
squash_layers.py — merge all OCI image layers into a single squashed layer.

Usage:
    squash_layers.py --input IMAGE.tar --output SQUASHED.tar [--compress gzip|zstd]

Merges all layers from a docker-save tar into one, processing whiteout entries.
Compresses the squashed layer with gzip (default) or zstd.

Pure Python, stdlib only (zstd requires the zstd CLI binary).
"""

import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile

_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
_XZ_MAGIC = b'\xfd7zXZ\x00'


def _zstd_decompress(data):
    """Decompress zstd with the stdlib module (3.14+) or the zstd CLI."""
    try:
        from compression import zstd as _zstd  # Python 3.14+
    except ImportError:
        _zstd = None
    if _zstd is not None:
        try:
            return _zstd.decompress(data)
        except _zstd.ZstdError as e:
            raise ValueError(f"zstd layer: {e}") from e
    result = subprocess.run(['zstd', '-dc', '-q', '-'], input=data,
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise ValueError("zstd layer: zstd CLI not available or failed")
    return result.stdout


def decompress_layer(layer_data):
    """Return the uncompressed tar bytes of a gzip/zstd/xz/plain layer."""
    if layer_data[:2] == b'\x1f\x8b':
        return gzip.decompress(layer_data)
    if layer_data[:4] == _ZSTD_MAGIC:
        return _zstd_decompress(layer_data)
    if layer_data[:6] == _XZ_MAGIC:
        return lzma.decompress(layer_data)
    return layer_data


def open_layer(layer_data):
    """Open a layer tarball, handling gzip, zstd and xz compression."""
    return tarfile.open(fileobj=io.BytesIO(decompress_layer(layer_data)),
                        mode='r:')


def _normalise_member_name(name):
    while name.startswith('./') or name.startswith('/'):
        name = name[2:] if name.startswith('./') else name[1:]
    return name.rstrip('/')


def _remove_tree(file_dict, path):
    """Drop `path` and everything below it ('' = the whole tree)."""
    if not path:
        file_dict.clear()
        return
    file_dict.pop(path, None)
    prefix = path + '/'
    for k in [k for k in file_dict if k.startswith(prefix)]:
        del file_dict[k]


def _remove_children(file_dict, path):
    """Drop everything below `path` but keep `path` itself (opaque dir)."""
    prefix = path + '/' if path else ''
    for k in [k for k in file_dict if k.startswith(prefix) and k != path]:
        del file_dict[k]


def squash_oci_tar(input_path, output_path, compress='gzip'):
    """
    Read input docker-save tar, merge all layers into one squashed layer,
    write output docker-save tar.
    """
    with open(input_path, 'rb') as f:
        outer_data = f.read()

    try:
        outer_tf = tarfile.open(fileobj=io.BytesIO(outer_data), mode='r')
    except tarfile.TarError as e:
        print(f"squash: tar error: {e}", file=sys.stderr)
        sys.exit(1)

    # Read manifest.json
    try:
        manifest_member = outer_tf.getmember('manifest.json')
    except KeyError:
        print("squash: manifest.json not found", file=sys.stderr)
        sys.exit(1)
    manifest = json.loads(outer_tf.extractfile(manifest_member).read())

    # Read config
    config_name = manifest[0].get('Config', '')
    if not config_name:
        print("squash: no Config in manifest", file=sys.stderr)
        sys.exit(1)
    try:
        config_member = outer_tf.getmember(config_name)
    except KeyError:
        print(f"squash: config not found: {config_name}", file=sys.stderr)
        sys.exit(1)
    config = json.loads(outer_tf.extractfile(config_member).read())

    layers_names = manifest[0].get('Layers', [])

    # Merge all layers into a single in-memory filesystem dict
    # file_dict: path -> (tarinfo, data_bytes_or_None)
    #
    # Whiteouts in a layer apply to the layers BELOW it, so each layer is
    # handled in two passes: first its whiteouts are applied to what has been
    # merged so far, then its own entries are added.  Applying them in tar
    # order let an opaque marker that sorts after its siblings delete the
    # layer's own new files.  An opaque dir (.wh..wh..opq) clears the
    # directory's children but keeps the directory entry — dropping the entry
    # lost its mode (e.g. /tmp 1777).  A plain .wh.X removes X and, if X was a
    # directory, everything under it.
    file_dict = {}

    for layer_name in layers_names:
        try:
            layer_member = outer_tf.getmember(layer_name)
        except KeyError:
            print(f"squash: layer not found: {layer_name}", file=sys.stderr)
            sys.exit(1)
        layer_data = outer_tf.extractfile(layer_member).read()

        try:
            layer_tf = open_layer(layer_data)
            members = layer_tf.getmembers()
        except (tarfile.TarError, ValueError, OSError, lzma.LZMAError) as e:
            # Squashing without a layer would silently produce a different
            # image; refuse instead.
            print(f"squash: cannot read layer {layer_name}: {e}",
                  file=sys.stderr)
            sys.exit(1)

        entries = []
        for m in members:
            name = _normalise_member_name(m.name)
            if not name:
                continue
            # Reject path traversal components
            if '..' in name.split('/'):
                continue
            basename = os.path.basename(name)
            parent = os.path.dirname(name)
            if basename == '.wh..wh..opq':
                _remove_children(file_dict, parent)
            elif basename.startswith('.wh.'):
                _remove_tree(file_dict,
                             os.path.join(parent, basename[4:]).lstrip('/'))
            else:
                entries.append((name, m))

        for name, m in entries:
            # A non-directory replacing a directory hides its subtree.
            prev = file_dict.get(name)
            if prev is not None and prev[0].isdir() and not m.isdir():
                _remove_tree(file_dict, name)
            # Read data for regular files
            data = None
            if m.isfile():
                try:
                    f = layer_tf.extractfile(m)
                    data = f.read() if f else b''
                except (tarfile.TarError, OSError) as e:
                    print(f"squash: failed to read {name!r} "
                          f"in {layer_name}: {e}", file=sys.stderr)
                    sys.exit(1)
            file_dict[name] = (m, data)

        layer_tf.close()

    outer_tf.close()

    # Build squashed layer tar in memory
    squashed_buf = io.BytesIO()
    with tarfile.open(fileobj=squashed_buf, mode='w:') as sq_tf:
        for name, (m, data) in sorted(file_dict.items()):
            new_m = tarfile.TarInfo(name=name)
            new_m.mode  = m.mode
            new_m.uid   = 0
            new_m.gid   = 0
            new_m.uname = ''
            new_m.gname = ''
            new_m.mtime = m.mtime
            new_m.type  = m.type

            if m.isdir():
                new_m.type = tarfile.DIRTYPE
                sq_tf.addfile(new_m)
            elif m.isfile():
                new_m.size = len(data) if data else 0
                sq_tf.addfile(new_m, io.BytesIO(data or b''))
            elif m.issym():
                new_m.type     = tarfile.SYMTYPE
                new_m.linkname = m.linkname
                sq_tf.addfile(new_m)
            elif m.islnk():
                new_m.type     = tarfile.LNKTYPE
                new_m.linkname = m.linkname
                sq_tf.addfile(new_m)

    squashed_raw = squashed_buf.getvalue()

    # Compress the squashed layer
    if compress == 'zstd':
        # Use zstd binary (streaming)
        result = subprocess.run(
            ['zstd', '-q', '-'],
            input=squashed_raw,
            capture_output=True,
        )
        if result.returncode != 0:
            print("squash: zstd compression failed", file=sys.stderr)
            sys.exit(1)
        squashed_compressed = result.stdout
        layer_ext = 'tar.zst'
    else:
        squashed_compressed = gzip.compress(squashed_raw, compresslevel=6)
        layer_ext = 'tar.gz'

    # Compute diff_id (uncompressed layer sha256)
    diff_id = 'sha256:' + hashlib.sha256(squashed_raw).hexdigest()
    layer_sha256 = hashlib.sha256(squashed_compressed).hexdigest()
    layer_name = f"squashed/{layer_sha256[:12]}/layer.{layer_ext}"

    # Update config: replace all layers with the squashed one
    config['rootfs']['diff_ids'] = [diff_id]
    # Remove history to keep things clean
    config.pop('history', None)

    config_bytes  = json.dumps(config).encode()
    config_sha256 = hashlib.sha256(config_bytes).hexdigest()
    new_config_name = f"{config_sha256}.json"

    # Update manifest
    tags = manifest[0].get('RepoTags', [])
    new_manifest = [{
        'Config': new_config_name,
        'RepoTags': tags,
        'Layers': [layer_name],
    }]

    # Write output tar
    with tarfile.open(output_path, 'w:') as out_tf:
        # manifest.json
        manifest_bytes = json.dumps(new_manifest).encode()
        mi = tarfile.TarInfo('manifest.json')
        mi.size = len(manifest_bytes)
        out_tf.addfile(mi, io.BytesIO(manifest_bytes))

        # config
        ci = tarfile.TarInfo(new_config_name)
        ci.size = len(config_bytes)
        out_tf.addfile(ci, io.BytesIO(config_bytes))

        # squashed layer (need dir entry too)
        layer_dir = layer_name.rsplit('/', 1)[0]
        di = tarfile.TarInfo(layer_dir)
        di.type = tarfile.DIRTYPE
        di.mode = 0o755
        out_tf.addfile(di)

        li = tarfile.TarInfo(layer_name)
        li.size = len(squashed_compressed)
        out_tf.addfile(li, io.BytesIO(squashed_compressed))

    orig_size = os.path.getsize(input_path)
    new_size  = os.path.getsize(output_path)
    print(f"squash: {len(file_dict)} files, "
          f"{orig_size // (1024 * 1024)} MB → {new_size // (1024 * 1024)} MB",
          file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Squash OCI image layers into one')
    parser.add_argument('--input',    required=True, help='Input docker-save tar')
    parser.add_argument('--output',   required=True, help='Output docker-save tar')
    parser.add_argument('--compress', choices=['gzip', 'zstd'], default='gzip',
                        help='Compression format (default: gzip)')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"squash: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    squash_oci_tar(args.input, args.output, args.compress)


if __name__ == '__main__':
    main()
