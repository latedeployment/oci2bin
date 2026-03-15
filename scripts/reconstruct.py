#!/usr/bin/env python3
"""
reconstruct.py — Rebuild an oci2bin polyglot from a Docker image that was
previously built with --embed-loader-layer or --embed-loader-labels.

Usage:
    oci2bin reconstruct <image-or-file> [--output PATH] [--no-strip]

<image-or-file> can be:
  - A Docker image name (e.g. alpine:latest) — docker save is called
  - A path to an existing .tar, .img, or any file — used directly

The script reads oci2bin.loader.* labels from the image config to locate and
extract the embedded loader binary, then calls build_polyglot to rebuild the
polyglot.

--no-strip   Keep the loader layer / labels in the rebuilt polyglot's OCI data.
             By default the loader embedding is stripped so the result is
             identical to a fresh oci2bin build.
"""

import argparse
import base64
import hashlib
import io
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


# ── load build_polyglot module ────────────────────────────────────────────────

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    'build_polyglot', ROOT / 'scripts' / 'build_polyglot.py'
)
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)


# ── OCI tar helpers ───────────────────────────────────────────────────────────

def _read_oci_tar(tar_bytes):
    """Return (manifest_list, config_path, config_dict, all_member_names)."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:*') as tf:
        manifest = json.loads(tf.extractfile('manifest.json').read())
        config_path = manifest[0]['Config']
        config = json.loads(tf.extractfile(config_path).read())
        names = tf.getnames()
    return manifest, config_path, config, names


def _get_labels(config):
    return (config.get('config') or {}).get('Labels') or {}


def _extract_file_from_layer(tar_bytes, layer_path, file_path):
    """
    Extract file_path from the layer blob at layer_path inside tar_bytes.
    Returns the file bytes or raises KeyError.
    """
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:*') as outer:
        layer_data = outer.extractfile(layer_path).read()

    with tarfile.open(fileobj=io.BytesIO(layer_data), mode='r:gz') as lt:
        # Try both with and without leading "./"
        for candidate in (file_path, './' + file_path, file_path.lstrip('./')):
            try:
                return lt.extractfile(candidate).read()
            except KeyError:
                pass
    raise KeyError(f'{file_path!r} not found in layer {layer_path!r}')


# ── extraction strategies ─────────────────────────────────────────────────────

def extract_loader_from_layer(tar_bytes, labels):
    """
    Approach 2.1: pull the loader binary from the embedded OCI layer.
    Returns (loader_bytes, arch).
    """
    loader_path = labels.get('oci2bin.loader.path', '.oci2bin/loader')
    arch = labels.get('oci2bin.loader.arch', 'x86_64')
    expected_sha = labels.get('oci2bin.loader.sha256', '')

    manifest, _, _, _ = _read_oci_tar(tar_bytes)
    layers = manifest[0]['Layers']
    if not layers:
        raise ValueError('Image has no layers')

    # The loader layer is the last one (appended by embed_loader_as_layer)
    layer_path = layers[-1]
    try:
        loader_bytes = _extract_file_from_layer(tar_bytes, layer_path,
                                                loader_path)
    except KeyError as exc:
        raise ValueError(
            f'Loader file {loader_path!r} not found in layer {layer_path!r}'
        ) from exc

    if expected_sha:
        actual = hashlib.sha256(loader_bytes).hexdigest()
        if actual != expected_sha:
            raise ValueError(
                f'Loader sha256 mismatch: expected {expected_sha}, got {actual}')

    return loader_bytes, arch


def extract_loader_from_labels(tar_bytes, labels):
    """
    Approach 2.2: reassemble loader from chunked base64 labels.
    Returns (loader_bytes, arch).
    """
    arch = labels.get('oci2bin.loader.arch', 'x86_64')
    expected_sha = labels.get('oci2bin.loader.sha256', '')
    n_chunks_str = labels.get('oci2bin.loader.chunks', '')

    if not n_chunks_str:
        raise ValueError('oci2bin.loader.chunks label missing')

    n = int(n_chunks_str)
    parts = []
    for i in range(n):
        key = f'oci2bin.loader.{i}'
        if key not in labels:
            raise ValueError(f'Missing label {key!r} (expected {n} chunks)')
        parts.append(base64.b64decode(labels[key]))

    loader_bytes = b''.join(parts)

    if expected_sha:
        actual = hashlib.sha256(loader_bytes).hexdigest()
        if actual != expected_sha:
            raise ValueError(
                f'Loader sha256 mismatch: expected {expected_sha}, got {actual}')

    return loader_bytes, arch


# ── strip helpers ─────────────────────────────────────────────────────────────

def strip_loader_layer(tar_bytes):
    """Remove the last OCI layer (the loader layer) from the image tar."""
    manifest, config_path, config, _ = _read_oci_tar(tar_bytes)
    layers = manifest[0]['Layers']
    if not layers:
        return tar_bytes

    loader_layer_path = layers[-1]
    manifest[0]['Layers'] = layers[:-1]

    diff_ids = (config.get('rootfs') or {}).get('diff_ids', [])
    if diff_ids:
        config.setdefault('rootfs', {})['diff_ids'] = diff_ids[:-1]

    # Remove oci2bin labels
    labels = (config.get('config') or {}).get('Labels') or {}
    for key in list(labels.keys()):
        if key.startswith('oci2bin.loader.'):
            del labels[key]

    new_config_raw = json.dumps(config, separators=(',', ':')).encode()
    new_config_sha = hashlib.sha256(new_config_raw).hexdigest()
    new_config_path = f'blobs/sha256/{new_config_sha}'
    manifest[0]['Config'] = new_config_path

    new_manifest_raw = json.dumps(manifest, separators=(',', ':')).encode()

    new_config_info = bp._make_tar_info(new_config_path, len(new_config_raw))
    new_manifest_info = bp._make_tar_info('manifest.json', len(new_manifest_raw))

    replacements = {
        config_path: (new_config_info, new_config_raw),
        'manifest.json': (new_manifest_info, new_manifest_raw),
        loader_layer_path: None,   # signals deletion
    }

    # Rebuild tar, skipping the loader layer entry
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as out_tf:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:*') as in_tf:
            for member in in_tf.getmembers():
                if member.name in replacements:
                    val = replacements[member.name]
                    if val is None:
                        continue   # delete this entry
                    new_info, new_data = val
                    out_tf.addfile(new_info, io.BytesIO(new_data))
                else:
                    fobj = in_tf.extractfile(member)
                    out_tf.addfile(member, fobj)
    return buf.getvalue()


def strip_loader_labels(tar_bytes):
    """Remove oci2bin.loader.* labels from the image config (label approach)."""
    manifest, config_path, config, _ = _read_oci_tar(tar_bytes)

    labels = (config.get('config') or {}).get('Labels') or {}
    for key in list(labels.keys()):
        if key.startswith('oci2bin.loader.'):
            del labels[key]

    new_oci, _ = bp._rebuild_oci_with_new_config(
        tar_bytes, manifest, config_path, config)
    return new_oci


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Reconstruct an oci2bin polyglot from an image that '
                    'was built with --embed-loader-layer or --embed-loader-labels',
    )
    parser.add_argument('source',
                        help='Docker image name or path to an OCI tar / .img file')
    parser.add_argument('--output', default=None,
                        help='Output file path (default: <source>_reconstructed)')
    parser.add_argument('--no-strip', action='store_true', default=False,
                        help='Keep the loader embedding in the rebuilt OCI data '
                             '(by default it is stripped for a clean result)')
    args = parser.parse_args()

    # ── resolve OCI tar ───────────────────────────────────────────────────────

    tmp_tar = None
    if os.path.exists(args.source):
        tar_path = args.source
        print(f'oci2bin reconstruct: using {tar_path}', file=sys.stderr)
    else:
        # Treat as Docker image name
        tmp_tar = tempfile.NamedTemporaryFile(suffix='.tar', delete=False)
        tmp_tar.close()
        tar_path = tmp_tar.name
        print(f'oci2bin reconstruct: running docker save {args.source!r} ...',
              file=sys.stderr)
        r = subprocess.run(
            ['docker', 'save', '-o', tar_path, args.source],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f'docker save failed:\n{r.stderr}', file=sys.stderr)
            sys.exit(1)

    try:
        with open(tar_path, 'rb') as f:
            tar_bytes = f.read()

        # ── detect embedding strategy ─────────────────────────────────────────

        manifest, config_path, config, _ = _read_oci_tar(tar_bytes)
        labels = _get_labels(config)

        if 'oci2bin.loader.path' in labels:
            strategy = 'layer'
        elif 'oci2bin.loader.chunks' in labels:
            strategy = 'labels'
        else:
            print('oci2bin reconstruct: no oci2bin.loader.* labels found in '
                  'image config.\nBuild with --embed-loader-layer or '
                  '--embed-loader-labels to enable reconstruction.',
                  file=sys.stderr)
            sys.exit(1)

        # ── extract loader ────────────────────────────────────────────────────

        if strategy == 'layer':
            print('oci2bin reconstruct: extracting loader from OCI layer ...',
                  file=sys.stderr)
            loader_bytes, arch = extract_loader_from_layer(tar_bytes, labels)
        else:
            print('oci2bin reconstruct: reassembling loader from labels ...',
                  file=sys.stderr)
            loader_bytes, arch = extract_loader_from_labels(tar_bytes, labels)

        print(f'oci2bin reconstruct: loader extracted '
              f'({len(loader_bytes)} bytes, arch={arch})', file=sys.stderr)

        # ── optionally strip embedding ────────────────────────────────────────

        if not args.no_strip:
            if strategy == 'layer':
                tar_bytes = strip_loader_layer(tar_bytes)
            else:
                tar_bytes = strip_loader_labels(tar_bytes)

        # ── write temp files for build_polyglot ───────────────────────────────

        with tempfile.NamedTemporaryFile(
                suffix='.bin', delete=False) as lf:
            lf.write(loader_bytes)
            loader_tmp = lf.name

        with tempfile.NamedTemporaryFile(
                suffix='.tar', delete=False) as tf2:
            tf2.write(tar_bytes)
            clean_tar_tmp = tf2.name

        # ── output path ───────────────────────────────────────────────────────

        if args.output:
            out_path = args.output
        else:
            src_stem = os.path.splitext(os.path.basename(args.source))[0]
            out_path = f'{src_stem}_reconstructed'

        # ── rebuild polyglot ──────────────────────────────────────────────────

        image_name = (manifest[0].get('RepoTags') or ['unknown'])[0]
        print(f'oci2bin reconstruct: rebuilding polyglot → {out_path}',
              file=sys.stderr)

        bp.build_polyglot(
            loader_path=loader_tmp,
            image_name=image_name,
            output_path=out_path,
            tar_path=clean_tar_tmp,
        )

    finally:
        if tmp_tar:
            try:
                os.unlink(tmp_tar.name)
            except OSError:
                pass
        for p in ('loader_tmp', 'clean_tar_tmp'):
            path = locals().get(p)
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


if __name__ == '__main__':
    main()
