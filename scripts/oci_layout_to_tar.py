#!/usr/bin/env python3
"""
oci_layout_to_tar.py — convert an OCI image layout directory to a docker-save tar.

Usage:
    oci_layout_to_tar.py --oci-dir DIR --output TAR [--tag IMAGE:TAG]

Reads an OCI image layout directory (produced by skopeo, crane, buildah, etc.)
and writes a docker-save-format tar that can be passed to build_polyglot.py.

OCI image layout spec:
  DIR/oci-layout          JSON: {"imageLayoutVersion": "1.0.0"}
  DIR/index.json          JSON: index manifest (list of manifests)
  DIR/blobs/sha256/<hex>  Content-addressed blobs (manifests, configs, layers)

Docker-save format:
  <config_short>.json     Image config JSON
  <layer_dir>/layer.tar   Each layer blob (copied as-is)
  manifest.json           [{Config, RepoTags, Layers}]

Pure Python, stdlib only.
"""

import argparse
import io
import json
import os
import sys
import tarfile


def read_blob(oci_dir, descriptor):
    """Read a blob from blobs/<alg>/<hex> given a descriptor dict."""
    digest = descriptor['digest']   # e.g. "sha256:abcdef..."
    alg, hex_val = digest.split(':', 1)
    blob_path = os.path.join(oci_dir, 'blobs', alg, hex_val)
    if not os.path.isfile(blob_path):
        print(f"oci_layout_to_tar: blob not found: {blob_path}", file=sys.stderr)
        sys.exit(1)
    with open(blob_path, 'rb') as f:
        return f.read()


def read_blob_path(oci_dir, descriptor):
    """Return the filesystem path of a blob."""
    digest = descriptor['digest']
    alg, hex_val = digest.split(':', 1)
    return os.path.join(oci_dir, 'blobs', alg, hex_val)


def convert(oci_dir, output_tar, tag=None):
    # Validate OCI layout
    layout_file = os.path.join(oci_dir, 'oci-layout')
    if not os.path.isfile(layout_file):
        print(f"oci_layout_to_tar: not an OCI image layout (missing oci-layout): {oci_dir}",
              file=sys.stderr)
        sys.exit(1)

    index_path = os.path.join(oci_dir, 'index.json')
    if not os.path.isfile(index_path):
        print(f"oci_layout_to_tar: index.json not found in {oci_dir}", file=sys.stderr)
        sys.exit(1)

    with open(index_path) as f:
        index = json.load(f)

    manifests = index.get('manifests', [])
    if not manifests:
        print("oci_layout_to_tar: index.json has no manifests", file=sys.stderr)
        sys.exit(1)

    # Pick the first manifest (or match by tag annotation if available)
    manifest_desc = manifests[0]
    if tag and len(manifests) > 1:
        for m in manifests:
            annotations = m.get('annotations', {})
            if annotations.get('org.opencontainers.image.ref.name') == tag:
                manifest_desc = m
                break

    # Read the manifest
    manifest_bytes = read_blob(oci_dir, manifest_desc)
    manifest = json.loads(manifest_bytes)

    config_desc  = manifest['config']
    layer_descs  = manifest.get('layers', [])

    config_bytes = read_blob(oci_dir, config_desc)

    # Build docker-save compatible names
    config_digest_short = config_desc['digest'].split(':', 1)[1][:64]
    config_name = f'{config_digest_short}.json'

    # Determine repo tag
    repo_tags = []
    if tag:
        repo_tags = [tag]
    else:
        # Try annotation
        ann = manifest_desc.get('annotations', {})
        ref = ann.get('org.opencontainers.image.ref.name')
        if ref:
            repo_tags = [ref]

    # Build layer name list for manifest.json
    layer_names = []
    for i, layer_desc in enumerate(layer_descs):
        layer_hex = layer_desc['digest'].split(':', 1)[1]
        layer_names.append(f'{layer_hex}/layer.tar')

    docker_manifest = [{
        'Config':   config_name,
        'RepoTags': repo_tags if repo_tags else None,
        'Layers':   layer_names,
    }]
    docker_manifest_bytes = json.dumps(docker_manifest).encode()

    with tarfile.open(output_tar, 'w') as out_tf:
        # Write config
        info = tarfile.TarInfo(name=config_name)
        info.size = len(config_bytes)
        info.mode = 0o644
        out_tf.addfile(info, io.BytesIO(config_bytes))

        # Write each layer
        for layer_desc, layer_name in zip(layer_descs, layer_names):
            blob_path = read_blob_path(oci_dir, layer_desc)
            with open(blob_path, 'rb') as f:
                layer_data = f.read()
            info = tarfile.TarInfo(name=layer_name)
            info.size = len(layer_data)
            info.mode = 0o644
            out_tf.addfile(info, io.BytesIO(layer_data))

        # Write manifest.json
        info = tarfile.TarInfo(name='manifest.json')
        info.size = len(docker_manifest_bytes)
        info.mode = 0o644
        out_tf.addfile(info, io.BytesIO(docker_manifest_bytes))

    print(f"oci_layout_to_tar: wrote {output_tar} "
          f"({len(layer_descs)} layer(s), config {config_digest_short[:12]})")


def main():
    parser = argparse.ArgumentParser(
        description='Convert OCI image layout directory to docker-save tar',
    )
    parser.add_argument('--oci-dir', required=True,
                        help='OCI image layout directory')
    parser.add_argument('--output', required=True,
                        help='Output docker-save tar path')
    parser.add_argument('--tag', default=None,
                        help='Image tag to select (if index has multiple manifests)')
    args = parser.parse_args()

    if not os.path.isdir(args.oci_dir):
        print(f"oci_layout_to_tar: directory not found: {args.oci_dir}", file=sys.stderr)
        sys.exit(1)

    convert(args.oci_dir, args.output, tag=args.tag)


if __name__ == '__main__':
    main()
