#!/usr/bin/env python3
"""
merge_layers.py — merge additional OCI image layers onto a base image tar.

Usage:
    merge_layers.py --base BASE_TAR --layer LAYER_TAR [--layer ...] --output OUT_TAR

Reads manifest.json from each tar to get layer list.
Writes a new tar containing:
  - all layers from base
  - all layers from each overlay image in order
  - a merged manifest.json
  - a merged config (base config with Cmd/Entrypoint/Env from the last --layer
    image if they are non-null)

Pure Python, stdlib only.
"""

import argparse
import io
import json
import os
import sys
import tarfile


def read_tar_member(tf, name):
    """Read and return the bytes of a named member from a TarFile."""
    try:
        member = tf.getmember(name)
    except KeyError:
        return None
    f = tf.extractfile(member)
    if f is None:
        return None
    return f.read()


def get_manifest(tf):
    """Parse manifest.json from a docker-save tar and return the first entry."""
    data = read_tar_member(tf, 'manifest.json')
    if data is None:
        print("merge_layers: manifest.json not found in tar", file=sys.stderr)
        sys.exit(1)
    manifest = json.loads(data)
    if not manifest:
        print("merge_layers: empty manifest.json", file=sys.stderr)
        sys.exit(1)
    return manifest[0]


def get_config(tf, config_name):
    """Parse the image config JSON from a docker-save tar."""
    data = read_tar_member(tf, config_name)
    if data is None:
        print(f"merge_layers: config {config_name} not found", file=sys.stderr)
        sys.exit(1)
    return json.loads(data)


def copy_layers(src_tf, layer_names, out_tf, seen_layers):
    """Copy layer tarballs from src_tf to out_tf, skipping already-copied ones."""
    for layer_name in layer_names:
        if layer_name in seen_layers:
            continue
        seen_layers.add(layer_name)
        try:
            member = src_tf.getmember(layer_name)
        except KeyError:
            print(f"merge_layers: layer {layer_name} not found in tar",
                  file=sys.stderr)
            sys.exit(1)
        f = src_tf.extractfile(member)
        if f is None:
            print(f"merge_layers: cannot read layer {layer_name}",
                  file=sys.stderr)
            sys.exit(1)
        data = f.read()
        info = tarfile.TarInfo(name=layer_name)
        info.size = len(data)
        info.mode = 0o644
        out_tf.addfile(info, io.BytesIO(data))


def merge(base_tar, layer_tars, output_tar):
    with tarfile.open(base_tar, 'r') as base_tf:
        base_manifest = get_manifest(base_tf)
        base_config_name = base_manifest['Config']
        base_config = get_config(base_tf, base_config_name)
        base_layers = base_manifest['Layers']

        # Collect overlay layer info
        overlay_configs = []
        overlay_layers_list = []
        for lt in layer_tars:
            with tarfile.open(lt, 'r') as overlay_tf:
                ov_manifest = get_manifest(overlay_tf)
                ov_config = get_config(overlay_tf, ov_manifest['Config'])
                overlay_configs.append(ov_config)
                overlay_layers_list.append(ov_manifest['Layers'])

        # Merged layer list: base layers first, then each overlay's layers
        all_layers = list(base_layers)
        for ov_layers in overlay_layers_list:
            for layer in ov_layers:
                if layer not in all_layers:
                    all_layers.append(layer)

        # Merged config: start from base, override Cmd/Entrypoint/Env from last overlay
        merged_config = base_config
        last_overlay_config = overlay_configs[-1] if overlay_configs else None
        if last_overlay_config:
            container_cfg = last_overlay_config.get('config', {})
            base_cfg = merged_config.setdefault('config', {})
            for key in ('Cmd', 'Entrypoint', 'Env'):
                val = container_cfg.get(key)
                if val is not None:
                    base_cfg[key] = val

        merged_config_json = json.dumps(merged_config).encode()
        merged_config_name = base_config_name  # reuse same filename

        # Merged manifest
        merged_manifest = [{
            'Config': merged_config_name,
            'RepoTags': base_manifest.get('RepoTags', []),
            'Layers': all_layers,
        }]
        merged_manifest_json = json.dumps(merged_manifest).encode()

        seen_layers = set()
        with tarfile.open(output_tar, 'w') as out_tf:
            # Write config
            info = tarfile.TarInfo(name=merged_config_name)
            info.size = len(merged_config_json)
            info.mode = 0o644
            out_tf.addfile(info, io.BytesIO(merged_config_json))

            # Copy base layers
            copy_layers(base_tf, base_layers, out_tf, seen_layers)

            # Copy overlay layers
            for lt, ov_layers in zip(layer_tars, overlay_layers_list):
                with tarfile.open(lt, 'r') as overlay_tf:
                    copy_layers(overlay_tf, ov_layers, out_tf, seen_layers)

            # Write merged manifest.json last
            info = tarfile.TarInfo(name='manifest.json')
            info.size = len(merged_manifest_json)
            info.mode = 0o644
            out_tf.addfile(info, io.BytesIO(merged_manifest_json))

    print(f"merge_layers: wrote {output_tar} with {len(all_layers)} layer(s)")


def main():
    parser = argparse.ArgumentParser(
        description='Merge OCI image layers from multiple docker-save tars',
    )
    parser.add_argument('--base', required=True,
                        help='Base image tar (docker save output)')
    parser.add_argument('--layer', action='append', default=[],
                        metavar='LAYER_TAR',
                        help='Additional layer tar to merge on top (repeatable)')
    parser.add_argument('--output', required=True,
                        help='Output merged tar path')
    args = parser.parse_args()

    if not args.layer:
        print("merge_layers: at least one --layer is required", file=sys.stderr)
        sys.exit(1)

    for path in [args.base] + args.layer:
        if not os.path.isfile(path):
            print(f"merge_layers: file not found: {path}", file=sys.stderr)
            sys.exit(1)

    merge(args.base, args.layer, args.output)


if __name__ == '__main__':
    main()
