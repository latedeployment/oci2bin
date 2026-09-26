#!/usr/bin/env python3
"""
oci_tar.py — keep a docker-save / OCI-layout tar internally consistent.

Every build-side transform that rewrites a blob (re-gzipping layers for
--reproducible, a new config for --label / --entrypoint / --cmd, an extra
layer for --add-file or --embed-loader-layer, ...) used to update
manifest.json only.  The content-addressed names under blobs/sha256/ then no
longer matched their bytes, and index.json kept pointing at the original OCI
manifest blob, so `docker load` with the containerd image store (Docker
Desktop, the Docker 29 default) failed digest verification.

normalize_oci_layout() is the single place that fixes this up, run once
after the last transform: it renames every content-addressed blob to the
digest of its bytes, and — when the image changed — writes a fresh OCI image
manifest blob and index.json describing exactly what manifest.json lists.

Pure Python, stdlib only.
"""

import hashlib
import io
import json
import re
import tarfile

_SHA256_HEX = re.compile(r'^[0-9a-f]{64}$')

OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'


def _blob_hex(name):
    """The hex digest a blobs/sha256/<hex> member name claims, else None."""
    parts = name.split('/')
    if len(parts) == 3 and parts[0] == 'blobs' and parts[1] == 'sha256' \
            and _SHA256_HEX.fullmatch(parts[2]):
        return parts[2]
    return None


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def layer_media_type(data, docker_style=False):
    """Media type for a layer blob, from its compression magic."""
    if docker_style:
        if data[:2] == b'\x1f\x8b':
            return 'application/vnd.docker.image.rootfs.diff.tar.gzip'
        if data[:4] == b'\x28\xb5\x2f\xfd':
            return 'application/vnd.docker.image.rootfs.diff.tar.zstd'
        return 'application/vnd.docker.image.rootfs.diff.tar'
    if data[:2] == b'\x1f\x8b':
        return 'application/vnd.oci.image.layer.v1.tar+gzip'
    if data[:4] == b'\x28\xb5\x2f\xfd':
        return 'application/vnd.oci.image.layer.v1.tar+zstd'
    return 'application/vnd.oci.image.layer.v1.tar'


def _json_bytes(obj):
    return json.dumps(obj, separators=(',', ':')).encode()


def _find_image_manifest(bodies, index):
    """Follow index.json (possibly through nested indexes) to the first
    image manifest.  Returns (manifest_obj, manifest_blob_name) or
    (None, None)."""
    seen = set()
    todo = list(index.get('manifests') or [])
    while todo:
        desc = todo.pop(0)
        digest = str(desc.get('digest', ''))
        if not digest.startswith('sha256:'):
            continue
        name = 'blobs/sha256/' + digest[7:]
        if name in seen or name not in bodies:
            continue
        seen.add(name)
        try:
            obj = json.loads(bodies[name])
        except ValueError:
            continue
        mt = obj.get('mediaType') or desc.get('mediaType', '')
        if 'index' in mt or 'manifest.list' in mt or 'manifests' in obj:
            todo[0:0] = list(obj.get('manifests') or [])
            continue
        if 'config' in obj and 'layers' in obj:
            return obj, name
    return None, None


def normalize_oci_layout(oci_data, sort_members=False):
    """Return oci_data with blob names, manifest.json and index.json made
    consistent with the blob contents.  Unchanged input is returned as is
    (same bytes).  sort_members emits members sorted by name (for
    --reproducible, whose sorting pass ran before this one)."""
    with tarfile.open(fileobj=io.BytesIO(oci_data), mode='r:*') as tf:
        members = tf.getmembers()
        bodies = {}
        for m in members:
            if m.isfile():
                f = tf.extractfile(m)
                bodies[m.name] = f.read() if f else b''

    if 'manifest.json' not in bodies:
        return oci_data
    manifest = json.loads(bodies['manifest.json'])
    if not isinstance(manifest, list) or not manifest:
        return oci_data
    entry = manifest[0]
    config_name = entry.get('Config', '')
    layer_names = list(entry.get('Layers') or [])
    if config_name not in bodies or any(n not in bodies for n in layer_names):
        return oci_data  # not ours to repair; the loader will refuse it

    # 1. Content-addressed names must match content.
    renames = {}
    for name in [config_name] + layer_names:
        claimed = _blob_hex(name)
        if claimed is None or name in renames:
            continue
        actual = _sha256(bodies[name])
        if actual != claimed:
            renames[name] = 'blobs/sha256/' + actual

    new_config_name = renames.get(config_name, config_name)
    new_layer_names = [renames.get(n, n) for n in layer_names]

    # 2. index.json -> OCI manifest must describe manifest.json's image.
    new_index = None
    new_manifest_blob = None
    old_manifest_blob = None
    if 'index.json' in bodies:
        try:
            index = json.loads(bodies['index.json'])
        except ValueError:
            index = None
        if isinstance(index, dict):
            old_manifest, old_manifest_blob = _find_image_manifest(bodies,
                                                                   index)
            docker_style = bool(old_manifest and old_manifest.get(
                'mediaType') == DOCKER_MANIFEST)
            config_bytes = bodies[config_name]
            old_cfg = (old_manifest or {}).get('config') or {}
            config_desc = {
                'mediaType': old_cfg.get('mediaType') or (
                    DOCKER_CONFIG if docker_style else OCI_CONFIG),
                'digest': 'sha256:' + _sha256(config_bytes),
                'size': len(config_bytes),
            }
            old_layers = {str(d.get('digest', '')): d
                          for d in (old_manifest or {}).get('layers') or []}
            layers = []
            for name in layer_names:
                data = bodies[name]
                digest = 'sha256:' + _sha256(data)
                desc = dict(old_layers.get(digest) or {})
                desc['mediaType'] = layer_media_type(data, docker_style)
                desc['digest'] = digest
                desc['size'] = len(data)
                layers.append(desc)
            unchanged = (old_manifest is not None and
                         old_cfg.get('digest') == config_desc['digest'] and
                         [d.get('digest') for d in old_manifest.get('layers')
                          or []] == [d['digest'] for d in layers] and
                         [d.get('mediaType') for d in old_manifest.get(
                             'layers') or []] ==
                         [d['mediaType'] for d in layers])
            if not unchanged:
                new_manifest = {
                    'schemaVersion': 2,
                    'mediaType': DOCKER_MANIFEST if docker_style
                    else OCI_MANIFEST,
                    'config': config_desc,
                    'layers': layers,
                }
                if old_manifest and old_manifest.get('annotations'):
                    new_manifest['annotations'] = old_manifest['annotations']
                mbytes = _json_bytes(new_manifest)
                new_manifest_blob = ('blobs/sha256/' + _sha256(mbytes),
                                     mbytes)
                old_first = (index.get('manifests') or [{}])[0]
                mdesc = {
                    'mediaType': new_manifest['mediaType'],
                    'digest': 'sha256:' + _sha256(mbytes),
                    'size': len(mbytes),
                }
                if old_first.get('annotations'):
                    mdesc['annotations'] = old_first['annotations']
                new_index = {
                    'schemaVersion': 2,
                    'mediaType': OCI_INDEX,
                    'manifests': [mdesc],
                }
            else:
                old_manifest_blob = None

    if not renames and new_index is None:
        return oci_data

    # 3. Re-emit.  Renamed blobs keep their member metadata; the replaced
    # manifest blob (and any index it sat in) is dropped only when nothing
    # else in manifest.json references it.
    entry['Config'] = new_config_name
    entry['Layers'] = new_layer_names
    bodies['manifest.json'] = _json_bytes(manifest)
    if new_index is not None:
        bodies['index.json'] = _json_bytes(new_index)

    # Renamed blobs are re-emitted under their new name below; only the
    # superseded manifest blob goes away (unless manifest.json still uses it).
    referenced = {new_config_name, *new_layer_names}
    drop = set()
    if old_manifest_blob and old_manifest_blob not in referenced:
        drop.add(old_manifest_blob)

    out_members = []
    emitted = set()
    for m in members:
        if m.name in drop:
            continue
        name = renames.get(m.name, m.name)
        if name in emitted:
            continue  # two old names collapsed onto one digest
        emitted.add(name)
        out_members.append((m, name))

    extra = []
    if new_manifest_blob and new_manifest_blob[0] not in emitted:
        info = tarfile.TarInfo(name=new_manifest_blob[0])
        info.mode = 0o644
        extra.append((info, new_manifest_blob[0]))
        bodies[new_manifest_blob[0]] = new_manifest_blob[1]

    items = [(m, name) for m, name in out_members] + extra
    if sort_members:
        items.sort(key=lambda it: it[1])

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:',
                      format=tarfile.USTAR_FORMAT if sort_members
                      else tarfile.GNU_FORMAT) as out:
        for m, name in items:
            info = tarfile.TarInfo(name=name)
            info.mode = m.mode
            info.type = m.type
            info.linkname = m.linkname
            info.uid = m.uid
            info.gid = m.gid
            info.uname = m.uname
            info.gname = m.gname
            info.mtime = m.mtime
            if m.isfile():
                # Bodies stay keyed by the original member name; renamed
                # blobs carry their bytes over under the new name.
                source = bodies[m.name]
                info.size = len(source)
                out.addfile(info, io.BytesIO(source))
            else:
                out.addfile(info)
    return buf.getvalue()
