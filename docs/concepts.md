# Concepts

## The Output File

An `oci2bin` output file is an ELF+TAR polyglot.

That means the same bytes are accepted by two different readers:

- the Linux kernel sees an ELF executable
- `docker load` sees a saved-image tar archive

The executable part is a small loader. The tar part contains the OCI image
payload and metadata.

```text
+-------------------------------+
| ELF loader                     |
+-------------------------------+
| OCI image tar payload          |
+-------------------------------+
| oci2bin metadata and options   |
+-------------------------------+
```

Run it:

```bash
./myapp
```

Load it:

```bash
docker load < myapp
```

## Build-Time Options And Runtime Options

There are two command lines to understand.

Build-time options go to `oci2bin`:

```bash
oci2bin --strip --add-file config.yaml:/etc/app/config.yaml app:latest app.bin
```

Runtime options go to the generated binary:

```bash
./app.bin --read-only --tmpfs /tmp -e LOG_LEVEL=debug
```

The build step changes what is inside the file. The runtime step changes how
the embedded image starts on this host.

## Rootless Container Model

The generated binary starts the image using Linux namespaces.

Inside the container, the process can appear as UID 0. On the host, it runs as
the invoking user. The loader uses user namespaces and mount namespaces so it
can prepare a root filesystem without requiring a daemon.

When subordinate ID mappings are available through `/etc/subuid`,
`/etc/subgid`, `newuidmap`, and `newgidmap`, the container gets a wider UID/GID
range. Without them, it can fall back to a single-ID mapping with reduced
compatibility.

## Image Sources

`oci2bin` can build from several sources:

- an image in Docker or Podman
- an OCI image layout directory from tools such as `skopeo`, `crane`, or
  `buildah`
- an existing saved tar
- a chroot directory
- a Dockerfile interpreted by `oci2bin` without a Docker daemon

## Single-Architecture And Fat Binaries

The normal output targets one architecture:

```bash
oci2bin --arch x86_64 alpine:latest
oci2bin --arch aarch64 alpine:latest
```

`--arch all` builds x86_64 and aarch64 outputs plus a wrapper that chooses the
right one at runtime:

```bash
oci2bin --arch all alpine:latest
```

The wrapper and both architecture-specific files must stay in the same
directory.

## Container Mode And VM Mode

Normal `oci2bin` outputs run as rootless containers.

`oci2vm` builds binaries that run in VM mode by default:

```bash
oci2vm alpine:latest
./oci2vm_alpine_latest
```

VM mode is for stronger isolation. It needs VM backend support and suitable
embedded VM assets.

## The Docker Compatibility Tradeoff

Most `oci2bin` binaries can be loaded with:

```bash
docker load < myapp
```

Some features intentionally change that:

- `--compress-binary zstd` compresses the embedded payload and needs `zstd` at
  runtime
- encryption makes the embedded image opaque at rest

Use those features when the smaller or encrypted executable matters more than
direct `docker load` compatibility.

