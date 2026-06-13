# How It Works

`oci2bin` builds one file that can be treated as an executable or as an image
archive.

## Build Flow

```text
image source
  |
  |  Docker, Podman, OCI layout, tar, chroot, or Dockerfile builder
  v
saved OCI payload
  |
  |  optional transforms
  |  add files, merge layers, strip, squash, labels, encrypt, compress
  v
loader + payload + metadata
  |
  v
ELF+TAR polyglot executable
```

The loader is compiled for the target architecture. The image payload is
attached in a layout that the loader can find at runtime and that `docker load`
can read when the payload is left as a plain tar archive.

## Polyglot Layout

The file has an executable loader and an image archive in the same byte stream.

```text
+--------------------------------------------------+
| ELF executable loader                            |
+--------------------------------------------------+
| tar-compatible OCI image payload                 |
+--------------------------------------------------+
| metadata: image name, labels, digest, policies   |
+--------------------------------------------------+
```

The kernel starts the ELF loader:

```bash
./app.bin
```

Docker reads the tar payload:

```bash
docker load < app.bin
```

Encryption and zstd payload compression change the direct `docker load`
property because the image tar is no longer visible as plain tar bytes.

The two formats use magic bytes at different offsets:

```text
byte 0-3     ELF magic: 7f 45 4c 46
byte 257-262 tar magic: ustar\0
```

The ELF header fits inside the tar header area. The kernel follows the ELF
rules. Tar readers follow the tar rules.

The practical layout is:

```text
tar entry 1 header: contains the ELF header bytes
tar entry 1 data:   padding plus the statically linked loader
tar entries 2+:     OCI image archive entries
tar EOF:            two zero blocks
metadata:           oci2bin metadata outside the tar stream
```

Docker sees the OCI image archive entries. Runtime execution starts the loader.

## OCI Image Payload

The embedded image payload follows the shape produced by `docker save` and OCI
layout tools:

```text
manifest.json
<sha256>.json
<sha256>/layer.tar
```

The image config contains values such as `Entrypoint`, `Cmd`, `Env`,
`WorkingDir`, `User`, and labels. Each layer tar contains filesystem changes.
The loader applies layers in order, including OCI whiteout deletion markers, so
later layers win.

## Runtime Flow

When the generated binary starts, the loader:

1. Parses runtime options.
2. Verifies policy if `--verify-key`, `--require-signed`, or digest pinning is
   active.
3. Decrypts or decompresses the embedded payload when required.
4. Extracts or prepares the root filesystem.
5. Sets up namespaces, mounts, environment, user mapping, limits, and security
   policy.
6. Starts the image entrypoint or the command supplied on the command line.
7. Returns the container process exit code.

In more concrete terms, the loader opens `/proc/self/exe`, finds the embedded
payload, parses the manifest and config, prepares a temporary rootfs, applies
layers, enters the requested namespaces, sets up mounts, then `exec`s the final
process.

## Root Filesystem Preparation

The loader prepares a root filesystem from the embedded image layers. Runtime
options then modify that filesystem view:

- `-v` adds bind mounts
- `--secret` adds read-only secret files
- `--tmpfs` adds in-memory writable paths
- `--read-only` uses a read-only rootfs view
- `--overlay-persist` keeps overlay state on the host
- `--device`, `--gpus`, and `--cdi-device` expose selected host devices

## Namespaces

The runtime uses Linux namespaces for isolation:

- user namespace for rootless UID/GID mapping
- mount namespace for the container filesystem
- network namespace when using `--net none`, `slirp`, `pasta`, pods, or
  namespace sharing
- IPC namespace when requested
- cgroup namespace when cgroup v2 limits are active
- time namespace when clock offset is requested

## Security Policy Setup

Depending on options and host support, the loader can apply:

- seccomp syscall filtering
- custom Docker-compatible seccomp profiles
- Landlock filesystem restrictions
- capability drops and ambient capability additions
- AppArmor profile selection
- SELinux exec labels
- cgroup v2 resource limits
- signature and digest checks before extraction
- encrypted payload unlock before use

## Single-ID Fallback

When subordinate ID mappings are unavailable, the runtime can fall back to a
single-ID user namespace. Container UID 0 maps to the invoking host user. Other
container IDs are not available.

Some images expect user switching tools to work. In this fallback mode, the
loader applies compatibility patches so common images keep starting:

| File or tool | Runtime adjustment |
| --- | --- |
| `/etc/passwd` | UIDs are mapped to `0` except `65534` |
| `/etc/group` | GIDs are mapped to `0` except `65534` |
| apt sandbox config | apt sandbox user is set to root |
| `/etc/resolv.conf` | resolver content is copied into the rootfs |
| `setpriv`, `gosu`, `su-exec` | replaced with no-op shims that exec the command |

This is a compatibility path, not a privilege escalation. The host process
still runs as the invoking user.

## Command Resolution

The image config provides `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, and
labels. Runtime options override them:

- `--entrypoint` replaces the image entrypoint
- command arguments replace `Cmd`
- `--workdir` replaces image `WorkingDir`
- `-e` and `--env-file` add or override environment variables
- `--user` replaces image user

## Reconstructable Images

A normal polyglot is self-contained for running, but the loader is not
automatically part of the image if the image is pushed elsewhere. The
reconstruction features store the loader inside the image itself:

- `--embed-loader-layer` writes it as an OCI layer
- `--embed-loader-labels` writes it as chunked image config labels

After a registry round trip, `oci2bin reconstruct` can rebuild the executable:

```bash
oci2bin reconstruct registry.example.com/app:latest --output app.bin
```

## VM Mode

VM mode changes the execution backend. Instead of only using Linux namespaces,
the generated binary starts the image workload inside a lightweight VM backend.

```bash
oci2vm app:latest
./oci2vm_app_latest
```

The binary can embed VM assets such as a kernel and initramfs. Backend selection
can use libkrun or the static loader path, depending on build options and host
support.

## Why The File Can Still Be Useful As An Image

The `docker load` property makes `oci2bin` artifacts easy to inspect and move
between workflows:

```bash
docker load < app.bin
docker image inspect app:latest
```

That means the same artifact can be:

- executed directly on a target host
- stored as a single file
- imported into Docker for debugging
- reconstructed after being pushed through an OCI registry, when loader
  embedding is enabled
