# oci2bin

**oci2bin** converts any Docker (OCI) image into a single executable file. The output runs as a rootless container on any Linux machine — without Docker, without a daemon, and without any installation on the target.

```bash
./oci2bin alpine:latest    # produces ./alpine_latest
./alpine_latest            # runs the container
```

The output file is also a valid tar archive, so `docker load` accepts it:

```bash
docker load < alpine_latest
```

The file can be copied to any Linux host with user namespace support (kernel 3.8 or later) and executed directly.

## Getting started

**Build dependencies:** `gcc`, `glibc-static`, `python3`, `docker`

`gcc` and `glibc-static` are needed to compile the embedded loader binary. On most systems `gcc` is already installed; `glibc-static` may need to be added explicitly:

```bash
# Arch Linux — gcc is in base-devel (installed by default)
sudo pacman -S glibc

# Fedora
sudo dnf install gcc glibc-static

# Debian / Ubuntu
sudo apt install gcc libc6-dev

# openSUSE Tumbleweed
sudo zypper install gcc glibc-devel-static

# NixOS / nix-shell
nix-shell -p gcc python3 docker
```

After cloning the repository, run `oci2bin` with an image name. The loader is compiled on first use; the image is pulled automatically if not already present locally.

```bash
./oci2bin alpine:latest        # output: ./alpine_latest
./oci2bin nginx:1.25 my-nginx  # explicit output name
```

### Caching builds

`--cache` stores the output binary in `~/.cache/oci2bin/<image>/output` so repeated builds of the same image are instant:

```bash
./oci2bin --cache alpine:latest   # builds and caches
./oci2bin --cache alpine:latest   # returns cached binary immediately
```

The cache key is derived from the image name (`:` and `/` replaced with `_`). To rebuild, delete the cache entry: `rm -rf ~/.cache/oci2bin/alpine_latest`.

## Running containers

By default, the binary executes the image's configured entrypoint — equivalent to `docker run <image>`:

```bash
./alpine_latest
/ # whoami
root
/ # echo $$
1
```

### Passing commands

Arguments provided after the binary name replace the image's default command:

```bash
./alpine_latest /bin/ls /etc
./alpine_latest /bin/sh -c 'cat /etc/os-release'
```

### Overriding the entrypoint

`--entrypoint` replaces the image entrypoint with an arbitrary executable:

```bash
./alpine_latest --entrypoint /bin/echo hello
./alpine_latest --entrypoint /bin/sh -- -c 'echo hello'
```

When the command following `--entrypoint` begins with a `-`, use `--` to terminate option parsing before it.

### Working directory

`--workdir PATH` sets the working directory inside the container before executing the entrypoint. If `--workdir` is not given, the directory from the image's `WorkingDir` field is used instead. If neither is set, the container starts at `/`.

```bash
./my-app --workdir /app
./my-app --workdir /tmp /bin/sh -c 'pwd'
```

### Setting environment variables

`-e KEY=VALUE` sets an environment variable inside the container. It can be specified multiple times. User-supplied variables take precedence over the built-in defaults (`PATH`, `HOME`, `TERM`).

```bash
./alpine_latest -e DEBUG=1 /bin/sh -c 'echo $DEBUG'
./alpine_latest -e API_URL=https://example.com -e TIMEOUT=30 /bin/sh
./alpine_latest -e PATH=/custom/bin:/bin /bin/sh -c 'echo $PATH'
```

### Volume mounts

`-v HOST_PATH:CONTAINER_PATH` bind-mounts a host directory into the container. The mount point is created inside the container if it does not exist. Multiple `-v` flags are accepted.

```bash
./alpine_latest -v /data:/data /bin/ls /data

./alpine_latest \
  -v /data/input:/input \
  -v /data/output:/output \
  /bin/sh -c 'cp /input/file /output/'
```

### End of options

`--` terminates option parsing. Arguments following it are passed to the container as-is, which is useful when the command begins with a `-`:

```bash
./alpine_latest -- -v
```

### Exit codes

The container process exit code is forwarded to the calling shell:

```bash
./alpine_latest /bin/sh -c 'exit 42'
echo $?   # 42
```

## Environment

The container process runs as root inside a user namespace. The host UID is mapped to UID 0 inside the namespace — no real privilege is granted on the host. The following environment variables are set:

```
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
TERM=xterm
```

The network namespace is not isolated — the container shares the host network stack. `/etc/resolv.conf` from the host is copied into the rootfs so DNS resolution works correctly.

## Networking

By default containers run in host networking mode — they share the host network stack and can reach the internet. To create an isolated network namespace with no interfaces, use `--net none`:

```bash
./alpine_latest --net none /bin/sh -c 'ip link'   # only loopback visible
./alpine_latest --net host /bin/sh -c 'curl ...'  # host networking (default)
```

`--net none` adds `CLONE_NEWNET` to the namespace flags. The container gets its own network stack with only a loopback interface and cannot reach the host network or internet.

## Testing

```bash
make test-unit        # unit tests only, no Docker required (~5s)
make test             # full suite, requires Docker and a built image
make test-c           # C unit tests (TAP, x86_64)
make test-python      # Python unit tests
make test-integration # runtime and build integration tests
```

The suite covers the polyglot builder, loader internals, structural invariants of the output file, and all runtime features: volume mounts, entrypoint override, argument passthrough, exit code forwarding, and execution without Docker.

### aarch64 unit tests

The C unit tests can be cross-compiled and run under `qemu-aarch64-static` without a real aarch64 machine:

```bash
# Fedora
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc qemu-user-static

make test-unit-aarch64
```

The `QEMU_AARCH64` variable can be overridden if the binary is in a non-standard path:

```bash
make test-unit-aarch64 QEMU_AARCH64=/usr/bin/qemu-aarch64-static
```

## Cross-compilation

To build an aarch64 polyglot on an x86_64 host, pass `--arch aarch64`. This requires `gcc-aarch64-linux-gnu` and its sysroot:

```bash
# Fedora
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc

./oci2bin --arch aarch64 alpine:latest
```

The sysroot defaults to `/usr/aarch64-redhat-linux/sys-root/fc43`. Override it if yours differs:

```bash
AARCH64_SYSROOT=/path/to/sysroot ./oci2bin --arch aarch64 alpine:latest
# or for make:
make loader-aarch64 AARCH64_SYSROOT=/path/to/sysroot
```

The output binary is an aarch64 ELF and runs only on aarch64 Linux hosts (or under qemu). Cross-compilation in the other direction (aarch64 → x86_64) is not currently supported.

## How it works

The output file is a [polyglot](https://sysfatal.github.io/polyglottar-en.html): simultaneously a valid ELF64 executable and a valid POSIX tar archive. The two formats place their magic bytes at non-overlapping offsets:

```
Byte   0-3:   7f 45 4c 46   ELF magic  (kernel identifies it as an executable)
Byte 257-262: 75 73 74 61   ustar\0    (tar identifies it as an archive)
```

The 64-byte ELF header fits within the tar header's 100-byte filename field, leaving both formats intact. When executed, the kernel processes the ELF; when passed to `tar` or `docker load`, the tar structure is read.

At runtime the loader:

1. Opens itself via `/proc/self/exe` and reads the embedded OCI tar from the patched offset
2. Extracts the image layers into a temporary rootfs under `/tmp`
3. Patches the rootfs for single-UID namespace compatibility (see below)
4. Enters a user namespace (UID mapped to host UID)
5. Enters mount, PID, and UTS namespaces
6. Applies volume bind mounts before `chroot`
7. `chroot`s into the rootfs and `exec`s the entrypoint

The only runtime dependency on the target machine is `tar`.

### File layout

```
[0-63]       ELF64 header  (embedded in the tar filename field)
[64-511]     Remaining tar header fields (ustar magic at byte 257)
[512-4095]   NUL padding   (page-aligns the loader for mmap)
[4096-~75K]  Loader binary (statically linked)
[~75K-end]   OCI image tar (manifest.json, config, layer tarballs)
```

### Rootfs patching for single-UID namespaces

An unprivileged user namespace allows exactly one UID mapping. Container UID 0 maps to the invoking user's UID on the host; no other UIDs exist inside the namespace. Tools that attempt to change to a different UID (such as `apt`'s `_apt` sandbox user) would receive `EPERM`.

The loader rewrites the following files in the extracted rootfs before entering the namespace:

| File | Modification | Reason |
|---|---|---|
| `/etc/passwd` | All UIDs set to `0` (except `65534`) | `seteuid(0)` succeeds; privilege-dropping code becomes a no-op |
| `/etc/group` | All GIDs set to `0` (except `65534`) | Same for GID operations |
| `/etc/apt/apt.conf.d/99oci2bin` | `APT::Sandbox::User "root";` | Disables the apt sandbox as an additional safeguard |
| `/etc/resolv.conf` | Replaced with host resolver content | The original symlink target is not present inside the chroot |

GID `65534` (`nogroup` / `nobody`) is preserved because it is the kernel's overflow GID — the identity assigned to objects not covered by the UID/GID map.

### Security properties

- The process is unprivileged on the host; `CLONE_NEWUSER` does not confer real root
- Layer and config paths from the OCI manifest are validated against path traversal before use
- Volume container paths must be absolute and must not contain `..`
- Tar extraction uses `--no-same-permissions --no-same-owner` to prevent setuid bit restoration from crafted layers
- Temporary directories are created with `mkdtemp` (mode `0700`)

## References

- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [Polyglottar technique](https://sysfatal.github.io/polyglottar-en.html)
- [tar(5) format](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
- [Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
