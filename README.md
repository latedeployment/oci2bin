# oci2bin

**oci2bin** converts any Docker (OCI) image into a single executable file. The output runs as a rootless container on any Linux machine — without Docker, without a daemon, and without any installation on the target.

```bash
./oci2bin alpine:latest    # produces ./alpine_latest
./alpine_latest            # runs the container
```

The output file is also a valid tar archive accepted by `docker load`:

```bash
docker load < alpine_latest
```

See below [How it works](#how-it-works).

## Table of contents

- [Getting started](#getting-started)
- [Building binaries](#building-binaries)
  - [Cross-architecture builds](#cross-architecture-builds)
  - [Injecting files at build time](#injecting-files-at-build-time)
  - [Merging image layers](#merging-image-layers)
  - [Stripping images](#stripping-images)
  - [Using OCI image layout](#using-oci-image-layout-no-docker-daemon)
  - [Caching builds](#caching-builds)
  - [Reproducible builds and digest pinning](#reproducible-builds-and-digest-pinning)
- [Running containers](#running-containers)
  - [Overriding the entrypoint](#overriding-the-entrypoint)
  - [Working directory](#working-directory)
  - [Environment variables](#environment-variables)
  - [Volume mounts](#volume-mounts)
  - [Secrets](#secrets)
  - [SSH agent forwarding](#ssh-agent-forwarding)
  - [Extra tmpfs mounts](#extra-tmpfs-mounts)
  - [Resource limits](#resource-limits)
  - [Exit codes](#exit-codes)
- [Isolation and security](#isolation-and-security)
  - [Networking](#networking)
  - [Read-only containers](#read-only-containers)
  - [Capabilities](#capabilities)
  - [Seccomp filter](#seccomp-filter)
  - [Running as non-root](#running-as-non-root)
  - [Custom hostname](#custom-hostname)
  - [Exposing host devices](#exposing-host-devices)
- [Process management](#process-management)
  - [Init process and zombie reaping](#init-process-and-zombie-reaping)
  - [Running in background](#running-in-background)
- [Subcommands](#subcommands)
  - [inspect](#inspect)
  - [list](#list)
  - [prune](#prune)
  - [diff](#diff)
- [Testing](#testing)
- [How it works](#how-it-works)
- [References](#references)

---

## Getting started

**Build dependencies:** `gcc`, `glibc-static`, `python3`, `docker`

```bash
# Arch Linux
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

---

## Building binaries

### Cross-architecture builds

Build an aarch64 binary on an x86_64 host with `--arch aarch64`:

```bash
# Fedora
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc

./oci2bin --arch aarch64 alpine:latest
```

The sysroot defaults to `/usr/aarch64-redhat-linux/sys-root/fc43`. Override with:

```bash
AARCH64_SYSROOT=/path/to/sysroot ./oci2bin --arch aarch64 alpine:latest
```

The output runs only on aarch64 Linux (or under qemu-aarch64).

### Injecting files at build time

Use `--add-file HOST:CONTAINER` and `--add-dir HOST:CONTAINER` to inject files or directories into the image at build time, without needing a volume mount at runtime:

```bash
# Inject a config file
oci2bin --add-file ./myapp.conf:/etc/myapp/myapp.conf myapp:latest

# Inject a CA certificate bundle
oci2bin --add-file /etc/ssl/certs/ca-bundle.crt:/etc/ssl/certs/ca-bundle.crt base:latest

# Inject a directory
oci2bin --add-dir ./config:/etc/myapp myapp:latest

# Combine both (repeatable)
oci2bin --add-file ./secret.pem:/run/secrets/key.pem \
        --add-dir  ./migrations:/app/migrations \
        myapp:latest
```

Files are added as a new layer on top of existing image layers. Both flags may be repeated.

### Merging image layers

Use `--layer IMAGE` to overlay additional Docker images on top of the base image:

```bash
oci2bin --layer debugtools:latest myapp:latest myapp-debug
```

Multiple `--layer` flags are applied in order. The base image layers come first; each `--layer` image's layers are appended on top. The image config (Cmd, Entrypoint, Env) from the last `--layer` image overrides the base if non-null. Images not already present locally are pulled automatically.

### Stripping images

Use `--strip` to remove documentation, man pages, locale data, and apt caches before packaging:

```bash
oci2bin --strip ubuntu:22.04 my-ubuntu
oci2bin --strip --layer extra:latest base:latest output
```

Removed path prefixes: `usr/share/doc/`, `usr/share/man/`, `usr/share/info/`, `usr/share/locale/`, `usr/share/i18n/`, `var/cache/apt/`, `var/lib/apt/lists/`, `tmp/`.

### Using OCI image layout (no Docker daemon)

Use `--oci-dir DIR` to build from an OCI image layout directory instead of pulling via Docker. This works with `skopeo`, `crane`, `buildah`, or any tool that produces OCI layout output:

```bash
# Copy image to OCI layout using skopeo
skopeo copy docker://redis:7-alpine oci:./redis-oci:latest

# Build from the layout directory (no Docker daemon required)
oci2bin --oci-dir ./redis-oci redis:7-alpine redis_7-alpine
```

The `IMAGE` argument is optional and used only for the output filename default and embedded metadata. Compatible with `--add-file`, `--add-dir`, and `--strip`.

### Caching builds

`--cache` stores the output binary in `~/.cache/oci2bin/<image>_<digest>/output` so repeated builds of the same image are instant:

```bash
./oci2bin --cache alpine:latest   # builds and caches
./oci2bin --cache alpine:latest   # returns cached binary immediately
```

The cache key includes the first 12 hex characters of the image's sha256 digest, so tag updates are detected. See [list](#list), [prune](#prune) for cache management.

### Reproducible builds and digest pinning

After pulling, oci2bin prints the content-addressed digest to stderr:

```
oci2bin: image digest: redis@sha256:abc123...
```

When `--cache` is active, the cache key includes the digest so that `redis:latest` updates produce a fresh cache entry rather than reusing a stale binary. If the image has no registry origin (locally built), the digest lookup is skipped with a warning and the tag-only key is used.

---

## Running containers

By default the binary executes the image's configured entrypoint — equivalent to `docker run <image>`. Arguments provided after the binary name replace the image's default command:

```bash
./alpine_latest                          # run default entrypoint
./alpine_latest /bin/ls /etc             # override CMD
./alpine_latest /bin/sh -c 'uname -a'
```

Use `--` to terminate option parsing when a command argument starts with `-`:

```bash
./alpine_latest -- -v
```

### Overriding the entrypoint

`--entrypoint PATH` replaces the image entrypoint:

```bash
./alpine_latest --entrypoint /bin/echo hello
./alpine_latest --entrypoint /bin/sh -- -c 'echo hello'
```

### Working directory

`--workdir PATH` sets the working directory inside the container. If not given, the image's `WorkingDir` is used; if neither is set, the container starts at `/`.

```bash
./my-app --workdir /app
./my-app --workdir /tmp /bin/sh -c 'pwd'
```

### Environment variables

`-e KEY=VALUE` sets a variable inside the container. `-e KEY` (no `=VALUE`) passes the variable from the host; if the variable is not set on the host, a warning is printed and it is skipped. User-supplied variables take precedence over the image defaults.

```bash
./alpine_latest -e DEBUG=1 /bin/sh -c 'echo $DEBUG'
./alpine_latest -e API_URL=https://example.com -e TIMEOUT=30 /bin/sh
./alpine_latest -e HOME -e USER /bin/sh   # pass host HOME and USER
```

`--env-file FILE` loads `KEY=VALUE` pairs from a file. The file format:
- One `KEY=VALUE` per line
- Blank lines and lines starting with `#` are ignored
- Empty values (`KEY=`) are valid

`--env-file` and `-e` are additive; the file is processed first so `-e` flags override it. Both may be repeated.

```bash
./my-app --env-file /etc/myapp.env
./my-app --env-file base.env --env-file override.env -e DEBUG=1
```

### Volume mounts

`-v HOST:CONTAINER` bind-mounts a host directory into the container. The mount point is created inside the container if it does not exist. May be repeated.

```bash
./alpine_latest -v /data:/data /bin/ls /data

./alpine_latest \
  -v /data/input:/input \
  -v /data/output:/output \
  /bin/sh -c 'cp /input/file /output/'
```

### Secrets

`--secret HOST_FILE[:CONTAINER_PATH]` bind-mounts a single host file into the container read-only. If no container path is given, the file lands at `/run/secrets/<basename>`. The mount is enforced read-only with `MS_NOEXEC|MS_NOSUID|MS_NODEV`. May be repeated.

```bash
./my-app --secret ~/.config/api_key           # → /run/secrets/api_key
./my-app --secret /etc/ssl/cert.pem:/certs/ca.pem
./my-app --secret /run/secrets/db_pass --secret /run/secrets/jwt_key
```

If the remount read-only step fails, the secret is not mounted at all.

### SSH agent forwarding

`--ssh-agent` forwards the host `SSH_AUTH_SOCK` Unix socket into the container at `/run/ssh-agent.sock` and sets `SSH_AUTH_SOCK` accordingly:

```bash
./my-app --ssh-agent                           # git, ssh, etc. work inside
./my-app --ssh-agent /bin/sh -c 'ssh git@github.com'
```

The socket is bind-mounted read-only. If `SSH_AUTH_SOCK` is unset or points to a non-socket, a warning is printed and the container runs without agent forwarding.

### Extra tmpfs mounts

`--tmpfs PATH` mounts a fresh in-memory filesystem inside the container. Useful for writable scratch space when `--read-only` is active. Paths must be absolute and must not contain `..`. May be repeated.

```bash
./my-app --read-only --tmpfs /tmp --tmpfs /var/cache
```

### Resource limits

`--ulimit TYPE=N` sets resource limits via `setrlimit(2)`. May be repeated.

```bash
./my-app --ulimit nofile=1024       # max open file descriptors
./my-app --ulimit nproc=64          # max processes
./my-app --ulimit cpu=30            # max CPU time (seconds)
./my-app --ulimit as=536870912      # max virtual memory (512 MiB)
./my-app --ulimit fsize=10485760    # max file size (10 MiB)
```

Both `rlim_cur` and `rlim_max` are set to the given value. Failure is non-fatal.

### Exit codes

The container process exit code is forwarded to the calling shell:

```bash
./alpine_latest /bin/sh -c 'exit 42'
echo $?   # 42
```

---

## Isolation and security

### Networking

By default, containers share the host network stack. Use `--net none` for a fully isolated network namespace:

```bash
./alpine_latest --net none /bin/sh -c 'ip link'   # only loopback visible
./alpine_latest --net host /bin/sh -c 'curl ...'  # host networking (default)
```

The container process runs as root inside a user namespace. The host UID is mapped to UID 0 — no real privilege is granted on the host. `/etc/resolv.conf` from the host is copied into the rootfs so DNS resolution works.

### Read-only containers

`--read-only` mounts the rootfs read-only via overlayfs. Writes go to a temporary upper layer discarded on exit. The on-disk rootfs is never modified.

```bash
./alpine_latest --read-only /bin/sh -c 'touch /test'
```

If overlayfs is not available, a warning is printed and the container runs read-write.

### Capabilities

Use `--cap-drop` and `--cap-add` to manage Linux capabilities:

```bash
# Drop all capabilities (maximum restriction)
./my-app --cap-drop all

# Drop all, but keep net_bind_service (bind to ports < 1024)
./my-app --cap-drop all --cap-add net_bind_service

# Drop individual capabilities
./my-app --cap-drop net_raw --cap-drop sys_ptrace
```

Capability names are case-insensitive; the `CAP_` prefix is optional (`net_raw` and `CAP_NET_RAW` are equivalent). Supported names: `chown`, `dac_override`, `dac_read_search`, `fowner`, `fsetid`, `kill`, `setgid`, `setuid`, `setpcap`, `net_bind_service`, `net_raw`, `net_admin`, `sys_chroot`, `sys_admin`, `sys_ptrace`, `sys_module`, `mknod`, `audit_write`, `setfcap`, `ipc_lock`.

`--cap-add` raises the capability as an ambient capability so it survives `exec`. Capability operations are non-fatal.

### Seccomp filter

Containers run with a default seccomp-BPF filter that blocks syscalls with no legitimate use inside a container:

| Blocked syscall | Reason |
|---|---|
| `kexec_load`, `kexec_file_load` | Load a new kernel |
| `reboot` | Reboot the host |
| `syslog` | Kernel ring buffer access |
| `perf_event_open` | Used in kernel exploit chains |
| `bpf` | Load arbitrary BPF programs |
| `add_key`, `request_key`, `keyctl` | Kernel keyring manipulation |
| `userfaultfd` | Exploited in kernel escapes |
| `pivot_root` | Namespace escape vector |
| `ptrace` | Process tracing / container escape |
| `process_vm_readv`, `process_vm_writev` | Cross-process memory access |
| `init_module`, `finit_module` | Kernel module loading |

`PR_SET_NO_NEW_PRIVS` is also set so the container cannot gain privileges via setuid or capabilities. To disable the filter:

```bash
./my-app --no-seccomp
```

### Running as non-root

By default the container process runs as UID 0 inside the user namespace. Use `--user` to run as a different numeric UID:

```bash
./my-app --user 1000          # run as UID 1000, GID 1000
./my-app --user 1000:2000     # run as UID 1000, GID 2000
```

Only numeric UIDs/GIDs are accepted. Values must be ≤ 65534. If any of `setgroups`, `setgid`, or `setuid` fail, the container exits immediately.

### Custom hostname

`--hostname NAME` sets the hostname inside the UTS namespace. Failure is non-fatal.

```bash
./my-app --hostname mycontainer
```

### Exposing host devices

`--device /dev/HOST[:CONTAINER]` exposes a host device node inside the container:

```bash
./my-app --device /dev/nvidia0            # GPU passthrough
./my-app --device /dev/ttyUSB0            # serial port
./my-app --device /dev/fuse               # FUSE filesystem support
./my-app --device /dev/snd:/dev/snd       # audio (explicit container path)
```

The host path must start with `/dev/`. The container path defaults to the same path if omitted. oci2bin first attempts `mknod` with the host device's `st_rdev`; if that fails it falls back to a bind mount. Failure is non-fatal. May be repeated.

---

## Process management

### Init process and zombie reaping

By default the container process runs directly as PID 1. If it spawns children that exit before it does, those become zombies. Use `--init` to run a tiny reaper as PID 1:

```bash
./my-app --init
```

With `--init`, oci2bin forks the entrypoint as a child and the parent loops calling `waitpid(-1, ...)` to reap zombies. SIGTERM, SIGINT, SIGHUP, SIGUSR1, and SIGUSR2 are forwarded to the child. When the main child exits, remaining zombies are drained and the exit status is returned (128+signal for signal deaths).

### Running in background

`--detach` (or `-d`) forks the container to the background, prints the child PID to stdout, and exits:

```bash
PID=$(./redis --detach)
echo "Redis running as PID $PID"
sleep 1
kill "$PID"
```

The child calls `setsid()` to detach from the terminal and redirects stdin from `/dev/null`. Combine with `--init` for a fully-managed background service.

---

## Subcommands

### inspect

Display metadata embedded in any oci2bin binary without running it:

```bash
oci2bin inspect ./redis_7-alpine
```

```
Image:        redis:7-alpine
Architecture: amd64
Layers:       6
Entrypoint:   ["docker-entrypoint.sh"]
Cmd:          ["redis-server"]
WorkingDir:   /data
Env:
              PATH=/usr/local/sbin:...
              REDIS_VERSION=7.4.2

Build metadata:
  Image:     redis:7-alpine
  Digest:    redis@sha256:abc123...
  Built:     2026-03-10T12:00:00Z
  oci2bin:   0.3.0
```

### list

List all binaries in the cache with image name, digest, size, and build date:

```bash
oci2bin list           # human-readable table
oci2bin list --json    # machine-readable JSON
```

```
IMAGE                            DIGEST           SIZE        BUILT
redis:7-alpine                   abc123def456    12.4 MB  2026-03-10T12:00:00Z
nginx:alpine                     deadbeef1234     8.1 MB  2026-03-10T11:00:00Z
alpine:latest                    cafebabe9876     3.2 MB  2026-03-09T08:30:00Z
```

### prune

Remove outdated cache entries, keeping only the most recently built binary for each image name:

```bash
oci2bin prune            # delete old entries, print space freed
oci2bin prune --dry-run  # show what would be deleted without deleting
```

### diff

Compare the filesystem contents of two oci2bin binaries:

```bash
oci2bin diff ./redis_old ./redis_new
```

```
- /usr/bin/redis-trib.rb   (12.3 KB)
+ /usr/bin/redis-sentinel  (1.2 MB)
M /usr/bin/redis-server    (1.1 MB -> 1.2 MB)
M /etc/redis/redis.conf    (512 B -> 768 B)

1 added, 1 removed, 2 modified
```

Exits with status 0 if the filesystems are identical, or 1 if there are differences.

---

## Testing

```bash
make test-unit               # unit tests only, no Docker required (~5s)
make test                    # full suite, requires Docker and a built image
make test-c                  # C unit tests (TAP, x86_64)
make test-python             # Python unit tests
make test-integration        # all integration tests (runtime, build, Redis, nginx)
make test-integration-redis  # Redis PING/SET/GET smoke test
make test-integration-nginx  # nginx HTTP 200 smoke test
```

The aarch64 C unit tests can be cross-compiled and run under qemu without real hardware:

```bash
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc qemu-user-static
make test-unit-aarch64
```

---

## How it works

The output file is a [polyglot](https://sysfatal.github.io/polyglottar-en.html): simultaneously a valid ELF64 executable and a valid POSIX tar archive. The two formats place their magic bytes at non-overlapping offsets:

```
Byte   0-3:   7f 45 4c 46   ELF magic  (kernel identifies it as an executable)
Byte 257-262: 75 73 74 61   ustar\0    (tar identifies it as an archive)
```

The 64-byte ELF header fits within the tar header's 100-byte filename field. When executed, the kernel processes the ELF; when passed to `tar` or `docker load`, the tar structure is read.

**File layout:**

```
[0-63]       ELF64 header  (embedded in the tar filename field)
[64-511]     Remaining tar header fields (ustar magic at byte 257)
[512-4095]   NUL padding   (page-aligns the loader for mmap)
[4096-~75K]  Loader binary (statically linked)
[~75K-end]   OCI image tar (manifest.json, config, layer tarballs)
```

**At runtime the loader:**

1. Opens itself via `/proc/self/exe` and reads the embedded OCI tar from the patched offset
2. Extracts the image layers into a temporary rootfs under `/tmp`
3. Patches the rootfs for single-UID namespace compatibility
4. Enters a user namespace (UID mapped to host UID)
5. Enters mount, PID, and UTS namespaces
6. Applies volume bind mounts before `chroot`
7. `chroot`s into the rootfs and `exec`s the entrypoint

The only runtime dependency on the target machine is `tar`.

**Rootfs patching for single-UID namespaces:**

An unprivileged user namespace allows exactly one UID mapping. Container UID 0 maps to the invoking user's UID on the host. Tools that attempt to change to a different UID (such as `apt`'s `_apt` sandbox user) would receive `EPERM`. The loader rewrites:

| File | Modification | Reason |
|---|---|---|
| `/etc/passwd` | All UIDs set to `0` (except `65534`) | `seteuid(0)` succeeds |
| `/etc/group` | All GIDs set to `0` (except `65534`) | Same for GID operations |
| `/etc/apt/apt.conf.d/99oci2bin` | `APT::Sandbox::User "root";` | Disables the apt sandbox |
| `/etc/resolv.conf` | Replaced with host resolver content | Symlink target not present in chroot |

**Security properties:**

- The process is unprivileged on the host; `CLONE_NEWUSER` does not confer real root
- Layer and config paths from the OCI manifest are validated against path traversal
- Volume container paths must be absolute and must not contain `..`
- Tar extraction uses `--no-same-permissions --no-same-owner` to prevent setuid bit restoration
- Temporary directories are created with `mkdtemp` (mode `0700`)

---

## References

- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [Polyglottar technique](https://sysfatal.github.io/polyglottar-en.html)
- [tar(5) format](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
- [Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
