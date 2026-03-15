# oci2bin

**oci2bin** converts any Docker (OCI) image into a single executable file. The output runs as a rootless container on any Linux machine — without Docker, without a daemon, and without any installation on the target.

```bash
oci2bin alpine:latest    # produces ./alpine_latest
./alpine_latest            # runs the container
```

The output file is also a valid tar archive accepted by `docker load`:

```bash
docker load < alpine_latest
```

See below [How it works](#how-it-works).

## Table of contents

- [Getting started](#getting-started)
  - [Installation](#installation)
- [Building binaries](#building-binaries)
  - [Cross-architecture builds](#cross-architecture-builds)
  - [Injecting files at build time](#injecting-files-at-build-time)
  - [Merging image layers](#merging-image-layers)
  - [Stripping images](#stripping-images)
  - [Using OCI image layout](#using-oci-image-layout-no-docker-daemon)
  - [Caching builds](#caching-builds)
  - [Reproducible builds and digest pinning](#reproducible-builds-and-digest-pinning)
  - [VM-mode binaries (oci2vm)](#vm-mode-binaries-oci2vm)
  - [Embedding the loader for reconstruction](#embedding-the-loader-for-reconstruction)
    - [Registry persistence](#registry-persistence)
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
  - [reconstruct](#reconstruct)
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

### Installation

Clone the repository and build the loader:

```bash
git clone https://github.com/latedeployment/oci2bin
cd oci2bin
make          # compiles the loader into build/
make install  # installs oci2bin to /usr/local/bin (PREFIX=/usr/local)
```

`PREFIX` can be overridden: `make install PREFIX=~/.local`. After `make install`, `oci2bin` is on your PATH. Alternatively, run it directly from the repository root without installing.

After cloning the repository, run `oci2bin` with an image name. The loader is compiled on first use; the image is pulled automatically if not already present locally.

```bash
oci2bin alpine:latest        # output: ./alpine_latest
oci2bin nginx:1.25 my-nginx  # explicit output name
```

---

## Building binaries

### Cross-architecture builds

Build an aarch64 binary on an x86_64 host with `--arch aarch64`:

```bash
# Fedora
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc

oci2bin --arch aarch64 alpine:latest
```

The sysroot defaults to `/usr/aarch64-redhat-linux/sys-root/fc43`. Override with:

```bash
AARCH64_SYSROOT=/path/to/sysroot oci2bin --arch aarch64 alpine:latest
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
oci2bin --cache alpine:latest   # builds and caches
oci2bin --cache alpine:latest   # returns cached binary immediately
```

The cache key includes the first 12 hex characters of the image's sha256 digest, so tag updates are detected. See [list](#list), [prune](#prune) for cache management.

### Reproducible builds and digest pinning

After pulling, oci2bin prints the content-addressed digest to stderr:

```
oci2bin: image digest: redis@sha256:abc123...
```

When `--cache` is active, the cache key includes the digest so that `redis:latest` updates produce a fresh cache entry rather than reusing a stale binary. If the image has no registry origin (locally built), the digest lookup is skipped with a warning and the tag-only key is used.

### VM-mode binaries (oci2vm)

`oci2vm` is a symlink to `oci2bin` that builds binaries which run in VM mode by default — no `--vm` flag needed at runtime. The output is named `oci2vm_<image>` so that the embedded loader detects the invocation name and enables VM mode automatically.

```bash
oci2vm redis:7-alpine          # -> oci2vm_redis_7-alpine (runs as VM by default)
./oci2vm_redis_7-alpine        # starts a VM, no --vm required
./oci2vm_redis_7-alpine --net host redis-server --port 6380
```

This is equivalent to building with `oci2bin` and always running with `--vm`, but removes the need to remember the flag. You can also rename or symlink any oci2bin binary to a name starting with `oci2vm` to get the same effect.

### Embedding the loader for reconstruction

By default, a polyglot binary is self-sufficient but not self-reconstructing — if you lose the `.img` file you cannot rebuild it from the Docker image alone, because the loader binary is not stored there. The two `--embed-loader-*` flags fix this by persisting the loader inside the Docker image so that `oci2bin reconstruct` can rebuild the polyglot from any Docker image name or saved tar.

**`--embed-loader-layer`** — adds the loader binary as a dedicated OCI layer (`<loader-dir>/loader` inside the container filesystem) and records its location in image labels:

```bash
oci2bin --embed-loader-layer redis:7-alpine
docker load < redis_7-alpine   # layer is stored in Docker's image store
oci2bin reconstruct redis:7-alpine --output redis_7-alpine  # rebuilds from Docker
```

The directory (default `.oci2bin/`) will appear in the container's filesystem (read-only, ~75 KB). This is the recommended option — the binary is self-contained and survives push/pull through any OCI registry.

**`--embed-loader-labels`** — encodes the loader binary as chunked base64 strings in the image config labels. No filesystem layer is added:

```bash
oci2bin --embed-loader-labels redis:7-alpine
oci2bin reconstruct redis:7-alpine --output redis_7-alpine
```

The default chunk size is 6144 binary bytes per label (~8 KB base64 each). Use `--label-chunk-size BYTES` to tune this if your registry enforces per-label or total-config size limits:

```bash
oci2bin --embed-loader-labels --label-chunk-size 4096 redis:7-alpine
```

Both approaches store `<prefix>.sha256`, `<prefix>.arch`, and strategy-specific labels in the image config (prefix defaults to `oci2bin.loader`). `oci2bin reconstruct` verifies the sha256 before rebuilding.

**`--loader-dir DIR`** — overrides the directory inside the container filesystem where the loader binary is placed when using `--embed-loader-layer` (default: `.oci2bin`). Use this to avoid naming conflicts with application directories:

```bash
oci2bin --embed-loader-layer --loader-dir .myapp-meta redis:7-alpine
```

**`--label-prefix PREFIX`** — overrides the label key prefix for all embed metadata (default: `oci2bin.loader`). Use this when the default prefix conflicts with existing image labels or internal naming conventions:

```bash
oci2bin --embed-loader-layer --label-prefix myorg.loader redis:7-alpine
oci2bin reconstruct redis:7-alpine --label-prefix myorg.loader
```

The same prefix must be passed to both `oci2bin` at build time and `oci2bin reconstruct` at reconstruction time.

#### Registry persistence

Both embedding strategies are designed to survive a full registry round-trip. OCI registries store each layer blob and the image config separately, content-addressed by SHA256. Because the loader layer and the `<prefix>.*` labels (default `oci2bin.loader.*`) are part of the image config and layer list, they are preserved exactly through `docker push` and `docker pull` — there is nothing special for the registry to strip or rewrite.

```bash
# Build once, push to registry
oci2bin --embed-loader-layer redis:7-alpine
docker load < redis_7-alpine
docker tag redis:7-alpine registry.example.com/redis:7-alpine
docker push registry.example.com/redis:7-alpine

# Rebuild from registry on any machine — no local .img file needed
docker pull registry.example.com/redis:7-alpine
oci2bin reconstruct registry.example.com/redis:7-alpine
```

The label approach (`--embed-loader-labels`) works the same way — config labels are part of the image manifest that registries store verbatim. The only registry-specific consideration is per-label or total-config size limits; use `--label-chunk-size` to reduce individual label size if your registry enforces one. See [`--embed-loader-layer`](#embedding-the-loader-for-reconstruction), [`--embed-loader-labels`](#embedding-the-loader-for-reconstruction), and [`--label-chunk-size`](#embedding-the-loader-for-reconstruction) for details.

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

### Resource limits (cgroup v2)

`--memory`, `--cpus`, and `--pids-limit` enforce hard limits across the entire
container process tree using Linux cgroup v2. Unlike `--ulimit`, these limits
apply to all forked children as well.

```bash
./my-app --memory 512m           # hard memory limit (k/m/g suffix)
./my-app --cpus 0.5              # 50% of one CPU core
./my-app --pids-limit 100        # max 100 PIDs in the container
./my-app --memory 1g --cpus 2 --pids-limit 256
```

Requires cgroup v2 (`/sys/fs/cgroup/cgroup.controllers` must exist). If cgroup
v2 is unavailable, a warning is printed and the container runs unconstrained.
The loader creates `/sys/fs/cgroup/oci2bin-<pid>/`, moves itself in, sets the
limits, then calls `unshare(CLONE_NEWCGROUP)` so the container only sees its
own cgroup subtree. The cgroup dir is removed on exit.

### Exit codes

The container process exit code is forwarded to the calling shell:

```bash
./alpine_latest /bin/sh -c 'exit 42'
echo $?   # 42
```

---

## VM isolation (--vm)

`--vm` runs the container inside a hardware-isolated microVM instead of a Linux
namespace. The OCI rootfs becomes the VM's root filesystem; the container
process runs as PID 1 via a minimal in-binary init.

### Prerequisites

Two backends are supported:

| Backend | When to use | Kernel required? | Extra requirements |
|---|---|---|---|
| **libkrun** (default when available) | macOS (HVF) or Linux (KVM) | **No** — libkrun bundles its own kernel internally | `libkrun-dev` at build time |
| **cloud-hypervisor** | Linux (KVM); full VM control | **Yes** — you must embed a vmlinux (see below) | `cloud-hypervisor` in `$PATH`, embedded kernel |

`--vm` requires `/dev/kvm` on Linux. On macOS, libkrun uses the Hypervisor
framework (HVF) — no KVM is needed.

### Building with libkrun

```bash
make loader-libkrun     # builds build/loader-libkrun-$(ARCH)
oci2bin alpine myapp    # auto-detects libkrun loader if present
```

Requires the `libkrun` and `libkrun-dev` packages (available on Fedora, Ubuntu,
and from [containers/libkrun](https://github.com/containers/libkrun)).

libkrun is an in-process microVM library that includes its own guest kernel, so
the output binary does not need a separate kernel blob embedded. Just pass
`--vm` at runtime and it works.

### Building the kernel (cloud-hypervisor only)

The cloud-hypervisor backend requires an external Linux kernel embedded in the
binary. This is **not needed for libkrun**.

```bash
make kernel             # downloads Linux 6.1, builds vmlinux (~10 min first time)
oci2bin alpine myapp --kernel build/vmlinux   # embeds kernel in polyglot
```

The embedded kernel adds ~10 MB to the binary. The initramfs is built at
runtime from the extracted rootfs if not pre-embedded.

### Custom VM defaults

Override the default vCPU count (1) and memory (256 MiB) at build time:

```bash
make VM_CPUS=4 VM_MEM_MB=512             # Makefile
VM_CPUS=4 VM_MEM_MB=512 oci2bin alpine myapp  # oci2bin wrapper
```

These defaults apply when `--cpus` or `--memory` are not passed at runtime.

### Usage

```bash
# Basic: run command inside microVM
./myapp --vm /bin/echo hello

# Custom resources
./myapp --vm --memory 512m --cpus 2 /bin/sh

# Persistent state across runs (ext2 data disk, cloud-hypervisor path)
./myapp --vm --overlay-persist ./state /bin/sh

# Volume mount via virtiofs (cloud-hypervisor) or mapped volume (libkrun)
./myapp --vm -v $(pwd):/work /bin/sh

# Explicit VMM selection
./myapp --vmm cloud-hypervisor /bin/echo hello
./myapp --vmm /opt/bin/cloud-hypervisor /bin/echo hello
```

### Options

| Flag | Description |
|---|---|
| `--vm` | Enable microVM isolation |
| `--vmm PATH` | VMM binary or name (`cloud-hypervisor`; default is libkrun if available) |
| `--memory SIZE` | VM RAM (e.g. `256m`, `1g`; default 256 MiB) |
| `--cpus N` | Number of vCPUs (default 1) |
| `--overlay-persist DIR` | Persist a 1 GiB ext2 data disk in `DIR/oci2bin-data.ext2` |
| `-v HOST:CTR` | Mount host directory inside the VM |
| `--debug` | Print verbose runtime diagnostics (execution path, VM config, extracted paths) |

### Notes

- The binary itself becomes the VM's `/init`. When the kernel starts, it detects
  `OCI2BIN_VM_INIT=1` in the cmdline and runs `vm_init_main()` instead of the
  host extraction path.
- Volume mounts use **virtiofs** (cloud-hypervisor) or libkrun mapped volumes.
  `virtiofsd` must be in `$PATH` for the cloud-hypervisor path.
- `--overlay-persist` in VM mode creates a separate ext2 block device. It does
  not use overlayfs (that is the namespace-mode behaviour).

## Isolation and security

### Networking

By default, containers share the host network stack. Use `--net none` for a fully isolated network namespace:

```bash
./alpine_latest --net none /bin/sh -c 'ip link'   # only loopback visible
./alpine_latest --net host /bin/sh -c 'curl ...'  # host networking (default)
```

The container process runs as root inside a user namespace. The host UID is mapped to UID 0 — no real privilege is granted on the host. `/etc/resolv.conf` from the host is copied into the rootfs so DNS resolution works.

#### Userspace networking with slirp4netns or pasta

`--net slirp` and `--net pasta` give the container a fully isolated network
namespace with real outbound TCP/UDP without requiring root. This uses
[slirp4netns](https://github.com/rootless-containers/slirp4netns) or
[pasta](https://passt.top/passt/) respectively.

```bash
./myapp --net slirp             # outbound internet via slirp4netns
./myapp --net pasta             # outbound internet via pasta (faster, IPv6)
./myapp --net slirp:8080:80     # slirp + port-forward host:8080 → ctr:80
```

`slirp4netns` or `pasta` must be installed (`dnf install slirp4netns` /
`apt install slirp4netns` or `dnf install passt`). The loader forks the
network helper after `unshare(CLONE_NEWNET)`, sends it a ready signal, and
waits for it to configure the `tap0` interface. On container exit the helper
is sent `SIGTERM`.

### Sharing namespaces between containers

Two containers can share the same network or IPC namespace using `--net container:<PID>` and `--ipc container:<PID>`. This is useful for sidecar patterns (e.g. a proxy sharing network with a service) or for processes that communicate via SysV shared memory or message queues.

```bash
# Start the main container and capture its PID
./myapp --net none --detach
MAIN_PID=$!

# Start a sidecar that joins the same network namespace
./sidecar --net container:$MAIN_PID

# Share the IPC namespace (SysV semaphores, message queues, shared memory)
./sidecar --ipc container:$MAIN_PID
```

Both flags can be combined:

```bash
./sidecar --net container:$MAIN_PID --ipc container:$MAIN_PID
```

**Scope of sharing:**

| Flag | What is shared |
|------|---------------|
| `--net container:<PID>` | Network interfaces, routing table, port bindings |
| `--ipc container:<PID>` | SysV semaphores, message queues, SysV shared memory (`shmget`/`shmat`) |

POSIX shared memory (`shm_open`, `/dev/shm`) lives in the mount namespace and is not shared automatically. To share it, bind-mount the host's `/dev/shm` into both containers with `-v /dev/shm:/dev/shm`, or pass the target container's `/dev/shm` via `-v /proc/<PID>/root/dev/shm:/dev/shm`.

**Privilege note:** Joining a network or IPC namespace created by another container requires that both containers were started by a process with matching user namespace ownership, or that the joining process has root privileges. If the `setns()` call fails, a clear error is printed.

### Pod mode (multi-container)

`oci2bin pod run` starts multiple binaries sharing network and IPC namespaces —
a pod primitive without any orchestrator.

```bash
oci2bin pod run \
    --net shared \
    --ipc shared \
    ./envoy \
    ./myapp \
    ./fluentbit
```

The command:
1. Creates a lightweight "pause" process via `unshare` to hold the shared namespaces
2. Starts each binary with `--net container:<pause_pid>` and/or `--ipc container:<pause_pid>`
3. If any binary exits with a non-zero status, sends `SIGTERM` to the others
4. Reports the worst non-zero exit code seen

SIGTERM and SIGINT are forwarded to all children. Use with `--detach` in the
individual binaries for fully background pods.

### Read-only containers

`--read-only` mounts the rootfs read-only via overlayfs. Writes go to a temporary upper layer discarded on exit. The on-disk rootfs is never modified.

```bash
./alpine_latest --read-only /bin/sh -c 'touch /test'
```

If overlayfs is not available, a warning is printed and the container runs read-write.

### Persistent state (--overlay-persist)

`--overlay-persist DIR` keeps the overlay upper layer between runs. Instead of
discarding writes on exit, changes accumulate in `DIR/upper`. On the next run
the same upper layer is used as a starting point.

```bash
./myapp --overlay-persist /var/lib/myapp/state   # first run — changes saved
./myapp --overlay-persist /var/lib/myapp/state   # second run — state preserved
```

Use cases:
- CLI tools that accumulate config (`~/.config`, shell history)
- Dev environments with installed packages that persist
- Staged rollouts: inspect `DIR/upper` before promoting as the new base

`DIR/upper` and `DIR/work` must be on the same filesystem. The immutable base
(extracted OCI rootfs) is never modified.

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

### Config file (--config)

All runtime options can be loaded from a simple `key=value` text file with
`--config PATH`. This avoids long command lines and allows per-application
defaults.

```ini
# /etc/myapp/oci2bin.conf
memory=512m
cpus=0.5
pids-limit=100
net=none
read-only
user=1000
```

```bash
./myapp --config /etc/myapp/oci2bin.conf
./myapp --config /etc/myapp/oci2bin.conf --memory 1g   # override file values
```

Lines starting with `#` or blank lines are ignored. A line `key=value` becomes
`--key value`. A line with no `=` (like `read-only`) becomes a boolean `--key`
flag. Nested `--config` is not allowed.

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

## Binary signing

oci2bin binaries can be signed with an ECDSA key. The signature block is
appended after the OCI tar and verified before any extraction occurs.

### Signing

```bash
# Generate a key pair
openssl ecparam -name prime256v1 -genkey -noout -out signing.key
openssl ec -in signing.key -pubout -out signing.pub

# Sign a binary (in-place or to a new file)
oci2bin sign --key signing.key --in ./redis_7-alpine
oci2bin sign --key signing.key --in ./redis_7-alpine --out ./redis_7-alpine.signed
```

### Verifying

```bash
# Verify before running
oci2bin verify --key signing.pub --in ./redis_7-alpine
echo $?   # 0 = OK, 1 = not signed, 2 = invalid

# Loader-side verification: abort before any write if signature is wrong
./redis_7-alpine --verify-key /etc/oci2bin/trusted.pub
```

`--verify-key` checks the signature at startup, before any rootfs extraction.
If verification fails the process exits immediately without writing a single byte
to disk.

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

### reconstruct

Rebuild a polyglot binary from a Docker image that was built with `--embed-loader-layer` or `--embed-loader-labels`. Accepts either a Docker image name (runs `docker save` internally) or a path to an existing tar or `.img` file:

```bash
# From a Docker image name
oci2bin reconstruct redis:7-alpine --output redis_7-alpine

# From a saved tar
oci2bin reconstruct ./backup.tar --output redis_7-alpine

# From an existing polyglot file
oci2bin reconstruct ./redis_7-alpine.img --output redis_7-alpine_new
```

By default the loader embedding (layer or labels) is stripped from the OCI data before rebuilding, producing a clean result identical to a fresh `oci2bin` build. Pass `--no-strip` to keep the embedding in the rebuilt binary:

```bash
oci2bin reconstruct redis:7-alpine --no-strip --output redis_7-alpine
```

`reconstruct` verifies the loader's SHA256 before rebuilding and exits with a non-zero status if the digest does not match or if no `oci2bin.loader.*` labels are present in the image.

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
make test-integration-services  # Redis (container+VM) + 5 service images (container+VM)
```

`test-integration-services` validates:
- `redis:7-alpine` (SET/GET in both container mode and `--vm`)
- `nginx:alpine`
- `caddy:2-alpine`
- `postgres:16-alpine`
- `memcached:1.6-alpine`
- `httpd:2.4-alpine`

The aarch64 C unit tests can be cross-compiled and run under qemu without real hardware:

```bash
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc qemu-user-static
make test-unit-aarch64
```

---

## How it works

The output file is a [polyglot](https://sysfatal.github.io/polyglottar-en.html): simultaneously a valid ELF64 executable and a valid POSIX tar archive, which is the OCI file format as well. The two formats place their magic bytes at non-overlapping offsets:

```
Byte   0-3:   7f 45 4c 46   ELF magic  (kernel identifies it as an executable)
Byte 257-262: 75 73 74 61   ustar\0    (tar identifies it as an archive)
```

The 64-byte ELF header fits within the tar header's 100-byte filename field. When executed, the kernel processes the ELF; when passed to `tar` or `docker load`, the tar structure is read.

**OCI images are tar archives:**

An OCI image (as produced by `docker save` or `skopeo copy`) is itself a POSIX tar archive containing:

```
manifest.json          — list of layers and the config blob digest
<sha256>.json          — image config (Entrypoint, Cmd, Env, WorkingDir, …)
<sha256>/layer.tar     — one gzip-compressed tar per filesystem layer
```

Each layer tar records filesystem additions, modifications, and deletions (whiteout files). The loader applies them in order — earlier layers first — so later layers win, exactly as a union filesystem would. The final result is a complete rootfs directory tree ready for `chroot`.

**File layout:**

```
[0-511]      Tar entry #1 header  (ELF header in filename field, ustar magic at byte 257)
[512-4095]   Tar entry #1 data: NUL padding  (page-aligns loader for mmap)
[4096-~75K]  Tar entry #1 data: loader binary  (statically linked)
[~75K-end]   Tar entries #2+: OCI image tar  (manifest.json, config, layer tarballs)
             Two 512-byte zero blocks  (tar EOF)
             OCI2BIN_META block  (image name, digest, version — outside the tar)
```

**What `docker load` sees:**

The loader binary is stored as tar entry #1, whose "filename" is the 64-byte ELF header — binary data that Docker does not recognise and silently skips. Entries #2 onwards are the unmodified `docker save` output (`manifest.json`, config blob, layer tarballs), so `docker load` imports exactly the original image. The loader binary is never written into Docker's image store. Any VM blobs (kernel, initramfs) and the metadata block are appended after the tar EOF markers and are completely invisible to Docker.

**At runtime the loader:**

1. Opens itself via `/proc/self/exe` and reads the embedded OCI tar from the patched offset
2. Parses `manifest.json` and the image config to find the layer list and runtime settings
3. Extracts each layer tar in order into a temporary rootfs under `/tmp`, applying whiteout deletions
4. Patches the rootfs for single-UID namespace compatibility
5. Enters a user namespace (UID mapped to host UID)
6. Enters mount, PID, and UTS namespaces
7. Applies volume bind mounts before `chroot`
8. `chroot`s into the rootfs and `exec`s the entrypoint

The only runtime dependency on the target machine is `tar`.

**Rootfs patching for single-UID namespaces:**

An unprivileged user namespace allows exactly one UID mapping. Container UID 0 maps to the invoking user's UID on the host. Tools that attempt to change to a different UID (such as `apt`'s `_apt` sandbox user) would receive `EPERM`. The loader rewrites:

| File | Modification | Reason |
|---|---|---|
| `/etc/passwd` | All UIDs set to `0` (except `65534`) | `seteuid(0)` succeeds |
| `/etc/group` | All GIDs set to `0` (except `65534`) | Same for GID operations |
| `/etc/apt/apt.conf.d/99oci2bin` | `APT::Sandbox::User "root";` | Disables the apt sandbox |
| `/etc/resolv.conf` | Replaced with host resolver content | Symlink target not present in chroot |
| `/usr/bin/setpriv` | Replaced with no-op shim (skips flags, execs command) | `setpriv --reuid` fails in single-UID namespace |
| `gosu`, `su-exec` | Replaced with no-op shim (skips user arg, execs command) | Same — user switching is impossible |

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
