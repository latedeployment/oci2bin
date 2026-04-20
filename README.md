# oci2bin

**oci2bin** converts any Docker (OCI) image into a single executable file. The output runs as a rootless container on any Linux machine — without Docker, without a daemon, and without any installation on the target.

```bash
oci2bin alpine:latest    # produces ./alpine_latest
./alpine_latest            # runs the container
```

## What you can do

| | Feature | One-liner |
|---|---------|-----------|
| 📦 | **Pack any image** | `oci2bin redis:7-alpine` |
| 🏃 | **Run anywhere, no Docker** | `scp redis_7-alpine remote: && ssh remote ./redis_7-alpine` |
| 🏗️ | **Build from a chroot** | `oci2bin from-chroot ./rootfs -o myapp.bin` |
| 📄 | **Build from a Dockerfile** | `oci2bin build-dockerfile -o myapp.bin` |
| 🔐 | **Inject secrets at runtime** | `./myapp --secret /run/secrets/key:/run/secrets/key` |
| 🔑 | **TPM2-sealed secrets** | `./myapp --secret tpm2:mykey` |
| 🔒 | **memfd_secret protection** | Secrets are kernel-protected (no page cache, no swap) on Linux ≥ 5.14 |
| 🌐 | **SSH agent in builds** | `RUN --mount=type=ssh git clone git@github.com:...` |
| 💾 | **Persistent build cache** | `RUN --mount=type=cache,target=/var/cache/apt apt-get install ...` |
| 🖥️ | **Run as a VM** | `oci2vm alpine:latest` |
| 🏛️ | **Cross-arch builds** | `oci2bin --arch aarch64 alpine:latest` |
| 🎭 | **Fat binaries (x86+arm)** | `oci2bin --arch all alpine:latest` |
| 📁 | **Volume mounts** | `./myapp -v /data:/data` |
| 🔇 | **Read-only container** | `./myapp --read-only` |
| 🛡️ | **Custom seccomp profile** | `./myapp --seccomp profile.json` |
| 🔬 | **Diff two images** | `oci2bin diff image_v1 image_v2` |
| 🔏 | **Sign the binary** | `oci2bin sign myapp.bin --key priv.pem` |
| 🩺 | **Health check** | `oci2bin healthcheck myapp.bin` |
| 📊 | **Live stats** | `oci2bin top` |
| 🔄 | **systemd unit** | `oci2bin systemd myapp.bin` |
| 📦 | **SBOM generation** | `oci2bin sbom myapp.bin` |
| 🤖 | **AI/MCP integration** | `oci2bin mcp-serve` |
| ♻️ | **Reconstruct from registry** | `oci2bin reconstruct myapp.bin` |
| 💿 | **Reloadable into Docker** | `docker load < myapp.bin` |

The output is an [ELF+TAR polyglot](https://en.wikipedia.org/wiki/Polyglot_(computing)): simultaneously a native Linux executable and a valid `docker save` tar archive.

See below [How it works](#how-it-works).

## Table of contents

- [Getting started](#getting-started)
  - [Installation](#installation)
- [Building binaries](#building-binaries)
  - [Cross-architecture builds](#cross-architecture-builds)
  - [Injecting files at build time](#injecting-files-at-build-time)
  - [Merging image layers](#merging-image-layers)
  - [Stripping images](#stripping-images)
  - [Squashing layers](#squashing-layers)
  - [Verifying image signatures (cosign)](#verifying-image-signatures-cosign)
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
  - [Prometheus metrics socket](#prometheus-metrics-socket)
  - [Exit codes](#exit-codes)
- [Isolation and security](#isolation-and-security)
  - [Networking](#networking)
  - [Read-only containers](#read-only-containers)
  - [Capabilities](#capabilities)
  - [Seccomp filter](#seccomp-filter)
    - [Generating a minimal seccomp profile](#generating-a-minimal-seccomp-profile)
  - [Debugging with gdb](#debugging-with-gdb)
  - [Clock offset (time namespace)](#clock-offset-time-namespace)
  - [Audit logging](#audit-logging)
  - [Running as non-root](#running-as-non-root)
  - [Custom hostname](#custom-hostname)
  - [Exposing host devices](#exposing-host-devices)
- [Process management](#process-management)
  - [Init process and zombie reaping](#init-process-and-zombie-reaping)
  - [Running in background](#running-in-background)
  - [Named containers and lifecycle management](#named-containers-and-lifecycle-management)
  - [Interactive and TTY mode](#interactive-and-tty-mode)
- [Subcommands](#subcommands)
  - [exec](#exec)
  - [inspect](#inspect)
  - [list](#list)
  - [prune](#prune)
  - [diff](#diff)
  - [reconstruct](#reconstruct)
  - [push](#push)
  - [sbom](#sbom)
  - [update](#update)
  - [run](#run)
  - [systemd](#systemd)
  - [healthcheck](#healthcheck)
  - [ps](#ps)
  - [stop](#stop)
  - [logs](#logs)
  - [checkpoint](#checkpoint)
  - [restore](#restore)
  - [top](#top)
- [Testing](#testing)
  - [Security linting](#security-linting)
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

#### Multi-arch fat binaries

`--arch all` builds both x86_64 and aarch64 variants and emits a thin wrapper shell script that auto-selects the correct binary at runtime using `uname -m`:

```bash
oci2bin --arch all alpine:latest
# produces:
#   alpine_latest          ← wrapper script (any host)
#   alpine_latest_x86_64   ← ELF for x86_64
#   alpine_latest_aarch64  ← ELF for aarch64
```

The wrapper and the arch-specific binaries must remain in the same directory.

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

Default removed prefixes: `usr/share/doc/`, `usr/share/man/`, `usr/share/info/`, `usr/share/locale/`, `usr/share/i18n/`, `var/cache/apt/`, `var/lib/apt/lists/`, `tmp/`.

Use `--strip-prefix` to strip different paths instead of the built-in defaults (each use also implies `--strip`):

```bash
# Strip only pip cache and compiled Python files
oci2bin --strip-prefix usr/lib/python3/dist-packages/tests/ \
        --strip-prefix root/.cache/pip/ \
        python:3.12-slim my-python

# Strip a Go module cache
oci2bin --strip-prefix root/go/pkg/mod/cache/ golang:1.22 my-go
```

`--strip-prefix` values must not start with `/` or contain `..`.

#### Package-manager auto-detection

Add `--strip-auto` to pre-scan image layers and automatically add extra cache paths for any package managers found:

| Detected | Extra paths stripped |
|---|---|
| `apt` / `dpkg` | `var/cache/apt/`, `var/lib/apt/lists/` |
| `apk` | `var/cache/apk/`, `etc/apk/cache/` |
| `pip` | `root/.cache/pip/` |
| `npm` | `root/.npm/_cacache/`, `usr/lib/node_modules/.cache/` |
| `dnf` / `yum` | `var/cache/dnf/`, `var/cache/yum/` |
| `gem` | `root/.gem/cache/` |
| `go` | `root/go/pkg/mod/cache/` |
| `cargo` | `root/.cargo/registry/cache/` |
| Python stdlib | `usr/lib/python3.X/{test,tests,unittest,turtledemo,...}/` |

```bash
oci2bin --strip --strip-auto ubuntu:22.04 my-ubuntu
```

### Squashing layers

`--squash` merges all image layers into a single squashed layer before packaging. This reduces the number of layers and can shrink the output binary for images with many overlapping writes:

```bash
oci2bin --squash ubuntu:22.04 ubuntu-squashed
```

Combine with `--compress` to choose the layer compression format (default: gzip):

```bash
oci2bin --squash --compress zstd ubuntu:22.04 ubuntu-squashed
```

`--compress zstd` requires the `zstd` binary to be installed. Whiteout entries are processed correctly so the squashed layer faithfully represents the final filesystem state.

### Verifying image signatures (cosign)

`--verify-cosign` checks the OCI image's Sigstore/cosign signature before packaging:

```bash
oci2bin --verify-cosign redis:7-alpine
```

If verification fails, a warning is printed but the build continues. Use `--require-cosign` to abort on failure:

```bash
oci2bin --require-cosign redis:7-alpine
```

Specify a local public key with `--cosign-key`:

```bash
oci2bin --require-cosign --cosign-key /etc/keys/trusted.pub redis:7-alpine
```

Requires the `cosign` binary to be installed. With `--require-cosign`, the build aborts if `cosign` is not found.

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

Separately, the builder keeps a per-layer tar cache under `~/.cache/oci2bin/layers/` (or `$XDG_CACHE_HOME/oci2bin/layers/` when set). Layer blobs are keyed by their `rootfs.diff_ids`, so repeated builds can skip re-extracting unchanged layers from the saved OCI tar. Pass `--no-cache` to disable that per-layer cache for a single build; this does not disable the top-level `--cache` output-binary cache.

### Reproducible builds and digest pinning

After pulling, oci2bin prints the content-addressed digest to stderr:

```
oci2bin: image digest: redis@sha256:abc123...
```

When `--cache` is active, the cache key includes the digest so that `redis:latest` updates produce a fresh cache entry rather than reusing a stale binary. If the image has no registry origin (locally built), the digest lookup is skipped with a warning and the tag-only key is used.

`--self-update-url URL` embeds the URL of a signed update manifest into the binary metadata. At runtime, `--check-update` and `--self-update` fetch that manifest, verify its detached signature with the user-supplied `--verify-key`, and then compare versions and hashes before replacing the binary.

`--pin-digest auto` keeps the legacy SHA-256 behavior. Stronger hashes are also supported with an explicit prefix such as `--pin-digest sha512:auto` or `--pin-digest sha512:<hex>`. On startup, the loader recomputes the canonical digest (with the digest field zeroed before hashing) before extraction and aborts if it does not match. This is most useful together with signatures: the digest gives a stable integrity assertion, while the external key provides the trust anchor.

### VM-mode binaries (oci2vm)

`oci2vm` is a symlink to `oci2bin` that builds binaries which run in VM mode by default — no `--vm` flag needed at runtime. The output is named `oci2vm_<image>` so that the embedded loader detects the invocation name and enables VM mode automatically.

```bash
oci2vm redis:7-alpine          # -> oci2vm_redis_7-alpine (runs as VM by default)
./oci2vm_redis_7-alpine        # starts a VM, no --vm required
./oci2vm_redis_7-alpine --net host redis-server --port 6380
```

This is equivalent to building with `oci2bin` and always running with `--vm`, but removes the need to remember the flag. You can also rename or symlink any oci2bin binary to a name starting with `oci2vm` to get the same effect.

### Embedding the loader for reconstruction

By default, a polyglot binary is self-sufficient but not self-reconstructing, so if you lose the `.img` file you cannot rebuild it from the Docker image alone, because the loader binary is not stored there. The two `--embed-loader-*` flags fix this by persisting the loader inside the Docker image so that `oci2bin reconstruct` can rebuild the polyglot from any Docker image name or saved tar.

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

#### TPM2-sealed secrets via systemd-creds

`--secret tpm2:CREDENTIAL_NAME[:CONTAINER_PATH]` decrypts a TPM2-sealed credential at container start and places the plaintext inside the container. The credential is decrypted using `systemd-creds decrypt` (from systemd ≥ 250) and written as a mode-0400 file on the container's tmpfs. The plaintext is zeroed in memory immediately after writing.

```bash
# Seal a secret with the TPM2 at image build time
systemd-creds encrypt --name=dbpass /dev/stdin /etc/credstore/dbpass.cred

# Unseal and inject at container start (no plaintext on disk)
./my-app --secret tpm2:dbpass                        # → /run/secrets/dbpass
./my-app --secret tpm2:dbpass:/run/secrets/db_pass   # custom path
```

**Requirements:** `systemd-creds` must be in `PATH`; the host must have a reachable TPM2 device. The credential name may contain only alphanumeric characters, `-`, `_`, and `.`.

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

### Prometheus metrics socket

`--metrics-socket PATH` starts a small Unix-domain socket server that exports
Prometheus text metrics for the container cgroup. The socket accepts one
connection at a time, writes the current sample, and closes the connection.
Samples are refreshed every 5 seconds while the container is running.

```bash
./my-app --metrics-socket /tmp/my-app.metrics.sock
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/my-app.metrics.sock")
print(s.recv(65535).decode(), end="")
PY
```

The exported metrics come from cgroup v2:

- `oci2bin_cpu_usage_usec`
- `oci2bin_cpu_user_usec`
- `oci2bin_cpu_system_usec`
- `oci2bin_cpu_nr_periods`
- `oci2bin_cpu_nr_throttled`
- `oci2bin_cpu_throttled_usec`
- `oci2bin_memory_current`
- `oci2bin_pids_current`

This feature requires cgroup v2 and a writable cgroup subtree. If the socket
cannot be created, container startup fails with an error.

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
| **libkrun** (default when available) | Linux (KVM) | **No** — libkrun bundles its own kernel internally | `libkrun-dev` at build time |
| **cloud-hypervisor** | Linux (KVM); full VM control | **Yes** — you must embed a vmlinux (see below) | `cloud-hypervisor` in `$PATH`, embedded kernel |

`--vm` requires `/dev/kvm`.

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

The container process runs as root inside a user namespace. The host UID is mapped to UID 0 — no real privilege is granted on the host. `/etc/resolv.conf` from the host is copied into the rootfs so DNS resolution works out of the box.

#### Custom DNS

Override the DNS servers and search domains inside the container:

```bash
./myapp --dns 1.1.1.1 --dns 8.8.8.8          # use Cloudflare + Google DNS
./myapp --dns 192.168.1.1 --dns-search corp.example.com
```

`--dns` and `--dns-search` write a custom `resolv.conf` into the container rootfs, overriding the host's resolver. May each be repeated up to 8 times.

#### Custom /etc/hosts entries

Inject hostname→IP mappings with `--add-host`:

```bash
./myapp --add-host db.internal:10.0.0.5
./myapp --add-host redis.local:127.0.0.1 --add-host api.local:10.1.2.3
```

Entries are appended to the container's `/etc/hosts` before exec. May be repeated up to 32 times.

#### Userspace networking with slirp4netns or pasta

`--net slirp` and `--net pasta` give the container a fully isolated network
namespace with real outbound TCP/UDP without requiring root. This uses
[slirp4netns](https://github.com/rootless-containers/slirp4netns) or
[pasta](https://passt.top/passt/) respectively.

```bash
./myapp --net slirp             # outbound internet via slirp4netns
./myapp --net pasta             # outbound internet via pasta (faster, IPv6)
./myapp --net slirp:8080:80     # slirp + port-forward host:8080 → ctr:80
./myapp -p 8080:80              # shorthand for the above (implies --net slirp)
./myapp -p 8080:80 -p 8443:443  # multiple ports (may be repeated)
```

`-p HOST_PORT:CTR_PORT` is a Docker-style shorthand for `--net slirp:HOST:CTR`. It automatically enables slirp networking if `--net` was not already set.

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

`--network-alias NAME` registers a hostname alias resolvable via `--add-host` injection into each container's `/etc/hosts`. In shared-net mode all containers share `127.0.0.1` loopback, so aliases resolve to the loopback address:

```bash
oci2bin pod run \
    --net shared \
    --network-alias myapp \
    --network-alias backend \
    ./envoy \
    ./myapp
```

### Read-only containers

`--read-only` mounts the rootfs read-only via overlayfs. Writes go to a temporary upper layer discarded on exit. The on-disk rootfs is never modified.

```bash
./alpine_latest --read-only /bin/sh -c 'touch /test'
```

If overlayfs is not available, a warning is printed and the container runs read-write.

### Lazy rootfs extraction (experimental)

`--lazy` enables experimental on-demand rootfs paging via `userfaultfd(2)` (Linux 4.3+). When the kernel supports UFFD, the loader prints a warning that lazy mode is experimental and falls back to full extraction. On kernels without UFFD support the flag is silently treated as a no-op with a diagnostic message.

```bash
./my-app --lazy /bin/sh
# → oci2bin: --lazy: userfaultfd available (Linux ≥4.3); lazy rootfs paging
#   is experimental — falling back to full extraction
```

This flag is a no-op in the current release and is reserved for a future implementation that faults individual rootfs pages from the embedded tar on first access rather than extracting all layers up front.

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

#### Custom seccomp profiles

Load a Docker-compatible JSON seccomp profile with `--seccomp-profile`:

```bash
./my-app --seccomp-profile ./my-seccomp.json
```

The profile format is a subset of Docker's seccomp schema:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    { "names": ["read","write","exit","exit_group","brk","mmap","mprotect","munmap","rt_sigreturn"], "action": "SCMP_ACT_ALLOW" }
  ]
}
```

`defaultAction` must be `SCMP_ACT_ALLOW`, `SCMP_ACT_ERRNO`, or `SCMP_ACT_KILL`. When `defaultAction` is `ALLOW`, listed syscalls with non-ALLOW actions are blocked. When `defaultAction` is `ERRNO` or `KILL`, only the listed ALLOW syscalls are permitted. If the profile cannot be parsed, oci2bin falls back to the built-in default filter and prints a warning.

#### Generating a minimal seccomp profile

`--gen-seccomp FILE` traces the container's syscalls via ptrace and writes a
tight Docker-compatible allowlist JSON to `FILE`. Use this to produce a
least-privilege profile for production runs:

```bash
# Step 1: run the container through its normal workload while tracing
./redis_7-alpine --gen-seccomp redis.seccomp.json

# Step 2: use the generated profile in production
./redis_7-alpine --seccomp-profile redis.seccomp.json
```

The generated profile has `defaultAction: SCMP_ACT_ERRNO` and a single
`SCMP_ACT_ALLOW` entry listing every unique syscall observed during the trace
run. Forked and cloned child processes are traced automatically. Syscall names
are resolved using the loader's built-in name table, so no external tools are
required.

> **Tip:** Run the tracer against a representative workload — startup, warm-up
> requests, graceful shutdown — to ensure all syscalls are captured before
> locking down the profile.

### Debugging with gdb

`--gdb` launches `gdb` inside the container with the image entrypoint as the
debuggee — no manual `nsenter`, PID tracking, or custom debug images needed.

```bash
./my-app --gdb
# gdb is started with:  gdb --args <entrypoint> [args...]

# Override entrypoint to debug a specific binary:
./my-app --gdb --entrypoint /usr/bin/my-server -- --config /etc/my-server.conf
```

**What happens automatically:**

1. If `gdb` is not present in the container, the host's `/usr/bin/gdb` (or
   `/usr/local/bin/gdb`) is bind-mounted read-only at `/usr/bin/gdb` inside
   the rootfs.
2. seccomp is disabled for the session (gdb needs `ptrace` and many ancillary
   syscalls to operate). A notice is printed to stderr.
3. The loader execs `gdb --args <entrypoint> [args...]` inside the fully
   configured namespace — all volumes, secrets, environment variables, and
   networking are set up exactly as they would be for a normal run.

**Requirements:** `gdb` must be installed on the host (e.g. `dnf install gdb`
or `apt install gdb`). The container runs without seccomp, so use only in
development or trusted environments.

### Clock offset (time namespace)

`--clock-offset SECS` shifts the container's monotonic and boottime clocks by
the given number of seconds using a Linux time namespace (`CLONE_NEWTIME`,
kernel 5.6+). The wall clock is unaffected.

```bash
# Run as if the system started 3600 seconds ago (1 hour earlier)
./my-app --clock-offset -3600

# Freeze-test time-sensitive logic by shifting far into the future
./my-app --clock-offset 86400
```

Useful for deterministic replay testing, license-expiry simulations, and
anything that reads `CLOCK_MONOTONIC` or `CLOCK_BOOTTIME`. A warning is
printed and the container runs normally if the kernel does not support
`CLONE_NEWTIME`.

### Audit logging

`--audit-log FILE` appends one JSON object per lifecycle event to `FILE`. Pass
`-` to write the audit stream to stderr instead of a file.

```bash
./my-app --audit-log /var/log/my-app.audit.jsonl
./my-app --audit-log - /bin/true 2>audit.log
```

The loader emits newline-delimited JSON for these events: `start`, `mount`,
`cap_set`, `exec`, `exit`, and `stop`. Timestamps are generated from
`clock_gettime(CLOCK_REALTIME)` and written in UTC ISO-8601 form.

Example lines:

```json
{"event":"start","time":"2026-04-18T18:40:12Z","pid":12345,"image":"/home/user/my-app","name":"","net":"host","caps":"0x0"}
{"event":"cap_set","time":"2026-04-18T18:40:12Z","pid":1,"caps":"0xa80425fb","drop_all":false,"drop_mask":"0x0","add_mask":"0x0"}
{"event":"exit","time":"2026-04-18T18:40:14Z","pid":12345,"exit_code":0}
{"event":"stop","time":"2026-04-18T18:40:14Z","pid":12345,"exit_code":0}
```

`exit` records either `exit_code` or `signal`, depending on how the workload
finished. `stop` records the final container stop status after cleanup.

#### AppArmor and SELinux confinement

Apply an AppArmor profile or SELinux exec label with `--security-opt`:

```bash
./my-app --security-opt apparmor=docker-default
./my-app --security-opt label=type:svirt_sandbox_file_t
```

AppArmor support requires building with `-DHAVE_APPARMOR -lapparmor`. SELinux support requires `-DHAVE_SELINUX -lselinux`. Without these flags the option is accepted but a warning is printed at runtime. Both options are non-fatal if the underlying system call fails.

### Running as non-root

By default the container process runs as UID 0 inside the user namespace. Use `--user` to run as a different numeric UID:

```bash
./my-app --user 1000          # run as UID 1000, GID 1000
./my-app --user 1000:2000     # run as UID 1000, GID 2000
```

On rootless runs, oci2bin first tries to install a full `0-65535` container UID/GID range by calling `newuidmap` and `newgidmap` with the current user's ranges from `/etc/subuid` and `/etc/subgid`. When that succeeds, normal in-container user switching works without rewriting `/etc/passwd` or `/etc/group`.

If the helpers or subordinate ID ranges are unavailable, oci2bin falls back to the older single-ID user namespace where only container UID/GID `0` is mapped to the invoking host user. In that mode it patches the extracted rootfs so common privilege-dropping tools keep working. Pass `--no-userns-remap` to force that fallback even when subordinate ranges are configured.

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

### Named containers and lifecycle management

`--name NAME` assigns a name to the container. Combined with `--detach`, it writes a JSON state file to `$HOME/.cache/oci2bin/containers/<name>.json` and redirects the container's stdout/stderr to a log file at the same location. This enables the `ps`, `stop`, and `logs` subcommands.

```bash
# Start a named container in the background
./redis --detach --name myredis

# List running containers
oci2bin ps

# Tail container logs
oci2bin logs -f myredis

# Stop it gracefully
oci2bin stop myredis
```

### Interactive and TTY mode

`-t` / `--tty` allocates a pseudo-terminal for the container, even if stdin is not a terminal. `-i` / `--interactive` keeps stdin open for piped input without a PTY. Combine them as `-it` for an interactive shell session:

```bash
# Interactive shell with TTY
./alpine_latest -it /bin/sh

# Feed commands via stdin (no TTY)
echo "ls /" | ./alpine_latest -i /bin/sh

# Explicit TTY even when stdin is redirected
./alpine_latest -t /bin/sh
```

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
oci2bin sign --key signing.key --hash-algorithm sha512 --in ./redis_7-alpine --out ./redis_7-alpine.signed

# Sign a detached update manifest or checksum file
oci2bin sign-file --key signing.key --hash-algorithm sha512 --in ./update.json --out ./update.json.sig
```

### Verifying

```bash
# Verify before running
oci2bin verify --key signing.pub --in ./redis_7-alpine
echo $?   # 0 = OK, 1 = not signed, 2 = invalid

# Loader-side verification: abort before any write if signature is wrong
./redis_7-alpine --verify-key /etc/oci2bin/trusted.pub

# Verify a detached manifest signature
oci2bin verify-file --key signing.pub --in ./update.json --sig ./update.json.sig
```

`oci2bin sign` and `oci2bin sign-file` accept `--hash-algorithm sha256|sha512` and default to `sha512`. `verify` and `verify-file` auto-detect the hash from the stored signature metadata, while still accepting legacy SHA-256 signatures.

`--verify-key` checks the signature at startup, before any rootfs extraction.
If verification fails the process exits immediately without writing a single byte
to disk.

For self-updating binaries, point `--self-update-url` at a JSON manifest and sign that manifest with `sign-file`. The manifest format is:

```json
{
  "version": "1.4.2",
  "url": "https://example.com/releases/mybinary",
  "digest": "sha512:abc123..."
}
```

`digest` accepts `sha256` or `sha512`. Legacy manifests with a top-level `sha256` field are still accepted for compatibility. Store the detached signature next to it as `update.json.sig`. Runtime update checks require `--verify-key /path/to/vendor.pub`.

---

## Building without Docker

### from-chroot

Build a self-contained binary directly from a chroot directory — no Docker daemon required. The directory is packed into a single OCI image layer and processed by the standard build pipeline.

```bash
oci2bin from-chroot /path/to/rootfs -o myapp.bin
oci2bin from-chroot /path/to/rootfs \
    --entrypoint /usr/bin/myapp --serve \
    --env PORT=8080 \
    --workdir /app \
    --arch arm64 \
    -o myapp-arm64.bin
```

Options:

| Flag | Description |
|------|-------------|
| `-o PATH` | Output binary path (default: `<dirname>.bin`) |
| `--entrypoint CMD [ARGS...]` | Container entrypoint |
| `--cmd CMD [ARGS...]` | Default command arguments |
| `--env KEY=VAL` | Environment variable (repeatable) |
| `--workdir PATH` | Working directory inside the container |
| `--arch amd64\|arm64` | Target CPU architecture |
| `--user UID[:GID]` | Default user |
| `--label KEY=VAL` | Image label (repeatable) |
| `-- [BUILD_OPTIONS]` | Extra flags passed to the build pipeline |

The chroot directory may contain any Linux rootfs. The builder strips setuid/setgid bits and skips `proc`, `sys`, and `dev` (they are created at runtime).

### build-dockerfile

Build a self-contained binary from a Dockerfile — no Docker daemon required. Supports a BuildKit-compatible subset of Dockerfile syntax including `RUN --mount`.

```bash
oci2bin build-dockerfile                     # uses ./Dockerfile, output <dir>.bin
oci2bin build-dockerfile -o redis.bin        # explicit output name
oci2bin build-dockerfile -f myapp.dockerfile --context ./src -o myapp.bin

# Pass secrets and build args
oci2bin build-dockerfile \
    --build-secret id=npmrc,src=$HOME/.npmrc \
    --build-arg VERSION=1.2.3 \
    -o myapp.bin
```

#### Supported instructions

| Instruction | Notes |
|-------------|-------|
| `FROM scratch` | Empty rootfs |
| `FROM <oci-layout-dir>` | Local OCI image layout directory |
| `FROM <image>` | Docker pull (requires `docker` in PATH) |
| `COPY [--chown=] <src...> <dst>` | Copy from build context |
| `ADD <src> <dst>` | Same as COPY for local sources |
| `RUN [--mount=...] <cmd>` | Execute via `unshare + chroot` (no daemon) |
| `ENV KEY=VAL` | Set environment variable |
| `ENTRYPOINT ["cmd","arg"]` | JSON array or shell form |
| `CMD ["cmd","arg"]` | JSON array or shell form |
| `WORKDIR /path` | Set working directory (created if absent) |
| `LABEL key=value` | Image label |
| `USER uid[:gid]` | Default user |
| `EXPOSE port` | Informational; not enforced |
| `ARG NAME[=default]` | Build-time variable |

#### RUN --mount types

Mount options are applied inside a private mount namespace for the duration of the `RUN` step and do not appear in the final image layer.

**`type=secret`** — inject a host secret file (not baked into the layer):

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm install
```

```bash
oci2bin build-dockerfile --build-secret id=npmrc,src=$HOME/.npmrc -o app.bin
```

**`type=ssh`** — forward the host SSH agent (`$SSH_AUTH_SOCK`):

```dockerfile
RUN --mount=type=ssh \
    git clone git@github.com:example/private-repo.git /app
```

**`type=cache`** — persistent cache directory across builds:

```dockerfile
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y build-essential
```

Cache is stored at `~/.cache/oci2bin/build-cache/<id>`.

**`type=bind`** — bind-mount from build context (read-only by default):

```dockerfile
RUN --mount=type=bind,source=scripts,target=/scripts,rw \
    /scripts/configure.sh
```

**`type=tmpfs`** — in-memory scratch space:

```dockerfile
RUN --mount=type=tmpfs,target=/tmp/scratch \
    ./build.sh
```

#### Snap-like distribution

Once built, the binary is fully self-contained:

```bash
# Build once
oci2bin build-dockerfile -o myapp

# Distribute and run anywhere
scp myapp remote-host:
ssh remote-host ./myapp
```

---

## Secure secrets at runtime

When `--secret` is used at runtime, oci2bin attempts to back the secret with
`memfd_secret(2)` (Linux ≥ 5.14, `CONFIG_SECRETMEM=y`). The secret data is
placed in a memory region that is excluded from the kernel's direct mapping,
crash dumps, and swap. The container sees a normal file path
(`/run/secrets/<name>`) via bind-mount of `/proc/self/fd/<n>`.

On older kernels, oci2bin falls back transparently to a read-only bind-mount of
the host file. The log line indicates which path was taken:

```
oci2bin: secret /run/secrets/mykey -> /run/secrets/mykey (memfd_secret)
oci2bin: secret /run/secrets/mykey -> /run/secrets/mykey (read-only)
```

TPM2-sealed secrets (decrypted via `systemd-creds`) also use `memfd_secret` when
available, so the decrypted plaintext never enters the page cache.

---

## Subcommands

### exec

Attach to a running container by PID and execute a command inside its namespaces. Requires `nsenter(1)` from `util-linux`.

```bash
# Start a container in the background
./redis_7-alpine --detach
PID=$!

# Exec a shell inside the running container
oci2bin exec $PID /bin/sh

# Run a one-shot command
oci2bin exec $PID redis-cli PING

# With argument separator
oci2bin exec $PID -- redis-cli -p 6379 INFO server
```

`exec` joins the user, mount, PID, UTS, and IPC namespaces of the target process. The process must still be running — use `--detach` or run in another terminal.

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

`--live PID BINARY` compares a running container's live filesystem against the image embedded in BINARY. Requires access to `/proc/<PID>/root` (same user or root):

```bash
# Compare live container filesystem against the original image
oci2bin diff --live $CONTAINER_PID ./redis_7-alpine
```

This is useful for detecting drift between the running filesystem and the packaged image (e.g. after exec-ing into the container and modifying files).

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

### push

Re-load an oci2bin binary into Docker and push it to a registry:

```bash
oci2bin push ./redis_7-alpine registry.example.com/myredis:latest
```

The binary is loaded via `docker load`, tagged as the target, pushed, and the local tag cleaned up. Requires `docker` and write access to the registry.

### sbom

Generate a Software Bill of Materials (SBOM) from an oci2bin binary by extracting the embedded OCI rootfs and reading its package database:

```bash
oci2bin sbom ./redis_7-alpine                        # SPDX 2.3 JSON (default)
oci2bin sbom ./redis_7-alpine --format cyclonedx     # CycloneDX 1.4 JSON
oci2bin sbom ./redis_7-alpine > sbom.spdx.json
```

Supported package managers: `dpkg` (Debian/Ubuntu), `apk` (Alpine), `rpm` (Fedora/RHEL). The output goes to stdout; status messages go to stderr.

### update

Rebuild an existing oci2bin binary from the same Docker image it was built from:

```bash
oci2bin update ./redis_7-alpine
```

Reads the embedded image name from the binary's metadata block, pulls the latest version of that image, rebuilds the polyglot, and atomically replaces the original file. Useful for updating binaries when the upstream image is refreshed.

`--check` performs the comparison only:

```bash
oci2bin update --check ./redis_7-alpine
```

If the binary was built with `--self-update-url`, `oci2bin update --check --verify-key PUBKEY BINARY` delegates to the embedded signed-manifest flow instead of Docker digest comparison.

### run

Build and execute an image in one step without keeping the generated binary:

```bash
oci2bin run alpine:latest -- /bin/sh -c 'echo hello'
oci2bin run --strip redis:7-alpine -- redis-server --version
```

Build options come before `IMAGE`. Everything after `IMAGE` is passed to the temporary binary as runtime arguments.

### systemd

Generate a ready-to-use systemd unit file for a binary:

```bash
oci2bin systemd ./redis_7-alpine --restart always > redis_7-alpine.service
oci2bin systemd ./vaultwarden --user > ~/.config/systemd/user/vaultwarden.service
```

The generated unit derives its description and name from embedded metadata and OCI labels when available, uses the current user for system units, and defaults to `Restart=on-failure`.

### healthcheck

Run the embedded OCI `HEALTHCHECK` command:

```bash
oci2bin healthcheck ./redis_7-alpine
oci2bin healthcheck ./redis_7-alpine --pid 12345
```

Without `--pid`, the healthcheck runs in a fresh container execution. With `--pid`, `oci2bin` uses `nsenter` to run the check inside the namespaces of an already-running container process.

### ps

List named containers that were started with `--detach --name`:

```bash
oci2bin ps
```

```
NAME                 PID      STATUS   BINARY                         STARTED
myredis              12345    running  redis_7-alpine                 2026-03-21T10:00:00
myweb                12346    stopped  nginx_alpine                   2026-03-21T09:00:00
```

### stop

Gracefully stop a named container:

```bash
oci2bin stop myredis
```

Sends `SIGTERM`, waits up to 10 seconds, then sends `SIGKILL` if still running. Removes the state file on completion.

### logs

Print or follow the log output of a named container started with `--detach --name`:

```bash
oci2bin logs myredis          # print all logs
oci2bin logs -f myredis       # follow (tail -f)
oci2bin logs --follow myredis
```

### checkpoint

Create a CRIU checkpoint for a named detached container:

```bash
oci2bin checkpoint myredis
```

This runs `criu dump --tree <PID> --images-dir ~/.local/share/oci2bin/checkpoints/myredis` after verifying that the saved state file still matches the running process. The `criu` binary must be installed. `checkpoint` operates on containers started with `--detach --name`.

### restore

Restore a CRIU checkpoint created with `oci2bin checkpoint`:

```bash
oci2bin restore myredis
```

This runs `criu restore --images-dir ~/.local/share/oci2bin/checkpoints/myredis --shell-job`. The checkpoint directory must already exist, and `criu` must be installed.

### top

Show a live view of named running containers:

```bash
oci2bin top
oci2bin top --once
```

The display reports CPU percentage, memory, PID count, uptime, and binary name for each running container listed under `~/.cache/oci2bin/containers/`. When a cgroup v2 path is visible for the process, `top` reads memory and PID counts from that cgroup; otherwise it falls back to `/proc`.

---

## Testing

```bash
make test-unit               # unit tests only, no Docker required (~5s)
make test                    # full suite, requires Docker and a built image
make test-c                  # C unit tests (TAP, x86_64)
make test-python             # Python unit tests
make test-shellcheck         # shellcheck on all shell scripts
make test-integration        # all integration tests (runtime, build, Redis, nginx)
make test-integration-redis  # Redis PING/SET/GET smoke test
make test-integration-nginx  # nginx HTTP 200 smoke test
make test-integration-services  # Redis (container+VM) + 5 service images (container+VM)
```

### Fuzzing

libFuzzer harnesses target the JSON helpers and MCP JSON-RPC parser. Requires clang with `-fsanitize=fuzzer`.

```bash
make fuzz-json       # fuzz JSON helpers (json_get_string, json_get_array, etc.)
make fuzz-seccomp    # fuzz seccomp profile parser
make fuzz-parse-opts # fuzz parse_opts + load_env_file
make fuzz-mcp        # fuzz MCP JSON-RPC parser (mcp-serve input surface)
make fuzz-all        # build all harnesses
```

Run a harness against the seed corpus:

```bash
./build/fuzz_mcp_jsonrpc tests/fuzz/corpus/mcp -max_len=65536 -jobs=4
```

Seed inputs for the MCP fuzzer live in `tests/fuzz/corpus/mcp/` and cover:
empty input, truncated JSON, deeply nested objects, oversized strings, null bytes
mid-string, invalid UTF-8, and method names at maximum length.

### Security linting

```bash
make lint                # run all linters in sequence
make lint-clang          # clang extended warnings (-Wall -Wextra -Werror + security flags)
make lint-scan-build     # clang static analyzer (null-deref, memory leaks, POSIX API misuse)
make lint-shellcheck     # shellcheck on oci2bin and all .sh scripts
make lint-semgrep        # semgrep OWASP / security-audit rules (requires semgrep)
```

`make lint-scan-build` uses `clang --analyze` with interprocedural analysis. The
`DeprecatedOrUnsafeBufferHandling` checker is disabled because the C11 Annex K
`*_s` functions are not available in glibc; all other security checkers are
enabled. Additional tools useful for one-off audits:

| Tool | Purpose |
|---|---|
| `cppcheck --enable=all src/loader.c` | Static analysis, value-flow, style |
| `flawfinder src/loader.c` | Dangerous C function scanner with CWE refs |
| `bandit -r scripts/` | Python security linter |
| `checksec --file=build/loader-x86_64` | Binary hardening flags (NX, stack canary, RELRO) |

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
4. Plans the user namespace mapping: subordinate `0-65535` remap when `newuidmap`/`newgidmap` and `/etc/subuid`/`/etc/subgid` are available, otherwise the single-ID fallback
5. Applies the compatibility rootfs patch only for the single-ID fallback or microVM mode
6. Enters the user namespace and installs the chosen UID/GID mapping
7. Enters mount, PID, and UTS namespaces
8. Applies volume bind mounts before `chroot`
9. `chroot`s into the rootfs and `exec`s the entrypoint

The only mandatory runtime dependency on the target machine is `tar`. Rootless subordinate-ID remapping additionally uses `newuidmap` and `newgidmap` when they are installed, but falls back cleanly when they are absent.

**Rootfs patching for the single-ID fallback:**

When subordinate-ID remapping is unavailable, oci2bin falls back to a single-ID user namespace. Container UID 0 maps to the invoking user's UID on the host, and other container IDs are unmapped. Tools that attempt to change to a different UID (such as `apt`'s `_apt` sandbox user) would otherwise receive `EPERM`. In that fallback mode the loader rewrites:

| File | Modification | Reason |
|---|---|---|
| `/etc/passwd` | All UIDs set to `0` (except `65534`) | `seteuid(0)` succeeds |
| `/etc/group` | All GIDs set to `0` (except `65534`) | Same for GID operations |
| `/etc/apt/apt.conf.d/99oci2bin` | `APT::Sandbox::User "root";` | Disables the apt sandbox |
| `/etc/resolv.conf` | Replaced with host resolver content | Symlink target not present in chroot |
| `/usr/bin/setpriv` | Replaced with no-op shim (skips flags, execs command) | `setpriv --reuid` fails in the single-ID fallback |
| `gosu`, `su-exec` | Replaced with no-op shim (skips user arg, execs command) | Same — user switching is impossible |

**Security properties:**

- The process is unprivileged on the host; `CLONE_NEWUSER` does not confer real root
- Layer and config paths from the OCI manifest are validated against path traversal
- Volume container paths must be absolute and must not contain `..`
- Tar extraction uses `--no-same-permissions --no-same-owner` to prevent setuid bit restoration
- Temporary directories are created with `mkdtemp` (mode `0700`)

---

## MCP server (AI tool integration)

`oci2bin` binaries expose a [Model Context Protocol](https://modelcontextprotocol.io/) server for AI tools via the `mcp-serve` subcommand:

```bash
./my-app mcp-serve [--allow-net]
```

The server reads newline-delimited JSON-RPC 2.0 requests from stdin and writes responses to stdout. It exposes six tools:

| Tool | Description |
|------|-------------|
| `run_container` | Start a container from a local oci2bin binary |
| `exec_in_container` | Run a command inside a running container (via `nsenter`) |
| `list_containers` | List all tracked containers and their status |
| `stop_container` | Stop a container (SIGTERM then SIGKILL) |
| `inspect_image` | Return OCI metadata (entrypoint, env) for an image binary |
| `get_logs` | Tail the container's log output |

**Security defaults enforced in MCP mode:**

- Network is forced to `--net none` unless `--allow-net` was passed to `mcp-serve` **and** the caller explicitly requests `net="host"`.
- `--device` flags are never exposed through MCP.
- Container names are validated: only `[a-zA-Z0-9._-]` characters allowed.
- Image paths must be absolute and clean (no `..` components).

**Inspect support:**

Any oci2bin binary supports `OCI2BIN_INSPECT=1` in its environment: it prints a JSON object with `entrypoint`, `cmd`, and `env` from the embedded OCI config to stdout, then exits. The `inspect_image` MCP tool uses this mechanism.

**Example (connect from Claude Desktop):**

```json
{
  "mcpServers": {
    "oci2bin": {
      "command": "/path/to/my-app",
      "args": ["mcp-serve"]
    }
  }
}
```

---

## References

- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [Polyglottar technique](https://sysfatal.github.io/polyglottar-en.html)
- [tar(5) format](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
- [Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
