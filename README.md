# oci2bin

**oci2bin** packages an OCI or Docker image as a single executable Linux file.
Copy it to another host and run it without installing Docker, starting a daemon,
or installing oci2bin on the target.

```bash
oci2bin alpine:latest    # produces ./alpine_latest
./alpine_latest          # runs the image
```

The result is mostly hermetic: it contains the image layers, OCI configuration,
and loader. A normal rootless run needs a Linux kernel with unprivileged user
namespaces and `tar`. Optional features can add dependencies.

With `oci2vm`, the artifact is deployed directly as a microVM. Copy it to a KVM
host and run it; VM mode requires `/dev/kvm` and a supported VMM backend.

By default, the file is also an
[ELF+TAR polyglot](https://en.wikipedia.org/wiki/Polyglot_(computing)): a native
Linux executable and a valid `docker save` archive.

## Documentation

The complete documentation is available at
**[latedeployment.github.io/oci2bin](https://latedeployment.github.io/oci2bin/)**.

| Guide | Covers |
|---|---|
| [Quickstart](https://latedeployment.github.io/oci2bin/quickstart/) | Install, build, run, copy, and reload an artifact |
| [Use cases](https://latedeployment.github.io/oci2bin/use-cases/) | Servers, homelabs, air gaps, secrets, and debugging |
| [Concepts](https://latedeployment.github.io/oci2bin/concepts/) | Artifact format, container mode, and VM mode |
| [Build binaries](https://latedeployment.github.io/oci2bin/build/) | Image sources, Dockerfiles, cross-architecture builds, signing, and reproducibility |
| [Run binaries](https://latedeployment.github.io/oci2bin/runtime/) | Environment, mounts, networking, resources, state, and process management |
| [Security](https://latedeployment.github.io/oci2bin/security/) | Rootless isolation, seccomp, Landlock, signatures, and secrets |
| [Operations](https://latedeployment.github.io/oci2bin/operations/) | systemd, stacks, lifecycle commands, logs, and backups |
| [Command reference](https://latedeployment.github.io/oci2bin/reference/commands/) | Build flags, runtime flags, and subcommands |
| [Feature inventory](https://latedeployment.github.io/oci2bin/reference/features/) | Complete feature checklist |
| [Dependencies](https://latedeployment.github.io/oci2bin/reference/dependencies/) | Build-host and target-host requirements |
| [How it works](https://latedeployment.github.io/oci2bin/internals/how-it-works/) | Loader flow and polyglot layout |

## Useful features

| Feature | Example |
|---|---|
| Package an image as one executable | `oci2bin redis:7-alpine` |
| Copy and run without Docker | `scp ./redis_7-alpine host:/opt/redis/ && ssh host /opt/redis/redis_7-alpine` |
| Deploy directly as a microVM | `oci2vm alpine:latest` |
| Build from a Dockerfile | `oci2bin build-dockerfile -o myapp.bin` |
| Build from a chroot directory | `oci2bin from-chroot ./rootfs -o myapp.bin` |
| Pull without a daemon | `oci2bin --pull-with skopeo redis:7-alpine` |
| Mount host directories | `./myapp -v /srv/data:/data` |
| Build for another architecture | `oci2bin --arch aarch64 alpine:latest` |
| Build a multi-architecture bundle | `oci2bin --arch all alpine:latest` |
| Sign and verify an artifact | `oci2bin sign --key private.pem --in myapp.bin` |
| Inject runtime secrets | `./myapp --secret /etc/myapp/key:/run/secrets/key` |
| Run a multi-binary stack | `oci2bin up -f stack.yaml` |
| Reload the default artifact into Docker | `docker load < myapp.bin` |

See the
[feature inventory](https://latedeployment.github.io/oci2bin/reference/features/)
for health checks, restart policies, compression, GPUs, SBOMs, notifications,
runtime hardening, and other specialized capabilities.

## Requirements

### Build host

The basic build path requires:

- Linux
- Python 3.9 or newer
- GCC and static libc support

When building from an image reference with `oci2bin IMAGE`, the builder
auto-detects Docker, Podman, or Skopeo. None of them is required when building
from an OCI layout, a chroot directory, or a Dockerfile based on `scratch` or
an OCI layout.

Run the host check to see what is installed and get distro-specific fix
commands:

```bash
./oci2bin doctor
```

### Target host

A normal namespace-mode artifact requires:

- Linux with unprivileged user namespaces enabled
- `tar` with gzip support

The target does not need Docker, a container daemon, or oci2bin itself.

VM mode instead requires `/dev/kvm` and either libkrun or cloud-hypervisor with
the appropriate VM assets. Features such as encrypted payloads, zstd
compression, userspace networking, and enforced signature checks add their own
dependencies.

Use the artifact's built-in readiness check on the machine where it will run:

```bash
./myapp.bin --doctor
```

See the
[dependency reference](https://latedeployment.github.io/oci2bin/reference/dependencies/)
for the complete feature-by-feature list and the libkrun runtime caveat.

## Install

Build from the repository:

```bash
git clone https://github.com/latedeployment/oci2bin.git
cd oci2bin
make
```

Run `./oci2bin` directly from the checkout, or install it system-wide:

```bash
sudo make install
```

Install for the current user instead:

```bash
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

## Quickstart

Build and run an image:

```bash
oci2bin redis:7-alpine
./redis_7-alpine redis-server --port 6379
```

Pass environment variables, mount persistent data, or override the image
command:

```bash
./redis_7-alpine \
  -e REDIS_LOGLEVEL=notice \
  -v /srv/redis:/data \
  redis-server --port 6379
```

Copy the artifact to another Linux host:

```bash
scp ./redis_7-alpine deploy@server.example.com:/opt/redis/redis_7-alpine
ssh deploy@server.example.com /opt/redis/redis_7-alpine
```

The default unencrypted and uncompressed artifact can also be imported into
Docker:

```bash
docker load < redis_7-alpine
```

Continue with the
[full quickstart](https://latedeployment.github.io/oci2bin/quickstart/).

## Common workflows

Build directly through Skopeo without Docker or Podman:

```bash
oci2bin --pull-with skopeo nginx:alpine my-nginx
```

Build from a Dockerfile without a Docker daemon:

```bash
oci2bin build-dockerfile -f Dockerfile --context . -o myapp.bin
```

Build from an existing root filesystem:

```bash
oci2bin from-chroot ./rootfs \
  --entrypoint /usr/bin/myapp \
  --workdir /app \
  -o myapp.bin
```

Deploy the image directly as a microVM:

```bash
oci2vm redis:7-alpine
./oci2vm_redis_7-alpine
```

Build for another CPU architecture:

```bash
oci2bin --arch aarch64 alpine:latest
```

`--arch all` produces a wrapper plus separate x86_64 and aarch64 artifacts.
Those three files must stay together; it is a multi-architecture bundle, not a
single fat executable.

Apply common runtime restrictions:

```bash
./myapp.bin \
  --read-only \
  --tmpfs /tmp \
  --net none \
  --cap-drop all \
  --memory 512m \
  --pids-limit 128
```

Sign and verify an artifact:

```bash
oci2bin sign --key signing.key --in myapp.bin
oci2bin verify --key signing.pub --in myapp.bin
```

Detailed examples live in the
[build](https://latedeployment.github.io/oci2bin/build/),
[runtime](https://latedeployment.github.io/oci2bin/runtime/), and
[security](https://latedeployment.github.io/oci2bin/security/) guides.

## Artifact boundaries

- A normal artifact is mostly self-contained, but still depends on the target
  kernel and `tar`.
- Encrypted (`--encrypt` or `--passphrase`) and whole-payload zstd-compressed
  (`--compress-binary`) artifacts are intentionally opaque to `docker load`.
- Feature-specific helpers are resolved only when the corresponding feature is
  used.
- `--offline-only` describes how an artifact was built; it is separate from the
  mostly hermetic packaging of the output.
- Namespace mode and VM mode have different host requirements. Check the target
  with `./artifact --doctor` before deployment.

## How it works

The default output is interpreted differently depending on how it is opened:

```text
Linux kernel  ──> ELF loader ──> rootless container or microVM
Docker/tar    ──> saved-image archive
```

The loader reads the embedded image configuration and layers, prepares the
root filesystem, applies the requested isolation and runtime settings, and
starts the image entrypoint.

See
[How it works](https://latedeployment.github.io/oci2bin/internals/how-it-works/)
for the file layout, extraction flow, namespace setup, and security boundaries.

## Development

```bash
make test-unit       # unit tests; no Docker required
make test            # full suite; Docker required
make lint            # configured linters
make check-version   # verify release-version consistency
```

Additional integration, VM, sanitizer, coverage, and fuzzing targets are
documented in the repository `Makefile`.

## License

oci2bin is released under the [MIT License](LICENSE).
