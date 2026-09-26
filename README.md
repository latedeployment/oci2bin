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

## Highlights

| Area | What oci2bin provides |
|---|---|
| Portable deployment | Copy one mostly self-contained file and run it without installing Docker, a daemon, or oci2bin on the target |
| Rootless isolation | User, mount, network, IPC, cgroup, and time namespaces with seccomp, Landlock, capabilities, and resource controls |
| Artifact trust | Signing, mandatory runtime signature policy, digest pinning, source-image Cosign verification, Rekor, and SLSA/in-toto attestations |
| Secrets and encryption | Read-only runtime secrets, TPM2-sealed credentials, and age or passphrase encryption for the embedded image |
| Flexible builds | Docker, Podman, Skopeo, OCI layouts, chroots, and a daemonless Dockerfile builder |
| Fast-start filesystem | Optional SquashFS rootfs mounts on demand with a disposable writable overlay, while the default OCI tar path remains unchanged |
| Production runtime | Health checks, restart policies, systemd units, pods, declarative stacks, logs, metrics, notifications, and audit logs |
| Architectures and hardware | x86_64 and aarch64 builds, multi-architecture bundles, GPU/CDI devices, direct microVM deployment, and rootless libkrun VM networking |
| OCI interoperability | Load the executable into Docker, push its image payload, or preserve and reconstruct the loader through a registry round trip |

## Related projects

Several projects also package containers as executables, but make different
format and runtime tradeoffs:

| Project | Approach | How oci2bin differs |
|---|---|---|
| [dockerc](https://github.com/NilsIrl/dockerc) | A focused, standalone rootless container executable built around `crun`, SquashFS, and FUSE | The default oci2bin artifact remains a Docker-loadable OCI image archive and emphasizes embedded trust policy, artifact inspection and reconstruction, offline workflows, and an optional VM path |
| [Bottlefire](https://bottlefire.dev/) / [bake](https://github.com/losfair/bake) | A Firecracker microVM executable that bundles the VM runtime assets | oci2bin uses rootless namespaces by default and can instead deploy through a supported VM backend; it prioritizes OCI round trips and one policy-bearing artifact across both modes |

The projects overlap around portable container artifacts while exploring
different executable formats, runtime components, and isolation boundaries.

## Security highlights

Security controls are available at the artifact, extraction, isolation, and
workload layers:

- Execution is rootless and daemonless by default. The container's root user
  maps to an unprivileged host user.
- A default seccomp filter and Landlock filesystem sandbox reduce the runtime
  surface when the host supports them. Custom and generated seccomp profiles,
  AppArmor profiles, and SELinux labels are also supported.
- Read-only roots, tmpfs mounts, capability controls, network isolation,
  default-deny egress allowlists, cgroup v2 limits, and `--strict` provide a
  fail-closed hardening path.
- Artifacts can be signed, verified at runtime, or built with a mandatory
  embedded signature policy. Digest pinning, source-image Cosign verification,
  Rekor entries, and provenance attestations extend the chain of trust.
- Embedded image payloads can be encrypted with age recipients or a
  passphrase; the executable loader and routing metadata remain readable so
  Linux can start the file. Runtime secrets are mounted read-only; TPM2-sealed
  secrets are staged in memory rather than disk-backed storage.
- Untrusted image layers are extracted defensively: set-ID bits and file
  capabilities are removed, extended attributes are allowlisted, and symlink
  traversal protections are applied.
- For a stronger isolation boundary, `oci2vm` deploys and runs the workload
  directly as a microVM.

A locked-down namespace-mode run can be expressed directly:

```bash
./myapp.bin \
  --read-only \
  --tmpfs /tmp \
  --net none \
  --cap-drop all \
  --memory 512m \
  --pids-limit 128 \
  --strict
```

See the [security guide](https://latedeployment.github.io/oci2bin/security/)
for threat boundaries, requirements, and complete hardening examples.

## Selected features

| Feature | Example |
|---|---|
| Package an image as one executable | `oci2bin redis:7-alpine` |
| Copy and run without Docker | `scp ./redis_7-alpine host:/opt/redis/ && ssh host /opt/redis/redis_7-alpine` |
| Deploy directly as a microVM | `oci2vm alpine:latest` |
| Build from a Dockerfile without Docker | `oci2bin build-dockerfile -o myapp.bin` |
| Build from a chroot | `oci2bin from-chroot ./rootfs -o myapp.bin` |
| Pull without a daemon | `oci2bin --pull-with skopeo redis:7-alpine` |
| Build reproducibly with digest pinning | `oci2bin --reproducible --pin-digest auto app:latest app.bin` |
| Build fully offline from an OCI layout | `oci2bin --offline-only --oci-dir ./layout app:latest app.bin` |
| Build for another architecture | `oci2bin --arch aarch64 alpine:latest` |
| Build a multi-architecture bundle | `oci2bin --arch all alpine:latest` |
| Keep writable state between runs | `./myapp.bin --overlay-persist /srv/myapp/state` |
| Skip layer extraction on repeat launches | on by default (`~/.cache/oci2bin/rootfs`); `./myapp.bin --rootfs-cache off` to opt out |
| Avoid extracting layers at startup | `oci2bin --rootfs-format squashfs app:latest app.bin && ./app.bin --lazy` |
| Publish a port from a rootless VM | `./app.bin --vm --net userspace -p 8080:80` |
| Run with health and restart policies | `./myapp.bin --health-cmd /healthcheck --restart on-failure:5` |
| Run a pod or declarative stack | `oci2bin up -f stack.yaml -d` |
| Generate a systemd unit | `oci2bin systemd ./myapp.bin` |
| Inspect or compare artifacts | `oci2bin inspect ./myapp.bin` / `oci2bin diff old.bin new.bin` |
| Compare extraction, lazy, and VM startup | `oci2bin benchmark ./myapp.bin --modes extract,lazy,vm` |
| Generate an SBOM | `oci2bin sbom ./myapp.bin` |
| Use GPUs or CDI devices | `./myapp.bin --gpus all` |
| Reload the default artifact into Docker | `docker load < myapp.bin` |

The [feature inventory](https://latedeployment.github.io/oci2bin/reference/features/)
contains the complete build, runtime, security, VM, and operations surface.

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
| [Benchmarks](https://latedeployment.github.io/oci2bin/benchmarks/) | Startup latency, peak RSS, reliability, and mode comparisons |
| [Command reference](https://latedeployment.github.io/oci2bin/reference/commands/) | Build flags, runtime flags, and subcommands |
| [Feature inventory](https://latedeployment.github.io/oci2bin/reference/features/) | Complete feature checklist |
| [Dependencies](https://latedeployment.github.io/oci2bin/reference/dependencies/) | Build-host and target-host requirements |
| [How it works](https://latedeployment.github.io/oci2bin/internals/how-it-works/) | Loader flow and polyglot layout |

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

SquashFS lazy mode requires `mksquashfs` on the build host and `squashfuse`
plus `fuse-overlayfs`, `/dev/fuse`, and `user_allow_other` enabled in
`/etc/fuse.conf` on the target.

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

Packagers stage the install with `DESTDIR`; only `PREFIX` ends up in the
installed files:

```bash
make install DESTDIR="$PWD/pkgroot" PREFIX=/usr
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

The builder handles multi-stage builds (`FROM ... AS`, `COPY --from`),
heredocs, `SHELL`, exec-form `RUN`, `COPY --chmod` and Docker's `${VAR:-default}`
expansion; `RUN` runs in `WORKDIR` as root (see the build guide for the
limitations).

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

Give a libkrun VM rootless outbound networking and publish only selected
inbound TCP ports:

```bash
./oci2vm_redis_7-alpine --net userspace -p 6379:6379
```

Build an optional directly mountable rootfs and skip OCI layer extraction on
each start:

```bash
oci2bin --rootfs-format squashfs app:latest app.bin
./app.bin --lazy
```

This artifact retains the OCI tar for inspection and `docker load`, so it is
larger than a tar-only or SquashFS-only design. Age encryption cannot be
combined with this mode because the independently mountable filesystem would
otherwise expose the plaintext image.

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
- `--rootfs-format squashfs` appends a second rootfs representation for
  `--lazy`; it retains the OCI tar and therefore remains Docker-loadable, at
  the cost of a larger artifact.
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
make check-packaging # stage `make install` and run the installed oci2bin/oci2vm
```

Additional integration, VM, sanitizer, coverage, and fuzzing targets are
documented in the repository `Makefile`.

## License

oci2bin is released under the [MIT License](LICENSE).
