# oci2bin

`oci2bin` converts an OCI or Docker image into one executable Linux file.

By default, the output file is both:

- a native Linux executable that starts the image as a rootless container
- a valid tar archive that can be loaded back into Docker with `docker load`

It is close to a **hermetic executable**: the image layers, OCI config, and
loader are embedded in one file. A normal run still needs two things from the
host: a Linux kernel that allows unprivileged user namespaces and `tar` to
unpack the root filesystem. Optional features add the requirements listed in
[Dependencies](reference/dependencies.md).

Encryption and whole-payload zstd compression deliberately trade away the
plain-tar half of the format. Those artifacts still execute, but cannot be
passed directly to `docker load`.

With `oci2vm`, this file is deployed directly as a VM: copy it to a KVM host
and run it to boot the image as a microVM. That mode needs `/dev/kvm` and its
selected VMM backend instead of unprivileged user namespaces.

Here, “hermetic” describes how the output is packaged. It is separate from the
`hermetic` marker that
[`--offline-only`](build.md#air-gap-builds) records to describe the build.

```bash
oci2bin redis:7-alpine # builds ./redis_7-alpine
scp ./redis_7-alpine deploy@server.example.com:/opt/redis/redis_7-alpine
ssh deploy@server.example.com /opt/redis/redis_7-alpine
```

There is no daemon on the target machine. There is no install step on the
target machine. The file carries the image payload and the loader code needed to
start it.

## The Short Version

```text
Docker or OCI image
        |
        v
oci2bin builds one file
        |
        +-- ./myapp runs the image rootlessly
        +-- docker load < myapp imports a default artifact again
```

Use it when you want container packaging without requiring a container runtime
on every host.

## First Example

```bash
oci2bin alpine:latest
./alpine_latest /bin/sh -c 'cat /etc/os-release'
```

Send it to another Linux host:

```bash
scp ./alpine_latest deploy@host.example.com:/usr/local/bin/alpine_latest
ssh deploy@host.example.com /usr/local/bin/alpine_latest /bin/uname -a
```

Load it back into Docker:

```bash
docker load < alpine_latest
```

## What It Is Good For

- shipping one binary to a server, VM, lab machine, CI worker, or appliance
- running containers on machines where Docker is not installed
- packaging homelab services with systemd units
- moving signed, reproducible, air-gap-friendly image artifacts
- producing rootless runtime bundles with explicit limits, mounts, secrets, and
  networking choices
- building from Docker images, OCI layouts, chroot directories, or Dockerfiles

## Important Boundaries

`oci2bin` is Linux-only.

The target machine needs a Linux kernel with user namespaces. Some features need
extra host support:

- `--net slirp` needs `slirp4netns`
- `--net pasta` needs `pasta`
- `--lazy` needs an artifact built with `--rootfs-format squashfs`,
  `squashfuse`, `fuse-overlayfs`, `/dev/fuse`, and `user_allow_other` enabled
  in `/etc/fuse.conf`
- cgroup resource limits need cgroup v2
- `--vm` needs `/dev/kvm` and a VM backend such as libkrun or
  cloud-hypervisor; rootless userspace VM networking is currently libkrun-only
- encrypted payloads need the matching `age` identity or passphrase at runtime
- compressed payloads need `zstd` at runtime

Run this on a target host to see what is available:

```bash
./artifact --doctor
```

## Where To Go Next

- [Quickstart](quickstart.md): install, build, run, copy, load into Docker
- [Use Cases](use-cases.md): practical examples for servers, secrets, systemd,
  air gaps, and debugging
- [Concepts](concepts.md): the file format and runtime model
- [Build Binaries](build.md): image sources, cross-arch, signing, compression,
  reproducibility, VM mode
- [Run Binaries](runtime.md): runtime flags for mounts, env, networking,
  resources, process management, and state
- [Benchmarks](benchmarks.md): compare extraction, lazy-mount, and VM startup
- [Security](security.md): rootless isolation, seccomp, capabilities,
  signatures, secrets, and limits
- [Operations](operations.md): systemd, lifecycle commands, stacks, backups,
  logs, and observability
- [Command Reference](reference/commands.md): build options, runtime options,
  and subcommands
- [Feature Inventory](reference/features.md): the complete feature checklist
- [Dependencies](reference/dependencies.md): build-host and target-host
  requirements per feature (and the libkrun caveat)
- [Environment Variables](reference/environment.md): every `OCI2BIN_*` and
  related variable, for run time and build time
- [How It Works](internals/how-it-works.md): loader flow and polyglot layout
