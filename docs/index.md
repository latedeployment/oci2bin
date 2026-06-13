# oci2bin

`oci2bin` converts an OCI or Docker image into one executable Linux file.

The output file is both:

- a native Linux executable that starts the image as a rootless container
- a valid tar archive that can be loaded back into Docker with `docker load`

```bash
oci2bin redis:7-alpine
scp redis_7-alpine server:
ssh server ./redis_7-alpine
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
        +-- docker load < myapp imports the image again
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
scp alpine_latest host:
ssh host ./alpine_latest /bin/uname -a
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
- cgroup resource limits need cgroup v2
- `--vm` needs a VM backend such as libkrun or cloud-hypervisor support
- encrypted payloads need the matching `age` identity or passphrase at runtime
- compressed payloads need `zstd` at runtime

Run this on a target host to see what is available:

```bash
oci2bin doctor
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
- [Security](security.md): rootless isolation, seccomp, capabilities,
  signatures, secrets, and limits
- [Feature Inventory](reference/features.md): the complete feature checklist
- [Dependencies](reference/dependencies.md): build-host and target-host
  requirements per feature (and the libkrun caveat)
- [How It Works](internals/how-it-works.md): loader flow and polyglot layout

