# Performance Benchmarks

`oci2bin benchmark` measures the complete path from invoking an artifact until
the requested command exits. It can compare normal OCI layer extraction,
SquashFS lazy mounting, and direct libkrun VM deployment on the same host.

## Quick Comparison

Build one SquashFS artifact, then benchmark both namespace rootfs paths:

```bash
oci2bin --rootfs-format squashfs alpine:latest alpine.bin
oci2bin benchmark ./alpine.bin \
  --modes extract,cached,lazy \
  --runs 20 \
  -- /bin/true
```

Add VM mode when the artifact uses the libkrun loader and `/dev/kvm` is
available:

```bash
oci2bin --libkrun alpine:latest alpine-vm.bin
oci2bin benchmark ./alpine-vm.bin \
  --modes extract,vm \
  --runs 20 \
  -- /bin/true
```

The `extract` mode runs with `--rootfs-cache off` and measures a full layer
extraction on every launch; `cached` is the default launch path once the
extracted-rootfs cache is warm (the warmup launch fills it). `cached` is
skipped for encrypted artifacts, which auto mode never caches.

The benchmark skips modes whose host prerequisites are unavailable. A mode
that starts but cannot run the command is reported as failed rather than being
silently omitted.

## Measurements

For each mode the report includes:

- first observed launch latency;
- minimum, median, mean, p95, maximum, and standard deviation for measured
  launches;
- peak resident memory (RSS), when `/usr/bin/time` is available;
- successful launches, total launches, and captured failures;
- artifact size and host kernel, architecture, and CPU details.

The first launch is deliberately shown separately. It is useful as a
cold-ish observation, but the benchmark does not drop the kernel page cache:
doing that requires root and would disturb every workload on the host. Warmup
launches are not included in the summary.

## Machine-Readable Results

Keep raw samples and host metadata as JSON:

```bash
oci2bin benchmark ./alpine.bin \
  --modes extract,lazy \
  --runs 50 \
  --json \
  --output benchmark.json \
  -- /bin/true
```

Commit or publish the JSON when comparing changes across revisions. Record
results on an otherwise quiet host, use the same command and run count, and
keep CPU power-management settings consistent.

## Choosing The Command

`/bin/true` isolates runtime startup and teardown. A real application command
measures runtime startup plus that application's initialization:

```bash
oci2bin benchmark ./app.bin --runs 20 -- app --version
```

The command must terminate. This benchmark reports launch reliability, not
the long-term availability of a service. Use the runtime health/restart
features and an external service monitor for uptime over hours or days.

## Prerequisites

Normal extraction needs the same user-namespace support as an ordinary
artifact run.

Lazy mode additionally needs:

- an artifact built with `--rootfs-format squashfs`;
- `squashfuse`, `fuse-overlayfs`, and an accessible `/dev/fuse`;
- `user_allow_other` enabled in `/etc/fuse.conf`.

`allow_other` is needed because the rootless FUSE mounts are created by the
host user before the runtime changes to the image's mapped UID. The temporary
mount tree remains private to the invoking user.

VM mode needs an accessible `/dev/kvm` and a usable VM backend. For a direct
rootfs deployment without an embedded kernel, build the artifact with
`--libkrun`.

Check the artifact and host before a run:

```bash
./app.bin --doctor
test -r /dev/kvm && test -w /dev/kvm && echo "KVM accessible"
```
