# Build Binaries

This page covers features that affect the generated file.

## Build From Docker Or Podman

```bash
oci2bin alpine:latest
oci2bin redis:7-alpine redis_7-alpine
```

If the image is not local, `oci2bin` pulls it. The image is saved as an OCI tar
payload, combined with the loader, and written as one executable file.

## Build From An OCI Layout

```bash
skopeo copy docker://redis:7-alpine oci:./redis-oci:latest
oci2bin --oci-dir ./redis-oci redis:7-alpine redis_7-alpine
```

The image argument is used for naming and embedded metadata. The content comes
from the OCI layout directory.

## Build From A Saved Tar

```bash
oci2bin --tar image.tar myimage:latest myimage.bin
```

Use this when another tool already produced a saved image tar.

## Build From A Chroot

```bash
oci2bin from-chroot ./rootfs -o app.bin \
  --entrypoint /usr/bin/app \
  --cmd '--serve' \
  --env APP_ENV=prod \
  --workdir /app \
  --user 1000:1000 \
  --label org.example.service=app
```

This path does not require Docker.

## Build From A Dockerfile Without Docker

```bash
oci2bin build-dockerfile -f Dockerfile -o app.bin --context .
```

Supported instructions:

- `FROM scratch`
- `FROM <oci-dir>`
- `FROM <image>`
- `COPY`
- `ADD`
- `RUN`
- `ENV`
- `ENTRYPOINT`
- `CMD`
- `WORKDIR`
- `LABEL`
- `USER`
- `EXPOSE`
- `ARG`

Supported `RUN --mount` types:

- `type=bind`
- `type=secret`
- `type=ssh`
- `type=cache`
- `type=tmpfs`

Examples:

```dockerfile
FROM scratch
COPY rootfs/ /
ENTRYPOINT ["/usr/bin/myapp"]
```

```dockerfile
FROM alpine:3.20
RUN --mount=type=cache,target=/var/cache/apk apk add --no-cache curl
RUN --mount=type=secret,id=token cat /run/secrets/token >/dev/null
ENTRYPOINT ["/bin/sh"]
```

Build with arguments and secrets:

```bash
oci2bin build-dockerfile \
  -f Dockerfile \
  --context . \
  --build-arg VERSION=1.2.3 \
  --build-secret id=token,src=./token.txt \
  -o app.bin
```

Build with SSH agent access:

```bash
oci2bin build-dockerfile -o app.bin --context . --ssh
```

Snap-like distribution after the build:

```bash
oci2bin build-dockerfile -o myapp
scp myapp remote-host:
ssh remote-host ./myapp
```

The result is a self-contained executable artifact. The target host does not
need the Dockerfile builder or Docker.

## Cross-Architecture Builds

Build for a specific architecture:

```bash
oci2bin --arch x86_64 alpine:latest
oci2bin --arch aarch64 alpine:latest
```

For aarch64 from an x86_64 host, install the matching cross compiler and
sysroot:

```bash
sudo dnf install gcc-aarch64-linux-gnu sysroot-aarch64-fc43-glibc
```

Override the sysroot:

```bash
AARCH64_SYSROOT=/path/to/sysroot oci2bin --arch aarch64 alpine:latest
```

Build a wrapper plus both supported architectures:

```bash
oci2bin --arch all alpine:latest
```

This produces:

```text
alpine_latest
alpine_latest_x86_64
alpine_latest_aarch64
```

If the host cannot execute either bundled architecture natively, the wrapper
can use `qemu-user-static` when installed.

## Add Files And Directories

```bash
oci2bin \
  --add-file ./app.conf:/etc/app/app.conf \
  --add-dir ./templates:/usr/share/app/templates \
  app:latest \
  app.bin
```

Use this for files that should become part of the artifact. Use runtime mounts
for host-specific state.

## Merge Additional Image Layers

```bash
oci2bin \
  --layer company/base-hardening:latest \
  --layer company/app-overrides:latest \
  app:latest \
  app.bin
```

Layers are applied in order. Later image config fields such as `Cmd`,
`Entrypoint`, and `Env` can override earlier values when present.

## Strip Image Content

Remove common documentation and cache paths:

```bash
oci2bin --strip debian:stable-slim debian.bin
```

Add custom strip prefixes:

```bash
oci2bin \
  --strip \
  --strip-prefix /usr/share/zoneinfo \
  --strip-prefix /opt/vendor/cache \
  app:latest \
  app.bin
```

Auto-detect package manager cache paths:

```bash
oci2bin --strip-auto app:latest app.bin
```

## Squash Layers

```bash
oci2bin --squash app:latest app.bin
```

Squashing rewrites the image payload as fewer layers. Use it when artifact
shape matters more than preserving upstream layer boundaries.

## Compress The Binary

```bash
oci2bin --compress-binary zstd redis:7-alpine redis_7-alpine
```

This shrinks the embedded payload. The runtime host needs `zstd`.

Compressed outputs are no longer directly loadable with `docker load` because
the embedded tar is not visible as a plain tar payload.

## Labels For Fleet Management

```bash
oci2bin \
  --label app=api \
  --label env=prod \
  --label owner=platform \
  app:latest \
  api.bin
```

Labels are shown by inspection commands and can be used by list and ps filters.

## Verify Source Images With Cosign

```bash
oci2bin --verify-cosign app:latest app.bin
```

Use source-image verification when the build should reject unsigned or
incorrectly signed upstream images.

## Encrypt The Embedded Image

Recipient mode:

```bash
oci2bin \
  --encrypt \
  --recipient age1example... \
  --recipient ssh-ed25519 AAAA... \
  app:latest \
  app.bin
```

Recipient file mode:

```bash
oci2bin \
  --encrypt \
  --recipients-file recipients.txt \
  app:latest \
  app.bin
```

Runtime:

```bash
OCI2BIN_IDENTITY=/etc/oci2bin/identity.txt ./app.bin
```

Passphrase mode:

```bash
oci2bin --passphrase --password-file ./pass.txt app:latest app.bin
OCI2BIN_PASSWORD_FILE=/etc/oci2bin/pass.txt ./app.bin
```

If no password environment variable or password file is set, the runtime can
prompt on the terminal.

## Self-Enforcing Signature Policy

Embed the public key requirement at build time:

```bash
oci2bin --require-signed pub.pem app:latest app.bin
```

Sign the output:

```bash
oci2bin sign --key priv.pem --in app.bin
```

The binary checks itself at startup and refuses to run if the signature is
missing or invalid.

## Reproducible Builds And Digest Pinning

```bash
oci2bin --reproducible --pin-digest auto app:latest app.bin
```

`--reproducible` normalizes timestamps and tar metadata controlled by
`oci2bin`. `--pin-digest` embeds a canonical digest that is checked at runtime.

Use a stronger hash:

```bash
oci2bin --pin-digest sha512:auto app:latest app.bin
```

## Air-Gap Builds

```bash
docker pull alpine:3.20
oci2bin --offline-only alpine:3.20 alpine_3.20
```

`--offline-only` refuses registry fetches, implies reproducible mode, and
records hermetic metadata.

From an OCI layout:

```bash
oci2bin --offline-only --oci-dir ./layout alpine:3.20 alpine_3.20
```

## Embed Loader For Reconstruction

Store the loader as an OCI layer:

```bash
oci2bin --embed-loader-layer redis:7-alpine redis_7-alpine
```

Store the loader as labels:

```bash
oci2bin --embed-loader-labels redis:7-alpine redis_7-alpine
```

Tune label size:

```bash
oci2bin --embed-loader-labels --label-chunk-size 4096 redis:7-alpine
```

Change the filesystem location for the loader layer:

```bash
oci2bin --embed-loader-layer --loader-dir .my-loader redis:7-alpine
```

Change label prefix:

```bash
oci2bin --embed-loader-layer --label-prefix myorg.loader redis:7-alpine
```

Reconstruct:

```bash
oci2bin reconstruct redis:7-alpine --output redis_7-alpine
```

## VM-Mode Binaries

Build with `oci2vm`:

```bash
oci2vm alpine:latest
./oci2vm_alpine_latest
```

Run an existing VM-capable binary in VM mode:

```bash
./app.bin --vm /bin/echo hello
```

Build with explicit VM assets:

```bash
oci2bin --kernel ./vmlinux --initramfs ./initramfs.cpio.gz alpine:latest vm.bin
```

Backend selection:

```bash
oci2bin --libkrun alpine:latest vm.bin
oci2bin --no-libkrun alpine:latest static-loader.bin
```

> **libkrun is a lazy runtime dependency, not a load-time one.** If `libkrun`
> is installed on the build host, oci2bin selects the libkrun loader by default.
> That loader is dynamically linked against **libc only** — it `dlopen`s
> `libkrun.so.1` on demand, the first time `--vm` actually uses the libkrun
> backend. So a libkrun-built binary:
>
> - **starts and runs in namespace mode on any host with glibc**, even one
>   without libkrun installed (no `error while loading shared libraries`);
> - needs `libkrun.so.1` present **only when you pass `--vm`** with the libkrun
>   backend — otherwise the library is never loaded. If it is missing at that
>   point, the run aborts with a clear message suggesting
>   `--vmm cloud-hypervisor`.
>
> The default loader (or `--no-libkrun`) is fully static — no shared library at
> all — and runs `--vm` through the cloud-hypervisor backend instead (which
> needs an embedded kernel and the `cloud-hypervisor` binary at runtime).

Build the libkrun loader:

```bash
make loader-libkrun
```

Build a cloud-hypervisor kernel:

```bash
make kernel
oci2bin alpine:latest vm.bin --kernel build/vmlinux
```

Set VM defaults at build time:

```bash
make VM_CPUS=4 VM_MEM_MB=512
VM_CPUS=4 VM_MEM_MB=512 oci2bin alpine:latest vm.bin
```

Select a VMM at runtime:

```bash
./vm.bin --vm --vmm cloud-hypervisor /bin/sh
./vm.bin --vm --vmm /opt/bin/cloud-hypervisor /bin/sh
```

VM mode is covered in more detail in [Security](security.md#vm-isolation).
