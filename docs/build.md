# Build Binaries

This page covers features that affect the generated file.

## Build From Docker, Podman, Or Skopeo

```bash
oci2bin alpine:latest
oci2bin redis:7-alpine redis_7-alpine
```

If the image is not local, `oci2bin` pulls it. The image is saved as an OCI tar
payload, combined with the loader, and written as one executable file.

### Pull backend (`--pull-with`)

The default `oci2bin IMAGE` path fetches the image with one of three backends,
auto-detected in the order **docker → podman → skopeo**:

| Backend  | How it fetches                                  | Daemon? |
|----------|-------------------------------------------------|---------|
| `docker` | `docker pull` + `docker save`                   | yes     |
| `podman` | `podman pull` + `podman save` (CLI-compatible)  | no      |
| `skopeo` | `skopeo copy docker://IMAGE oci:…` → OCI layout | no      |

`skopeo` makes `oci2bin IMAGE` work with **no container engine at all** — one
command, no manual `skopeo copy` + `--oci-dir` two-step. Force a specific
backend with `--pull-with`:

```bash
oci2bin --pull-with skopeo alpine:latest        # daemonless pull
oci2bin --pull-with podman redis:7-alpine
```

Notes:

- **Short image names work out of the box.** `docker` implicitly resolves a
  bare name like `redis:7-alpine` against `docker.io`, but `podman` and
  `skopeo` do not unless the host configures `unqualified-search-registries`.
  So when those backends pull a *not-yet-local* short name, oci2bin qualifies it
  to `docker.io/...` the way docker does (`redis:7-alpine` →
  `docker.io/library/redis:7-alpine`, `user/app` → `docker.io/user/app`) and
  prints the rewrite. References that already name a registry
  (`quay.io/…`, `localhost/…`, `registry:5000/…`) and locally-built images are
  left untouched. Pass a fully-qualified name to target a different registry.
- A pull backend is only needed for this default path — `--oci-dir`,
  `from-chroot`, and `build-dockerfile` build without one. `oci2bin doctor`
  reports the backend as *optional* and accepts any of the three.
- `--pull-with skopeo` does not support `--layer`, `--offline-only`, or cosign
  verification (which need the docker/podman CLI); oci2bin aborts with a clear
  message rather than silently skipping them.
- For a non-host `--arch`, the skopeo backend selects the matching image from a
  multi-arch manifest (`--override-arch`).

### Pin by digest (validated)

Pass an immutable `name@sha256:...` reference to build from a specific content
digest instead of a mutable tag:

```bash
oci2bin alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
# → builds ./alpine_25109184c71b
```

oci2bin verifies the digest before building: a digest-pinned image already in
the local store is used without a pull (so `docker` never re-validates it), so
oci2bin re-checks that the resolved image actually reports the requested digest
and **refuses to build on a mismatch** — defending against a tampered or
mis-tagged local image. A malformed digest is rejected up front. With
`--pull-with skopeo`, skopeo fetches the digest-pinned reference directly
(`docker://name@sha256:…`) and verifies it on copy. This pins the build
*input*; [`--pin-digest`](#reproducible-builds-and-digest-pinning) pins what the
*loader* re-checks at run time.

## Build From An OCI Layout

```bash
skopeo copy docker://redis:7-alpine oci:./redis-oci:latest
oci2bin --oci-dir ./redis-oci redis:7-alpine redis_7-alpine
```

The image argument is used for naming and embedded metadata. The content comes
from the OCI layout directory.

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
oci2bin build-dockerfile -o app.bin --context .
```

Use `RUN --mount=type=ssh ...` in the Dockerfile and run the builder with
`SSH_AUTH_SOCK` set in the host environment. The builder forwards that socket
for the `RUN` step and does not include the socket or SSH credentials in the
image layer.

Snap-like distribution after the build:

```bash
oci2bin build-dockerfile -o myapp
scp ./myapp deploy@remote-host.example.com:/opt/app/myapp
ssh deploy@remote-host.example.com /opt/app/myapp
```

The result is a mostly self-contained executable artifact. The target host
does not need the Dockerfile builder or Docker, but it still needs the normal
[runtime dependencies](reference/dependencies.md#target-host-runtime).

## Override Entrypoint Or Command

Change what the binary runs by default — without writing a Dockerfile — by
rewriting the embedded image config at build time:

```bash
# Shell-split string form
oci2bin --entrypoint '/usr/bin/myserver --config /etc/app.conf' myapp:latest

# JSON-array (exec) form, with a separate default command
oci2bin --entrypoint '["redis-server"]' --cmd '["--port","6380"]' redis:7-alpine myredis
```

A value starting with `[` is parsed as a JSON array; otherwise it is
shell-split. `--entrypoint` without `--cmd` clears the image's default `Cmd`
(like `docker run --entrypoint`). The change is baked into the artifact and
appears in `oci2bin inspect`. To override per launch instead (no rebuild), use
the runtime `--entrypoint` flag on the produced binary.

## Cross-Architecture Builds

Build for a specific architecture:

```bash
oci2bin --arch x86_64 alpine:latest
oci2bin --arch aarch64 alpine:latest
```

Cross-compilation works in **both directions**: the host's native architecture
uses plain `gcc`, the other uses a cross compiler + sysroot. Install the matching
toolchain for the non-native target:

```bash
# x86_64 host -> aarch64
sudo dnf install gcc-aarch64-linux-gnu \
  "sysroot-aarch64-fc$(rpm -E %fedora)-glibc"                       # Fedora
sudo apt install gcc-aarch64-linux-gnu                              # Debian/Ubuntu
# aarch64 host -> x86_64
sudo dnf install gcc-x86_64-linux-gnu \
  "sysroot-x86_64-fc$(rpm -E %fedora)-glibc"                        # Fedora
sudo apt install gcc-x86-64-linux-gnu                               # Debian/Ubuntu (note: x86-64 hyphen)
```

On Fedora, `oci2bin` selects the newest installed `fc*` sysroot. On
Debian/Ubuntu it uses the cross compiler's built-in default. `oci2bin doctor`
prints the right install command for the current distro. Override discovery
with the matching variable:

```bash
AARCH64_SYSROOT=/path/to/sysroot oci2bin --arch aarch64 alpine:latest
X86_64_SYSROOT=/path/to/sysroot  oci2bin --arch x86_64  alpine:latest
```

`oci2bin doctor` reports whether the cross-compiler for the non-native
architecture is installed.

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
  --strip-prefix usr/share/zoneinfo \
  --strip-prefix opt/vendor/cache \
  app:latest \
  app.bin
```

Prefixes are relative to the image root: do not start them with `/`, and do not
use `..`.

Auto-detect package manager cache paths:

```bash
oci2bin --strip-auto app:latest app.bin
```

## Squash Layers

```bash
oci2bin --squash app:latest app.bin
oci2bin --squash --compress zstd app:latest app.bin
```

Squashing rewrites the image payload as fewer layers. Use it when artifact
shape matters more than preserving upstream layer boundaries. `--compress
gzip|zstd` selects the codec for the squashed layer and is valid only with
`--squash`; this is distinct from `--compress-binary`, which wraps the entire
embedded payload.

## Mountable SquashFS Rootfs

Build an artifact with a second, directly mountable root filesystem:

```bash
oci2bin --rootfs-format squashfs app:latest app.bin
./app.bin --lazy
```

The builder applies the OCI layers once, writes the runtime image config into
the normalized rootfs, and runs `mksquashfs`. At runtime, `squashfuse` mounts
that payload directly from the executable and `fuse-overlayfs` supplies the
normal writable view. This avoids extracting every layer for every launch.

`tar` remains the default format. The SquashFS option appends the mountable
rootfs while retaining the original OCI payload, so the artifact remains
inspectable and directly accepted by `docker load`; the tradeoff is that it
carries both representations and is larger.

Use persistent state with the same runtime flag:

```bash
./app.bin --lazy --overlay-persist /srv/app/state
```

Build requirements and constraints:

- `mksquashfs` is required on the build host.
- `squashfuse`, `fuse-overlayfs`, `/dev/fuse`, and `user_allow_other` enabled
  in `/etc/fuse.conf` are required on the runtime host.
- `--reproducible` gives `mksquashfs` fixed filesystem and file timestamps.
- age encryption cannot be combined with SquashFS mode. The separately
  mountable filesystem would otherwise be a plaintext copy of the encrypted
  OCI payload, so the builder rejects the combination.
- Whole-OCI zstd compression remains allowed; `--lazy` mounts the SquashFS
  copy, while ordinary extraction needs `zstd`.

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
oci2bin --require-cosign --cosign-key cosign.pub app:latest app.bin
```

Use `--require-cosign` when the build must reject an unsigned or incorrectly
signed upstream image, or when `cosign` being absent must abort the build.
`--verify-cosign` performs the same check but warns and continues on failure;
it is an advisory check, not an enforcement boundary. To record the result in
a later `--attest auto` signature, pass `--cosign-image-ref`,
`--cosign-key-path`, and `--cosign-result` to `oci2bin sign` explicitly.

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

`--recipient` is repeatable and passes each value to the installed `age`
program. Native age recipients and SSH recipients supported by that version of
age can therefore be used. A recipients file may contain several public
recipients; the runtime identity file may likewise contain multiple private
identities. If `OCI2BIN_IDENTITY` is unset, the loader tries
`~/.config/oci2bin/identity`, `~/.ssh/id_ed25519`, then `~/.ssh/id_rsa`.

Passphrase mode:

```bash
oci2bin --passphrase --password-file ./pass.txt app:latest app.bin
OCI2BIN_PASSWORD_FILE=/etc/oci2bin/pass.txt ./app.bin
```

If no password environment variable or password file is set, the runtime can
prompt on the terminal.

Recipient and passphrase modes are mutually exclusive. In either mode,
encryption covers the embedded OCI payload—image configuration and layers
after any requested compression—not the ELF loader or the small outer metadata
needed to locate and start it. A completely age-encrypted file could not remain
directly executable because the Linux kernel must read a plaintext ELF header.

At runtime the loader asks `age` to decrypt into a temporary tar inside its
private extraction directory, uses it to prepare the rootfs, and removes that
directory during normal cleanup. This is not automatically memory-backed. On a
host with enough RAM, set `OCI2BIN_TMPDIR=/dev/shm` to keep both the decrypted
tar and extracted rootfs on tmpfs. The selected mount must permit execution of
the extracted workload; many hardened systems mount `/dev/shm` with `noexec`,
in which case use a dedicated executable tmpfs instead.

Encryption provides payload confidentiality, not publisher authentication.
Combine it with `--require-signed`, digest pinning, or an external signature
policy when authenticity matters. Encrypted artifacts are intentionally opaque
to direct `docker load`, normal inspection, reconstruction, and label filtering
unless the payload is separately decrypted with the matching material.

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
Recipient and passphrase encryption use fresh age randomness, so encrypted
builds are not byte-for-byte reproducible even when `--reproducible` is set.

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

The libkrun backend also provides rootless VM userspace networking:

```bash
./vm.bin --vm --net userspace
./vm.bin --vm -p 8080:80
./vm.bin --vm --net none
```

No TAP device or privileged host network setup is required. Inbound ports are
closed unless explicitly published. This networking path is currently
libkrun-only; cloud-hypervisor rejects `--net userspace` and `-p` instead of
silently booting without the requested connectivity.

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
