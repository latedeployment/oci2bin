# Dependencies

oci2bin keeps its hard dependencies small and resolves other helpers **only
when a selected feature needs them**.

There are two separate environments:

- **Build host** — the machine that runs `oci2bin` to *produce* a binary.
- **Target host** — the machine that *runs* the produced `./mybinary`.

Use the matching check for each environment:

```bash
oci2bin doctor             # build host
oci2bin doctor --json      # build host, machine-readable
./mybinary --doctor        # target host, using the deployed artifact
```

## Failure And Fallback Rules

A missing dependency does not block an unrelated run. The exact behavior
depends on the feature:

- **Baseline protections can fall back.** A normal namespace run needs `tar`
  and unprivileged user namespaces. The default seccomp and Landlock
  protections warn or fall back when unavailable; `--strict` turns supported
  hardening degradations into failures. Missing `newuidmap`/`newgidmap` falls
  back to a single-ID mapping.
- **A dependency is required only when its feature is in play.** `age` only when
  the payload is encrypted; `zstd` only when it is compressed; `slirp4netns`/
  `pasta` only for `--net slirp`/`pasta`; `nft` only for `--allow-egress`;
  `squashfuse`, `fuse-overlayfs`, `/dev/fuse`, and FUSE `user_allow_other`
  only for an artifact's `--lazy` path;
  `systemd-creds` only for `--secret tpm2:`; `rekor-cli` only for `--rekor`; and
  so on. If you do not use the feature, the tool is not invoked. The one
  lightweight exception is startup auto-detection of an installed libkrun
  backend.
- **Explicit controls normally fail closed.** Examples include an unavailable
  VM backend, a missing CDI device, an egress allowlist without `nft`, an
  invalid volume or secret, a custom seccomp profile that cannot load, and an
  encrypted or compressed payload without its helper. Requested cgroup limits
  also abort if they cannot be applied unless `--allow-degraded` is given.
- **Best-effort features say so explicitly.** Notifications are skipped when
  `curl` is unavailable. They are observability, not an enforcement boundary.

## Target host (runtime)

The produced binary is statically linked by default, so the runtime surface is
small. Each dependency below is needed **only** for the feature in its row.

| Dependency | Needed for | Hard / optional |
| --- | --- | --- |
| `tar` (with gzip support) | Normal OCI rootfs extraction | Hard for the default path. A SquashFS artifact run with `--lazy` mounts instead. GNU tar >= 1.32 is used with `--keep-directory-symlink`; on older or non-GNU tar the loader drops that flag and replaces symlinked directories with real ones instead of following them |
| `squashfuse` + `fuse-overlayfs` + `/dev/fuse` + `user_allow_other` in `/etc/fuse.conf` | `--lazy` on a `--rootfs-format squashfs` artifact | Required for that mode; `allow_other` lets the mapped image UID enter the rootless FUSE mounts, while the private temporary mount tree prevents unrelated host users from traversing them |
| `age` | Encrypted payloads (`--encrypt` / `--passphrase`) | Required if the image is encrypted |
| `zstd` | zstd-compressed layers (`--squash --compress zstd`) or whole payloads (`--compress-binary zstd`) | Required if either form is used |
| `slirp4netns` | Container-mode `--net slirp`, `-p PORT` | Required for that mode; VM-mode `-p` uses libkrun instead |
| `pasta` | `--net pasta` | Required for that mode |
| `nft` (nftables) | `--allow-egress` (fail-closed) | Required for that mode |
| `newuidmap` / `newgidmap` + `/etc/subuid`,`/etc/subgid` | Full rootless UID/GID range | Optional — falls back to single-ID mapping |
| `nsenter` (util-linux) | `oci2bin exec`, `freeze` / `thaw` | Required for those subcommands |
| `sqlite3` | `freeze` / `thaw` (DB-consistent snapshots) | Required for that subcommand |
| `systemd-creds` | `--secret tpm2:NAME` | Required for TPM2 secrets (root only; also needs a credential in `/etc/credstore.encrypted` or another system credential store) |
| `gdb` | `--gdb` | Required for that mode |
| `openssl` + `python3` | `--check-update` / `--self-update`; `--verify-key` and `--require-signed` with a non-P-256 key | The signature and pin checks are built into the loader (ECDSA P-256, SHA-256/512) and need neither. Where a helper is still used it is resolved by absolute path (`/usr/bin/python3`; `openssl` from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) and never through `$PATH` — an `openssl` installed elsewhere counts as missing and the check fails closed |
| `curl` | `--notify` | Optional — notifications are silently skipped if absent |
| `rekor-cli` | `oci2bin verify --rekor` (inclusion check) | Required for that check |
| `/dev/kvm` | `--vm` (either backend) | Hard for VM mode |
| `cloud-hypervisor` + embedded kernel | `--vm` via cloud-hypervisor | Required for that backend. The kernel needs `CONFIG_PVH`, virtio-PCI, virtio-fs and ACPI (`make kernel` builds one from `kernel/microvm.config`) |
| `virtiofsd` | `-v` volume mounts under cloud-hypervisor `--vm` | Required for that case; found on `PATH`, `/usr/bin`, `/usr/sbin`, or `/usr/libexec` |
| `mkfs.ext2` | `--vm --overlay-persist` under cloud-hypervisor (creates the data disk once) | Required for that case |
| `libkrun.so.1` | `--vm` on a libkrun-built binary, including `--net userspace` and VM `-p` | Lazy — `dlopen`'d only when `--vm` runs; **see the note below** |
| `qemu-<arch>-static` | running a foreign-arch fat-binary without binfmt | Optional fallback |

### Unprivileged user namespaces (read this if a plain run says "Operation not permitted")

A namespace-mode binary needs the kernel to allow **unprivileged user
namespaces**. Most distros enable them by default. Two gotchas:

- **Ubuntu 23.10+** enables
  `kernel.apparmor_restrict_unprivileged_userns=1` by default; other
  AppArmor-configured systems can enable it too. The user namespace is still
  created, but AppArmor strips its capabilities, so the follow-up
  `unshare(NEWNS|NEWPID|NEWUTS)` fails with `EPERM` ("Operation not permitted").
  Prefer a targeted AppArmor profile granting `userns,` for an artifact at a
  stable path. Globally setting the sysctl to `0` is a broader security
  tradeoff. VM mode avoids the namespace requirement.
- **Hardened kernels** may set `kernel.unprivileged_userns_clone=0`; enable it
  with `sudo sysctl -w kernel.unprivileged_userns_clone=1`.

`oci2bin doctor` reports both knobs on the build host; `./artifact --doctor`
checks the target host.

### The libkrun note (read this if you build VM binaries)

The **default** loader is fully static and adds no runtime library dependency —
the "only needs `tar`" guarantee. If `libkrun` is installed on the **build**
host, oci2bin auto-selects the libkrun loader, which is dynamically linked
against **libc only** and `dlopen`s `libkrun.so.1` lazily:

> A libkrun-built binary starts and runs in namespace mode on any glibc host,
> even without libkrun installed. `libkrun.so.1` is loaded **only when you pass
> `--vm`** with the libkrun backend; if it is missing at that point, the run
> aborts with a clear message (use `--vmm cloud-hypervisor` instead).

Build with `--no-libkrun` to force the fully static loader; `--vm` then uses the
cloud-hypervisor backend. See
[Build Binaries → VM-Mode Binaries](../build.md#vm-mode-binaries).

## Build host

| Dependency | Needed for | Hard / optional |
| --- | --- | --- |
| `gcc` + static libc (`glibc-static` or `musl-gcc`) | Compiling the loader (first build only; then cached) | Hard |
| `python3` (stdlib only) | The builder itself | Hard |
| `docker`, `podman`, or `skopeo` | Pull backend for `oci2bin IMAGE` (auto-detected docker → podman → skopeo; force with `--pull-with`) | Optional - not needed with `--oci-dir`, `from-chroot`, or `build-dockerfile FROM scratch`/OCI dir |
| `zstd` | `--squash --compress zstd`, `--compress-binary zstd` | Required for those flags |
| `mksquashfs` (`squashfs-tools`) | `--rootfs-format squashfs` | Required for that build mode |
| `age` | `--encrypt`, `--passphrase` | Required for those flags |
| `cosign` | `--verify-cosign`, `--require-cosign` | Required for those flags |
| `rekor-cli` | `oci2bin sign --rekor` | Required for that flag |
| `openssl` | `sign`, `verify`, `--require-signed` | Required for signing. Resolved from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` only, not `$PATH` |
| aarch64 cross-toolchain + sysroot | `--arch aarch64` / `--arch all` | Required for cross builds |
| discoverable `libkrun` (`pkg-config` or `ldconfig`) | Automatically selecting the libkrun-capable loader | Optional; `--libkrun` can force that loader without headers or build-time linking, but `libkrun.so.1` is still required when VM mode actually runs |
| `skopeo` / `crane` / `buildah` | Producing OCI layouts for `--oci-dir`; `skopeo` also works as a direct daemonless pull backend (`--pull-with skopeo`) | Optional, your choice of tool |

## Check a host

```bash
oci2bin doctor            # human-readable table with fix: commands
oci2bin doctor --json     # machine-readable
oci2bin explain ./app.bin # what a specific binary needs + host capability check
```

`doctor` reports each item as `OK`, `DEGRADED` (informational, e.g. `cosign`
absent), or `MISSING`, and exits non-zero only when something it considers
required is `MISSING`.
