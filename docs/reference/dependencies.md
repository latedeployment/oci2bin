# Dependencies

oci2bin keeps its hard dependencies tiny and pulls in everything else **only
when you use the feature that needs it**. Run `oci2bin doctor` (or
`oci2bin doctor --json`) on any host to see what is present and get the exact
install command for what is missing.

There are two separate environments:

- **Build host** — the machine that runs `oci2bin` to *produce* a binary.
- **Target host** — the machine that *runs* the produced `./mybinary`.

## Graceful degradation

A missing dependency never blocks an unrelated run. The rule is:

- **Always-applied hardening degrades silently.** The default seccomp filter,
  Landlock sandbox, cgroup v2 limits, the full rootless UID/GID range
  (`newuidmap`/`newgidmap`), `memfd_secret`-backed secrets, and `--notify`
  delivery all *warn and continue* (or fall back) when the kernel feature or
  helper is absent. A plain `./mybinary` needs only `tar` plus unprivileged
  user namespaces. (`--strict` is the opt-in that turns these degradations into
  hard failures.)
- **A dependency is required only when its feature is in play.** `age` only when
  the payload is encrypted; `zstd` only when it is compressed; `slirp4netns`/
  `pasta` only for `--net slirp`/`pasta`; `nft` only for `--allow-egress`;
  `systemd-creds` only for `--secret tpm2:`; `rekor-cli` only for `--rekor`; and
  so on. If you do not use the feature, the tool is never looked for.
- **Explicitly requested things fail loudly rather than silently wrong.** When
  you *do* ask for a feature whose dependency is missing, oci2bin aborts with a
  clear message instead of running degraded — `--vm` without a VM backend,
  `--gpus`/`--cdi-device` without a CDI spec, `--allow-egress` without `nft`
  (fail-closed), a `--seccomp-profile` that won't load, or an encrypted/
  compressed payload without `age`/`zstd`. These are the only "strict"
  requirements, and each is tied to something you opted into.

## Target host (runtime)

The produced binary is statically linked by default, so the runtime surface is
small. Each dependency below is needed **only** for the feature in its row.

| Dependency | Needed for | Hard / optional |
| --- | --- | --- |
| `tar` (with gzip support) | **Always** — rootfs extraction | Hard (the only universal runtime dep) |
| `age` | Encrypted payloads (`--encrypt` / `--passphrase`) | Required if the image is encrypted |
| `zstd` | Compressed payloads (`--compress-binary`) | Required if the payload is compressed |
| `slirp4netns` | `--net slirp`, `-p PORT` | Required for that mode |
| `pasta` | `--net pasta` | Required for that mode |
| `nft` (nftables) | `--allow-egress` (fail-closed) | Required for that mode |
| `newuidmap` / `newgidmap` + `/etc/subuid`,`/etc/subgid` | Full rootless UID/GID range | Optional — falls back to single-ID mapping |
| `nsenter` (util-linux) | `oci2bin exec`, `freeze` / `thaw` | Required for those subcommands |
| `sqlite3` | `freeze` / `thaw` (DB-consistent snapshots) | Required for that subcommand |
| `systemd-creds` | `--secret tpm2:NAME` | Required for TPM2 secrets |
| `gdb` | `--gdb` | Required for that mode |
| `openssl` + `python3` | `--verify-key`, `--require-signed`, `--pin-digest` runtime checks | Required if the binary enforces a signature/digest |
| `curl` | `--notify` | Optional — notifications are silently skipped if absent |
| `rekor-cli` | `oci2bin verify --rekor` (inclusion check) | Required for that check |
| `/dev/kvm` | `--vm` (either backend) | Hard for VM mode |
| `cloud-hypervisor` + embedded kernel | `--vm` via cloud-hypervisor | Required for that backend |
| `virtiofsd` | `-v` volume mounts under cloud-hypervisor `--vm` | Required for that case |
| `libkrun.so.1` | `--vm` on a libkrun-built binary | Lazy — `dlopen`'d only when `--vm` runs; **see the note below** |
| `qemu-<arch>-static` | running a foreign-arch fat-binary without binfmt | Optional fallback |

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
| `zstd` | `--compress`, `--compress-binary` | Required for those flags |
| `age` | `--encrypt`, `--passphrase` | Required for those flags |
| `cosign` | `--verify-cosign`, `--require-cosign` | Required for those flags |
| `rekor-cli` | `oci2bin sign --rekor` | Required for that flag |
| `openssl` | `sign`, `verify`, `--require-signed` | Required for signing |
| aarch64 cross-toolchain + sysroot | `--arch aarch64` / `--arch all` | Required for cross builds |
| `pkg-config` + `libkrun`/`libkrun-dev` | Building the libkrun VM loader | Required for that loader |
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
