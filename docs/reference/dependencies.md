# Dependencies

oci2bin keeps its hard dependencies tiny and pulls in everything else **only
when you use the feature that needs it**. Run `oci2bin doctor` (or
`oci2bin doctor --json`) on any host to see what is present and get the exact
install command for what is missing.

There are two separate environments:

- **Build host** — the machine that runs `oci2bin` to *produce* a binary.
- **Target host** — the machine that *runs* the produced `./mybinary`.

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
| `docker` or `podman` | Pulling/saving images | Optional — not needed with `--oci-dir`, `--tar`, `from-chroot`, or `build-dockerfile FROM scratch`/OCI dir |
| `zstd` | `--compress`, `--compress-binary` | Required for those flags |
| `age` | `--encrypt`, `--passphrase` | Required for those flags |
| `cosign` | `--verify-cosign`, `--require-cosign` | Required for those flags |
| `rekor-cli` | `oci2bin sign --rekor` | Required for that flag |
| `openssl` | `sign`, `verify`, `--require-signed` | Required for signing |
| aarch64 cross-toolchain + sysroot | `--arch aarch64` / `--arch all` | Required for cross builds |
| `pkg-config` + `libkrun`/`libkrun-dev` | Building the libkrun VM loader | Required for that loader |
| `skopeo` / `crane` / `buildah` | Producing OCI layouts for `--oci-dir` | Optional, your choice of tool |

## Check a host

```bash
oci2bin doctor            # human-readable table with fix: commands
oci2bin doctor --json     # machine-readable
oci2bin explain ./app.bin # what a specific binary needs + host capability check
```

`doctor` reports each item as `OK`, `DEGRADED` (informational, e.g. `cosign`
absent), or `MISSING`, and exits non-zero only when something it considers
required is `MISSING`.
