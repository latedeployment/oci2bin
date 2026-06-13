# Environment Variables

These environment variables tune oci2bin's behavior. They split into variables
read **at run time** (by a produced `./binary`), **at build time** (by the
`oci2bin` CLI), and a few **internal** ones that oci2bin sets itself.

## Run time (read by the produced binary)

| Variable | Effect |
| --- | --- |
| `OCI2BIN_DEBUG` | Set to any value to print verbose runtime diagnostics (same as `--debug`). |
| `OCI2BIN_TMPDIR` | Directory for the runtime extraction tmpdir. Tried first, before `TMPDIR`; point it at a tmpfs for speed and to keep the rootfs off disk. |
| `TMPDIR` | Fallback extraction directory (then `/tmp`, then `/var/tmp`). |
| `OCI2BIN_IDENTITY` | Path to the age identity (or SSH private key) used to decrypt an `--encrypt` recipient image. |
| `OCI2BIN_PASSWORD` | Passphrase used to decrypt a `--passphrase` image. |
| `OCI2BIN_PASSWORD_FILE` | File whose first line is the passphrase (tried before `OCI2BIN_PASSWORD`). |
| `OCI2BIN_CDI_DIR` | Extra directory searched **first** for CDI specs, ahead of `/etc/cdi` and `/run/cdi` (`--gpus` / `--cdi-device`). |
| `SSH_AUTH_SOCK` | The host SSH agent socket forwarded into the container by `--ssh-agent`. |
| `HOME` | Base for the named-container state/log directory (`~/.cache/oci2bin/containers/`). |

## Build time (read by the `oci2bin` CLI)

| Variable | Effect |
| --- | --- |
| `OCI2BIN_HOME` | Where shared resources live (`build_polyglot.py`, prebuilt loaders). Set automatically by `make install` to `PREFIX/share/oci2bin`. |
| `AARCH64_SYSROOT` | Sysroot for the aarch64 cross-compiler (default `/usr/aarch64-redhat-linux/sys-root/fc43`). |
| `X86_64_SYSROOT` | Sysroot for the x86_64 cross-compiler when building on an aarch64 host. |
| `SOURCE_DATE_EPOCH` | Fixed timestamp for `--reproducible` / `--offline-only` builds. |
| `VM_CPUS`, `VM_MEM_MB` | Default vCPU count and memory (MiB) baked into a VM-mode binary. |
| `XDG_CACHE_HOME` | Overrides `~/.cache` for the build-output and per-layer caches. |
| `XDG_DATA_HOME` | Overrides `~/.local/share` for detached-stack manifests/logs and freeze tokens. |
| `PREFIX` | Install prefix for `make install` (default `/usr/local`). |

## Internal (set by oci2bin, not for direct use)

`OCI2BIN_INSPECT`, `OCI2BIN_VM_INIT`, `OCI2BIN_GOSU_DEPTH`, `OCI2BIN_META`,
`OCI2BIN_SELF`, `OCI2BIN_ENGINE`, and `OCI2BIN_COSIGN_REF`/`OCI2BIN_COSIGN_KEY`/
`OCI2BIN_COSIGN_RESULT` are set by oci2bin itself (mode switches, the gosu
recursion guard, the container engine the wrapper resolved — `docker` or
`podman`, honoring `--pull-with` — so helper scripts reuse it instead of
assuming `docker`, and passing the build-time cosign result into
`sign --attest auto`). You normally do not set these.

## Examples

```bash
# Verbose run, extracting to a tmpfs
OCI2BIN_DEBUG=1 OCI2BIN_TMPDIR=/dev/shm ./myapp

# Decrypt an encrypted binary
OCI2BIN_IDENTITY=~/.config/oci2bin/identity ./myapp
OCI2BIN_PASSWORD_FILE=/run/secrets/img.pass ./myapp

# Cross-build for x86_64 on an aarch64 host with a custom sysroot
X86_64_SYSROOT=/opt/sysroots/x86_64 oci2bin --arch x86_64 alpine:latest
```
