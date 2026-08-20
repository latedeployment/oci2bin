# Security

This page explains the security controls available in `oci2bin` and how to use
them together.

## Security Boundaries

Namespace mode reduces a workload's access to the host, but shares the host
kernel and is not the same boundary as a VM. VM mode uses KVM and a VMM for a
stronger kernel boundary. In either mode, treat the embedded image and its
entrypoint as code: rootless execution limits host privilege, but does not make
untrusted code harmless.

The controls solve different problems:

- signing, digest pinning, Cosign, and attestations establish integrity,
  identity, or provenance
- age encryption protects the embedded image payload at rest
- namespaces, seccomp, Landlock, capabilities, mounts, and cgroups limit a
  running workload
- VM mode isolates the workload behind a guest kernel

Use the controls together according to the threat model; none substitutes for
all the others.

## Rootless By Default

The generated binary runs without a daemon and without host root privileges.

Inside the container, the process may see UID 0. On the host, the process runs
as the invoking user. User namespaces provide that mapping.

Check the build host:

```bash
oci2bin doctor
```

Check a deployment host with the artifact:

```bash
./app.bin --doctor
```

For better UID/GID compatibility, install `newuidmap` and `newgidmap` and
configure `/etc/subuid` and `/etc/subgid`.

## Reduce The Runtime Surface

A locked-down baseline:

```bash
./app.bin \
  --read-only \
  --tmpfs /tmp \
  --net none \
  --cap-drop all \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1
```

Add back only what the application needs.

## Network Isolation

Disable networking:

```bash
./app.bin --net none
```

Use userspace networking instead of host networking:

```bash
./app.bin --net slirp -p 8080:80
./app.bin --net pasta
```

Restrict egress:

```bash
./app.bin --net slirp \
  --allow-egress 10.10.0.0/16:443 \
  --allow-egress 198.51.100.10:443
```

Egress filtering is supported with `--net slirp` and `--net pasta`, and needs
`nft`. The run fails closed if the allowlist cannot be installed.

In libkrun VM mode, use its rootless userspace network or disable it:

```bash
./app.bin --vm --net userspace -p 8080:80
./app.bin --vm --net none
```

oci2bin passes an empty libkrun port map unless `-p` is present, preventing the
library's implicit “expose all guest listeners” behavior. TSI proxies guest
sockets in the VMM process's host network context; it is connectivity, not a
network security boundary. VM egress allowlists are not implemented, and
`--allow-egress` continues to fail with `--vm`.

## Read-Only Rootfs

```bash
./app.bin --read-only --tmpfs /tmp --tmpfs /run
```

Use `--overlay-persist` only when state needs to survive:

```bash
./app.bin --overlay-persist /srv/app/state
```

## Capabilities

Drop all capabilities:

```bash
./app.bin --cap-drop all
```

Add back a narrow capability:

```bash
./app.bin --cap-drop all --cap-add NET_BIND_SERVICE
```

## Seccomp

The loader applies a default syscall filter when available.

Disable it only for debugging or compatibility:

```bash
./app.bin --no-seccomp
```

Use a custom profile:

```bash
./app.bin --seccomp-profile ./seccomp.json
```

Generate a profile from a representative run:

```bash
./app.bin --gen-seccomp ./seccomp.json -- /usr/bin/app --warm-up
```

Then run with it:

```bash
./app.bin --seccomp-profile ./seccomp.json
```

## Landlock Filesystem Sandbox

When supported by the kernel, Landlock can restrict filesystem access from the
container process. Use it for defense in depth together with read-only rootfs,
explicit mounts, and secrets.

Check support on the build host:

```bash
oci2bin doctor
```

Check the deployment host with the artifact itself:

```bash
./app.bin --doctor
```

`--landlock` requires the sandbox: the run aborts if the kernel cannot provide
it or it cannot be enforced. Without the flag, Landlock is applied when
available and skipped otherwise — unless `--strict` is set, which also refuses
to start when the sandbox is unavailable or fails to install.

## Fail-Closed Mode

`--strict` turns every security-relevant degradation that would otherwise be a
warning into a hard failure:

- the default seccomp filter (or `PR_SET_NO_NEW_PRIVS`) failing to install
- Landlock unsupported by the kernel, or supported but not enforceable
- a capability drop or add the kernel rejects

Failures of an explicitly requested flag — `--read-only`, `--landlock`,
`--seccomp-profile`, `--seccomp-deny-write`, `-v`, `--secret`,
`--allow-egress` — always abort the run, with or without `--strict`.

## AppArmor And SELinux

```bash
./app.bin --security-opt apparmor=my-profile
./app.bin --security-opt label=type:container_t
```

The loader must be built with matching AppArmor or SELinux support.

## Secrets

Use runtime secrets instead of baking sensitive values into the image:

```bash
./app.bin --secret /etc/app/api_key
./app.bin --secret /etc/ssl/private/key.pem:/run/secrets/tls_key
```

TPM2-sealed credentials, read from the root-owned system credential stores
(`/etc/credstore.encrypted` and friends) and decrypted with `systemd-creds`:

```bash
sudo ./app.bin --secret tpm2:dbpass:/run/secrets/db_password
```

Decryption needs root (`/var/lib/systemd/credential.secret` and `/dev/tpmrm0`
are root-only), so this does not work in a rootless run. The credential file
must be a regular file that is not group- or world-writable — `systemd-creds`
will decrypt a host-key or `--with-key=null` blob just as readily as a
TPM2-sealed one, so guarding write access to the store is what makes the
`tpm2:` prefix meaningful. `--secret` is rejected with `--vm`.

Secrets that exist only in memory (TPM2) are staged on a private `ramfs`
mount, bind-mounted read-only at their destination, and the staging name is
unlinked — the plaintext never reaches disk-backed storage or swap. Plain-file
secrets are read-only bind mounts of the host file.

## Encrypted Payloads

Recipient encryption:

```bash
oci2bin --encrypt --recipient age1example... app:latest app.bin
OCI2BIN_IDENTITY=/etc/oci2bin/identity.txt ./app.bin
```

Passphrase encryption:

```bash
oci2bin --passphrase --password-file ./pass.txt app:latest app.bin
OCI2BIN_PASSWORD_FILE=/etc/oci2bin/pass.txt ./app.bin
```

Encryption protects the embedded image payload at rest. It does not replace
runtime isolation.

### What is encrypted

Encryption is the last payload transformation. It covers the OCI image config
and all layers, including any files added at build time, after optional
compression. It does not cover the ELF loader or the small outer metadata the
loader needs to find and start the payload. The outer file must retain a
plaintext ELF header to remain directly executable.

Recipient mode passes `--recipient` and `--recipients-file` values to the
installed `age` CLI. This includes native age and SSH recipient types supported
by that age version. Both options are repeatable. An identity file can hold
multiple private identities; the loader tries `OCI2BIN_IDENTITY` first, then
`~/.config/oci2bin/identity`, `~/.ssh/id_ed25519`, and `~/.ssh/id_rsa`.

Passphrase mode reads `OCI2BIN_PASSWORD_FILE` first, then
`OCI2BIN_PASSWORD`, and finally prompts on a terminal. Do not put a production
passphrase directly in a shell command or environment when a protected file or
secret manager can supply it.

`--rootfs-format squashfs` is deliberately incompatible with age encryption.
That mode appends an independently mountable root filesystem; leaving it
plaintext would bypass encryption, while encrypting it would prevent direct
mounting. The builder rejects the combination rather than providing partial
protection.

### Runtime plaintext and compatibility

The loader decrypts to a temporary tar in its private extraction directory,
then prepares the rootfs and removes the directory during normal cleanup.
Temporary storage is not guaranteed to be memory-backed. If the host has
enough memory, use:

```bash
OCI2BIN_TMPDIR=/dev/shm \
OCI2BIN_IDENTITY=/run/secrets/oci2bin.identity \
./app.bin
```

The extraction filesystem must permit execution because the workload runs from
the prepared rootfs. If `/dev/shm` is mounted `noexec`, use a dedicated tmpfs
with an appropriate mount policy instead.

An encrypted artifact cannot be passed directly to `docker load`, inspected as
a plain OCI archive, reconstructed, or label-filtered without decrypting the
payload. Encryption also uses fresh randomness, so two encrypted builds are
not byte-identical even with `--reproducible`.

Encryption provides confidentiality only. It does not authenticate who built
or published the artifact. Pair it with an enforced signature or provenance
policy where authenticity matters, and keep runtime decryption material
separate from the artifact.

## Signing And Verification

Sign a binary:

```bash
oci2bin sign --key priv.pem --in app.bin
```

Verify:

```bash
oci2bin verify --key pub.pem --in app.bin
```

Verify at runtime:

```bash
./app.bin --verify-key pub.pem
```

Embed a mandatory policy:

```bash
oci2bin --require-signed pub.pem app:latest app.bin
oci2bin sign --key priv.pem --in app.bin
./app.bin
```

All of these run the ECDSA check through `openssl`, which is resolved by
absolute path from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin` — never through
`$PATH`. An `openssl` reachable only via `$PATH` is treated as missing and the
check fails closed, so a stub planted in an attacker-writable `$PATH` entry
cannot make verification report success.

Detached file signing:

```bash
oci2bin sign-file --key priv.pem --in file --out file.sig
oci2bin verify-file --key pub.pem --in file --sig file.sig
```

Publish to a transparency log:

```bash
oci2bin sign --key priv.pem --rekor --in app.bin
```

Generate or verify provenance:

```bash
oci2bin sign --key priv.pem --attest slsa.json --in app.bin
```

## Source Image Trust

Verify upstream image signatures before building:

```bash
oci2bin --require-cosign --cosign-key cosign.pub app:latest app.bin
```

`--require-cosign` aborts if verification fails or `cosign` is unavailable.
The weaker `--verify-cosign` form warns and continues, which is suitable for
advisory validation but not for enforcing source trust. When policy also
requires an attested link to the source image, pass the verified image,
key path, and result to `oci2bin sign --attest auto` with its
`--cosign-image-ref`, `--cosign-key-path`, and `--cosign-result` options.

## Digest Pinning

```bash
oci2bin --pin-digest auto app:latest app.bin
```

At startup, the loader recomputes the canonical digest and aborts if it differs.

Use a specific algorithm:

```bash
oci2bin --pin-digest sha512:auto app:latest app.bin
```

## Untrusted Layer Content

Layer contents come from the image and are treated as attacker-controlled.

Extraction passes `--no-same-permissions --no-same-owner` so a crafted layer
cannot restore set-ID bits, and the merge step strips them again. Extended
attributes are allowlisted to `user.*` and `trusted.overlay.*`;
`security.capability` in particular is dropped, because a file capability set
grants the same privilege as a setuid bit and would otherwise walk straight
around the set-ID strip. This matters when oci2bin runs with `CAP_SETFCAP` —
privileged, or as root inside a user namespace.

`--keep-directory-symlink` is passed only to GNU tar 1.32 or newer, which
refuses to traverse a symlink it created earlier in the same run. On an older
or non-GNU tar the loader drops the flag and prints a notice; extraction then
replaces a symlinked directory with a real one instead of following it.
`oci2bin doctor` reports the host's tar version.

## Reproducible And Offline Builds

```bash
oci2bin --reproducible --pin-digest auto app:latest app.bin
```

Offline mode:

```bash
oci2bin --offline-only --oci-dir ./layout app:latest app.bin
```

Use these when auditability and byte-for-byte rebuilds matter. Reproducibility
applies only to inputs and metadata that `oci2bin` controls; recipient or
passphrase encryption deliberately uses fresh age randomness and therefore
does not produce byte-identical artifacts.

## VM Isolation

Build with `oci2vm`:

```bash
oci2vm app:latest
./oci2vm_app_latest
```

Or build with VM assets:

```bash
oci2bin --kernel ./vmlinux --initramfs ./initramfs.cpio.gz app:latest app-vm.bin
```

VM mode is a stronger isolation boundary than namespace-only container mode.
It needs host VM support.

## Practical Hardening Recipe

```bash
oci2bin \
  --reproducible \
  --pin-digest auto \
  --require-signed pub.pem \
  app:latest \
  app.bin

oci2bin sign --key priv.pem --in app.bin

./app.bin \
  --read-only \
  --tmpfs /tmp \
  --net slirp \
  -p 8080:8080 \
  --cap-drop all \
  --pids-limit 256 \
  --memory 512m \
  --seccomp-profile ./seccomp.json
```
