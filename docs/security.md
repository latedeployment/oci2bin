# Security

This page explains the security controls available in `oci2bin` and how to use
them together.

## Rootless By Default

The generated binary runs without a daemon and without host root privileges.

Inside the container, the process may see UID 0. On the host, the process runs
as the invoking user. User namespaces provide that mapping.

Check the host:

```bash
oci2bin doctor
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
./app.bin --allow-egress 10.10.0.0/16 --allow-egress 198.51.100.10:443
```

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

Check support:

```bash
oci2bin doctor
```

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

TPM2-sealed credentials:

```bash
./app.bin --secret tpm2:dbpass:/run/secrets/db_password
```

On Linux kernels with `memfd_secret`, `oci2bin` can keep secret material out of
page cache and swap where that path is available.

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
oci2bin --verify-cosign app:latest app.bin
```

Verify source-image signatures through attestation when your policy requires a
link between the generated binary and the source image identity.

## Digest Pinning

```bash
oci2bin --pin-digest auto app:latest app.bin
```

At startup, the loader recomputes the canonical digest and aborts if it differs.

Use a specific algorithm:

```bash
oci2bin --pin-digest sha512:auto app:latest app.bin
```

## Reproducible And Offline Builds

```bash
oci2bin --reproducible --pin-digest auto app:latest app.bin
```

Offline mode:

```bash
oci2bin --offline-only --oci-dir ./layout app:latest app.bin
```

Use these when auditability and byte-for-byte rebuilds matter.

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

