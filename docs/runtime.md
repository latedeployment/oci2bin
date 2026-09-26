# Run Binaries

Runtime options are passed to the generated binary, not to `oci2bin`.

```bash
./app.bin [OPTIONS] [-- CMD [ARGS...]]
```

## Rootless Requirements (unprivileged user namespaces)

The binary runs **as your normal user** — no root, no setuid, no daemon. To do
that it creates an unprivileged **user namespace** and then mount/PID/UTS
namespaces inside it. The host kernel must allow this. Most distros do by
default; two gotchas commonly bite:

### Ubuntu 23.10+ and AppArmor-restricted hosts

Ubuntu 23.10 and later enable
`kernel.apparmor_restrict_unprivileged_userns=1` by default. Other systems can
enable the same AppArmor restriction. The user namespace is still created, but
AppArmor strips its capabilities, so the follow-up
`unshare(NEWNS|NEWPID|NEWUTS)` fails and you see:

```
unshare(NEWNS|NEWPID|NEWUTS): Operation not permitted
```

The binary detects this and prints the fix. You have three options:

```bash
# 1. Relax the knob globally (broad security tradeoff; needs root once):
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | \
    sudo tee /etc/sysctl.d/60-oci2bin-userns.conf      # persist across reboots

# 2. Or author an AppArmor profile that grants `userns,` to the binary
#    (Ubuntu's intended per-application mechanism — see `man apparmor.d`).
#    Prefer this when the binary lives at a stable path.

# 3. Or sidestep host namespaces entirely with a microVM (needs KVM):
./app.bin --vm
```

> This is **not** a setuid problem. Unprivileged user namespaces exist precisely
> so no setuid/root is needed. The setuid `newuidmap`/`newgidmap` helpers are a
> separate thing — they only map *multiple* sub-UIDs/GIDs and are optional
> (oci2bin falls back to a single-ID mapping without them). Making the binary
> setuid would defeat the rootless design and is not the fix.

### Hardened kernels: userns clone disabled

Some hardened kernels set `kernel.unprivileged_userns_clone=0`. Enable it with:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

### Checking a host

`oci2bin doctor` reports both knobs (under **unprivileged user namespaces**),
but it only inspects the **build** host. When you ship the binary to a different
machine, ask the binary itself to check that host:

```bash
./app.bin --doctor      # report this host's runtime readiness, then exit
```

`--doctor` is read-only — it never extracts the image or creates namespaces. It
reports unprivileged user namespaces (including the AppArmor / `clone` knobs
above), `newuidmap`/`newgidmap` + `/etc/subuid`, seccomp, landlock, cgroup v2,
`tar`, `python3` + `openssl` (needed only for `--self-update` and for
signature keys that are not P-256; pinned digests and `--require-signed` are
checked by the loader itself), and `/dev/kvm` (for `--vm`), then exits
non-zero if a blocking issue is found. You can also probe the kernel knobs by hand:

```bash
sysctl kernel.apparmor_restrict_unprivileged_userns   # want 0 (or absent)
sysctl kernel.unprivileged_userns_clone               # want 1 (or absent)
```

## Commands And Entrypoints

Run the image default command:

```bash
./app.bin
```

Override `CMD`:

```bash
./app.bin /bin/ls /etc
```

Override `ENTRYPOINT`:

```bash
./app.bin --entrypoint /bin/sh -- -c 'echo hello'
```

Set the working directory:

```bash
./app.bin --workdir /app
```

Use `--` when the command begins with a dash:

```bash
./app.bin -- -v
```

## Environment

Set variables:

```bash
./app.bin -e DEBUG=1 -e API_URL=https://example.test
```

Pass a host variable by name:

```bash
./app.bin -e HOME -e USER
```

Load files:

```bash
./app.bin --env-file /etc/app/base.env --env-file /etc/app/override.env
```

`--env-file` is processed before `-e`, so explicit `-e` values win.

## Volumes

```bash
./app.bin -v /srv/app/data:/data
```

Multiple mounts:

```bash
./app.bin \
  -v /srv/app/input:/input \
  -v /srv/app/output:/output
```

Append `:ro` to remount a mount read-only (`:rw` is the default and may be
given explicitly):

```bash
./app.bin -v /srv/app/config:/etc/app/config:ro
```

A `-v` that fails to validate or mount aborts the run.

## Secrets

Host file secret:

```bash
./app.bin --secret /etc/app/token
```

Custom destination:

```bash
./app.bin --secret /etc/ssl/private/key.pem:/run/secrets/tls_key
```

TPM2-sealed credential, looked up in the system credential stores
(`/etc/credstore.encrypted/NAME`, `…/NAME.cred`, and the `/run`, `/var/lib`
and unencrypted variants). Requires root and `systemd-creds`; not supported
with `--vm`:

```bash
systemd-creds encrypt --with-key=tpm2 --name=dbpass /dev/stdin \
    /etc/credstore.encrypted/dbpass
sudo ./app.bin --secret tpm2:dbpass:/run/secrets/db_password
```

A `--secret` that fails to validate or install aborts the run.

## SSH Agent

```bash
./app.bin --ssh-agent
```

The host `SSH_AUTH_SOCK` is mounted into the container at
`/run/ssh-agent.sock`.

## Networking

Use host networking:

```bash
./app.bin --net host
```

Disable networking:

```bash
./app.bin --net none
```

Use slirp4netns:

```bash
./app.bin --net slirp
```

Use pasta:

```bash
./app.bin --net pasta
```

Publish ports:

```bash
./app.bin -p 8080:80
```

`-p` implies userspace networking.

Slirp with explicit port forwarding:

```bash
./app.bin --net slirp:8080:80
```

Custom DNS:

```bash
./app.bin --dns 1.1.1.1 --dns 9.9.9.9 --dns-search example.internal
```

Add hosts entries:

```bash
./app.bin --add-host db:10.0.0.5
```

Default-deny egress allowlist:

```bash
./app.bin --net slirp \
  --allow-egress 10.0.0.0/24:443 \
  --allow-egress api.example.com:443
```

Egress allowlists require `--net slirp` or `--net pasta` and the host `nft`
command. Hostnames are resolved once on the host, before the container's
network namespace exists, and pinned into its `/etc/hosts`. If validation or
rule installation fails, the workload does not start. The slirp4netns/pasta
helper runs in the host namespaces and is stopped when the binary exits.

## Namespace Sharing

Share network or IPC namespaces with another container:

```bash
./app.bin --net container:12345
./app.bin --ipc container:12345
```

Use pod mode for multiple binaries:

```bash
oci2bin pod run --net shared --ipc shared ./api ./worker
```

## Filesystem Modes

Read-only rootfs:

```bash
./app.bin --read-only
```

`--read-only` makes the image root mount genuinely read-only. `/tmp` remains a
runtime tmpfs and `/run` is automatically mounted as tmpfs unless disabled.

Writable tmpfs for selected paths:

```bash
./app.bin --read-only --tmpfs /tmp --tmpfs /run
```

Disable automatic tmpfs handling:

```bash
./app.bin --read-only --no-auto-tmpfs
```

Writable throwaway root:

```bash
./app.bin --ephemeral-root
```

`--ephemeral-root` uses a writable temporary overlay and discards its upper
layer on exit.

### Extracted rootfs cache

The first launch of a binary extracts its layers once and keeps the merged
tree under `${XDG_CACHE_HOME:-~/.cache}/oci2bin/rootfs/<key>/`, where `<key>`
is the SHA-256 of the image config. Every later launch of a binary carrying
the same image skips extraction entirely; `--debug` shows `cache.hit` instead
of `extract.begin`/`extract.done`. The key is read straight out of the embedded
tar, so a warm start never copies or unpacks the payload.

The cached tree is never written to. Each run gets a private writable layer
on top, chosen in this order:

1. kernel overlayfs mounted inside the container's user namespace (Linux
   5.11+),
2. `fuse-overlayfs` on the host side (needs `/dev/fuse` and
   `user_allow_other`),
3. a reflink or byte copy of the tree into the run's tmpdir (always works,
   and still far cheaper than gunzip + tar + merge).

`--ephemeral-root` is satisfied by that layer. With `--overlay-persist DIR`
the overlay kinds put their upper/work directories in `DIR`, as before.
Writes made by the workload land in the run's upper layer or copy and are
discarded with the runtime tmpdir; a corrupted or partially written cache
entry is detected on the next launch (marker plus tree fingerprint) and
rebuilt rather than trusted.

```bash
./app.bin --rootfs-cache off        # extract per run, as before
./app.bin --rootfs-cache always     # also cache the plaintext of an encrypted image
OCI2BIN_ROOTFS_CACHE=off ./app.bin  # same as the flag, for wrappers
OCI2BIN_ROOTFS_LAYER=copy ./app.bin # pin the writable-layer kind
```

Encrypted (`--encrypt` / `--passphrase`) images are not cached unless
`--rootfs-cache always` is given, because the cache holds the decrypted
tree in plaintext. `--lazy` artifacts use their SquashFS payload and do not
touch the cache. Entries are built in a sibling temp directory and renamed
into place; concurrent first launches of the same image serialize on a lock
and share one build. `oci2bin prune` evicts entries by age or total size and
skips entries a running container still uses; `oci2bin doctor` reports the
cache location and size.

Persist overlay state:

```bash
./app.bin --overlay-persist /srv/app/state
```

Mount an embedded SquashFS rootfs without extracting OCI layers:

```bash
oci2bin --rootfs-format squashfs app:latest app.bin
./app.bin --lazy
```

`--lazy` requires an artifact built with `--rootfs-format squashfs`, plus
`squashfuse`, `fuse-overlayfs`, an accessible `/dev/fuse`, and
`user_allow_other` enabled in `/etc/fuse.conf` on the target. The SquashFS
payload is the read-only lower filesystem; the loader creates a writable
temporary FUSE overlay by default. `--read-only` remounts the resulting view
read-only, and `--overlay-persist DIR` puts the overlay upper/work directories
in `DIR`.

The mode fails closed when the payload is absent or corrupt, a FUSE helper
cannot start, `/dev/fuse` is unavailable, or a mount does not become ready.
Concurrent runs use separate temporary mount trees.

## Runtime Profiles

`--profile NAME` applies a bundle of runtime **defaults**; any explicit flag on
the same command line overrides the field it touches.

```bash
./app.bin --profile dev           # marker only: host net, no read-only, full caps
./app.bin --profile prod          # --net none, --read-only, drop-all caps + a safe baseline
./app.bin --profile locked-down   # prod, plus Landlock required, --strict, default mem/PID caps
./app.bin --profile prod --cap-add net_raw   # later flags override profile defaults
```

`prod` and `locked-down` keep a minimal capability baseline (chown,
dac_override, fowner, setgid, setuid, net_bind_service, kill); add more with
`--cap-add` after the profile. The chosen profile is also recorded for
`oci2bin explain` and the audit log.

## Resource Limits

Classic `setrlimit`:

```bash
./app.bin --ulimit nofile=1024
./app.bin --ulimit nproc=64
./app.bin --ulimit cpu=30
./app.bin --ulimit as=536870912
./app.bin --ulimit fsize=10485760
```

cgroup v2 limits:

```bash
./app.bin --memory 512m --cpus 0.5 --pids-limit 100
```

If `--memory`, `--cpus`, or `--pids-limit` is requested but cgroup v2 setup
fails (e.g. no `/sys/fs/cgroup/cgroup.controllers`, or no writable subtree),
the run aborts rather than starting unconstrained. Pass `--allow-degraded` to
run without enforcement instead:

```bash
./app.bin --memory 512m --allow-degraded
```

Resource presets:

```bash
./app.bin --size pi-zero
./app.bin --size pi4
./app.bin --size vps-small
./app.bin --size vps-medium
./app.bin --size beefy
./app.bin --size auto
```

Explicit limits override preset values.

## Users, Hostname, Devices, And GPUs

Run as a numeric user:

```bash
./app.bin --user 1000:1000
```

Set hostname:

```bash
./app.bin --hostname api-1
```

Expose a device:

```bash
./app.bin --device /dev/fuse
./app.bin --device /dev/ttyUSB0:/dev/serial0
```

Use GPUs or CDI devices:

```bash
./app.bin --gpus all
./app.bin --cdi-device nvidia.com/gpu=all
```

A requested `--device` that cannot be exposed aborts the run.

By default the container gets the standard host `/dev` nodes (null, zero,
full, random, urandom, tty) on a fresh `/dev` tmpfs, plus its own `/dev/shm`
tmpfs, `/dev/fd` and `/dev/stdin|stdout|stderr` (links into `/proc/self/fd`,
so `access_log /dev/stdout` works) and, with a PTY, `/dev/console`. `-v`
volumes are mounted after `/dev` is set up, so `-v HOST:/dev/...` targets are
honoured. Skip bind-mounting the host nodes with `--no-host-dev`:

```bash
./app.bin --no-host-dev
```

## Capabilities

Drop one capability:

```bash
./app.bin --cap-drop NET_RAW
```

Drop all and add back one:

```bash
./app.bin --cap-drop all --cap-add NET_BIND_SERVICE
```

Only the added capabilities remain in the bounding set, and they survive a
`--user` switch (they are raised as ambient capabilities). All kernel
capability names are accepted.

## Seccomp And Debugging

Use the default seccomp profile:

```bash
./app.bin
```

Disable it:

```bash
./app.bin --no-seccomp
```

Use a custom Docker-compatible profile:

```bash
./app.bin --seccomp-profile ./seccomp.json
```

Generate a minimal profile from one run:

```bash
./app.bin --gen-seccomp ./seccomp.json -- /usr/bin/app --warm-up
```

The profile is written to the host path given, and replays with
`--seccomp-profile` (see [Security](security.md#seccomp) for how profiles are
installed).

Debug with gdb:

```bash
./app.bin --gdb
```

## AppArmor And SELinux

Apply an AppArmor profile:

```bash
./app.bin --security-opt apparmor=my-profile
```

Set an SELinux exec label:

```bash
./app.bin --security-opt label=type:container_t
```

These need loaders built with the matching support; a loader without it
refuses to start the workload unconfined.

## Process Management

Run with an init process:

```bash
./app.bin --init
```

Run in the background:

```bash
./app.bin --name api --detach
```

Restart policies:

```bash
./app.bin --restart no
./app.bin --restart always
./app.bin --restart on-failure:5
```

Run the image healthcheck:

```bash
./app.bin --health
./app.bin --health --restart always
```

Override the probe or its timing (implies `--health`); `--no-health` disables
it even if the image declares one:

```bash
./app.bin --health-cmd 'curl -fsS http://localhost:8080/healthz || exit 1' \
          --health-interval 10 --health-timeout 5 --health-retries 3 \
          --health-start-period 20
./app.bin --no-health
```

Interactive and TTY mode:

```bash
./app.bin -it /bin/sh
```

`--init`, `--restart` and `--health` run the workload with the same user
(`--user`, or the image `User`), PTY, capabilities, LSM labels and seccomp
profile as a direct run; health probes run as that user too. A stop signal
during a restart back-off ends the supervisor instead of starting another
attempt, and a workload that ignores the SIGTERM sent for failing health checks
is killed after 10 seconds. With `-t`, end-of-file on stdin (`</dev/null`, a
systemd unit) only closes the input side; the workload keeps running.

## VM Mode Runtime

Run inside a microVM:

```bash
./app.bin --vm /bin/echo hello
```

Select the VMM:

```bash
./app.bin --vm --vmm cloud-hypervisor /bin/sh
./app.bin --vm --vmm /opt/bin/cloud-hypervisor /bin/sh
```

Set VM resources:

```bash
./app.bin --vm --memory 1g --cpus 2 /bin/sh
```

Use rootless libkrun networking:

```bash
./app.bin --vm --net userspace
./app.bin --vm -p 8080:80
./app.bin --vm --net none
```

libkrun uses its in-process TSI/vsock backend, so outbound TCP, UDP, and DNS do
not need a guest NIC, TAP device, or root privileges. Passing an explicit empty
port map keeps inbound listeners closed by default; each `-p HOST:GUEST` adds
one TCP mapping. `--net none` disables libkrun's implicit vsock/TSI device.

This path requires a libkrun-built artifact and a recent `libkrun.so.1`.
Cloud-hypervisor currently supports `--net none` only; it rejects
`--net userspace`, slirp/pasta network flags, and `-p`.

With cloud-hypervisor, the guest console is the caller's terminal, the
command after the image (and `--entrypoint`, `-e`, `--workdir`) is passed to
the guest, and the binary exits with the workload's exit status. The guest
init reaps orphaned processes, forwards SIGTERM/SIGINT/SIGHUP, brings up
`lo`, and powers the VM off when the workload exits. Arguments, `-e` values
and `-v` specs travel on the kernel command line, which is limited to 2048
bytes. Because they are on the kernel command line, they are visible to other
local users in the host's process list (`ps` of cloud-hypervisor) and in the
guest's `/proc/cmdline`: pass secrets with `--secret`-style files or libkrun
rather than `-e` on this backend. The guest kernel needs `CONFIG_PVH`, virtio-PCI and virtio-fs (see
`kernel/microvm.config`); `-v` uses `virtiofsd` (also found in
`/usr/libexec`).

Persist VM state:

```bash
./app.bin --vm --overlay-persist ./state /bin/sh
```

With cloud-hypervisor, `./state/oci2bin-data.ext2` is the upper layer of an
overlay over the guest root, so changes to the root filesystem persist across
runs.

## Metrics And Notifications

Prometheus metrics over a Unix socket:

```bash
mkdir -p "$XDG_RUNTIME_DIR/oci2bin"
./app.bin --metrics-socket "$XDG_RUNTIME_DIR/oci2bin/app.metrics.sock"
```

`XDG_RUNTIME_DIR` must be set to a user-owned runtime directory. The loader
does not create missing parent directories.

Notifications:

```bash
./app.bin --notify ntfy://homelab.local/oci2bin
./app.bin --notify gotify://host/token
./app.bin --notify discord://discord.com/api/webhooks/ID/TOKEN
./app.bin --notify slack://hooks.slack.com/services/T0/B0/XXXX
./app.bin --notify https://my-webhook.local/post     # generic JSON webhook
./app.bin --notify ntfy://homelab.local/oci2bin --notify-name vault
```

## Config File

```bash
./app.bin --config /etc/app/oci2bin.conf
```

The config file uses `key=value` entries for runtime options.

## Audit, Time, And First-Run Hint

Write audit logs:

```bash
mkdir -p "$HOME/.local/state/oci2bin"
./app.bin --audit-log "$HOME/.local/state/oci2bin/app.audit"
```

Choose a path writable by the invoking user; rootless runs normally cannot
create files under `/var/log`.

Apply a clock offset with a time namespace:

```bash
./app.bin --clock-offset +3600
```

When the image declares required env vars with empty default values, the binary
prints a first-run hint automatically. Silence it, or fail closed when hints
are present:

```bash
./app.bin --no-hint        # silence the hint and continue
./app.bin --require-hint   # abort (exit 64) if the image declares unset env vars
```

## Exit Codes

The binary exits with the container process exit code when the container starts
successfully. Startup, verification, extraction, and policy failures return a
loader error before the image command runs.
