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

### Ubuntu 23.10+ / Debian-derived: AppArmor restriction

These ship `kernel.apparmor_restrict_unprivileged_userns=1`. The user namespace
is still created, but AppArmor strips its capabilities, so the follow-up
`unshare(NEWNS|NEWPID|NEWUTS)` fails and you see:

```
unshare(NEWNS|NEWPID|NEWUTS): Operation not permitted
```

The binary detects this and prints the fix. You have three options:

```bash
# 1. Relax the knob globally (simplest; needs root once):
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | \
    sudo tee /etc/sysctl.d/60-oci2bin-userns.conf      # persist across reboots

# 2. Or author an AppArmor profile that grants `userns,` to the binary
#    (Ubuntu's intended per-application mechanism — see `man apparmor.d`).
#    Practical when the binary lives at a stable path.

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
`tar`, and `/dev/kvm` (for `--vm`), then exits non-zero if a blocking issue is
found. You can also probe the kernel knobs by hand:

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

## Secrets

Host file secret:

```bash
./app.bin --secret /etc/app/token
```

Custom destination:

```bash
./app.bin --secret /etc/ssl/private/key.pem:/run/secrets/tls_key
```

TPM2-sealed credential:

```bash
./app.bin --secret tpm2:dbpass:/run/secrets/db_password
```

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
./app.bin --allow-egress 10.0.0.0/24:443 --allow-egress api.example.com:443
```

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

Writable tmpfs for selected paths:

```bash
./app.bin --read-only --tmpfs /tmp --tmpfs /run
```

Disable automatic tmpfs handling:

```bash
./app.bin --read-only --no-auto-tmpfs
```

Persist overlay state:

```bash
./app.bin --overlay-persist /srv/app/state
```

Lazy rootfs extraction probe:

```bash
./app.bin --lazy
```

The lazy extraction path is a `userfaultfd` capability probe only: it does not
yet enable on-demand paging and always falls back to full extraction. Reserved
for future use; treat as experimental.

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

By default the container gets the standard host `/dev` nodes (null, zero,
random, etc.). Skip bind-mounting them with `--no-host-dev`:

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

These need loaders built with the matching support.

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

Persist VM state:

```bash
./app.bin --vm --overlay-persist ./state /bin/sh
```

## Metrics And Notifications

Prometheus metrics over a Unix socket:

```bash
./app.bin --metrics-socket /run/oci2bin/app.metrics.sock
```

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
./app.bin --audit-log /var/log/oci2bin/app.audit
```

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
