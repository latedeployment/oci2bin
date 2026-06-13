# Feature Inventory

This page is a checklist of the feature surface documented by the site.

## Build Inputs

| Feature | Command |
| --- | --- |
| Build from Docker or Podman image | `oci2bin alpine:latest` |
| Build (and validate) by image digest | `oci2bin alpine@sha256:<64-hex>` |
| Build from OCI layout directory | `oci2bin --oci-dir ./layout alpine:latest` |
| Build from chroot | `oci2bin from-chroot ./rootfs -o app.bin` |
| Build from Dockerfile without Docker | `oci2bin build-dockerfile -f Dockerfile -o app.bin` |
| One-shot build and run | `oci2bin run IMAGE -- ARGS` |

## Build Transformations

| Feature | Command |
| --- | --- |
| Cross-architecture output (both directions) | `oci2bin --arch aarch64 ...` / `--arch x86_64 ...` |
| Multi-arch wrapper | `oci2bin --arch all alpine:latest` |
| qemu-user-static fallback | automatic through wrapper when available |
| Add file | `--add-file HOST:CONTAINER` |
| Add directory | `--add-dir HOST:CONTAINER` |
| Merge image layers | `--layer IMAGE` |
| Strip docs, locales, caches | `--strip` |
| Custom strip prefix | `--strip-prefix PREFIX` |
| Package-manager cache detection | `--strip-auto` |
| Squash layers | `--squash` |
| Override entrypoint at build | `--entrypoint '["redis-server"]'` |
| Override default command at build | `--cmd '["--port","6380"]'` |
| zstd-compress payload | `--compress-binary zstd` |
| Add labels | `--label KEY=VAL` |
| Cache output binary | `--cache` |
| Disable layer cache | `--no-cache` |
| Reproducible output | `--reproducible` |
| Offline, hermetic build | `--offline-only` |
| Pin runtime digest | `--pin-digest auto` |

## Dockerfile Builder

| Feature | Support |
| --- | --- |
| `FROM` | `scratch`, OCI dir, or image |
| `COPY` | supported |
| `ADD` | supported |
| `RUN` | supported |
| `RUN --mount=type=bind` | supported |
| `RUN --mount=type=secret` | supported |
| `RUN --mount=type=ssh` | supported |
| `RUN --mount=type=cache` | supported |
| `RUN --mount=type=tmpfs` | supported |
| `ENV` | supported |
| `ENTRYPOINT` | supported |
| `CMD` | supported |
| `WORKDIR` | supported |
| `LABEL` | supported |
| `USER` | supported |
| `EXPOSE` | supported |
| `ARG` | supported |

## Runtime Process

| Feature | Command |
| --- | --- |
| Override command | `./app CMD ARGS` |
| Override entrypoint | `--entrypoint PATH` |
| Set workdir | `--workdir PATH` |
| Environment variable | `-e KEY=VALUE` |
| Pass host environment variable | `-e KEY` |
| Environment file | `--env-file FILE` |
| Init and zombie reaping | `--init` |
| Detach | `--detach` or `-d` |
| Name container | `--name NAME` |
| Restart policy | `--restart always`, `--restart on-failure:5` |
| Health checks | `--health`, `oci2bin healthcheck` |
| Health probe override | `--health-cmd`, `--health-interval`, `--health-timeout`, `--health-retries`, `--health-start-period` |
| Disable health | `--no-health` |
| Runtime profile preset | `--profile dev\|prod\|locked-down` |
| Interactive TTY | `-it` (`--interactive` / `--tty`) |

## Runtime Filesystem

| Feature | Command |
| --- | --- |
| Bind mount | `-v HOST:CONTAINER` |
| Runtime secret file | `--secret HOST[:CONTAINER]` |
| TPM2-sealed secret | `--secret tpm2:NAME[:CONTAINER]` |
| SSH agent forwarding | `--ssh-agent` |
| tmpfs mount | `--tmpfs PATH` |
| Read-only rootfs | `--read-only` |
| Disable auto tmpfs | `--no-auto-tmpfs` |
| Persistent overlay state | `--overlay-persist DIR` |
| Lazy rootfs extraction probe | `--lazy` |
| Device mount | `--device /dev/HOST[:CONTAINER]` |
| Skip host /dev nodes | `--no-host-dev` |
| GPU selection | `--gpus all` |
| CDI device selection | `--cdi-device nvidia.com/gpu=all` |

## Runtime Networking

| Feature | Command |
| --- | --- |
| Host network | `--net host` |
| No network | `--net none` |
| slirp4netns | `--net slirp` |
| pasta | `--net pasta` |
| Publish port | `-p HOST:CONTAINER` |
| slirp port mapping | `--net slirp:HOST:CONTAINER` |
| Custom DNS server | `--dns IP` |
| DNS search domain | `--dns-search DOMAIN` |
| Extra hosts entry | `--add-host HOST:IP` |
| Default-deny egress allowlist | `--allow-egress HOST:PORT` or `CIDR:PORT` |
| Share container network namespace | `--net container:PID` |
| Share IPC namespace | `--ipc container:PID` |
| Pod mode | `oci2bin pod run --net shared --ipc shared ...` |
| Pod network alias | `--network-alias NAME` |

## Runtime Limits And Isolation

| Feature | Command |
| --- | --- |
| Memory limit | `--memory 512m` |
| CPU limit | `--cpus 0.5` |
| PID limit | `--pids-limit 100` |
| Resource preset | `--size pi4`, `--size auto` |
| `setrlimit` controls | `--ulimit nofile=1024` |
| Drop capability | `--cap-drop CAP` |
| Add capability | `--cap-add CAP` |
| Default seccomp | automatic |
| Disable seccomp | `--no-seccomp` |
| Custom seccomp profile | `--seccomp-profile FILE` |
| Generate seccomp profile | `--gen-seccomp FILE` |
| Read-only path inside writable subtree | `--seccomp-deny-write PATH` |
| Landlock filesystem sandbox | automatic; force `--landlock`, disable `--no-landlock` |
| Force single-ID userns fallback | `--no-userns-remap` |
| Fail-closed on degradations | `--strict` |
| gdb debugging | `--gdb` |
| AppArmor profile | `--security-opt apparmor=PROFILE` |
| SELinux label | `--security-opt label=TYPE:VAL` |
| Run as numeric user | `--user UID[:GID]` |
| Custom hostname | `--hostname NAME` |
| Time namespace offset | `--clock-offset OFFSET` |

## Integrity, Signing, And Encryption

| Feature | Command |
| --- | --- |
| Sign binary | `oci2bin sign --key priv.pem --in app.bin` |
| Verify binary | `oci2bin verify --key pub.pem --in app.bin` |
| Runtime verification | `./app.bin --verify-key pub.pem` |
| Mandatory embedded signature policy | `--require-signed pub.pem` |
| Sign a detached file | `oci2bin sign-file --key priv.pem --in file --out file.sig` |
| Verify a detached file | `oci2bin verify-file --key pub.pem --in file --sig file.sig` |
| Signature hash algorithm | `--hash-algorithm sha256\|sha512` |
| Rekor transparency log entry | `oci2bin sign --rekor [--rekor-url URL]` |
| Verify Rekor inclusion | `oci2bin verify --rekor ...` |
| SLSA or in-toto attestation | `oci2bin sign --attest auto\|provenance.json ...` |
| Require attestation on verify | `oci2bin verify --require-attestation ...` |
| Source image cosign verification | `--verify-cosign` (abort with `--require-cosign`, key `--cosign-key`) |
| Encrypt for recipients | `--encrypt --recipient AGE_PUB` |
| Encrypt with recipients file | `--encrypt --recipients-file FILE` |
| Encrypt with passphrase | `--passphrase` |
| Runtime age identity | `OCI2BIN_IDENTITY=FILE ./app.bin` |
| Runtime password | `OCI2BIN_PASSWORD=... ./app.bin` |
| Runtime password file | `OCI2BIN_PASSWORD_FILE=FILE ./app.bin` |
| Kernel-protected secret memory | automatic with `memfd_secret` where available |
| Show embedded attestation | `oci2bin attest-show --in app.bin` |
| Verify recorded source-image attestation | `oci2bin attest verify --in app.bin [--recheck]` |

## VM Mode

| Feature | Command |
| --- | --- |
| Build VM default binary | `oci2vm IMAGE` |
| Runtime VM mode | `./app.bin --vm` |
| Select VMM | `--vmm cloud-hypervisor` or `--vmm PATH` |
| Embed kernel | `--kernel PATH` |
| Embed initramfs | `--initramfs PATH` |
| Force libkrun loader | `--libkrun` |
| Force static loader | `--no-libkrun` |
| Custom VM defaults | VM-specific build/runtime options |

## Reconstruction And Registry Round Trip

| Feature | Command |
| --- | --- |
| Embed loader as image layer | `--embed-loader-layer` |
| Embed loader as image labels | `--embed-loader-labels` |
| Change label chunk size | `--label-chunk-size N` |
| Change loader directory | `--loader-dir DIR` |
| Change label prefix | `--label-prefix PREFIX` |
| Reconstruct from image or file | `oci2bin reconstruct SRC --output PATH` |
| Preserve loader through registry | push/pull image after embedding loader |

## Operations

| Feature | Command |
| --- | --- |
| Inspect binary | `oci2bin inspect app.bin` |
| Inspect as JSON | `oci2bin inspect app.bin --json` |
| Inspect with template | `oci2bin inspect app.bin --format TEMPLATE` |
| Explain binary | `oci2bin explain app.bin` |
| List cache | `oci2bin list`, `oci2bin list --json` |
| Prune cache | `oci2bin prune`, `oci2bin prune --dry-run` |
| Compare binaries | `oci2bin diff a b` |
| Compare overlay filesystem | `oci2bin diff-fs DIR` |
| Execute in running container | `oci2bin exec PID -- CMD` |
| Process list | `oci2bin ps` |
| Stop container | `oci2bin stop NAME` |
| Logs | `oci2bin logs NAME` |
| Live stats | `oci2bin top` |
| Generate systemd unit | `oci2bin systemd app.bin` |
| Generate SBOM | `oci2bin sbom app.bin` |
| Push image payload | `oci2bin push app.bin REF` |
| Update a binary from its signed manifest | `oci2bin update [--check] [--verify-key PATH] app.bin` |
| Self-update check | `./app.bin --check-update` |
| Self-update apply | `./app.bin --self-update` |
| Freeze and thaw | `oci2bin freeze NAME`, `oci2bin thaw NAME` |
| Checkpoint and restore | `oci2bin checkpoint NAME`, `oci2bin restore NAME` |
| Declarative stack up/down | `oci2bin up`, `oci2bin down` |
| Stack subcommands | `oci2bin stack up/down/logs/config` |
| Host capability checks | `oci2bin doctor`, `oci2bin doctor --json` |
| MCP server | `oci2bin mcp-serve` |
| Prometheus metrics socket | `--metrics-socket PATH` |
| Notifications | `--notify ntfy://...`, `gotify://`, `discord://`, `slack://`, `https://` |
| Notification label | `--notify-name NAME` |
| Audit logging | `--audit-log PATH` |
| First-run env hint | automatic; `--no-hint` / `--require-hint` |
