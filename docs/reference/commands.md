# Command Reference

This page gives command shapes and short explanations. See the guide pages for
full examples.

## Build

```bash
oci2bin [BUILD_OPTIONS] IMAGE[:TAG] [OUTPUT]
```

Common build options:

```text
--arch ARCH
--cache
--no-cache
--layer IMAGE
--strip
--strip-prefix PREFIX        # root-relative; no leading slash
--strip-auto
--squash
--rootfs-format tar|squashfs
--compress gzip|zstd         # squashed-layer codec; requires --squash
--add-file HOST:CONTAINER
--add-dir HOST:CONTAINER
--oci-dir DIR
--pull-with docker|podman|skopeo
--label KEY=VAL
--entrypoint JSON_OR_STRING
--cmd JSON_OR_STRING
--encrypt
--recipient AGE_PUB
--recipients-file FILE
--passphrase
--password-file FILE
--compress-binary zstd
--require-signed PUB
--self-update-url URL
--pin-digest DIGEST
--reproducible
--offline-only
--verify-cosign
--require-cosign
--cosign-key PUB
--embed-loader-layer
--embed-loader-labels
--label-chunk-size N
--loader-dir DIR
--label-prefix PREFIX
--kernel PATH
--initramfs PATH
--libkrun
--no-libkrun
```

`--verify-cosign` warns and continues if verification fails or `cosign` is
missing. Use `--require-cosign` when source verification is an enforced build
policy. A later `sign --attest auto` command needs explicit
`--cosign-image-ref`, `--cosign-key-path`, and `--cosign-result` arguments to
record that build-time result.

Age recipient and passphrase modes encrypt the embedded OCI payload, not the
executable loader. They are mutually exclusive, remove direct `docker load`
compatibility, and prevent byte-identical encrypted rebuilds because age uses
fresh randomness.

`--rootfs-format squashfs` retains the OCI tar and appends a mountable rootfs
for `--lazy`. It needs `mksquashfs` at build time and `squashfuse`,
`fuse-overlayfs`, `/dev/fuse`, and `user_allow_other` enabled in
`/etc/fuse.conf` at runtime. It cannot be combined with age encryption because
the second rootfs would disclose the plaintext image.

## Generated Binary

```bash
./OUTPUT [RUNTIME_OPTIONS] [-- CMD [ARGS...]]
```

Common runtime options:

```text
-v HOST:CONTAINER[:ro|:rw]
-e KEY=VALUE
--env-file FILE
--secret HOST_FILE[:CONTAINER_PATH]
--entrypoint PATH
--workdir PATH
--net host|none|userspace|slirp|pasta|container:PID
--ipc host|container:PID
-p HOST_PORT:CONTAINER_PORT
--add-host HOST:IP
--dns IP
--dns-search DOMAIN
--allow-egress HOST:PORT
--allow-egress CIDR:PORT
--read-only
--ephemeral-root
--overlay-persist DIR
--rootfs-cache auto|off|always
--no-rootfs-cache
--tmpfs PATH
--lazy
--no-auto-tmpfs
--ssh-agent
--device /dev/HOST[:CONTAINER]
--no-host-dev
--gpus all
--cdi-device NAME
--cap-drop CAP
--cap-add CAP
--user UID[:GID]
--hostname NAME
--memory SIZE
--cpus FLOAT
--pids-limit N
--size NAME
--ulimit TYPE=N
--no-seccomp
--seccomp-profile FILE
--gen-seccomp FILE
--landlock
--no-landlock
--seccomp-deny-write PATH
--gdb
--security-opt apparmor=PROFILE
--security-opt label=TYPE:VAL
--no-userns-remap
--strict
--allow-degraded
--init
--detach
--name NAME
--restart POLICY
--health
--health-cmd CMD
--health-interval N
--health-timeout N
--health-retries N
--health-start-period N
--no-health
-i | --interactive
-t | --tty
--vm
--vmm PATH
--verify-key PATH
--check-update
--self-update
--config PATH
--metrics-socket PATH
--notify URL
--notify-name NAME
--audit-log PATH
--clock-offset OFFSET
--no-hint
--require-hint
--debug
--doctor              # report this host's runtime readiness, then exit
```

`--net userspace` and VM-mode `-p` use libkrun's rootless TSI networking.
Outbound networking is available without a TAP device; inbound listeners stay
closed unless published with `-p`. Use `--vm --net none` to disable TSI.
Cloud-hypervisor currently accepts only `--net none` and rejects `-p`.

## Subcommands

```bash
oci2bin exec PID -- CMD
oci2bin inspect BINARY [--json | -o json | --format TEMPLATE]
oci2bin benchmark BINARY [--modes extract,lazy,vm] [--runs N]
                        [--warmups N] [--timeout SEC] [--json] [-o FILE]
                        [-- CMD...]
oci2bin explain BINARY
oci2bin list [--json] [--filter label=KEY[=VAL]]
oci2bin prune [--dry-run] [--max-age DAYS] [--max-size SIZE] [--all]
oci2bin diff BINARY1 BINARY2
oci2bin diff-fs OVERLAY_PATH
oci2bin freeze NAME [-- CMD]
oci2bin thaw NAME
oci2bin reconstruct SRC [--output PATH] [--no-strip] [--label-prefix PREFIX]
oci2bin push BINARY REF
oci2bin sbom BINARY
oci2bin update [--check] [--verify-key PATH] BINARY   # replays the recorded build options
oci2bin run [BUILD_OPTIONS] IMAGE [-- RUNTIME_ARGS...]
oci2bin systemd BINARY [--user] [--restart POLICY]
oci2bin healthcheck BINARY [--pid PID]
oci2bin ps [--filter label=KEY[=VAL]]
oci2bin stop NAME
oci2bin logs [-f | --follow] NAME
oci2bin checkpoint NAME
oci2bin restore NAME
oci2bin top [--once] [--interval SEC]
oci2bin doctor [--json]
oci2bin mcp-serve [--allow-net] [--allow-mount PATH] [--allow-mount-rw PATH]
```

## Signing Commands

```bash
oci2bin sign --key KEY.pem --in BINARY [--out BINARY] [--rekor] [--attest FILE]
oci2bin verify --key PUB.pem --in BINARY [--require-attestation] [--rekor]
oci2bin attest-show --in BINARY
oci2bin attest verify --signing-key PUB.pem --in BINARY [--recheck] [--key COSIGN_PUB]
oci2bin sign-file --key KEY.pem --in FILE --out SIG
oci2bin verify-file --key PUB.pem --in FILE --sig SIG
```

## Pod And Stack Commands

```bash
oci2bin pod run [--net shared] [--ipc shared] [--network-alias NAME] BINARY [BINARY ...]
oci2bin up [-f stack.yaml] [-d] [--start-delay SEC]
oci2bin down [STACK_NAME | -f stack.yaml]
oci2bin stack up [-f stack.yaml] [-d] [--start-delay SEC]
oci2bin stack down [STACK_NAME | -f stack.yaml]
oci2bin stack logs STACK_NAME [SERVICE] [-f]
oci2bin stack config [-f stack.yaml]
```

`up`/`down`/`config` take the stack file with `-f` (default `stack.yaml`);
`down` also accepts the stack name. `logs` is addressed by stack name (the
file's `name:`, default `stack`) with an optional service, and `-f` there means
*follow* (like `tail -f`), not a file.

`mcp-serve` starts a stdio JSON-RPC MCP server. It keeps networking disabled by
default; `--allow-net` only permits host networking when the MCP caller also
requests it. Host mounts are denied outright unless a root is allowed with
`--allow-mount` (read-only) or `--allow-mount-rw`; mounts with no explicit
suffix are read-only, and `:rw` is refused on a read-only root.

The `image` of `run_container` / `inspect_image` must be an oci2bin binary (an
ELF carrying an `OCI2BIN_META` block) outside every `--allow-mount-rw` root, so
a client cannot drop a script into a writable root and have the server run it.
`run_container` forwards only `KEY=VALUE` environment entries — a bare `NAME`
would copy the server's own environment into the container. `exec_in_container`
runs the command as root of the container's user namespace, inside its root
filesystem and namespaces, not with the server's credentials. Tool results are
always JSON strings.

## Build Without Docker

```bash
oci2bin from-chroot DIR -o OUTPUT \
  [--entrypoint PATH] \
  [--cmd CMD] \
  [--env KEY=VAL] \
  [--workdir DIR] \
  [--arch ARCH] \
  [--user UID[:GID]] \
  [--label KEY=VAL]
```

```bash
oci2bin build-dockerfile [FILE] \
  [-o OUTPUT] \
  [-f FILE] \
  [--context DIR] \
  [--build-arg KEY=VAL] \
  [--build-secret id=ID,src=PATH] \
  [--arch amd64|arm64]
```
