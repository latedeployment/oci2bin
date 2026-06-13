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
--strip-prefix PREFIX
--strip-auto
--squash
--add-file HOST:CONTAINER
--add-dir HOST:CONTAINER
--oci-dir DIR
--tar FILE
--label KEY=VAL
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

## Generated Binary

```bash
./OUTPUT [RUNTIME_OPTIONS] [-- CMD [ARGS...]]
```

Common runtime options:

```text
-v HOST:CONTAINER
-e KEY=VALUE
--env-file FILE
--secret HOST_FILE[:CONTAINER_PATH]
--entrypoint PATH
--workdir PATH
--net host|none|slirp|pasta|container:PID
--ipc host|container:PID
-p HOST_PORT:CONTAINER_PORT
--add-host HOST:IP
--dns IP
--dns-search DOMAIN
--allow-egress CIDR_OR_HOST
--read-only
--overlay-persist DIR
--tmpfs PATH
--no-auto-tmpfs
--ssh-agent
--device /dev/HOST[:CONTAINER]
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
--gdb
--security-opt apparmor=PROFILE
--security-opt label=TYPE:VAL
--init
--detach
--name NAME
--restart POLICY
--health
--vm
--vmm PATH
--verify-key PATH
--config PATH
--metrics-socket PATH
--notify URL
--audit-log PATH
--clock-offset OFFSET
--debug
```

## Subcommands

```bash
oci2bin exec PID -- CMD
oci2bin inspect BINARY [--json | -o json | --format TEMPLATE]
oci2bin explain BINARY
oci2bin list [--json]
oci2bin prune [--dry-run]
oci2bin diff BINARY1 BINARY2
oci2bin diff-fs OVERLAY_PATH
oci2bin freeze NAME [-- CMD]
oci2bin thaw NAME
oci2bin reconstruct SRC [--output PATH] [--no-strip] [--label-prefix PREFIX]
oci2bin push BINARY REF
oci2bin sbom BINARY
oci2bin run [BUILD_OPTIONS] IMAGE [-- RUNTIME_ARGS...]
oci2bin systemd BINARY [--user] [--restart POLICY]
oci2bin healthcheck BINARY [--pid PID]
oci2bin ps
oci2bin stop NAME
oci2bin logs NAME
oci2bin checkpoint NAME
oci2bin restore NAME
oci2bin top [--once] [--interval SEC]
oci2bin doctor [--json]
oci2bin mcp-serve
```

## Signing Commands

```bash
oci2bin sign --key KEY.pem --in BINARY [--out BINARY] [--rekor] [--attest FILE]
oci2bin verify --key PUB.pem --in BINARY
oci2bin sign-file --key KEY.pem --in FILE --out SIG
oci2bin verify-file --key PUB.pem --in FILE --sig SIG
```

## Pod And Stack Commands

```bash
oci2bin pod run [--net shared] [--ipc shared] BINARY [BINARY ...]
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
