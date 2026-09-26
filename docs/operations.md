# Operations

This page covers day-two commands: inspect, run under systemd, manage detached
containers, compare artifacts, update, checkpoint, and troubleshoot.

## Inspect A Binary

```bash
oci2bin inspect app.bin
```

JSON output:

```bash
oci2bin inspect app.bin --json
oci2bin inspect app.bin -o json
```

Template output:

```bash
oci2bin inspect app.bin --format '{{ .Image }} {{ .Digest }}'
```

Explain what is inside:

```bash
oci2bin explain app.bin
```

## Cache Management

List cached binaries:

```bash
oci2bin list
oci2bin list --json
```

Prune old cache entries:

```bash
oci2bin prune --dry-run
oci2bin prune
```

`prune` covers two caches. Superseded `--cache` build outputs under
`~/.cache/oci2bin` are removed, keeping the newest per image. The extracted
rootfs trees the produced binaries keep under
`${XDG_CACHE_HOME:-~/.cache}/oci2bin/rootfs` (see the runtime guide) are
evicted when unused for 30 days; `--max-age DAYS` changes that, `--max-size
SIZE` then evicts least-recently-used trees until the cache fits, and `--all`
empties it. Trees a running container still uses are skipped.

```bash
oci2bin prune --max-age 7 --max-size 5G
oci2bin prune --all
```

Build using the output cache:

```bash
oci2bin --cache redis:7-alpine
```

A cached binary is reused only when the image digest, the target
architecture, the loader and every build option (`--strip`, `--squash`,
`--label`, ...) match. Builds with `--encrypt`/`--passphrase`, `--add-file`,
`--add-dir` or `--layer` bypass the cache, since their inputs are not part of
the key.

Disable the per-layer cache for one build:

```bash
oci2bin --no-cache redis:7-alpine
```

`--no-cache` controls caching only. Every layer is still hashed and checked
against the `diff_id` the image config declares for it, on every build, and a
mismatch aborts the build. So does an image whose config does not let the
build determine the digests at all — a missing or malformed
`rootfs.diff_ids`, or a count that disagrees with the manifest's layer list.
(A `--tar` payload with no `manifest.json` is not an image and is passed
through with a note; the loader rejects such an artifact at run time.)

This is a self-consistency check: `diff_ids` travel in the same tar as the
layers, so it catches corruption, truncation and partial tampering, not a
forged image. For authenticity use `--require-signed`, `--pin-digest`, or
cosign verification.

## Detached Containers

Start a named container:

```bash
./app.bin --name api --detach
```

List:

```bash
oci2bin ps
```

Stop:

```bash
oci2bin stop api
```

Logs:

```bash
oci2bin logs api
```

Execute into a running container by PID:

```bash
oci2bin exec 12345 -- /bin/sh
```

## Health Checks

Run the embedded OCI healthcheck:

```bash
oci2bin healthcheck app.bin
```

Run against a process:

```bash
oci2bin healthcheck app.bin --pid 12345
```

Run at container startup:

```bash
./app.bin --health --restart always
```

## Restart Policy

```bash
./app.bin --restart no
./app.bin --restart always
./app.bin --restart on-failure:5
```

Use restart policy with health checks for simple supervision:

```bash
./app.bin --name api --detach --health --restart always
```

## systemd

Generate a unit:

```bash
oci2bin systemd ./app.bin --restart always > app.service
```

Generate a user unit:

```bash
oci2bin systemd ./app.bin --user --restart on-failure > app.service
```

Install:

```bash
mkdir -p ~/.config/systemd/user
cp app.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now app.service
```

## Declarative Stacks

Start a stack:

```bash
oci2bin up -f stack.yaml
```

Start in the background:

```bash
oci2bin up -f stack.yaml -d
```

Apply a start delay:

```bash
oci2bin up -f stack.yaml -d --start-delay 2
```

Stop:

```bash
oci2bin down -f stack.yaml
```

Stack subcommands:

```bash
oci2bin stack up -f stack.yaml
oci2bin stack down -f stack.yaml
oci2bin stack logs blog
oci2bin stack logs blog app -f
oci2bin stack config -f stack.yaml
```

`stack logs` is addressed by stack name, not by file path. Add a service name
to show one service and `-f` to follow.

## Pod Mode

```bash
oci2bin pod run --net shared --ipc shared ./api ./worker ./sidecar
```

Use pod mode when binaries should share network or IPC namespaces.

## Diff And Filesystem Changes

Compare two binaries:

```bash
oci2bin diff app_v1 app_v2
```

Compare a persisted overlay upperdir:

```bash
oci2bin diff-fs /srv/app/state
```

## Freeze And Thaw

Snapshot SQLite databases in a running named container:

```bash
oci2bin freeze api
oci2bin thaw api
```

Run a command while frozen:

```bash
oci2bin freeze api -- sqlite3 /data/app.db 'pragma integrity_check'
```

## Checkpoint And Restore

Checkpoint a named detached container:

```bash
oci2bin checkpoint api
```

Restore:

```bash
oci2bin restore api
```

Checkpoints are stored under:

```text
~/.local/share/oci2bin/checkpoints/
```

This path uses CRIU and needs host support.

## Live Stats

```bash
oci2bin top
oci2bin top --once
oci2bin top --interval 2
```

## SBOM

```bash
oci2bin sbom app.bin
```

Generate an SBOM when downstream inventory or vulnerability scanning needs a
software list for the embedded image. Packages are read from dpkg, apk and rpm
databases (rpm's `rpmdb.sqlite` header blobs, under `/usr/lib/sysimage/rpm` or
`/var/lib/rpm`), and each carries a canonical purl such as
`pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian`, which Grype and Trivy
consume.

## Push

```bash
oci2bin push app.bin registry.example.com/app:latest
```

Use push when the image payload should be sent back to an OCI registry.

## Update

Embed an update manifest URL:

```bash
oci2bin --self-update-url https://example.test/app.update.json app:latest app.bin
```

Check for updates:

```bash
./app.bin --check-update --verify-key pub.pem
```

Apply an update:

```bash
./app.bin --self-update --verify-key pub.pem
```

The manifest is signature-verified before replacement.

## Reconstruct

```bash
oci2bin reconstruct redis:7-alpine --output redis_7-alpine
```

From a file:

```bash
oci2bin reconstruct redis_7-alpine --output rebuilt
```

With a custom label prefix:

```bash
oci2bin reconstruct redis:7-alpine --label-prefix myorg.loader
```

## Doctor And Troubleshooting

```bash
oci2bin doctor          # build host
oci2bin doctor --json   # build host, machine-readable
./app.bin --doctor      # deployment host
```

The CLI doctor checks the machine that builds artifacts. The artifact doctor
checks the machine on which that exact file will run, without extracting it or
creating namespaces. Use the latter when a deployment host behaves differently
from the build machine.

Common checks:

- user namespaces are enabled
- `newuidmap` and `newgidmap` are installed for wider UID/GID mappings
- cgroup v2 exists for hard resource limits
- `slirp4netns` or `pasta` exists for userspace networking
- `zstd` exists when running zstd-compressed binaries
- age identity or password is available for encrypted binaries
- KVM and VM backend support exist for VM mode

## MCP Server

```bash
oci2bin mcp-serve
```

The MCP server exposes `oci2bin` functionality to AI agents through structured
tool calls. See [Commands](reference/commands.md) for its mount, network,
image and environment rules.

## Local Validation

Run the fast unit suite without Docker or Podman:

```bash
make test-unit
```

Run the full unit sweep on native x86_64 and cross-compiled aarch64:

```bash
make test-all
```

This target does not require Docker or Podman. Container-engine integration
tests are separate under `make test`.

Check the C unit suite with AddressSanitizer, UndefinedBehaviorSanitizer, and
LeakSanitizer:

```bash
make test-asan
```

These targets run locally; the project does not use hosted CI for tests.
