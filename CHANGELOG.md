# Changelog

All notable changes to oci2bin are documented here.

## [Unreleased]

### Added

- **`--vsock-port PORT`** — VM mode now ships an AF_VSOCK control agent
  inside the guest. The agent (folded into the loader binary, which is
  already the guest `/init`) forks before the entrypoint exec and listens
  on `PORT`. The host reaches it through the cloud-hypervisor hybrid-vsock
  UDS or the libkrun-mapped UDS. New `oci2bin vsock-ctl [--hybrid PORT]
  SOCKET CMD…` subcommand drives it. Wire protocol is one ASCII line per
  request: `exec ARGV…`, `stats`, or `stop`. Inputs are bounds-checked
  (4 KiB line, 64 args, no embedded control bytes) and `exec`'s child
  inherits the connection as stdio so workload output streams back.

## [0.11.0] - 2026-04-20

### Added

- **`memfd_secret` runtime secrets** — when `--secret` is used on Linux ≥ 5.14
  with `CONFIG_SECRETMEM=y`, the secret data is placed in a kernel-protected
  anonymous memory region excluded from the kernel direct mapping, crash dumps,
  and swap. The container still sees a normal path (`/run/secrets/<name>`) via
  a bind-mount of `/proc/self/fd/<n>`. TPM2-sealed secrets (decrypted via
  `systemd-creds`) use the same mechanism so the plaintext never enters the
  page cache. Falls back transparently to a read-only bind-mount on older
  kernels. All secret file opens now use `O_NOFOLLOW`.

- **`oci2bin from-chroot <dir>`** — build a self-contained binary directly
  from a chroot directory without Docker. The directory is packed into a single
  OCI image layer (setuid/setgid stripped, `proc`/`sys`/`dev` skipped, mtime
  forced to 0 for reproducibility) and piped through the standard build
  pipeline. Supports `--entrypoint`, `--cmd`, `--env`, `--workdir`, `--arch`,
  `--user`, `--label`, and pass-through `-- BUILD_OPTIONS`.

- **`oci2bin build-dockerfile [Dockerfile]`** — build a self-contained binary
  from a Dockerfile without a Docker daemon. Supports a BuildKit-compatible
  Dockerfile subset:
  - Instructions: `FROM scratch|<oci-layout-dir>|<docker-image>`, `COPY`,
    `ADD`, `RUN`, `ENV`, `ENTRYPOINT`, `CMD`, `WORKDIR`, `LABEL`, `USER`,
    `EXPOSE`, `ARG`
  - `RUN` executes via `unshare --user --map-root-user --mount --pid --fork
    chroot` — no daemon required
  - `RUN --mount=type=secret,id=<id>` — inject a `--build-secret` file into
    the build step only; not included in the image layer
  - `RUN --mount=type=ssh` — forward `$SSH_AUTH_SOCK` into the build step
  - `RUN --mount=type=cache,target=<path>` — persistent cache across builds at
    `~/.cache/oci2bin/build-cache/<id>`
  - `RUN --mount=type=bind,source=<src>` — bind-mount from the build context
  - `RUN --mount=type=tmpfs,target=<path>` — in-memory scratch space
  - `--build-secret id=<id>,src=<path>` and `--build-arg KEY=VAL` flags

- **`oci2bin mcp-serve`** — JSON-RPC 2.0 MCP server exposing container
  lifecycle tools (`run_container`, `stop_container`, `list_containers`,
  `inspect_image`) to AI agents and editors via stdin/stdout.

- **`--lazy` flag** — experimental userfaultfd-based lazy loading: registers
  the OCI tar region with the kernel and services page faults on demand,
  reducing startup latency for large images by avoiding an upfront full read.
  Requires `UFFD_FEATURE_MISSING_ANON` (Linux ≥ 5.7). Automatically disabled
  if the kernel does not support it.

- **TPM2-sealed secrets via `--secret tpm2:<cred>[:<path>]`** — decrypt
  credentials sealed with `systemd-creds encrypt --tpm2-device=auto` at
  container startup. Requires `systemd-creds` in PATH.

- **libFuzzer harnesses** — `fuzz_json.c` (JSON helpers), `fuzz_seccomp.c`,
  `fuzz_parse_opts.c`, `fuzz_mcp_jsonrpc.c` (MCP JSON-RPC parser). Corpus
  expanded with 8 new seed inputs targeting real edge cases: escaped strings,
  bracket-in-string (targeting `json_get_array` bracket-matcher), seccomp
  profiles, unicode keys, deep nesting, large arrays.

- **`RUN_CMD_CAPTURE_MAX` constant** — replaced bare `64 * 1024 * 1024`
  literal in `run_cmd_capture()` with a named constant.

### Fixed

- **MCP log symlink attack** — `open()` for `/tmp/oci2bin-mcp-<name>.log`
  now uses `O_NOFOLLOW`; a local attacker could have pre-created the path as a
  symlink to redirect log writes to an arbitrary file.

- **MCP volume path injection** — volume specs received from an MCP client are
  now validated with `path_is_absolute_and_clean` and
  `path_has_dotdot_component` before being forwarded to the container argv.
  Invalid specs are rejected and logged.

- **`inspect_image_main` config digest traversal** — `/` removed from the
  digest sanitizer charset; a crafted `Config` field like
  `"sha256:../../etc/shadow"` could have constructed a path outside the OCI
  directory. Added an explicit `strncmp` check that the resolved path stays
  under `oci_dir/`.

- **`inspect_image_main` tmpdir leak** — the function created a
  `mkdtemp`-allocated temporary directory but none of the ~15 return paths
  called `rm_rf_dir()`. Every invocation left a
  `/tmp/oci2bin-inspect.XXXXXX` directory.

- **`install_plain_secret` short read** — replaced single `read()` syscall
  with `read_all_fd()` loop. A short read would silently fall back from
  `memfd_secret` to a less-protected bind-mount without any warning.

- **`run_cmd_capture()` cap check** — tightened from `>` to `>=` so the
  64 MiB ceiling is enforced exactly at the boundary rather than one byte over.

## [0.10.0] - 2026-04-18

### Added

- **`oci2bin run IMAGE [-- ARGS]`** — build to a temp file and execute once;
  temp directory is cleaned up on exit.

- **`oci2bin systemd BINARY`** — emit a ready-to-use systemd unit file.
  Supports `--user` and `--restart always|on-failure|no`. Unit name derived
  from OCI labels (`oci2bin.name`, `org.opencontainers.image.title`) with
  safe character sanitisation.

- **`oci2bin healthcheck BINARY [--pid PID]`** — run the embedded OCI
  `HEALTHCHECK` command. With `--pid`, enters the container's namespaces via
  `nsenter`; without it, execs the command through the binary itself.

- **`oci2bin top [--once] [--interval SEC]`** — live stats table for all
  named running containers: CPU%, RSS/cgroup memory, PID count, uptime.

- **`oci2bin update --check [--verify-key KEY]`** — check whether a newer
  image or signed update manifest is available without rebuilding.

- **`oci2bin sign-file` / `oci2bin verify-file`** — detached ECDSA signing
  and verification for arbitrary files, using the same key format as binary
  signing. Supports `--hash-algorithm sha256|sha512`.

- **`--self-update-url URL`** — embed a signed update-manifest URL in the
  binary. At runtime `--check-update` fetches the manifest, verifies its
  ECDSA signature, and reports whether a newer version is available;
  `--self-update` downloads, hash-verifies, and atomically replaces the
  binary. Rollback manifests (lower version) are rejected.

- **`--pin-digest DIGEST|ALGO:auto`** — embed a canonical SHA-256 or SHA-512
  digest of the binary in the metadata block. At startup the binary verifies
  its own hash and refuses to run if it has been tampered with. `auto`
  computes and patches the digest at build time.

- **PyPI packaging** — `uv pip install oci2bin` / `pip install oci2bin`
  installs the `oci2bin` and `oci2vm` entry points. No Python runtime
  dependencies; requires `gcc` and `docker` at use time.

### Fixed

- **Signature verification bypass in `--self-update`** — `sign_binary.py` was
  opened via `SourceFileLoader` before being passed to the verifier subprocess
  as an fd path; the fd cursor was at EOF so the grandchild always read zero
  bytes and exited 0, accepting any manifest regardless of signature. Fixed by
  `os.lseek(fd, 0, 0)` before `subprocess.run`.

- **Unbounded manifest download** — `--self-update` fetched the manifest and
  `.sig` files with `r.read()` and no size cap; a hostile server could exhaust
  memory. Both downloads are now capped at 1 MiB.

- **`oci2bin top` crash on process exit** — `read_stat()` accessed
  `fields[21]` without a length guard; a process exiting between the
  `/proc/<pid>` existence check and the `stat` read caused an uncaught
  `IndexError` that crashed the display loop. Now raises `OSError` so the
  caller's `except OSError: continue` handles it.

- **PID-reuse hardening** — `stop` reads `start_ticks` (field 22 of
  `/proc/<pid>/stat`) from the container state JSON and re-verifies it before
  SIGTERM and before SIGKILL escalation, preventing signalling an unrelated
  process that reused the PID.

- **Symlink-safe state directory** — `container_state_dir_or_die()` validates
  that `$HOME` is absolute and that no component of the state path is a
  symlink before reading or writing state files.

- **`make install` missing scripts** — only `build_polyglot.py` and
  `reconstruct.py` were installed; `sign_binary.py`, `inspect_image.py`, and
  seven other helpers required by subcommands were missing. All 11 scripts are
  now installed.

### Tests

- `test_cli_features.py`: systemd unit emission, healthcheck short-circuit,
  sign/verify-file roundtrip, `top --once` output, `stop` PID-reuse rejection,
  signed update manifest check.
- `test_add_files.py`: layer injection via `add_files.py`.
- `test_build_meta.py`: metadata block embedding and `--pin-digest` patching.

## [0.9.0] - 2026-04-17

### Added

- **`--strip-prefix PREFIX`** — specify exact path prefixes to remove instead
  of the built-in docs/locale/cache defaults. Repeatable; each use implies
  `--strip`. Example: `oci2bin --strip-prefix root/.cache/pip/ python:3.12-slim`.

- **`--strip-auto`** — pre-scan image layers to auto-detect installed package
  managers (apt, apk, pip, npm, dnf/yum, gem, Go, Cargo, Python stdlib test
  dirs) and add their cache paths to the strip set automatically. Opt-in.

### Fixed

- **TOCTOU in `--verify-key`** — replaced `stat(path)` + `exec(path)` with
  `open` / `fstat` / exec via `/proc/self/fd/<n>` so the permission check and
  the execution always refer to the same inode; a `rename()`-based swap between
  the two calls is no longer possible.

- **Kernel cmdline injection in VM mode** — `-v` container paths are now
  rejected if they contain spaces before being appended to the kernel command
  line, preventing injection of additional kernel parameters.

- **`strip_image._norm` over-stripping** — replaced `lstrip('./')` with
  `removeprefix('./').lstrip('/')` so filenames beginning with multiple dots
  (e.g. `...hidden`) are no longer silently mangled.

- **Early path validation in `parse_opts`** — `-v` host/container paths,
  `--secret` host paths, and `--workdir` are now validated for absolute paths
  and `..` components at argument-parse time, not deferred to container setup.

- **`log_file` removed from container state JSON** — prevents leaking the log
  path through the state file (CodeQL `cpp/system-data-exposure`).

- **`chmod` → `fchmod`** — eliminates a TOCTOU race on the rootfs dev node
  permission change.

### Refactored

- Eliminated four duplicate fork/exec/wait blocks via shared `run_cmd` and
  `spawn_daemon` helpers.
- Decomposed `run_as_vm_ch` into focused helper functions.
- Moved 64 KB `cpbuf` from stack into `vm_ch_ctx` heap struct.

### Tests

- Added unit tests for previously-uncovered functions: `json_escape_string`,
  `parse_id_value`, `path_is_absolute_and_clean`, `path_join_suffix`.
- Added `parse_opts` boundary tests: `--name` allowlist/length, `--add-host`
  colon check, MAX_VOLUMES (32) boundary, `--net slirp`/`pasta`.
- Added `build_exec_args` tests: multi-element entrypoint, `max_args` overflow
  cap, both-null fallback.
- New `test_strip_image.py`: full coverage for `_norm`, `validate_prefix`,
  `should_strip`, `strip_layer`, and `autodetect_extra_prefixes`.

## [0.8.0] - 2026-03-21

### Added

- **`-t` / `--tty`** — explicitly allocate a pseudo-terminal for the container,
  even when stdin is not a terminal. `-i` / `--interactive` keeps stdin open for
  piped input without a PTY. Combine as `-it` for a full interactive shell
  session (equivalent to `docker run -it`).

- **`--name NAME`** — assign a name to a container. Combined with `--detach`,
  writes a JSON state file to `~/.cache/oci2bin/containers/<name>.json` and
  redirects the container's stdout/stderr to a log file at the same location.

- **`oci2bin ps`** — list all named containers with their PID and live running
  status (running / stopped).

- **`oci2bin stop NAME`** — send SIGTERM then SIGKILL to a named detached
  container and remove its state file.

- **`oci2bin logs [-f] NAME`** — print or follow the stdout/stderr log of a
  named detached container.

- **`oci2bin push BINARY REGISTRY/IMAGE:TAG`** — load the polyglot binary into
  Docker and push it to an OCI registry. The binary is already a valid
  `docker load` archive so no re-packaging is needed.

- **`oci2bin sbom BINARY [--format spdx|cyclonedx]`** — generate a Software
  Bill of Materials from the embedded OCI rootfs. Reads dpkg, apk, and rpm
  package databases and outputs SPDX 2.3 or CycloneDX 1.4 JSON.

- **`oci2bin update BINARY`** — re-pull the original image and atomically
  rebuild the binary in-place (temp file + rename). Reads the image reference
  from the embedded metadata block.

- **`oci2bin diff --live PID BINARY`** — compare a running container's live
  filesystem (`/proc/PID/root`) against its source binary. Shows added,
  removed, and modified files. Useful for auditing runtime changes and
  detecting unexpected mutations.

- **`--squash`** — merge all OCI image layers into a single squashed layer
  before embedding, processing whiteout entries correctly. Reduces layer count
  and can shrink the output binary for images with many overlapping writes.

- **`--compress gzip|zstd`** — choose the compression format for the squashed
  layer (default: gzip). `zstd` requires the `zstd` binary on the build host.

- **`--verify-cosign`** — verify the input image's Sigstore/cosign signature
  before embedding. `--require-cosign` makes a failed or missing verification
  fatal. `--cosign-key PATH` passes a specific public key to cosign.

- **`oci2bin pod run --network-alias NAME`** — register a hostname alias for a
  pod container. Injects `--add-host ALIAS:127.0.0.1` into every container in
  the pod so they can reach each other by name over the shared loopback.

## [0.7.0] - 2026-03-16

### Added

- **`oci2bin exec PID [--] CMD [ARGS...]`** — attach to a running container by
  host PID and execute a command inside its user/mount/PID/UTS/IPC namespaces
  via `nsenter(1)`. Requires `util-linux` nsenter on the host.

- **`-p HOST_PORT:CTR_PORT`** — Docker-style port publish shorthand. Equivalent
  to `--net slirp:HOST_PORT:CTR_PORT`; automatically enables slirp networking
  when `--net` is not already set. May be repeated for multiple ports.

- **`--dns IP`** — override DNS nameservers inside the container by writing a
  custom `resolv.conf` into the rootfs before exec. May be repeated up to 8
  times.

- **`--dns-search DOMAIN`** — set DNS search domains inside the container.
  May be repeated up to 8 times.

- **`--add-host HOSTNAME:IP`** — inject extra hostname→IP entries into the
  container's `/etc/hosts` before exec. May be repeated up to 32 times.

- **`--seccomp-profile FILE`** — load a Docker-compatible JSON seccomp profile
  instead of the built-in filter. Supports `SCMP_ACT_ALLOW`, `SCMP_ACT_ERRNO`,
  and `SCMP_ACT_KILL` as `defaultAction`; includes a ~250-entry static syscall
  name table covering x86_64 and aarch64. Falls back to the built-in filter on
  parse errors.

- **`--security-opt apparmor=PROFILE`** — apply an AppArmor profile via
  `aa_change_onexec()` before exec. Requires building with
  `-DHAVE_APPARMOR -lapparmor`.

- **`--security-opt label=TYPE:VAL`** — set an SELinux exec context via
  `setexeccon()` before exec. Requires building with
  `-DHAVE_SELINUX -lselinux`.

- **`--no-auto-tmpfs`** — opt out of the automatic `/run` tmpfs that is
  mounted when `--read-only` is active.

- **`--arch all`** — build both x86_64 and aarch64 binaries in a single
  invocation and emit a thin wrapper shell script (`uname -m` dispatch).
  The wrapper and arch-specific binaries must remain in the same directory.

- **SIGUSR1 / SIGUSR2 forwarding** — both signals are now forwarded to the
  container process alongside the existing SIGINT / SIGTERM / SIGHUP set.

### Fixed

- **Read-only rootfs + `/run`** — when `--read-only` is active, `/run` is
  automatically mounted as a tmpfs so applications that write pid-files or
  sockets there do not crash at startup.

- **BPF denylist jump offsets** — corrected the BPF jump offset formula in
  `apply_seccomp_profile` for denylist mode (was `remaining * 2`, should be
  `remaining + 1`). Also added a 128-rule cap to prevent silent unsigned-char
  overflow that would have misclassified allowed syscalls as denied.

- **`resolv.conf` builder snprintf truncation** — fixed incorrect truncation
  guards in `install_custom_resolv_conf` that could advance the write position
  past the end of the buffer when a DNS entry was longer than the remaining
  space.

## [0.6.0] - 2026-03-15

### Added

- **`oci2vm`** — symlink alias for `oci2bin` that enables VM mode by default.
  Binaries built via `oci2vm` are named `oci2vm_<image>` and detect their own
  invocation name (`basename argv[0] == "oci2vm"`) to prepend `--vm`
  automatically. Any `oci2bin` binary renamed or symlinked to a name starting
  with `oci2vm` gets the same behaviour.

- **`--embed-loader-layer`** — injects the loader binary as an extra OCI layer
  (`<loader-dir>/loader` inside the container filesystem, default
  `.oci2bin/loader`) and records its location via image config labels.
  The layer survives `docker load`, `docker push`, and `docker pull` intact.

- **`--embed-loader-labels`** — encodes the loader binary as chunked base64
  strings in the image config labels. No filesystem layer is added; useful
  when layer count matters.

- **`--label-chunk-size BYTES`** — controls the binary byte count per base64
  label when using `--embed-loader-labels` (default 6144 → ~8 KB base64 per
  label). Tune down for registries that enforce per-label or total-config size
  limits.

- **`--loader-dir DIR`** — overrides the directory inside the container
  filesystem where the embedded loader is stored when using
  `--embed-loader-layer` (default `.oci2bin`). Use when the default name
  conflicts with an application directory.

- **`--label-prefix PREFIX`** — overrides the label key namespace for all
  embed metadata (default `oci2bin.loader`). Must be passed identically to
  `oci2bin reconstruct` at reconstruction time.

- **`oci2bin reconstruct <image-or-file>`** — rebuilds a polyglot binary from
  a Docker image (or saved tar / `.img` file) that was built with
  `--embed-loader-layer` or `--embed-loader-labels`. Auto-detects the
  embedding strategy from the labels. Verifies the loader SHA-256 before
  rebuilding. By default strips the embedding from the reconstructed OCI data
  (pass `--no-strip` to keep it). Accepts `--label-prefix PREFIX` when a
  custom prefix was used at build time.

- **`--user UID[:GID]`** — OCI `USER` directive support. Reads the `User`
  field from the image config and resolves it via `/etc/passwd` inside the
  rootfs; supports numeric UID, `name`, and `name:group` / `uid:gid` forms.
  Runtime `--user` overrides the image default.

- **`VM_CPUS` / `VM_MEM_MB` build-time defaults** — compile-time constants
  that set the default vCPU count and memory for libkrun and
  cloud-hypervisor VM backends.

### Fixed

- **TTY / job control** — `setsid()` + `TIOCSCTTY` before exec so interactive
  shells get a controlling terminal; `devpts` mounted and `/dev/ptmx`
  bind-mounted for full PTY support; host `/dev` nodes bind-mounted before
  `chroot` so devices are available at container start.

- **PTY allocation hang** — fixed a hang that occurred when the output binary
  was run from an interactive terminal due to premature PTY setup.

- **`clearenv()` before exec** — host environment variables are now cleared
  before executing the container entrypoint; only variables from the OCI image
  config and explicit `-e` / `--env-file` flags are passed through.

- **`--vm` with images using `gosu` / `chown`** — fixed a re-entry loop in
  the chown shim and corrected gosu pass-through so Redis and similar images
  start correctly under VM mode.

- **libkrun API fixes** — corrected libkrun API call sequence and
  auto-detection logic in the `oci2bin` wrapper.

- **VM sentinel collision** — added `PATCHED` flag sentinels to distinguish
  unpatched from zero-patched values; fixed `build_polyglot.py` path search
  for kernel/initramfs blobs.

### Tests

- 38 new Python unit and Docker integration tests for loader embedding:
  `TestEmbedLoaderLayer` (14 tests), `TestEmbedLoaderLabels` (16 tests),
  `TestEmbedLoaderDockerPersistence` (6 Docker round-trip tests). The
  first two classes run as part of `make test-unit` (no Docker required).

- C unit tests for `path_has_dotdot_component` and `--tmpfs` edge cases.

- VM integration test script (`tests/test_vm_integration.sh`).

### Tooling

- `make lint-clang` — clang static analysis target (`clang --analyze`).
- `make lint-semgrep` — semgrep ruleset target.
- `make lint-scan-build` — scan-build wrapper target.

---

## [0.5.0] - 2026-03-13

### Added

- **`--memory SIZE` / `--cpus FLOAT` / `--pids-limit N`** — hard resource
  limits via Linux cgroup v2. Creates `/sys/fs/cgroup/oci2bin-<pid>/`, writes
  `memory.max`, `cpu.max` (`QUOTA 100000` format), and `pids.max`, then moves
  the process into the leaf cgroup. `unshare(CLONE_NEWCGROUP)` hides the host
  hierarchy. Graceful degradation if cgroup v2 is unavailable. Supports `k`,
  `m`, `g` suffixes for `--memory`; bounds-checked before suffix multiply to
  prevent integer overflow.
- **`oci2bin sign --key KEY.pem --in BINARY [--out BINARY]`** — sign a binary
  with an ECDSA P-256 key. Appends a `OCI2BIN_SIG` magic block (keyid,
  DER-encoded signature, total-length trailer) after the OCI tar.
- **`oci2bin verify --key PUB.pem --in BINARY`** — verify the signature;
  exits 0 (valid), 1 (not signed), or 2 (invalid). Implemented in
  `scripts/sign_binary.py` (stdlib + `openssl pkeyutl`).
- **`--verify-key PATH`** — loader-side verification: checks the binary's
  signature before any rootfs extraction. Aborts immediately on failure, before
  writing a single byte to disk.
- **`--net slirp` / `--net pasta` / `--net slirp:HOST:CTR`** — full outbound
  TCP/UDP networking inside an isolated network namespace without root. Forks a
  `slirp4netns` or `pasta` helper after `unshare(CLONE_NEWNET)`, syncs via a
  pipe, and reaps the helper on container exit. Port-forward syntax
  `slirp:HOST_PORT:CTR_PORT` supported (up to 16 forwards).
- **`oci2bin pod run [--net shared] [--ipc shared] BINARY [BINARY ...]`** —
  daemon-free multi-container pods. Creates a pause process via `unshare` to
  hold shared namespaces; starts each binary with
  `--net container:<pause_pid>` / `--ipc container:<pause_pid>`. Monitors
  lifecycle: non-zero exit SIGTERMs siblings; reports worst exit code.
  SIGTERM/SIGINT forwarded to all children.
- **`--overlay-persist DIR`** — keep the overlayfs upper layer between runs.
  Uses `DIR/upper` and `DIR/work` instead of a tmpdir; state accumulates
  across invocations. Verifies upper and work are on the same filesystem.
  The immutable extracted rootfs is never modified.
- **`--config PATH`** — load runtime options from a `key=value` text file.
  Lines `key=value` become `--key value`; bare `key` lines become `--key`
  boolean flags. Config file sets defaults; real argv overrides. Implemented
  via `build_merged_argv()`: pre-scans for `--config`, reads the file, builds
  a single merged argv, calls `parse_opts` exactly once — no recursive calls,
  no pointer-aliasing hazards.

### Fixed

- `--memory` parsing: bounds check now happens **before** the suffix multiply
  (`val *= 1024^N`) to prevent signed integer overflow / silent limit bypass.

---

## [0.4.0] - 2026-03-10

### Added

- **`--cap-drop CAP` / `--cap-add CAP`** — manage Linux capabilities inside the
  container. `--cap-drop all` removes all capabilities from the bounding set
  (caps 0–40) via `PR_CAPBSET_DROP`. `--cap-add` then raises the specified
  capability as an ambient capability (sets it in the permitted and inheritable
  sets first, then calls `PR_CAP_AMBIENT_RAISE`) so it survives `exec`. Supports
  both `CAP_NET_RAW` and `net_raw` spellings. Implemented without libcap using
  inline `struct cap_header`/`cap_data` and `syscall(SYS_capset, ...)`.
- **`--device /dev/HOST[:CONTAINER]`** — expose a host device node inside the
  container. `stat()`s the host path to get `st_rdev`/`st_mode`, then calls
  `mknod` inside the container; falls back to a bind mount if `mknod` fails
  (common in user namespaces). Host and container paths must start with `/dev/`
  and must not contain `..`. Non-fatal on failure. Repeatable.
- **`-e KEY` passthrough** — `-e VAR` without `=VALUE` now looks up `VAR` in
  the host environment via `getenv()` and constructs a `KEY=VALUE` string on
  the heap. If the variable is not set on the host, a warning is printed and
  the variable is skipped (not an error). Existing `KEY=VALUE` behaviour is
  unchanged.
- **`--init`** — run a zombie-reaping init as PID 1. Forks the entrypoint as a
  child; the parent loops `waitpid(-1, ...)` to reap any zombie. Forwards
  SIGTERM, SIGINT, SIGHUP, SIGUSR1, and SIGUSR2 to the child. Exit status is
  preserved (128+signal for signal deaths). Seccomp and capability drops happen
  before the fork; UID/GID drop happens in the child only.
- **`--detach` / `-d`** — fork the container to the background, print the child
  PID to stdout, and exit immediately. The child calls `setsid()` and redirects
  stdin from `/dev/null`. Can be combined with `--init`.
- **`--add-file HOST:CONTAINER` / `--add-dir HOST:CONTAINER`** (bash wrapper +
  `scripts/add_files.py`) — inject host files or directories into the image at
  build time as a new layer. The layer SHA256 is computed and embedded in
  `manifest.json` and the config `rootfs.diff_ids`. Both flags are repeatable
  and can be combined. Pure Python, stdlib only.
- **`--oci-dir DIR`** (bash wrapper + `scripts/oci_layout_to_tar.py`) — build
  from an OCI image layout directory instead of pulling via Docker. Reads
  `index.json` → manifest blob → config and layer blobs from
  `blobs/sha256/<hex>` and writes a docker-save-format tar passed directly to
  `build_polyglot.py`. The `IMAGE` argument becomes optional. Compatible with
  `--add-file`, `--add-dir`, and `--strip`.
- **`oci2bin list [--json]`** — list all binaries in `~/.cache/oci2bin/` with
  image name, digest, size, and build date. Reads the `OCI2BIN_META` block from
  each cached binary via `scripts/inspect_image.py`. `--json` outputs a JSON
  array for machine parsing.
- **`oci2bin prune [--dry-run]`** — remove outdated cache entries, keeping only
  the most recently built binary per image name (grouped by stripping the digest
  suffix from the cache directory name). Prints space freed. `--dry-run` shows
  what would be deleted without deleting.
- **`oci2bin diff <binary1> <binary2>`** — compare the filesystem contents of
  two oci2bin binaries. Extracts the embedded OCI tar from each, walks all
  layer tarballs (handling gzip and OCI whiteout entries), and prints `+`
  added, `-` removed, and `M` modified files with sizes. Summary line at the
  end. Exits 1 if any difference is found. Implemented in
  `scripts/diff_images.py` (stdlib only).
- **`scripts/inspect_image.py --json`** — new `--json` flag outputs the
  embedded metadata block as a JSON object (used by `oci2bin list`). Falls back
  to reading `RepoTags` from the OCI tar if no metadata block is present.

### Changed

- **README reorganised** — added a table of contents and regrouped all sections
  under logical headings: Building binaries, Running containers, Isolation and
  security, Process management, Subcommands.

---

## [0.3.0] - 2026-03-10

### Added

- **`--user UID[:GID]`** — run the container process as a specific numeric UID
  (and optional GID). Calls `setgroups(0, NULL)` → `setgid` → `setuid` in that
  order before exec. Fatal if any step fails. Only numeric values ≤ 65534
  accepted; names like `nobody` are rejected with a clear error.
- **`--hostname NAME`** — override the UTS hostname inside the container.
  Defaults to `oci2bin` when omitted. Non-fatal on failure.
- **`--env-file FILE`** — load `KEY=VALUE` pairs from a file into the container
  environment. Blank lines and `#`-prefixed comments are skipped. Additive with
  `-e`; the file is processed first so `-e` flags override file values. Uses
  `open()`/`read()` (no `fopen`). Files larger than 1 MiB are rejected.
- **`--tmpfs PATH`** — mount a fresh `tmpfs` at an arbitrary path inside the
  container (useful with `--read-only`). Path must be absolute and `..`-free.
  `MS_NOSUID|MS_NODEV` flags. Non-fatal on failure. Repeatable.
- **`--ulimit TYPE=N`** — set resource limits via `setrlimit(2)`. Supported
  types: `nofile`, `nproc`, `cpu`, `as`, `fsize`. Both `rlim_cur` and
  `rlim_max` are set to the given value. Non-fatal on failure. Repeatable.
- **`--layer IMAGE`** (bash wrapper) — merge additional Docker image layers on
  top of the base image before packaging. Layers are applied in order. Uses the
  new `scripts/merge_layers.py` helper. Repeatable.
- **`--strip`** (bash wrapper) — remove documentation, man pages, locale data,
  and apt caches from the image before packaging, reducing binary size. Uses the
  new `scripts/strip_image.py` helper. Can be combined with `--layer`.
- **Digest pinning in `--cache`** — after pulling, the image's content-addressed
  digest is obtained via `docker inspect --format '{{index .RepoDigests 0}}'`
  and printed to stderr. The cache key now includes the first 12 hex chars of
  the sha256 digest, preventing stale cache hits when a tag is updated.
- **`oci2bin inspect <binary>`** — new subcommand that reads the embedded OCI
  tar from a polyglot binary and prints a human-readable summary: architecture,
  Entrypoint, Cmd, WorkingDir, Env, ExposedPorts, and build metadata block.
  Implemented in `scripts/inspect_image.py` (stdlib only).
- **Embedded build metadata block** — every output binary now has a
  `OCI2BIN_META\x00` magic-prefixed JSON block appended after the tar
  end-of-archive marker. Contains image name, build timestamp (UTC ISO-8601),
  OCI digest (if available), and oci2bin version `0.2.0`. Does not affect ELF
  execution or tar parsing. Displayed by `oci2bin inspect`.
- **`--no-seccomp`** — disable the default seccomp-BPF syscall filter (added in
  0.2.0; first documented in this changelog).
- **seccomp-BPF default filter** — blocks `kexec_load`, `reboot`, `pivot_root`,
  `bpf`, `ptrace`, `perf_event_open`, `io_uring_setup`, `userfaultfd`, and
  `keyctl`. Sets `PR_SET_NO_NEW_PRIVS`. Added in 0.2.0.
- **Redis and nginx integration tests** — `make test-integration-redis` and
  `make test-integration-nginx` build those images with oci2bin and verify
  actual protocol responses (`PING`/`SET`/`GET` for Redis; HTTP 200 for nginx).

### Fixed

- **`execv` → `execvp`** — relative entrypoints like `docker-entrypoint.sh`
  were silently falling back to `/bin/sh` because `execv` requires an absolute
  path. Fixed to `execvp` which searches `PATH`.
- **`build_elf64_header` missing default** — the `e_machine` parameter added
  during aarch64 work had no default, breaking Python unit tests that call it
  with three positional arguments. Fixed with `e_machine=EM_X86_64` default.
- **Integration test port conflicts** — tests used hardcoded ports (16379,
  18080). Fixed to use a random free port via `python3 -c "import socket; ..."`.
- **Integration test TAP skips** — `test_runtime.sh` emitted `not ok $i - SKIP`
  instead of `ok $i # SKIP`, causing `make` to fail when `oci2bin.img` was
  absent. Fixed.
- **`strtoul` suffix validation for `--user`** — non-numeric suffixes in
  `--user 1000abc` were silently ignored. Fixed by checking that `endp` points
  to the expected delimiter after `strtoul` returns.

---

## [0.2.0] - 2026-03-10

### Added

- **aarch64 support** — loader and polyglot builder now produce binaries for both
  `x86_64` and `aarch64`. The `--arch` flag selects the target; cross-compilation
  from x86_64 to aarch64 uses `aarch64-linux-gnu-gcc` with a Fedora sysroot.
  Unit tests run under `qemu-aarch64-static` on x86_64 hosts.
- **`--workdir PATH`** — sets the working directory inside the container before
  exec. Falls back to the image's `WorkingDir` field when the flag is omitted.
- **`--net none`** — adds `CLONE_NEWNET` to the namespace flags, giving the
  container an isolated network stack with no external connectivity. Default
  (`--net host`) is unchanged.
- **`--cache`** (bash wrapper) — caches the built output binary under
  `~/.cache/oci2bin/<image>/output`. Subsequent builds of the same image return
  the cached file immediately, skipping the Docker pull and polyglot build.
- **`--read-only`** — mounts the rootfs read-only via overlayfs. Writes go to a
  temporary upper layer and are discarded on exit; the on-disk rootfs is never
  modified. Falls back to read-write with a warning if overlayfs is unavailable.
- **`--secret HOST_FILE[:CONTAINER_PATH]`** — bind-mounts a single host file into
  the container read-only (`MS_RDONLY|MS_NOEXEC|MS_NOSUID|MS_NODEV`). Defaults to
  `/run/secrets/<basename>` when no container path is given. The mount is aborted
  entirely if the read-only remount step fails, so container processes can never
  write to a host secret file.
- **`--ssh-agent`** — forwards the host `SSH_AUTH_SOCK` Unix socket into the
  container at `/run/secrets/ssh-agent.sock` and sets `SSH_AUTH_SOCK`
  accordingly. The source path is validated to be an absolute path pointing to an
  actual Unix socket. The bind-mount is enforced read-only.
- **OCI image `Env` applied automatically** — environment variables from the
  image config `Env` array are now applied before container exec. User-supplied
  `-e` flags still override image defaults.
- **`/tmp` and `/dev` isolation** — a fresh `tmpfs` is mounted on `/tmp`
  (`MS_NOSUID|MS_NODEV|MS_NOEXEC`) and essential device nodes are created via
  `mknod()` under a `tmpfs` `/dev`: `null`, `zero`, `urandom`, `random`, `tty`.
  Bind-mounting the host `/dev` is not possible in rootless user namespaces; this
  approach works without any host privileges.
- **Nix flake, AUR PKGBUILD, and RPM spec** — packaging for NixOS, Arch Linux
  (AUR), and Fedora (Copr) added under `flake.nix` and `packaging/`.

### Fixed

- **fork-after-CLONE_NEWPID crash** — after the container process (PID 1) exited,
  the parent's subsequent `fork()` for cleanup failed with `ENOMEM` because the
  PID namespace was already dead. Fixed by replacing the forked `rm -rf` with an
  in-process `nftw(FTW_DEPTH|FTW_PHYS)` recursive deletion.
- **`sethostname` length off-by-one** — `sethostname("oci2bin", 10)` passed a
  length larger than the string. Fixed to `7`.
- **JSON injection via OCI `WorkingDir`** — a crafted image could embed `"` or
  `\` in `WorkingDir` to inject keys into `.oci2bin_config`. Fixed with a
  `json_escape_string()` helper applied before serialisation.

---

## [0.1.0] - 2026-03-01

Initial public release.

### Added

- **Polyglot ELF+TAR builder** (`scripts/build_polyglot.py`) — combines a static
  ELF loader with an OCI image tarball into a single self-contained file that is
  simultaneously a valid ELF executable and a valid `docker load` archive.
- **Rootless container runtime** (`src/loader.c`) — at exec time the binary
  extracts its embedded OCI rootfs into a temporary directory and runs the
  container inside `CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS`
  namespaces. No daemon, no installation, no root required on the target.
- **`-v HOST:CONTAINER`** — bind-mount a host directory into the container.
  Container path is validated to be absolute and free of `..` components.
- **`--entrypoint PATH`** — override the image entrypoint at runtime.
- **`-e KEY=VALUE`** — set environment variables inside the container. May be
  repeated; later flags override earlier ones.
- **`oci2bin` bash wrapper** — pulls the image via Docker, compiles the loader if
  needed, and invokes the polyglot builder. Output filename defaults to
  `<image>_<tag>`.
- **Test suite** — unit tests for JSON helpers and option parsing (`make
  test-unit`); integration tests covering volume mounts, entrypoint override,
  argument passthrough, exit-code forwarding, and Docker-import round-trip (`make
  test`).
- **Packaging** — Nix flake (`flake.nix`), AUR `PKGBUILD`
  (`packaging/aur/`), and RPM spec (`packaging/rpm/`) for NixOS, Arch, and
  Fedora.
- **Security hardening** — static linking, `chroot` + namespace isolation,
  `MS_NOSUID|MS_NODEV` mounts, `..` path validation on all external inputs,
  `snprintf` truncation checks on all `PATH_MAX` buffers, no `system()`/`popen()`
  anywhere in the codebase.

[0.3.0]: https://github.com/latedeployment/oci2bin/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/latedeployment/oci2bin/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/latedeployment/oci2bin/releases/tag/v0.1.0
