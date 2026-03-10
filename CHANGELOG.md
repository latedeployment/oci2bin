# Changelog

All notable changes to oci2bin are documented here.

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
