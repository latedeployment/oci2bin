# Claude Code Instructions — oci2bin

> **Do not commit this file.** It is for Claude Code only and must stay out of version control.
> **Do not commit `.claude/`** — skills, commands, and other Claude Code local config must never be added to git.


## Security requirements

This project produces a binary that runs as a container runtime. Security is non-negotiable.

### Rules for all generated code

- **No `system()` or `popen()`** — use `execvp` with an argv array. Never invoke a shell to run a command.
- **No unvalidated external data in paths** — any path derived from OCI manifest content (Config, Layers, Env) must be checked for `..` components and absolute paths before use.
- **Check all return values** — `chroot`, `chdir`, `unshare`, `mount`, `mkdir`, `write`, `lseek`. If a security-sensitive call fails, abort.
- **No `assert` for security checks** — use explicit `if / print / sys.exit(1)` or `return -1`. Python `-O` and C `NDEBUG` strip assertions silently.
- **No shell injection in Python** — `subprocess.run` must always receive a list, never a string with `shell=True`.
- **Validate sizes before malloc** — reject negative or unreasonably large values (`st_size < 0`, `> 256 MiB`) before `malloc(size + 1)` to prevent integer overflow.
- **Tar extraction flags** — always pass `--no-same-permissions --no-same-owner` to prevent setuid bit restoration from crafted layers.
- **snprintf truncation** — after any `snprintf` into a PATH_MAX buffer, check that the return value is less than the buffer size. Truncated paths can silently redirect to unintended locations.
- **Buffer sizes for JSON keys** — the `needle` buffer in JSON helpers is 256 bytes; reject keys longer than 254 chars.

## Documentation

Every new user-facing feature must be documented in `README.md` before the commit that adds it. This includes:
- New runtime flags or options (like `-v`, `--entrypoint`)
- Changes to environment variables set inside the container
- New build or install steps
- New `make` targets

Do not merge feature commits without a corresponding README update.

## Code deduplication

Do not copy-paste logic across functions. If the same pattern appears in two or more places, extract a shared helper. Key helpers that already exist:

- `install_resolv_conf(rootfs)` — copies the host resolver into a rootfs, preferring the upstream file over the systemd-resolved stub.
- `read_oci_config(rootfs, &cfg)` / `free_oci_config(&cfg)` — reads and parses `.oci2bin_config` (Entrypoint, Cmd, Env, WorkingDir).
- `build_exec_args(&cfg, entrypoint, extra, n_extra, argv, max)` — builds the exec argv from OCI config with optional user overrides and `/bin/sh` fallback.

Before writing new code, check whether an existing helper already covers the operation. When adding a new feature that touches multiple code paths (container, libkrun VM, cloud-hypervisor VM), implement the shared logic once and call it from each path.

## Code style

All C code must be formatted with `scripts/style.sh` before committing. Run it from the directory containing the `.c` files:

```bash
cd src && bash ../scripts/style.sh
```

The script uses astyle with BSD style, 80-column line limit, braces on all control structures, and pointer/reference alignment. Any commit touching `.c` or `.h` files must pass through it first.

## Mandatory pre-commit checklist

Before every commit, run the full unit test suite and confirm it passes:

```bash
make clean && make test-unit
```

This covers C unit tests (parse_opts, JSON helpers) and Python unit tests (ELF builder, polyglot structure). No Docker required. If any test fails, fix it before committing — do not commit broken tests.

For changes to `src/loader.c`, also run the aarch64 cross-compiled tests:

```bash
make test-c-aarch64
```

## Mandatory workflow: security + performance revalidation

After generating or modifying any non-trivial code, **always** spawn a security subagent to review it before committing:

```
Spawn: general-purpose subagent
Task: security and performance audit of the changed files
- Check for the specific vulnerability classes listed in CLAUDE.md
- Check for unnecessary allocations, redundant copies, O(n²) loops
- Apply fixes directly
- Verify the C code still compiles with gcc -static
- Report what was found clean vs what was fixed
```

Do this even for small changes — a one-line fix can introduce a new truncation or NULL-deref.

## Process hygiene

After completing any task that spawns background processes (integration tests, container runs, redis/nginx smoke tests, VM boots), check for and kill leftover processes before finishing:

```bash
ps aux | grep -E "(redis|nginx|oci2bin|loader|cloud-hypervisor|qemu)" | grep -v grep
```

Kill any survivors by PID. Background Bash tasks that time out or get killed return exit 144 — that is expected and not an error.

## Project facts

- Loader: `src/loader.c` — compiled with `gcc -static -O2 -s`. Standard C only.
- Builder: `scripts/build_polyglot.py` — Python 3, stdlib only.
- CLI wrapper: `oci2bin` — bash, `set -euo pipefail`.
- The output binary requires only `tar` at runtime — no Docker, no runtime daemon.
- Tests: `make test-unit` (no Docker, ~5s) / `make test` (full suite, needs Docker).
- Commit style: no co-author lines.
