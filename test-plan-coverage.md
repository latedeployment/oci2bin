# Unit-test coverage plan — src/loader.c

Goal: raise C unit-test coverage of `src/loader.c` from the current **25.6 %**
(119/224 functions touched, 105 at 0 %) by adding deterministic unit tests for
the **security-relevant, unit-testable logic** that is presently exercised only
by fuzzers / integration tests — without trying to unit-test the privileged
runtime layer (fork/exec/chroot/namespaces/VM/cgroups), which belongs to
`make test` and the fuzz harnesses.

This file is the work queue. Each numbered item is one Ralph-loop iteration:
implement it, run the gates, check it off, move to the next.

---

## How to measure

```bash
make coverage-c          # prints src/loader.c line coverage via gcov
```

For per-function deltas while iterating:

```bash
rm -rf build/cov && mkdir -p build/cov
gcc --coverage -O0 -Wno-return-local-addr -c tests/test_c_units.c -o build/cov/test_c_units.o
gcc --coverage build/cov/test_c_units.o -o build/cov/test_c_units_cov
(cd build/cov && TMPDIR=$PWD OCI2BIN_TMPDIR=$PWD ./test_c_units_cov >/dev/null 2>&1 && gcov -f -r -o . test_c_units.o) \
  | grep -A1 "Function '<NAME>'"
```

Baseline to beat: **loader.c 25.6 % of 5833 lines**. Record the new number in
each iteration's "done when".

---

## Conventions (how to add a test)

All tests live in `tests/test_c_units.c`, which `#include`s `src/loader.c` with
`#define static` so every static function is callable. Follow the existing
style exactly:

- **TAP macros** already defined: `ASSERT(cond, desc)`, `ASSERT_NOT_NULL`,
  `ASSERT_NULL`, `ASSERT_STR_EQ(got, want, desc)`, `ASSERT_INT_EQ(got, want, desc)`.
- **One `static void test_<name>(void)` per function under test.** Add a call to
  it in `main()` (the list ending at `test_parse_opts_size();`) BEFORE the
  `printf("1..%d\n", ...)` line. Order matches the list; append at the end.
- **Filesystem tests**: model on `test_safe_merge_layer_blocks_escape` and
  `test_lookup_passwd_group`. Use `mkdtemp("/tmp/oci2bin-<x>-XXXXXX")`, build the
  fixture, assert, then clean up. Never assume CWD. Honor `$TMPDIR` is already
  set by the Makefile test env, but `/tmp/...-XXXXXX` templates are fine (the
  existing tests use them).
- **Cleanup**: remove every temp dir/file you create (use `rm_rf_dir()` from
  loader.c for trees — it is in scope). A leaked fixture can fail later runs.
- **No reliance on root / namespaces / network.** If a function needs those,
  it is out of scope (see "Not in scope" below) — test only its pure branches.
- **Determinism**: no time/PID/host-state assertions unless normalized.

### Gates for every iteration (must all pass before checking the box)

```bash
cd src && bash ../scripts/style.sh        # only if you touched .c/.h (you will)
cd .. && make clean && make test-unit     # full unit suite green
make coverage-c                           # confirm loader.c % moved up
```

Commit message style: no co-author line (per CLAUDE.md). One commit per item,
e.g. `test: cover build_merged_argv (NN%→MM% loader.c)`.

---

## Work queue (in priority order)

### 1. `build_merged_argv` — 0 % of 107 lines  ★ biggest single win
- **Why**: builds the final exec argv from `--config`/Entrypoint/Cmd merging —
  decides what actually runs in the container. Pure logic, no syscalls.
- **Signature**: `char** build_merged_argv(int argc, char* argv[], int* out_argc)`
  — returns malloc'd NULL-terminated argv (free each + array) or NULL on error.
- **Cases to assert**:
  - plain passthrough (no `--config`): argv preserved, `out_argc` correct.
  - single `--config PATH`: PATH consumed, not present in output.
  - `--config` with no following arg → returns NULL (error).
  - `--config` specified twice → returns NULL.
  - `--config ../foo` (dotdot) → returns NULL (path rejected).
  - interaction with other flags before/after `--config`.
- **Gotchas**: writes to stderr on the error paths (expected/ignored). Free the
  returned argv correctly to keep `make test` leak-clean under the stub builds.
- **Done when**: `build_merged_argv` ≥ 85 %; loader.c overall up ~1.5–2 pts.

### 2. `load_env_file` — 0 % of 57 lines
- **Why**: parses `KEY=VALUE` env files (`--env-file`). Fuzzed, never
  unit-asserted. Reads a file path → easy to fixture.
- **Signature**: `int load_env_file(const char* path, struct container_opts* opts)`
  — appends to `opts->env_vars[]` / `opts->n_env`; free each entry after.
- **Cases**: well-formed `K=V` lines; blank lines and `#` comments skipped;
  leading/trailing whitespace; missing `=` (rejected or skipped — assert actual
  behavior); over-long line; `MAX_ENV` cap respected; nonexistent path →
  nonzero return. Write fixtures with `mkstemp`.
- **Done when**: `load_env_file` ≥ 80 %.

### 3. `json_parse_names_array` — 0 % of 59 lines
- **Why**: parses seccomp syscall-name arrays (`"names":[...]`). Fuzzed, not
  unit-asserted. Pure string parser.
- **Signature**: `char** json_parse_names_array(const char* json, const char* key, int* n_out)`
  — malloc'd array of malloc'd strings (free each + array) or NULL.
- **Cases**: 2–3 element array → correct count + values; empty array → count 0;
  missing key → NULL; nested/escaped quotes inside names; array exceeding the
  internal cap; malformed (unterminated) → NULL/empty, no leak/crash. Mirror the
  existing `test_json_get_array` style.
- **Done when**: `json_parse_names_array` ≥ 85 %.

### 4. `resolve_user` + `lookup_user_name_from_passwd` — 0 % (33 + 35 lines)
- **Why**: decide the container's UID/GID. `lookup_passwd_user(path,...)` is
  already 83 % via `test_lookup_passwd_group`; these wrappers aren't covered.
- **`resolve_user(spec, &uid, &gid)`**: numeric branch is pure → fully testable.
  Cases: `"1000"` → uid=1000,gid=1000; `"1000:2000"` → uid/gid split;
  `"0:0"`; empty/NULL → -1; non-numeric garbage in the *numeric* position.
  The name-lookup branch reads host `/etc/passwd` — test only `"root"`
  (uid 0, present everywhere) and treat as best-effort; do NOT assert on names
  that may be absent.
- **Prefer `resolve_user_in_rootfs(rootfs, spec, ...)`** for the name path: it
  takes a rootfs dir, so drop a fake `etc/passwd` under a `mkdtemp` rootfs and
  assert a custom user name resolves to the planted uid/gid. This is the clean,
  host-independent way to cover the name branch.
- **`lookup_user_name_from_passwd(uid, out, outsz)`**: reverse lookup — covered
  incidentally once a fake-passwd rootfs fixture exists; add a direct case
  (uid 0 → "root") and a not-found case (huge uid → nonzero).
- **Done when**: `resolve_user` ≥ 70 %, `lookup_user_name_from_passwd` ≥ 70 %.

### 5. `plan_userns_map` — 0 % of 27 lines
- **Why**: plans the user-namespace uid/gid mapping (single-id vs subid ranges).
  Pure logic over `container_opts` + a `userns_map_plan` out-struct.
- **Signature**: `void plan_userns_map(const struct container_opts* opts, uid_t real_uid, struct userns_map_plan* plan)`.
- **Cases**: `no_userns_remap` set → plan reflects identity/no-remap; default
  remap with a given `real_uid` → expected map entries; any subid/count fields
  computed as expected. Read the struct fields and assert each. No syscalls.
- **Done when**: `plan_userns_map` ≥ 85 %.

### 6. Symlink-rejection filesystem helpers — 0 %
Group into one or two test functions sharing a `mkdtemp` fixture.
- **`mkdir_p_secure(path, mode, what)`** (31 lines): create nested dirs OK;
  reject when a path component is a symlink (plant `base/link -> /tmp`, then
  `mkdir_p_secure(base/link/x)` must fail); reject when a component is a
  non-directory file; over-long path → fail.
- **`ensure_bind_mount_target(src, dst, what)`** (30): dst parent created; dst
  that is an existing symlink → rejected; dir src makes dir dst; file src makes
  file dst; verify it never follows a symlink at dst.
- **`open_path_nofollow(path, flags, mode)`** (33): opens a regular file;
  refuses a symlink (`ELOOP`/failure); creates with `O_CREAT`. Assert the fd is
  valid / the call fails as expected; close fds.
- **Done when**: each ≥ 75 %.

### 7. `tar_layer_prescan` + `safe_extract_layer` — 0 % (35 + 20 lines)
- **Why**: the pre-extraction safety gate (`tar -tf` scan rejecting `../` and
  absolute entries) and the extract+merge entry point. Needs the system `tar`.
- **Approach**: build a tiny tar fixture in a temp dir with the BSD/GNU `tar`
  binary (or craft bytes). `tar_layer_prescan`: a clean tar → 0; a tar
  containing an entry named `../escape` or `/abs` → -1. `safe_extract_layer`:
  a benign single-file layer extracts and merges into a fresh rootfs fd; a
  malicious-name layer is rejected. Skip gracefully (don't fail) if `tar` is
  absent — guard with `access("/usr/bin/tar", X_OK)` or similar and emit a
  skipped-but-ok note, since `make test-unit` must stay tar-tolerant.
- **Done when**: both > 0 % with the safe + unsafe path each asserted.

### 8. `safe_merge_walk` top-up — 47 %→ higher
- **Why**: the merge escape test only exercises the symlink branch. Missed:
  regular-file copy into rootfs, nested-directory recursion, special-file skip,
  and the `tar_entry_name_unsafe` reject path inside the walk.
- **Approach**: extend `test_safe_merge_layer_blocks_escape` (or a sibling) with
  a staging tree containing: a normal file (assert it lands in rootfs with
  correct contents), a nested `a/b/c` dir+file (assert recursion), and a FIFO or
  device-ish node if creatable (assert skipped, no crash).
- **Done when**: `safe_merge_walk` ≥ 70 %.

### 9. `mkdirat_in_root` / `mkdir_p_in_root` top-up — ~50 %
- **Why**: error/edge branches (existing dir, deep path, in-root resolution of a
  `..`-laden relpath) aren't hit.
- **Approach**: direct calls against a `mkdtemp` rootfs fd — create deep paths,
  re-create existing (EEXIST tolerated), feed a relpath with `..` and assert it
  stays in-root. Likely folded into item 6's fixture.
- **Done when**: each ≥ 75 %.

---

## Not in scope (do NOT unit-test — wrong tool)

These are 0 % from unit tests **by design** — they fork/exec, chroot, unshare,
need root, talk to the network, or drive a VM. They are covered (where covered)
by `make test` integration tests and the fuzz harnesses:

`container_main`, `loader_main`, `mcp_serve_main` and `mcp_tool_*`, `vm_*` /
`run_as_vm_ch` / `vm_init_main`, `run_as_init`, `relay_pty`,
`start_metrics_helper`, `setup_cgroup` / `fork_into_cgroup`, `apply_capabilities`,
`apply_landlock_sandbox`, `setup_secrets` / `install_*_secret`,
`patch_rootfs_ids` / `rewrite_id_fields` / `run_newidmap`, `notify_post_one`,
`run_cmd` / `run_cmd_capture` (fork+exec).

Special note: `apply_seccomp_profile` (110 lines) and the seccomp/JSON parsers
are already **fuzzed** (`fuzz_seccomp`, `fuzz_json`); their parsing is exercised
even though gcov-of-unit-tests shows 0 %. We are not duplicating that in unit
tests — only adding deterministic assertions for the pure helpers above.

---

## Expected outcome

Items 1–6 are the high-value, low-friction wins (pure logic + simple fixtures)
and should move loader.c from ~25.6 % toward the mid-30s%. Items 7–9 add the
filesystem/merge depth. The ceiling for unit tests is bounded by the large
runtime layer above; the target is **maximal coverage of the testable logic**,
not a single global percentage.

## Progress log

| # | Item | Status | loader.c % after |
|---|------|--------|------------------|
| 1 | build_merged_argv | **done** (86.9% fn) | 27.31% |
| 2 | load_env_file | todo | — |
| 3 | json_parse_names_array | todo | — |
| 4 | resolve_user + passwd lookup | todo | — |
| 5 | plan_userns_map | todo | — |
| 6 | symlink-rejection fs helpers | todo | — |
| 7 | tar_layer_prescan + safe_extract_layer | todo | — |
| 8 | safe_merge_walk top-up | todo | — |
| 9 | mkdir*_in_root top-up | todo | — |
