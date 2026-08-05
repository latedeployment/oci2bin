# oci2bin Review Findings

Review date: 2026-06-25

Status legend:

- [ ] Open
- [x] Completed
- `[Critical]`, `[High]`, `[Medium]`, `[Low]` indicate priority.

## Summary

The project has strong security ambitions, but core OCI filesystem handling,
Dockerfile builds, read-only behavior, packaging, and policy enforcement need
work before it can be treated as an OCI-correct, fail-closed runtime.

## Critical and High Priority

- [ ] `[Critical]` Implement correct OCI layer application.
  - Process `.wh.<name>` whiteouts and `.wh..wh..opq` opaque directories.
  - Preserve ownership, modes, timestamps, xattrs and file capabilities.
  - Support hardlinks, special files and file-type replacement.
  - Abort on every missing, malformed or failed layer instead of continuing
    with a partial rootfs.
  - Evidence: `src/loader.c`, `safe_merge_walk()` and
    `extract_oci_rootfs()`.
  - Progress (2026-06-25):
    - Implemented fd-relative whiteouts, opaque directories, recursive
      replacement, hardlinks, FIFO recreation, timestamps, safe permission
      modes and xattrs. Set-ID bits are deliberately stripped.
    - Layer metadata or special-file failures now abort instead of silently
      skipping entries. Malformed, oversized, missing, unsafe or failed
      manifest layers now abort the entire extraction.
    - Manifest, layer and config reads now use fd-relative no-follow access,
      preventing symlink-swap TOCTOU attacks.
    - Added depth, entry-count, path and xattr-size limits; hardlink lookup is
      hashed instead of quadratic.
    - Added regression coverage for symlink escapes, both whiteout forms,
      file/directory replacement, hardlinks, timestamps, xattrs, FIFOs,
      malformed arrays, socket rejection and excessive directory depth.
    - Verified with x86_64 and aarch64 C unit tests, static GCC builds, Clang
      `-Werror` lint, Clang static analysis and the full local
      `make clean && make test-unit` suite.
    - Remaining before closing:
      - Preserve numeric archive UID/GID ownership across rootless
        subordinate-ID mappings. The mandatory `--no-same-owner` extraction
        currently makes staging ownership equal to the caller, so ownership
        needs an explicit metadata/remap phase rather than being inferred
        from the staging tree.
      - Preserve privileged xattrs/file capabilities in a user namespace.
      - Decide and implement safe device-node semantics. Device nodes and
        sockets are currently rejected fail-closed; FIFOs are supported.

- [x] `[Critical]` Prevent Dockerfile `COPY` and `ADD` source symlink escapes.
  - Added shared context-source confinement for `COPY`, `ADD` and
    `RUN --mount=type=bind`.
  - Direct paths, absolute context-relative paths, globs and explicit
    symlinked directories resolve inside the real build context or fail.
  - Recursive `**` expansion does not follow unrelated symlinked directories.
  - `.dockerignore` checks both lexical and resolved paths, preventing a
    symlink alias from exposing an ignored file.
  - Added regression tests for external file/directory symlinks, glob and
    parent traversal, recursive globs, absolute sources, ignored aliases,
    destination symlink escapes and internal symlink behavior.
  - Verified with 30 focused tests, `py_compile`, an independent security
    review and `make clean && make test-unit`.
  - Residual hardening idea: use fd-relative traversal to eliminate races with
    another process mutating the build context during a build.

- [x] `[High]` Make `--read-only` genuinely read-only.
  - `--read-only` now recursively bind-mounts the extracted rootfs onto
    itself and remounts the top root mount `MS_RDONLY`.
  - The mount namespace is made private after `CLONE_NEWNS`, preventing mount
    propagation through shared host peers.
  - Writable throwaway root behavior was renamed to `--ephemeral-root`.
  - `--read-only`, `--ephemeral-root` and `--overlay-persist` are mutually
    exclusive root modes by behavior; the last explicit mode wins, and
    profiles only set read-only as a default when no root mode was chosen.
  - Explicit writable locations remain explicit submounts: `/tmp` tmpfs,
    optional `/run` tmpfs, user `--tmpfs`, volumes, secrets and devices.
  - Updated README, docs site pages, man page, texinfo, wrapper help,
    loader help and changelog.
  - Verified with focused C/stub tests, `make clean && make test-unit`,
    `make test-c-aarch64`, static GCC build, Clang `-Werror`, Clang static
    analysis, `py_compile` and `git diff --check`.
  - Note: the required subagent audit was attempted, but the subagent failed
    with an account usage-limit error. A local security audit caught and fixed
    mount-propagation and root-mode-combination issues.

- [x] `[High]` Preserve Dockerfile `RUN` shell syntax.
  - Current parsing changes shell operators, expansion, pipelines and
    redirection.
  - Example: `echo hi && echo bye` becomes `echo hi '&&' echo bye`.
  - Remove only leading BuildKit options and preserve the command remainder
    byte-for-byte.
  - Evidence: `scripts/dockerfile_build.py`, `_parse_run_line()`.
  - Completed (2026-06-27):
    - `_parse_run_line()` now only consumes leading BuildKit option words and
      returns the shell command remainder byte-for-byte.
    - Added regression coverage for shell operators, pipelines, redirection,
      variable expansion, quoted mount values and malformed command tails.
    - Verified with `python3 -m unittest tests.test_dockerfile_run_parse`,
      `python3 -m unittest tests.test_dockerfile_safe_resolve` and
      `python3 -m py_compile scripts/dockerfile_build.py
      tests/test_dockerfile_run_parse.py`.

- [x] `[High]` Implement or reject Dockerfile `RUN --network` and
  `--security`.
  - `--network=none` is currently silently ignored.
  - Security-related options must never silently degrade.
  - Completed (2026-06-27):
    - Leading `RUN --network` and `RUN --security` forms are parsed as
      unsupported options.
    - Dockerfile builds now fail closed with an explicit error instead of
      executing the command with degraded semantics.
    - Added focused parser regression coverage and verified with
      `python3 -m unittest tests.test_dockerfile_run_parse`.

- [x] `[High]` Fix installed package contents.
  - `make install` omits `diff_fs.py`, `freeze.py`, `pod_stack.py`,
    `from_chroot.py` and `dockerfile_build.py`.
  - The wheel also omits `doctor.py` and `explain.py`.
  - Nix installs only `build_polyglot.py`.
  - Derive all package file lists from one canonical manifest.
  - Add installed-package command smoke tests.
  - Completed (2026-06-27):
    - Added `packaging/oci2bin-scripts.txt` as the canonical runtime helper
      manifest and `scripts/package_manifest.py` for install/sync operations.
    - `make install`, Nix and RPM packaging now install helper scripts through
      the manifest or the manifest-populated script directory.
    - Wheel/sdist builds sync `oci2bin_pkg/scripts` from the manifest before
      package metadata is generated.
    - Added packaging smoke tests that compare wrapper helper references with
      the manifest, verify bundled helper links, install helpers into a
      synthetic tree and invoke installed commands.
    - Verified with `python3 -m unittest tests.test_packaging_manifest -v`,
      wheel content inspection, installed-wheel command smoke tests and
      `make install` helper smoke tests.

- [x] `[High]` Regenerate OCI metadata after `--strip`.
  - Recompute layer digests and `rootfs.diff_ids`.
  - Recompute the config content-addressed name and manifest reference.
  - A mismatch between the rewritten layer and stored diff ID was reproduced.
  - Evidence: `scripts/strip_image.py`.
  - Completed (2026-06-27):
    - Rewritten layers now produce matching uncompressed `rootfs.diff_ids`.
    - OCI blob-style layer paths and content-addressed config paths are
      renamed to their new SHA-256 digests when bytes change.
    - Docker-save-style config names (`<sha>.json`) are recomputed and the
      manifest `Config` reference is updated.
    - Added regression tests for Docker-save and OCI blob-style metadata.

- [x] `[High]` Correct metadata generated by `--layer`.
  - Append matching diff IDs for appended layers.
  - Recompute the config digest/name after modifying config content.
  - Validate the final layer count against the diff ID count.
  - A two-layer image with one diff ID and a stale config name was reproduced.
  - Evidence: `scripts/merge_layers.py`.
  - Completed (2026-06-27):
    - Overlay layer diff IDs are appended alongside appended layer entries.
    - Merged config filenames are recomputed for content-addressed Docker-save
      and OCI blob-style config paths.
    - Inputs with layer/diff-ID count mismatches now fail instead of writing
      inconsistent output.
    - Added regression tests for appended diff IDs, config digest names and
      mismatch rejection.

- [x] `[High]` Fail closed when requested volumes or secrets cannot be mounted.
  - `setup_volumes()` and `setup_secrets()` used to log failures and allow
    the workload to start.
  - Completed (2026-07-12):
    - Both functions now return `int` instead of `void`. Any validation
      failure or `mount()`/`install_plain_secret()`/`install_tpm2_secret()`
      failure returns -1 immediately instead of `continue`-ing past it — a
      failure on the first of several requested volumes/secrets now
      short-circuits the rest rather than silently skipping just the one
      that failed.
    - `container_main()` checks both return values and aborts (`return 1`)
      with a clear stderr message on failure.
    - The mount audit event now reports the count of volumes that actually
      mounted, not the count requested (see the audit-count item below,
      folded into this fix).
    - Verified with new regression tests in `tests/test_c_stubs.c`
      (short-circuit on first-of-two failure, return-value assertions) and
      `make clean && make test-unit`.

- [x] `[High]` Fail closed when explicit resource limits cannot be applied.
  - Memory, CPU and PID limits used to disappear silently when cgroup setup
    failed.
  - Completed (2026-07-12):
    - `main()` now aborts if `--memory`/`--cpus`/`--pids-limit` was
      explicitly requested and `setup_cgroup()` did not succeed, unless the
      new `--allow-degraded` flag is passed.
    - `--allow-degraded` restores the old warn-and-continue behavior;
      `setup_cgroup()` itself is unchanged (still logs and returns 0 on
      failure — the new fail-closed check lives at the call site in
      `main()`).
    - Documented on all required surfaces: README (Resource limits
      section), docs/runtime.md, docs/reference/{commands,features}.md,
      CHANGELOG.md, the loader's own `--help` text, `doc/oci2bin.1`,
      `doc/oci2bin.texi`.
    - Verified with new `parse_opts` regression tests (default off, flag
      sets `opts.allow_degraded`) on both x86_64 (`make test-unit`) and
      aarch64 (`make test-c-aarch64`).
  - Follow-up gap closed (2026-07-19): the round-1 fix only caught the case
    where `setup_cgroup()` failed outright (e.g. couldn't unshare the
    cgroup namespace). It missed the case where the namespace setup
    succeeded but an individual limit write failed — `cg_set()` discarded
    `cg_write()`'s return value, so a failed `memory.max`/`cpu.max`/
    `pids.max` write was silently ignored and the container started
    unconstrained. `cg_set()` now returns the write result, `setup_cgroup()`
    takes an `int *out_limits_failed` output param set when any requested
    limit fails to apply, and the fail-closed check in `main()` (and the
    `fork_into_cgroup()` fallback fork path) now aborts on either kind of
    failure unless `--allow-degraded` is set. Verified with
    `make clean && make test-unit` and `make test-c-aarch64`.

- [x] `[High]` Overlay root mounting shadowed volume/secret submounts.
  - `--ephemeral-root`/`--overlay-persist` mounted the overlay onto `rootfs`
    inline, in the middle of `container_main()`, after some paths had already
    set up submounts elsewhere. Overlayfs does not see into a separately
    mounted `lowerdir`/`upperdir` submount at lookup time (a documented
    kernel limitation, not simple mount-stacking), so anything mounted
    before the overlay could be invisible or masked afterward depending on
    ordering.
  - Completed (2026-07-19):
    - Extracted the inline block into `setup_overlay_root(rootfs, opts)` and
      moved the call to the very start of the mount-setup sequence in
      `container_main()`, before `setup_volumes()`, the pre-chroot `/run`
      tmpfs block, and `setup_secrets()` — the overlay is now always the
      first thing mounted onto `rootfs`, so nothing it mounts can shadow a
      later submount.
    - Verified with `make clean && make test-unit` and
      `make test-c-aarch64`.
  - Follow-up cleanup (2026-07-19, found by the mandatory CLAUDE.md
    security-subagent review of this change): the `--ephemeral-root`
    branch's two `mkdir()` calls for the overlay `upper`/`work` dirs had
    their return values ignored, unconditionally setting `upper_ok = 1`
    (a literal violation of CLAUDE.md's "check all mkdir return values"
    rule, though not an exploitable one — a real failure there still made
    the subsequent `mount("overlay", ...)` fail and the function return
    -1). Added a `stat()`-based existence/type check after the `mkdir()`
    calls, matching the `--overlay-persist` branch's existing pattern, so
    the failure is reported specifically instead of falling through to a
    generic overlay-mount error. Verified with `make clean && make
    test-unit` and `make test-c-aarch64`.

- [x] `[High]` `--read-only`'s automatic `/run` tmpfs mount shadowed secrets.
  - The default `/run` tmpfs for `--read-only` was mounted post-chroot,
    after `setup_secrets()` had already bind-mounted secrets at their
    default `/run/secrets/<name>` location — the later tmpfs mount hid
    them from the workload.
  - Completed (2026-07-19):
    - The `/run` tmpfs (for `--read-only` or an explicit `--tmpfs /run`) is
      now mounted pre-chroot, immediately after `setup_overlay_root()` and
      before `setup_secrets()`, using a local `run_tmpfs_preinstalled` flag.
      The post-chroot generic `--tmpfs` loop skips `/run` when the flag is
      set instead of mounting it a second time.
    - This also removes the redundant post-chroot "mount /run as tmpfs for
      --read-only" block that used to duplicate this logic after chroot.
    - Verified with `make clean && make test-unit` and
      `make test-c-aarch64`.
  - Follow-up gap closed (2026-07-19, found by the mandatory CLAUDE.md
    security-subagent review of this change): if the pre-chroot `/run`
    tmpfs `mount()` call itself failed, the code only logged a warning and
    left `run_tmpfs_preinstalled` at 0. `setup_secrets()` would then still
    bind-mount secrets under the plain (non-tmpfs) `/run`, and the
    post-chroot generic `--tmpfs` loop — which only skips remounting
    `/run` when `run_tmpfs_preinstalled` is set — would mount a fresh
    tmpfs over it, reintroducing the exact secret-shadowing bug this fix
    targets, through the one path where the pre-chroot mount silently
    degrades. Now `return 1` on that `mount()` failure instead of
    continuing, consistent with the fail-closed handling already applied
    to `-v`/`--secret` a few lines later in the same function. Verified
    with `make clean && make test-unit` and `make test-c-aarch64`.

- [x] `[Medium]` `-v host:ctr:ro` used a non-recursive remount.
  - The `:ro` suffix bind-mounted the host path then did a plain
    `MS_BIND | MS_REMOUNT | MS_RDONLY`, which the kernel only applies to the
    top mount — any submount already nested under the host path (e.g. an
    additional filesystem mounted inside a bind-mounted directory) stayed
    writable from inside the container.
  - Completed (2026-07-19):
    - Added `recursive_remount_rdonly()`, which uses `mount_setattr(2)`
      (`MOUNT_ATTR_RDONLY | AT_RECURSIVE`) to atomically make the whole
      mount tree read-only, falling back to the old non-recursive
      `MS_REMOUNT | MS_RDONLY` only when the syscall isn't available
      (`ENOSYS`, i.e. pre-5.12 kernels) — any other failure is reported and
      fails closed rather than silently degrading.
      `mount_rootfs_read_only()` (used by plain `--read-only`) is
      intentionally left as-is: its non-recursive top-only remount after a
      recursive self-bind is already correct there, and explicit submounts
      like a plain `-v` are meant to keep their own flags.
    - Verified with `make clean && make test-unit` and
      `make test-c-aarch64`.
  - Follow-up gap closed (2026-07-19, found by the mandatory CLAUDE.md
    security-subagent review of this change): `recursive_remount_rdonly()`
    opens `path` with `O_PATH` before calling `mount_setattr(2)`. If that
    `open()` itself failed (EMFILE/ENOMEM/EACCES/...), the code fell
    through to the non-recursive fallback exactly as if the kernel lacked
    `mount_setattr(2)` (`ENOSYS`) — silently accepting the weaker guarantee
    the function's own doc comment says it never does, and printing no
    warning. Restructured so an `open()` failure returns `-1` directly;
    only a `mount_setattr(2)` call that actually returned `ENOSYS` falls
    back to the non-recursive remount. Verified end-to-end (nested bind
    mount inside a `-v ...:ro` volume rejects a write with "Read-only file
    system") plus `make clean && make test-unit` and `make test-c-aarch64`.

- [x] `[High]` MCP `run_container` silently dropped invalid volume specs.
  - The MCP JSON-RPC handler validated each requested `-v` spec but simply
    skipped ones that failed validation and launched the container anyway,
    contradicting the fail-closed volume policy enforced by the CLI path
    (`setup_volumes()`, see the earlier "Fail closed when requested volumes
    or secrets cannot be mounted" entry) — an MCP client requesting an
    invalid mount would get a running container missing a volume it
    expected, with no error.
  - Completed (2026-07-19):
    - The validation loop now aborts the whole request
      (`mcp_send_error(id, -32602, ...)` then `goto cleanup_env`) on the
      first invalid spec instead of filtering it out and continuing.
    - Verified the existing `cleanup_env:` cleanup path is safe to reuse
      here: `json_parse_string_array()` always returns a count exactly
      matching the number of allocated entries, so `n_vol` reflects real
      allocations at every point the `goto` can fire.
    - Verified the loader still compiles cleanly (`gcc -static -O2 -Wall
      -Wextra`) and `make clean && make test-unit` passes.
    - Verified end-to-end via `mcp-serve` over stdin/stdout: a request with
      one valid and one invalid volume spec is rejected in full
      (`-32602`), and `list_containers` afterward shows no container was
      launched — no partial application of the request.

- [x] `[Medium]` TPM2 secret plaintext fallback relied on mode 0400 alone.
  - When `memfd_secret` isn't available, `install_tpm2_secret()`'s fallback
    wrote the decrypted credential to a regular file with mode `0400` and
    stopped there. Permission bits don't restrict root, so a
    root-in-container workload (the common case for containers) could
    `chmod`/rewrite/unlink the file despite the "read-only" intent.
  - Completed (2026-07-19):
    - The fallback now self-bind-mounts the file and remounts it
      `MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV`,
      matching the existing pattern already used by
      `install_plain_secret()`'s bind-mount fallback, with `umount2(...,
      MNT_DETACH)` cleanup if the remount fails. Enforcement is now at the
      mount level, not just permission bits.
    - Verified with `make clean && make test-unit` and
      `make test-c-aarch64`.
  - Follow-up gap closed (2026-07-19, found by the mandatory CLAUDE.md
    security-subagent review of this change): unlike
    `install_plain_secret()`'s fallback (which bind-mounts a pre-existing
    host file and never writes secret bytes to a fresh location),
    `install_tpm2_secret()`'s fallback writes the freshly-decrypted
    plaintext directly to `dst_path` *before* the self-bind/remount. On
    either mount step failing afterward — or on a short/failed
    `write_all_fd()` — the function returned `-1` without touching the
    file, leaving the decrypted credential sitting on disk protected only
    by mode `0400` (which does not stop a root-owned process) until the
    rootfs tmpdir is eventually swept by unlink-only cleanup, or not at
    all on a hard kill. Added `wipe_and_unlink_secret_file()` (zero the
    file's contents, then `unlink()`) and call it on every one of these
    error paths before returning. Verified with `make clean && make
    test-unit` and `make test-c-aarch64`.

- [ ] `[High]` Replace or strictly constrain the custom seccomp parser.
  - It does not fully support argument filters, architecture conditions,
    include/exclude rules, errno values or mixed actions.
  - Prefer libseccomp.
  - Otherwise reject all unsupported constructs.

- [ ] `[High]` Make `--require-signed` enforcement unambiguously fail closed.
  - Metadata parse failures can currently produce successful verification.
  - Policy presence must not depend on searching for a removable text marker
    (`has_require_signed_marker()` scans the trailing 256 KiB for
    `"require_signed":true`).
  - The trust anchor (`verify_pubkey`) and the `require_signed` flag are both
    embedded in the same binary they protect, so an attacker who can rewrite
    the artifact can flip the flag or swap the key. This only guards against
    accidental corruption / foreign-signed swaps, not a determined tamperer.
    Document the limitation prominently and support pinning the key
    out-of-band or via a signed external policy file.
  - Evidence: `src/loader.c`, `enforce_require_signed()`,
    `has_require_signed_marker()`.

- [ ] `[High]` Make runtime signature and update verification standalone.
  - `--verify-key` looks for `../scripts/sign_binary.py` relative to the
    generated executable.
  - Implement verification in the loader or embed the helper in the artifact.

- [ ] `[High]` Add an MCP host-access policy.
  - Default-deny host mount paths.
  - Make mounts read-only by default.
  - Allow configured image roots and mount roots only.
  - Store executable identity and process start time, not only PID.
  - Reuse stopped tracking slots.
  - Generate unique automatic names.
  - Preserve string JSON-RPC IDs and remove the unsolicited initialization
    response.

- [x] `[High]` `--secret tpm2:NAME` never read the sealed credential.
  - `install_tpm2_secret()` ran `systemd-creds decrypt --name NAME - -`,
    where the first `-` means "read the ciphertext from stdin", and
    `run_cmd_capture()` only redirected the child's *stdout* — so the helper
    inherited the loader's own stdin. Nothing in the tree ever opened a
    credential file; `grep -r credstore` matched only the two doc files that
    documented the (impossible) `/etc/credstore/NAME.cred` flow. With a TTY
    on stdin the run blocked waiting for terminal input; with `/dev/null` it
    aborted with a decrypt failure. It also consumed the stdin meant for the
    workload, and a second `--secret tpm2:` could never work at all.
  - Completed (2026-08-04):
    - Added `open_tpm2_credential()`, which resolves `NAME` against
      `CREDSTORE_DIRS` (`/etc/credstore.encrypted`, `/run/…`, `/var/lib/…`
      plus the unencrypted variants, each tried as `NAME` and `NAME.cred`),
      opens it `O_NOFOLLOW`, and returns the fd so the file that was checked
      is the file that gets decrypted (no TOCTOU).
    - Split `run_cmd_capture()` into `run_cmd_capture_stdin(argv, in_fd,
      out_len)`. The child's stdin is now always replaced: with the caller's
      fd, or `/dev/null` when `in_fd < 0`. No captured helper can consume
      the loader's stdin again.
    - Verified end-to-end on a real built binary: a missing credential now
      prints the search list and aborts instead of hanging.

- [x] `[High]` `memfd_secret`-backed secrets never worked, and the fallback
      put TPM2 plaintext on disk.
  - `bind_mount_memfd_secret()` wrote into a `memfd_secret` fd and
    bind-mounted `/proc/self/fd/<n>` onto the destination. Two independent
    reasons that cannot work: secretmem implements `mmap` but no read/write
    file operations, so `write(2)` fails with `EINVAL`; and memfd inodes
    live on an internal kernel mount (`MNT_INTERNAL`), which `do_loopback()`
    rejects with `EINVAL`, so the bind always failed. Every secret silently
    took the fallback path. For `--secret tpm2:` that fallback wrote the
    decrypted credential to a regular file under the runtime tmpdir —
    `OCI2BIN_TMPDIR`/`TMPDIR`/`/tmp`/`/var/tmp`, the last of which is
    disk-backed — defeating the whole point of sealing it.
  - The existing stub test passed only because it mocked `mount()`;
    stubbing `mount()` cannot tell you whether a mount source is legal.
  - Completed (2026-08-04):
    - Removed the memfd path entirely, with a comment at
      `mount_secret_staging()` explaining why it must not be reintroduced.
    - Added `mount_secret_staging()` / `install_staged_secret()` /
      `umount_secret_staging()`: mount a private `ramfs` (pages are never
      swapped; `tmpfs` fallback with a warning) at
      `<rootfs>/.oci2bin-secrets`, write the plaintext there, bind-mount it
      onto the destination, remount
      `MS_RDONLY|MS_NOEXEC|MS_NOSUID|MS_NODEV`, then unlink the staging
      name so the read-only mount is the only path to the plaintext.
      `setup_secrets()` tears the staging mount down on every exit path.
    - Verified by probe that the installed secret survives the staging
      teardown and stays read-only, and that plain-file secrets no longer
      emit the `memfd_secret write: Invalid argument` warning.
    - Replaced the stub test with one covering `install_staged_secret()`.

- [x] `[Medium]` `--secret` was silently ignored under `--vm`.
  - `setup_secrets()` is only called from `container_main()`; the VM
    dispatch never looked at `opts.n_secrets`, so a VM run started without
    a credential the caller explicitly asked for. `--allow-egress` two
    lines earlier already rejected the same combination.
  - Completed (2026-08-04): `--secret` with `--vm` is now a hard error,
    matching the fail-closed contract documented for `setup_secrets()`.

- [x] `[Medium]` Sealed credentials were decrypted without validating the
      source file.
  - `systemd-creds decrypt` accepts host-key and even `--with-key=null`
    (unencrypted) blobs as readily as TPM2-sealed ones, and offers no flag
    to demand TPM2 binding at decrypt time. Combined with the stdin bug
    above, anything that could supply the loader's stdin could substitute
    a credential of its own.
  - Completed (2026-08-04): `credential_file_is_safe()` requires a regular
    file (an `lstat` reporting a symlink fails this, so a link cannot
    redirect past the check) that is not group- or world-writable. Since
    the blob can no longer come from stdin and only the root-owned system
    credential stores are searched, guarding the input path is the
    enforceable half of the guarantee. Documented honestly: the `tpm2:`
    prefix cannot prove TPM binding, so seal with `--with-key=tpm2`.

- [x] `[High]` `--tmpfs /run/` bypassed the `/run` secret-shadowing fix.
  - Found by the mandatory CLAUDE.md security review (2026-08-04). `--tmpfs`
    parsing accepts any absolute path without `..`, so `/run/` and `//run`
    are valid spellings — but both the pre-chroot `want_run_tmpfs` detection
    and the post-chroot skip compared with a plain `strcmp(..., "/run")`.
    With `--tmpfs /run/ --secret X` the tmpfs was therefore mounted
    post-chroot on top of `/run/secrets/*`, exactly the fail-open the
    pre-chroot `/run` mount exists to prevent.
  - Reproduced end-to-end before fixing: the loader printed
    `secret ... -> /run/secrets/apikey (read-only)` and the workload then
    got `cat: can't open '/run/secrets/apikey': No such file or directory`
    — the run started without a credential it had reported installing.
  - Completed (2026-08-04): added `path_equals_normalized()` (collapses
    runs of `/`, ignores trailing slashes) and used it at both comparison
    sites. Unit-tested across 9 spellings; verified end-to-end that
    `--tmpfs /run/ --secret X` now delivers the secret.

- [x] `[Medium]` `--overlay-persist` allowed overlayfs mount-option injection.
  - Found by the mandatory CLAUDE.md security review (2026-08-04). The path
    is interpolated into `lowerdir=%s,upperdir=%s,workdir=%s`, where `,`
    terminates an option and `:` separates lower layers, but only `..` was
    rejected.
  - Completed (2026-08-04): `parse_opts()` now rejects `,` and `:` in the
    `--overlay-persist` path, with unit coverage.

- [x] `[Medium]` Sealed credential ownership was not checked.
  - Found by the mandatory CLAUDE.md security review (2026-08-04).
    `credential_file_is_safe()` rejected group- and world-writable files,
    but an owner can always `chmod` its own file — so a mode-0400 blob
    owned by an arbitrary unprivileged uid was just as substitutable.
  - Completed (2026-08-04): the credential must now be owned by uid 0 or by
    the effective uid. Root takes the single-ID identity map
    (`plan_userns_map()` returns early when the caller has
    `CAP_SETUID`/`CAP_SETGID`), so a host root-owned credential reads as
    uid 0 inside the namespace. A rootless run, where the host credential
    is unmapped and reports as the overflow uid, gets an explicit pointer
    at the root requirement rather than a confusing ownership complaint.

- [x] `[Low]` `run_cmd_capture_stdin()` could exec a helper with no stdin.
  - Found by the mandatory CLAUDE.md security review (2026-08-04). When
    `in_fd < 0` and fd 0 was already closed, `open("/dev/null")` returned
    fd 0; the `child_in == STDIN_FILENO` branch cleared `FD_CLOEXEC` on it,
    and the unconditional `close(devnull)` immediately undid that.
  - Completed (2026-08-04): the close is skipped when `devnull` *is* fd 0.

- [x] `[Low]` `open_tpm2_credential()` could block indefinitely.
  - Found by the mandatory CLAUDE.md security review (2026-08-04). A FIFO
    planted under a candidate credential name would wedge the loader in
    `open(O_RDONLY)` until a writer appeared.
  - Completed (2026-08-04): opens with `O_NONBLOCK`, a no-op for the
    regular files that survive the subsequent `fstat` check.

- [x] `[Low]` Decrypted plaintext lingered in freed heap.
  - `run_cmd_capture()` grew its buffer with `realloc()`, which may copy
    and free the old block without zeroing it — leaving recoverable
    credential bytes for any secret over 4 KiB. Several error paths also
    `free()`d the buffer without zeroing.
  - Completed (2026-08-04): buffer growth is now malloc + memcpy +
    `explicit_bzero` + free, every error path zeroes before freeing, and
    decrypted credentials are capped at `SECRET_MAX_BYTES` (4 MiB) to match
    the plain-file secret limit.

## Correctness and Reliability

- [x] `[Medium]` Support (or reject) `:ro`/`:rw` suffixes on runtime `-v`.
  - The `-v HOST:CONTAINER` parser used to split on the first colon and treat
    the remainder as the container path, so `-v /data:/data:ro` created a
    mount point literally named `/data:ro`.
  - The MCP volume path already stripped `:ro`/`:rw` suffixes for its own
    validation but didn't check the suffix value, so the two entry points
    disagreed about the same spec.
  - Completed (2026-07-12):
    - `-v HOST:CONTAINER[:ro|:rw]` is now parsed and honoured: `:ro` remounts
      the bind mount `MS_RDONLY` after the initial `MS_BIND|MS_REC` bind
      (two-step pattern matching `mount_rootfs_read_only()`); any other
      suffix is rejected with an explicit error. `:rw` is the default and may
      be given explicitly.
    - The MCP volume validator now also checks the suffix is exactly `ro` or
      `rw` before forwarding the spec, instead of accepting any suffix value.
    - A failed read-only remount detaches the bind (`umount2(MNT_DETACH)`,
      with its return value checked and logged) and fails closed.
    - Documented on all required surfaces (README, docs/runtime.md,
      docs/reference/{commands,features}.md, CHANGELOG.md, loader `--help`,
      man page, texinfo, `oci2bin` wrapper help).
    - Verified with new regression tests covering suffix parsing (`:ro`,
      `:rw`, no suffix, invalid suffix), the two-step mount+remount call
      sequence and flags, and remount-failure cleanup, on both x86_64 and
      aarch64.

- [x] `[Low]` Volume audit event reports requested count, not mounted count.
  - `setup_volumes()` used to emit `"volumes":opts->n_vols` after the loop
    even when individual bind mounts failed.
  - Completed (2026-07-12): folded into the fail-closed volumes fix above —
    the audit event now emits the count of volumes that actually mounted,
    computed after the (now fail-closed) loop completes successfully.

- [ ] `[Medium]` Compare file contents in `oci2bin diff`.
  - Regular files are compared only by size.
  - Different same-size files are reported as unchanged.
  - Calculate a streaming content hash.

- [x] `[Medium]` Fix `strip_image.py` tests and behavior.
  - Full discovery currently reports four failures:
    - apt auto-detection
    - pip auto-detection
    - npm auto-detection
    - `_norm('.')`
  - Completed (2026-06-27):
    - `_norm('.')` now normalizes to an empty root-entry path.
    - Layer pre-scan now recognizes top-level `layer.tar`, fixing package
      manager auto-detection in minimal docker-save fixtures.
    - Verified with `python3 -m unittest tests.test_strip_image
      tests.test_merge_layers -v`.

- [ ] `[Medium]` Verify all OCI descriptors before execution.
  - Verify config and manifest consistency.
  - Verify compressed layer digests and uncompressed diff IDs.
  - Validate descriptor sizes, OS, architecture and layer counts.

- [ ] `[Medium]` Use one OCI implementation for runtime, inspect, diff, SBOM,
  Dockerfile extraction, strip, squash and reconstruction.
  - The current independent implementations disagree about the resulting
    filesystem.

- [ ] `[Medium]` Review C memory ownership.
  - ASan reported 16 small leaks totaling 140 bytes in unit-test paths,
    mainly health configuration and CDI allocations.

- [ ] `[Low]` Explicitly initialize syscall tracer PID state.
  - Cppcheck reported a possible uninitialized-state path.
  - The count appears to prevent actual access, but `memset` would remove
    ambiguity and improve analyzer confidence.

## Tests and CI

- [ ] `[High]` Add a code CI workflow.
  - Existing GitHub Actions only build and deploy documentation.
  - Run C compilation, Python tests, C tests, ShellCheck and packaging smoke
    tests on every pull request.

- [ ] `[High]` Replace manually enumerated Python tests with discovery.
  - `make test-unit` passed while full discovery failed.
  - Currently omitted modules include:
    - `test_dockerfile_from_arch`
    - `test_encrypt`
    - `test_require_signed`
    - `test_strip_image`
    - `test_user_labels`

- [ ] `[Medium]` Add sanitizer CI.
  - AddressSanitizer
  - UndefinedBehaviorSanitizer
  - LeakSanitizer

- [ ] `[Medium]` Add package installation tests.
  - Build and install the wheel into a clean environment.
  - Test `doctor`, `explain`, `up`, `freeze`, `diff-fs`, `from-chroot` and
    `build-dockerfile`.
  - Test Make, RPM and Nix installations where practical.

- [ ] `[Medium]` Make Semgrep reproducible.
  - The local target failed to start because its environment lacked `attr`.
  - Pin lint dependencies in a dedicated dependency group or container.

- [ ] `[Medium]` Run short fuzz smoke tests in CI.
  - Keep longer fuzz campaigns scheduled or manual.

## Packaging and Release

- [ ] `[High]` Use one canonical project version.
  - `pyproject.toml`: `0.17.0`
  - Embedded metadata: `0.14.0`
  - AUR: `0.9.0`
  - RPM: `0.9.0`
  - Nix: `0.1.0`
  - MCP server: `1.0`

- [ ] `[High]` Replace AUR `sha256sums=('SKIP')` with the release checksum.

- [ ] `[Medium]` Update setuptools license metadata.
  - Use a SPDX license expression instead of the deprecated license table.
  - Remove the deprecated license classifier if appropriate.

- [ ] `[Medium]` Generate RPM, AUR, Nix and Python package metadata from shared
  release data.

## Architecture and Code Quality

- [ ] `[Medium]` Split `src/loader.c`, currently over 18,000 lines.
  - Suggested modules:
    - options
    - OCI extraction
    - namespaces
    - mounts
    - seccomp
    - signatures
    - cgroups
    - VM
    - MCP

- [ ] `[Medium]` Reduce the nearly 3,000-line shell CLI.
  - Move subcommands into a proper Python package or smaller executable
    modules.
  - Remove large embedded Python programs from the shell script.

- [ ] `[Medium]` Stop calling `sys.exit()` deep inside reusable Python
  functions.
  - Raise typed exceptions and let CLI entry points decide exit codes.

- [ ] `[Medium]` Replace `sys.path` manipulation and dynamic file loading with
  package imports.

- [ ] `[Medium]` Centralize repeated logic.
  - OCI data discovery
  - Metadata and signature parsing
  - Layer decompression
  - Config rewriting
  - Process identity checks
  - HOME/state path validation
  - Package file manifests

- [ ] `[Medium]` Stream large images and layers where possible.
  - Several commands read complete binaries, OCI archives and layers into
    memory.

## Product Ideas

- [x] Add per-volume read-only / read-write control to `-v`.
  - Completed (2026-07-12): see the `:ro`/`:rw` item under Correctness and
    Reliability above.
  - The `--allow-degraded` toggle was added for the cgroup fail-closed case
    (see High Priority above); `-v`/`--secret` failures remain unconditionally
    fatal, matching how `--read-only`/`--seccomp-profile` already treat
    explicit-flag failures — they are not gated behind a toggle.

- [ ] Add `oci2bin verify --all`.
  - Verify signatures, pinned digest, metadata, OCI descriptors, layers, SBOM,
    provenance and Rekor receipt.

- [ ] Add signed runtime policy files.
  - Control mount roots, write access, networking, capabilities, devices,
    user, resource ceilings and MCP permissions.

- [ ] Embed an exact build recipe.
  - Record source digest, architecture, layers, labels, strip options,
    encryption, compression, profiles and signing policy.
  - Let updates reproduce the original artifact instead of rebuilding with
    defaults.

- [ ] Add a real immutable/lazy filesystem backend.
  - Evaluate EROFS, SquashFS, FUSE content-addressed mounts or dm-verity for VM
    mode.

- [ ] Expand SBOM and vulnerability integrations.
  - Syft, Trivy and Grype
  - SPDX and newer CycloneDX versions
  - Signed SBOM attestations
  - Vulnerability and license policy gates

- [ ] Expand stack orchestration.
  - Health-based dependencies
  - Secrets
  - Per-service limits and users
  - Log rotation
  - Restart backoff
  - Detached shared networks
  - Compose import/export

## Positive Existing Work

- `openat2(RESOLVE_IN_ROOT)` is used for destination confinement.
- Sensitive path handling frequently uses `O_NOFOLLOW`.
- Lifecycle commands include process start-time identity checks.
- Runtime environments are rebuilt instead of inheriting host variables.
- Rootless namespaces, Landlock and seccomp are supported.
- Fuzz harnesses cover JSON, seccomp, option parsing, MCP and layer merging.
- The project includes signatures, attestations, encryption and reproducible
  build features.

## Recommended Execution Order

1. Correct and centralize OCI layer handling.
2. Fix Dockerfile context escapes and `RUN` parsing.
3. Separate true read-only and ephemeral root behavior.
4. Make explicit security, mount and resource requests fail closed.
5. Repair package contents and add installed-package tests.
6. Repair strip/merge OCI metadata.
7. Harden signature, seccomp and MCP policy enforcement.
8. Replace curated tests with discovery and add CI.
9. Centralize version and release metadata.
10. Refactor the large C and shell files after correctness is protected by
    tests.
