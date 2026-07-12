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
