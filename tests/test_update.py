"""Behavioral regressions for the oci2bin update command."""

import importlib.util
import os
from pathlib import Path
import platform
import stat
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
OCI2BIN = ROOT / "oci2bin"

# Stands in for the rebuild: records its argv, then writes OUTPUT (its last
# argument) the way the real builder does.
FAKE_REBUILD = """#!/bin/sh
printf '%s\\n' "$@" > "$REBUILD_LOG"
for last; do :; done
printf 'rebuilt' > "$last"
chmod 755 "$last"
"""


def _meta_block(image, **kwargs):
    spec = importlib.util.spec_from_file_location(
        "build_polyglot", ROOT / "scripts" / "build_polyglot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_meta_block(image, **kwargs)


def _executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


def _hermetic_env(root):
    """An OCI2BIN_HOME whose loader is fresh, so the build path can neither
    compile into the checkout's build/ nor depend on a compiler."""
    home = root / "home"
    (home / "build").mkdir(parents=True)
    (home / "scripts").symlink_to(ROOT / "scripts")
    for flavor in ("", "libkrun-"):
        (home / "build" / f"loader-{flavor}{platform.machine()}").touch()
    env = os.environ.copy()
    env["OCI2BIN_HOME"] = str(home)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _fake_docker_env(root):
    """A docker that logs each call and fails, so nothing real is reached."""
    fake_bin = root / "bin"
    fake_bin.mkdir()
    log = root / "docker.log"
    _executable(fake_bin / "docker",
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexit 1\n")
    env = _hermetic_env(root)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    return env, log


def _run_with_fake_rebuild(root, target, script=FAKE_REBUILD):
    """Run `update` with the rebuild ($0) replaced by script.

    Invoked as `bash oci2bin` from the checkout, $0 has no slash and resolves
    through PATH, which is the one way to substitute the rebuild step.
    Returns the result and the rebuild's argv.
    """
    fake_bin = root / "rebuild-bin"
    fake_bin.mkdir()
    _executable(fake_bin / "oci2bin", script)
    log = root / "rebuild.log"
    env = _hermetic_env(root)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    env["REBUILD_LOG"] = str(log)
    result = subprocess.run(
        ["bash", OCI2BIN.name, "update", str(target)],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=30)
    argv = log.read_text().splitlines() if log.exists() else []
    return result, argv


class UpdateTest(unittest.TestCase):
    def test_failed_pull_cannot_report_cached_image_as_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = "example@sha256:" + "a" * 64
            binary = root / "app.bin"
            binary.write_bytes(_meta_block("example:latest", digest=digest))

            fake_bin = root / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  pull) exit 1 ;;\n"
                f"  inspect) printf '%s\\n' '{digest}'; exit 0 ;;\n"
                "esac\n"
                "exit 1\n")
            docker.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            result = subprocess.run(
                [str(OCI2BIN), "update", "--check", str(binary)],
                capture_output=True, text=True, env=env, timeout=30)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("failed to pull", result.stderr)
            self.assertNotIn("up to date", result.stderr)

    def test_failed_rebuild_does_not_execute_directory_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crafted_dir = root / "dir$(touch marker)"
            crafted_dir.mkdir()
            binary = crafted_dir / "app.bin"
            binary.write_bytes(_meta_block(
                "example:latest",
                build_args=["--oci-dir", str(root / "missing-oci-layout")]))

            result = subprocess.run(
                [str(OCI2BIN), "update", str(binary)],
                cwd=root, capture_output=True, text=True, timeout=30,
                env=_hermetic_env(root))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--oci-dir: directory not found", result.stderr)
            self.assertFalse((root / "marker").exists())
            self.assertEqual(list(crafted_dir.glob(".oci2bin-update.*")), [])
            self.assertTrue(binary.exists())

    def test_image_name_cannot_be_an_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "app.bin"
            original = _meta_block("--all-tags", digest="d")
            binary.write_bytes(original)
            env, log = _fake_docker_env(root)

            for args in (["--check"], []):
                result = subprocess.run(
                    [str(OCI2BIN), "update", *args, str(binary)],
                    capture_output=True, text=True, env=env, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid image name", result.stderr)
            self.assertFalse(log.exists())
            self.assertEqual(binary.read_bytes(), original)

    def test_image_name_cannot_select_a_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "app.bin"
            # `oci2bin explain TMP` exits 0 without writing TMP, which used
            # to replace the binary with an empty file.
            env, log = _fake_docker_env(root)

            for block in (_meta_block("explain"),
                          _meta_block("explain", build_args=[])):
                binary.write_bytes(block)
                result = subprocess.run(
                    [str(OCI2BIN), "update", str(binary)],
                    cwd=root, capture_output=True, text=True, env=env,
                    timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binary.read_bytes(), block)
            self.assertIn("image inspect explain", log.read_text())

    def test_trailing_compress_binary_cannot_eat_the_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "app.bin"
            binary.write_bytes(_meta_block(
                "zstd", build_args=["--compress-binary"]))
            env, log = _fake_docker_env(root)

            result = subprocess.run(
                [str(OCI2BIN), "update", str(binary)],
                cwd=root, capture_output=True, text=True, env=env, timeout=30)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("image inspect zstd", log.read_text())
            self.assertNotIn(".oci2bin-update", log.read_text())

    def test_malformed_tokens_are_refused_not_dropped(self):
        for tokens in (["--strip", "\ud800", "--require-cosign"],
                       ["--strip\0--squash"],
                       ["--arch", "all"]):
            with self.subTest(tokens=tokens), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary = root / "app.bin"
                original = _meta_block("example:latest", build_args=tokens)
                binary.write_bytes(original)
                env, log = _fake_docker_env(root)

                result = subprocess.run(
                    [str(OCI2BIN), "update", str(binary)],
                    capture_output=True, text=True, env=env, timeout=30)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("malformed build_args", result.stderr)
                self.assertFalse(log.exists())
                self.assertEqual(binary.read_bytes(), original)


class UpdateReplacesBinaryTest(unittest.TestCase):
    """The final rename, with the rebuild step replaced by a fake."""

    def _binary(self, root, name="app.bin"):
        binary = root / name
        binary.write_bytes(_meta_block("example:latest", build_args=[]))
        return binary

    def test_rebuild_writing_nothing_keeps_the_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = self._binary(root)
            original = binary.read_bytes()

            result, _ = _run_with_fake_rebuild(
                root, binary, script="#!/bin/sh\nexit 0\n")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("wrote no output", result.stderr)
            self.assertEqual(binary.read_bytes(), original)
            self.assertEqual(list(root.glob(".oci2bin-update.*")), [])

    def test_image_is_passed_after_end_of_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = self._binary(root)

            result, argv = _run_with_fake_rebuild(root, binary)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(argv[:2], ["--", "example:latest"])
            self.assertEqual(binary.read_bytes(), b"rebuilt")
            self.assertEqual(list(root.glob(".oci2bin-update.*")), [])

    def test_restricted_mode_is_not_widened(self):
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)
        for before, after in ((0o700, 0o700), (0o750, 0o750), (0o555, 0o555),
                              (0o644, 0o744), (0o4755, 0o755)):
            with self.subTest(mode=oct(before)), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary = self._binary(root)
                binary.chmod(before)

                result, _ = _run_with_fake_rebuild(root, binary)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    stat.S_IMODE(binary.stat().st_mode), after)

    def test_symlink_updates_its_target_and_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._binary(root, "real.bin")
            link_dir = root / "links"
            link_dir.mkdir()
            link = link_dir / "app"
            link.symlink_to(target)

            result, _ = _run_with_fake_rebuild(root, link)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_bytes(), b"rebuilt")
            self.assertEqual(list(link_dir.iterdir()), [link])

    def test_path_starting_with_a_dash(self):
        for relative in ("-app", "-dir/app"):
            with self.subTest(path=relative), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary = root / relative
                binary.parent.mkdir(exist_ok=True)
                binary.write_bytes(_meta_block("example:latest"))
                original = binary.read_bytes()
                env, log = _fake_docker_env(root)

                result = subprocess.run(
                    [str(OCI2BIN), "update", relative],
                    cwd=root, capture_output=True, text=True, env=env,
                    timeout=30)

                # The fake docker fails the rebuild once it is reached.
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("invalid option", result.stderr)
                self.assertIn("image inspect example:latest", log.read_text())
                self.assertEqual(binary.read_bytes(), original)


class UpdatePullTest(unittest.TestCase):
    """Which images a rebuild refreshes. The fake engine has the image locally,
    logs each call and fails `save`, so a rebuild stops right after the pull
    decision and nothing real is reached."""

    REGISTRY = "example@sha256:" + "a" * 64

    def _run(self, *args, image="example:latest", build_args=None,
             digests=REGISTRY, identity=None, pull_rc=0, save_rc=1,
             engine="docker", extra_env=None, local=True, trailing=(),
             meta_digest=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "app.bin"
            binary.write_bytes(_meta_block(image, digest=meta_digest,
                                           build_args=build_args))
            original = binary.read_bytes()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "engine.log"
            # None is an engine without the field: its template fails. False is
            # Docker's classic store: it has the field and leaves it unset.
            if identity is None:
                identity_case = "      *Identity*) exit 1 ;;\n"
            elif identity is False:
                identity_case = "      *Identity*) exit 0 ;;\n"
            else:
                identity_case = (
                    "      *Identity*) "
                    f"printf '%s\\n' identity '{identity}'; exit 0 ;;\n")
            _executable(fake_bin / engine, (
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> '{log}'\n"
                "case \"$1 $2\" in\n"
                "  'image inspect')\n"
                + ("" if local else "    exit 1\n") +
                "    case \"$*\" in\n"
                + identity_case +
                f"      *--format*) printf '%s\\n' '{digests}' ;;\n"
                "    esac\n"
                "    exit 0 ;;\n"
                "esac\n"
                f"[ \"$1\" = inspect ] && {{ printf '%s\\n' '{digests}'; exit 0; }}\n"
                f"[ \"$1\" = pull ] && exit {pull_rc}\n"
                f"[ \"$1\" = save ] && exit {save_rc}\n"
                "exit 1\n"))
            env = _hermetic_env(root)
            build = Path(env["OCI2BIN_HOME"]) / "build"
            for arch in ("x86_64", "aarch64"):
                (build / f"loader-{arch}").touch()
                (build / f"loader-libkrun-{arch}").touch()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env.update(extra_env or {})
            result = subprocess.run(
                [str(OCI2BIN), *args, str(binary), *trailing],
                cwd=root, capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(binary.read_bytes(), original)
            return result, log.read_text() if log.exists() else ""

    def _pulls(self, calls):
        return [c for c in calls.splitlines() if c.startswith("pull ")]

    def test_update_pulls_an_image_it_already_has(self):
        _, calls = self._run("update")
        self.assertEqual(self._pulls(calls), ["pull example:latest"])

    def test_failed_pull_stops_the_rebuild(self):
        result, calls = self._run("update", pull_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._pulls(calls), ["pull example:latest"])
        # The digest lookup is the build's next step after the pull.
        self.assertNotIn("\ninspect --format", calls)
        self.assertIn("Use --no-pull", result.stderr)

    def test_no_pull_uses_the_local_copy(self):
        # An inherited value must not override the flag.
        _, calls = self._run("update", "--no-pull",
                             extra_env={"OCI2BIN_UPDATE_PULL": "1"})
        self.assertIn("\ninspect --format", calls)
        self.assertEqual(self._pulls(calls), [])

    def test_no_pull_never_fetches_a_missing_image(self):
        result, calls = self._run("update", "--no-pull", local=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not in the local store", result.stderr)
        self.assertEqual(self._pulls(calls), [])

    def test_no_pull_refuses_skopeo(self):
        result, calls = self._run("update", "--no-pull", engine="skopeo",
                                  build_args=["--pull-with", "skopeo"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--no-pull requires", result.stderr)
        self.assertEqual(calls, "")

    def test_flag_after_the_binary_is_refused(self):
        for flag in ("--no-pull", "--check"):
            with self.subTest(flag=flag):
                result, calls = self._run("update", trailing=[flag])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Usage:", result.stderr)
                self.assertEqual(calls, "")

    def test_classic_store_falls_back_to_repo_digests(self):
        # That store has no Identity to read: a digest is the pull record.
        _, calls = self._run("update", identity=False)
        self.assertEqual(self._pulls(calls), ["pull example:latest"])
        result, calls = self._run("update", identity=False, digests="")
        self.assertIn("no registry origin", result.stderr)
        self.assertEqual(self._pulls(calls), [])

    def test_retag_keeps_the_source_digest_but_is_not_pulled(self):
        digests = "docker.io/library/alpine@sha256:" + "a" * 64
        for name, extra in (("docker", {}),
                            ("podman", {"build_args": ["--pull-with", "podman"]})):
            with self.subTest(engine=name):
                _, calls = self._run("update", image="acme/app:1", engine=name,
                                     digests=digests, **extra)
                self.assertEqual(self._pulls(calls), [])

    def test_locally_built_image_is_never_pulled(self):
        result, calls = self._run("update", digests="")
        self.assertIn("no registry origin", result.stderr)
        self.assertEqual(self._pulls(calls), [])

    def test_identity_shows_the_image_was_pulled(self):
        for image in ("example:latest", "docker.io/library/example:latest",
                      "docker.io/example:latest",
                      "index.docker.io/library/example:latest"):
            with self.subTest(image=image):
                _, calls = self._run(
                    "update", image=image,
                    identity="docker.io/library/example")
                self.assertEqual(self._pulls(calls), [f"pull {image}"])

    def test_identity_without_pull_is_local_despite_a_digest(self):
        # Docker's containerd store reports a digest for local builds too.
        result, calls = self._run("update", identity="")
        self.assertIn("no registry origin", result.stderr)
        self.assertEqual(self._pulls(calls), [])

    def test_retagged_image_does_not_pull_its_new_name(self):
        _, calls = self._run("update", image="acme/app:1",
                             identity="docker.io/library/alpine")
        self.assertEqual(self._pulls(calls), [])

    def test_podman_localhost_digest_is_not_a_registry_origin(self):
        digest = "localhost/app@sha256:" + "b" * 64
        for image in ("app:1", "localhost/app:1"):
            with self.subTest(image=image):
                _, calls = self._run("update", image=image, digests=digest,
                                     engine="podman",
                                     build_args=["--pull-with", "podman"])
                self.assertEqual(self._pulls(calls), [])

    def test_offline_only_is_never_pulled(self):
        _, calls = self._run("update", build_args=["--offline-only"])
        self.assertEqual(self._pulls(calls), [])
        # The rebuild goes on from the local copy instead of refusing.
        self.assertIn("\ninspect --format", calls)

    def test_digest_pinned_image_is_never_pulled(self):
        _, calls = self._run("update", image=self.REGISTRY)
        self.assertEqual(self._pulls(calls), [])

    def test_cross_arch_pull_keeps_the_target_arch(self):
        machine = platform.machine()
        target, name = (("x86_64", "amd64") if machine == "aarch64"
                        else ("aarch64", "arm64"))
        _, calls = self._run("update", build_args=["--arch", target])
        self.assertEqual(self._pulls(calls),
                         [f"pull --platform linux/{name} example:latest"])

    def test_recorded_layer_is_refreshed_too(self):
        # `save` must succeed for the build to reach the layer images.
        digests = self.REGISTRY + "\nextra@sha256:" + "a" * 64
        _, calls = self._run("update", build_args=["--layer", "extra:1"],
                             digests=digests, save_rc=0)
        self.assertIn("pull extra:1", self._pulls(calls))

    def test_podman_layer_pull_is_qualified(self):
        digests = ("docker.io/library/example@sha256:" + "a" * 64 +
                   "\ndocker.io/library/extra@sha256:" + "a" * 64)
        _, calls = self._run("update", engine="podman", digests=digests,
                             build_args=["--pull-with", "podman",
                                         "--layer", "extra:1"], save_rc=0)
        self.assertIn("pull docker.io/library/extra:1", self._pulls(calls))

    def test_check_refuses_a_locally_built_image(self):
        result, calls = self._run("update", "--check", digests="",
                                  meta_digest=self.REGISTRY)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no registry origin to check", result.stderr)
        self.assertEqual(self._pulls(calls), [])

    def test_check_cannot_combine_with_no_pull(self):
        result, calls = self._run("update", "--check", "--no-pull")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot use --no-pull", result.stderr)
        self.assertEqual(calls, "")


class UpdateCheckTest(unittest.TestCase):
    """`--check` follows what the binary recorded. The fake engines log every
    call, so a test can assert that a refused check touched nothing."""

    CURRENT = "example@sha256:" + "a" * 64
    NEWER = "example@sha256:" + "b" * 64

    def _check(self, build_args=None, digest=CURRENT, listed=None,
               engines=("docker", "podman"), pull_rc=0, inspect_rc=0,
               path_only=False, hermetic=False):
        listed = self.CURRENT if listed is None else listed
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "app.bin"
            binary.write_bytes(_meta_block("example:latest", digest=digest,
                                           offline_only=hermetic,
                                           build_args=build_args))
            original = binary.read_bytes()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "engine.log"
            for engine in engines:
                _executable(fake_bin / engine, (
                    "#!/bin/sh\n"
                    f"printf '{engine} %s\\n' \"$*\" >> '{log}'\n"
                    "case \"$1\" in\n"
                    f"  pull) exit {pull_rc} ;;\n"
                    f"  inspect) printf '%s\\n' '{listed}'; exit {inspect_rc} ;;\n"
                    "esac\n"
                    "exit 1\n"))
            env = _hermetic_env(root)
            # python3, uname and the coreutils the script needs stay reachable
            # through symlinks, so a missing engine is really missing.
            if path_only:
                for tool in ("python3", "uname", "readlink", "dirname", "sed",
                             "cat", "grep", "mktemp", "rm", "mkdir", "bash"):
                    found = shutil.which(tool)
                    if found:
                        (fake_bin / tool).symlink_to(found)
                env["PATH"] = str(fake_bin)
            else:
                env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            result = subprocess.run(
                [str(OCI2BIN), "update", "--check", str(binary)],
                cwd=root, capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(binary.read_bytes(), original)
            return result, log.read_text() if log.exists() else ""

    def _pulls(self, calls):
        return [c for c in calls.splitlines() if " pull " in f" {c} "]

    def test_up_to_date_and_update_available(self):
        result, _ = self._check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("up to date", result.stderr)
        result, _ = self._check(listed=self.NEWER)
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn("update available", result.stderr)

    def test_any_listed_digest_of_this_name_counts_as_current(self):
        # podman lists the index digest and the platform digest.
        listed = f"{self.NEWER}\n{self.CURRENT}"
        result, _ = self._check(listed=listed)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_matching_digest_under_another_name_does_not_count(self):
        other = "other/app@sha256:" + "a" * 64
        result, _ = self._check(listed=f"{other}\n{self.NEWER}")
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn(self.NEWER, result.stderr)

    def test_engines_format_their_digests_differently(self):
        # Built with one engine and checked with the other.
        podman_form = "docker.io/library/example@sha256:" + "a" * 64
        result, _ = self._check(listed=podman_form)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_recorded_pull_with_is_used(self):
        _, calls = self._check(build_args=["--pull-with", "podman"])
        self.assertEqual(self._pulls(calls),
                         ["podman pull docker.io/library/example:latest"])
        self.assertNotIn("docker ", calls.replace("docker.io", ""))

    def test_auto_detect_falls_back_to_podman(self):
        result, calls = self._check(engines=("podman",), path_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._pulls(calls),
                         ["podman pull docker.io/library/example:latest"])

    def test_no_engine_is_a_clear_error(self):
        result, _ = self._check(engines=(), path_only=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("needs docker or podman", result.stderr)

    def test_recorded_skopeo_is_refused_before_any_call(self):
        result, calls = self._check(build_args=["--pull-with", "skopeo"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("not 'skopeo'", result.stderr)
        self.assertEqual(calls, "")

    def test_offline_only_is_refused_before_any_call(self):
        result, calls = self._check(build_args=["--offline-only"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("--offline-only", result.stderr)
        self.assertEqual(calls, "")

    def test_older_offline_binary_is_refused_before_any_call(self):
        result, calls = self._check(hermetic=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--offline-only", result.stderr)
        self.assertEqual(calls, "")

    def test_malformed_build_args_are_refused_before_any_call(self):
        result, calls = self._check(build_args=["--not-an-option"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("malformed build_args", result.stderr)
        self.assertEqual(calls, "")

    def test_no_recorded_digest_is_refused_before_any_call(self):
        result, calls = self._check(digest=None,
                                    build_args=["--oci-dir", "/nonexistent"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("records no image digest", result.stderr)
        self.assertEqual(calls, "")

    def test_malformed_recorded_digest_is_refused_before_any_call(self):
        for digest in ("garbage", "example@", "@", 123, "x@*",
                       "sha256:" + "a" * 64):
            with self.subTest(digest=digest):
                result, calls = self._check(digest=digest)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("malformed image digest", result.stderr)
                self.assertEqual(calls, "")

    def test_malformed_engine_line_is_not_a_digest(self):
        result, _ = self._check(listed="example\nexample@")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("unable to compare", result.stderr)

    def test_failed_or_empty_inspect_is_not_a_result(self):
        for listed, rc in ((self.CURRENT, 1), (self.NEWER, 1), ("", 1), ("", 0)):
            with self.subTest(listed=listed, rc=rc):
                result, _ = self._check(listed=listed, inspect_rc=rc)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("unable to compare", result.stderr)

    def test_value_that_looks_like_an_option_is_not_one(self):
        # --label takes a value, so this is not an offline build.
        result, calls = self._check(build_args=["--label", "--offline-only"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._pulls(calls), ["docker pull example:latest"])

    def test_cross_arch_pull_keeps_the_target_arch(self):
        target, name = (("x86_64", "amd64")
                        if platform.machine() == "aarch64"
                        else ("aarch64", "arm64"))
        _, calls = self._check(build_args=["--arch", target])
        self.assertEqual(self._pulls(calls),
                         [f"docker pull --platform linux/{name} example:latest"])

    def test_unknown_arch_is_refused_before_any_call(self):
        result, calls = self._check(build_args=["--arch", "--evil"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported --arch", result.stderr)
        self.assertEqual(calls, "")


class PodPauseTest(unittest.TestCase):
    def test_tmpdir_is_not_evaluated_by_the_pause_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crafted = root / "tmp$(touch marker)"
            crafted.mkdir()
            member = root / "member"
            _executable(member, "#!/bin/sh\nexit 0\n")
            env = _hermetic_env(root)
            env["TMPDIR"] = str(crafted)

            result = subprocess.run(
                [str(OCI2BIN), "pod", "run", str(member)],
                cwd=root, capture_output=True, text=True, env=env, timeout=30)

            self.assertFalse((root / "marker").exists(), result.stderr)
            self.assertRegex(result.stderr, r"pause PID=\d+")


if __name__ == "__main__":
    unittest.main()
