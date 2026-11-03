"""Behavioral regressions for the oci2bin update command."""

import importlib.util
import os
from pathlib import Path
import platform
import stat
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


if __name__ == "__main__":
    unittest.main()
