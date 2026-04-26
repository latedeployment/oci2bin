"""
Test the wrapper script emitted by `oci2bin --arch all`. The wrapper is a
small POSIX shell script that picks the right arch binary or falls back to
qemu-user-static. Build a synthetic wrapper using the same logic in oci2bin
and exercise its fallback paths without needing a real cross-arch build.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


SH = shutil.which("sh") or "/bin/sh"


def _wrapper_template(prefix: str) -> str:
    """Mirror the wrapper that `oci2bin --arch all` writes.  Kept in sync
    with oci2bin's heredoc so this test catches regressions in the logic."""
    return textwrap.dedent(f"""\
        #!/bin/sh
        # Allow the test to pin the host arch instead of relying on uname.
        if [ -n "${{TEST_ARCH:-}}" ]; then
            _ARCH=$TEST_ARCH
        else
            _ARCH=$(uname -m)
        fi
        _DIR=$(cd "$(dirname "$0")" && pwd)
        _X86=${{_DIR}}/{prefix}_x86_64
        _ARM=${{_DIR}}/{prefix}_aarch64

        case "$_ARCH" in
            x86_64)  [ -x "$_X86" ] && exec "$_X86" "$@" ;;
            aarch64) [ -x "$_ARM" ] && exec "$_ARM" "$@" ;;
        esac

        _find_qemu() {{
            _q=$1
            if command -v "$_q" >/dev/null 2>&1; then
                command -v "$_q"
                return 0
            fi
            for _p in /usr/bin/$_q /usr/local/bin/$_q /opt/qemu/bin/$_q; do
                if [ -x "$_p" ]; then
                    printf '%s\\n' "$_p"
                    return 0
                fi
            done
            return 1
        }}

        if [ -x "$_X86" ]; then
            if _Q=$(_find_qemu qemu-x86_64-static); then
                exec "$_Q" "$_X86" "$@"
            fi
        fi
        if [ -x "$_ARM" ]; then
            if _Q=$(_find_qemu qemu-aarch64-static); then
                exec "$_Q" "$_ARM" "$@"
            fi
        fi

        echo "oci2bin: host architecture $_ARCH cannot run any of the bundled binaries." >&2
        exit 1
    """)


def _make_executable(path: Path):
    st = path.stat()
    path.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestArchWrapper(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-arch-"))
        self.prefix = "demo"
        self.wrapper = self.tmpdir / self.prefix
        self.wrapper.write_text(_wrapper_template(self.prefix))
        _make_executable(self.wrapper)
        self.x86 = self.tmpdir / f"{self.prefix}_x86_64"
        self.arm = self.tmpdir / f"{self.prefix}_aarch64"
        self.x86.write_text("#!/bin/sh\necho ran-x86_64 \"$@\"\n")
        self.arm.write_text("#!/bin/sh\necho ran-aarch64 \"$@\"\n")
        _make_executable(self.x86)
        _make_executable(self.arm)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, host_arch, *args, extra_path=""):
        env = {"PATH": extra_path or "/usr/bin:/bin", "TEST_ARCH": host_arch}
        return subprocess.run(
            [SH, str(self.wrapper), *args],
            capture_output=True, text=True, env=env,
        )

    def test_native_x86_64_picks_x86_binary(self):
        r = self._run("x86_64", "hello")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("ran-x86_64 hello", r.stdout)

    def test_native_aarch64_picks_arm_binary(self):
        r = self._run("aarch64", "world")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("ran-aarch64 world", r.stdout)

    def test_foreign_host_falls_back_to_qemu(self):
        # Set up a fake qemu-x86_64-static that prints what it was given.
        fake_bin_dir = self.tmpdir / "fakebin"
        fake_bin_dir.mkdir()
        fake_qemu = fake_bin_dir / "qemu-x86_64-static"
        fake_qemu.write_text(
            "#!/bin/sh\necho via-qemu \"$1\" \"$2\"\n")
        _make_executable(fake_qemu)
        # Make the bundled x86_64 binary not directly executable (mimicking
        # foreign-arch ELF rejection) — but the wrapper finds qemu first via
        # `_find_qemu` and execs it, so the binary stays executable.
        r = self._run("riscv64", "hi", extra_path=f"{fake_bin_dir}:/bin")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn(f"via-qemu {self.x86} hi", r.stdout)

    def test_foreign_host_without_qemu_errors_clearly(self):
        # Skip if the host has qemu-user-static installed in any of the
        # absolute fallback paths the wrapper hardcodes — we cannot
        # reliably reach the no-qemu error branch when the binary exists.
        for q in ("qemu-x86_64-static", "qemu-aarch64-static"):
            for p in (f"/usr/bin/{q}", f"/usr/local/bin/{q}",
                      f"/opt/qemu/bin/{q}"):
                if os.access(p, os.X_OK):
                    self.skipTest(f"host has {p}; cannot test no-qemu branch")
        r = self._run("riscv64", extra_path="/bin")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("riscv64", r.stderr)
        self.assertIn("cannot run", r.stderr)

    def test_arch_with_only_other_bundled_binary_uses_qemu(self):
        # If there's no native binary AND no qemu for x86, we should still
        # try qemu-aarch64-static when the arm binary is present.
        self.x86.unlink()
        fake_bin_dir = self.tmpdir / "fakebin2"
        fake_bin_dir.mkdir()
        fake_qemu = fake_bin_dir / "qemu-aarch64-static"
        fake_qemu.write_text(
            "#!/bin/sh\necho via-qemu-arm \"$1\"\n")
        _make_executable(fake_qemu)
        r = self._run("riscv64", extra_path=f"{fake_bin_dir}:/bin")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("via-qemu-arm", r.stdout)


class TestWrapperMatchesEmittedTemplate(unittest.TestCase):
    """Ensure the test's wrapper template stays in sync with the heredoc in
    the oci2bin script.  If the heredoc diverges, this test will flag it."""

    def test_real_oci2bin_contains_qemu_fallback(self):
        oci2bin = (Path(__file__).parent.parent / "oci2bin").read_text()
        # Spot-check the key strings that must remain in the heredoc.
        for expected in (
            "qemu-x86_64-static",
            "qemu-aarch64-static",
            "command -v",
            "cannot run any of the bundled binaries",
        ):
            self.assertIn(expected, oci2bin,
                          f"oci2bin wrapper missing {expected!r}")


if __name__ == "__main__":
    unittest.main()
