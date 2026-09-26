"""scripts/check_packaging.py: the tree checks on fabricated stages, and the
real staged install on this checkout."""

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_packaging", ROOT / "scripts" / "check_packaging.py")
cp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cp)


def _fake_stage(destdir, prefix="/usr", scripts=("a.py", "b.py"),
                arch="x86_64", wrapper_text=None):
    """A staged tree with everything expected_layout() asks for."""
    root = pathlib.Path(destdir) / prefix.lstrip("/")
    (root / "bin").mkdir(parents=True)
    wrapper = root / "bin" / "oci2bin"
    wrapper.write_text(wrapper_text if wrapper_text is not None else
                       f'OCI2BIN_HOME="${{OCI2BIN_HOME:-{prefix}/share/'
                       f'oci2bin}}"\n')
    wrapper.chmod(0o755)
    (root / "bin" / "oci2vm").symlink_to("oci2bin")
    share = root / "share" / "oci2bin"
    (share / "src").mkdir(parents=True)
    (share / "src" / "loader.c").write_text("int main(void){return 0;}\n")
    (share / "build").mkdir()
    loader = share / "build" / f"loader-{arch}"
    loader.write_bytes(b"\x7fELF")
    loader.chmod(0o755)
    (share / "scripts").mkdir()
    for name in scripts:
        (share / "scripts" / name).write_text("print('ok')\n")
    (root / "share" / "man" / "man1").mkdir(parents=True)
    (root / "share" / "man" / "man1" / "oci2bin.1").write_text(".TH x\n")
    return root


class CheckTreeTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="oci2bin-pkgtest-")
        self.destdir = pathlib.Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_complete_stage_has_no_problems(self):
        _fake_stage(self.destdir)
        self.assertEqual(
            cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"], "x86_64"),
            [])

    def test_missing_pieces_are_named(self):
        root = _fake_stage(self.destdir, scripts=("a.py",))
        (root / "share" / "man" / "man1" / "oci2bin.1").unlink()
        os.chmod(root / "share" / "oci2bin" / "build" / "loader-x86_64",
                 0o644)
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        joined = "\n".join(problems)
        self.assertIn("scripts/b.py: missing", joined)
        self.assertIn("oci2bin.1: missing", joined)
        self.assertIn("loader-x86_64: not executable", joined)
        self.assertEqual(len(problems), 3, problems)

    def test_oci2vm_must_be_a_relative_symlink_to_oci2bin(self):
        root = _fake_stage(self.destdir)
        (root / "bin" / "oci2vm").unlink()
        shutil.copy(root / "bin" / "oci2bin", root / "bin" / "oci2vm")
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        self.assertEqual(problems, ["usr/bin/oci2vm: expected a symlink"])
        (root / "bin" / "oci2vm").unlink()
        (root / "bin" / "oci2vm").symlink_to(str(root / "bin" / "oci2bin"))
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        self.assertTrue(any("not 'oci2bin'" in p for p in problems), problems)
        self.assertTrue(any("escapes the staged tree" in p for p in problems),
                        problems)

    def test_symlink_escaping_the_stage_is_reported(self):
        root = _fake_stage(self.destdir)
        (root / "share" / "oci2bin" / "scripts" / "a.py").unlink()
        (root / "share" / "oci2bin" / "scripts" / "a.py").symlink_to(
            "../../../../../../../../etc/hostname")
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        self.assertTrue(any("scripts/a.py: symlink escapes" in p
                            for p in problems), problems)

    def test_wrapper_must_point_at_the_prefix(self):
        _fake_stage(self.destdir,
                    wrapper_text='OCI2BIN_HOME="${OCI2BIN_HOME:-$SCRIPT_DIR}"\n')
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(any("not /usr/share/oci2bin" in p for p in problems))
        self.assertTrue(any("script directory" in p for p in problems))

    def test_helper_that_does_not_compile_is_reported(self):
        root = _fake_stage(self.destdir)
        (root / "share" / "oci2bin" / "scripts" / "b.py").write_text(
            "def (broken\n")
        problems = cp.check_tree(self.destdir, "/usr", ["a.py", "b.py"],
                                 "x86_64")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("scripts/b.py: does not compile", problems[0])

    def test_manifest_is_the_source_of_the_script_list(self):
        names = cp._manifest_scripts()
        self.assertIn("build_polyglot.py", names)
        self.assertIn("doctor.py", names)
        for name in names:
            self.assertTrue((ROOT / "scripts" / name).is_file(), name)


@unittest.skipUnless(shutil.which("make") and shutil.which("gcc"),
                     "make and gcc needed to stage an install")
class RealStageTest(unittest.TestCase):
    """The real thing: stage this checkout and run what was installed."""

    def test_staged_install_passes(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_packaging.py")],
            capture_output=True, text=True, timeout=900,
            env=dict(os.environ, HOME=tempfile.mkdtemp(prefix="pkg-home-")))
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        self.assertIn("check-packaging: OK", r.stdout)
        self.assertIn("oci2vm --help", r.stdout)

    def test_make_target_exists(self):
        r = subprocess.run(["make", "-n", "-C", str(ROOT), "check-packaging"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("check_packaging.py", r.stdout)


if __name__ == "__main__":
    unittest.main()
