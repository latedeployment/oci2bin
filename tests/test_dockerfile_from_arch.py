import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build",
    ROOT / "scripts" / "dockerfile_build.py",
)
MOD = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MOD)


class DockerfileFromArchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oci2bin-from-arch-")
        self.root = pathlib.Path(self.tmp.name)
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir()
        self.state = MOD._State(
            context_dir=str(self.root),
            build_args={},
            build_secrets={},
            arch="arm64",
        )
        self.state.rootfs = str(self.rootfs)

    def tearDown(self):
        self.tmp.cleanup()

    def test_docker_pull_uses_target_platform(self):
        calls = []

        def fake_run(argv, check):
            self.assertTrue(check)
            calls.append(argv)
            if argv[:2] == ["docker", "save"]:
                pathlib.Path(argv[3]).write_bytes(b"")

        with mock.patch.object(MOD.shutil, "which",
                               side_effect=lambda name:
                               "/usr/bin/docker" if name == "docker"
                               else None), \
                mock.patch.object(MOD.subprocess, "run",
                                  side_effect=fake_run), \
                mock.patch.object(MOD, "_extract_docker_save_to_rootfs",
                                  return_value={}):
            MOD._do_from(self.state, "alpine:latest", str(self.root))

        self.assertIn(
            ["docker", "pull", "--platform", "linux/arm64",
             "alpine:latest"],
            calls,
        )

    def test_skopeo_copy_uses_target_platform(self):
        calls = []

        def fake_run(argv, check):
            self.assertTrue(check)
            calls.append(argv)

        def fake_which(name):
            return "/usr/bin/skopeo" if name == "skopeo" else None

        with mock.patch.object(MOD.shutil, "which",
                               side_effect=fake_which), \
                mock.patch.object(MOD.subprocess, "run",
                                  side_effect=fake_run), \
                mock.patch.object(MOD, "_extract_oci_to_rootfs",
                                  return_value={}):
            MOD._do_from(self.state, "alpine:latest", str(self.root))

        self.assertEqual(calls[0][:6], [
            "skopeo", "copy",
            "--override-os", "linux",
            "--override-arch", "arm64",
        ])
        self.assertEqual(calls[0][6:], [
            "docker://alpine:latest",
            mock.ANY,
        ])


if __name__ == "__main__":
    unittest.main()
