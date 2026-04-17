import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
OCI2BIN = ROOT / "oci2bin"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_module("build_polyglot", ROOT / "scripts" / "build_polyglot.py")


def _minimal_oci_tar(labels=None, healthcheck=None):
    layer_raw = b"\x00" * 1024
    layer_sha = hashlib.sha256(layer_raw).hexdigest()
    layer_path = f"blobs/sha256/{layer_sha}"
    cfg = {"Cmd": ["/bin/sh"], "Labels": labels or {}}
    if healthcheck is not None:
        cfg["Healthcheck"] = healthcheck
    config = {
        "architecture": "amd64",
        "config": cfg,
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_sha}"]},
    }
    config_raw = json.dumps(config, separators=(",", ":")).encode()
    config_sha = hashlib.sha256(config_raw).hexdigest()
    config_path = f"blobs/sha256/{config_sha}"
    manifest = [{"Config": config_path, "RepoTags": ["test:latest"],
                 "Layers": [layer_path]}]
    manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, data in [
            ("manifest.json", manifest_raw),
            (config_path, config_raw),
            (layer_path, layer_raw),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestCliFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="oci2bin-cli-")
        cls.tmpdir = Path(cls._tmp.name)
        cls.loader = cls.tmpdir / "loader"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(cls.loader),
             str(ROOT / "src" / "loader.c")],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if build.returncode != 0:
            raise unittest.SkipTest(f"failed to build loader: {build.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _build_binary(self, name, *, labels=None, healthcheck=None,
                      self_update_url=None, pin_digest=None):
        tar_path = self.tmpdir / f"{name}.tar"
        tar_path.parent.mkdir(parents=True, exist_ok=True)
        tar_path.write_bytes(_minimal_oci_tar(labels=labels,
                                              healthcheck=healthcheck))
        out_path = self.tmpdir / name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        args = [
            "python3", str(ROOT / "scripts" / "build_polyglot.py"),
            "--loader", str(self.loader),
            "--tar", str(tar_path),
            "--image-name", "test:latest",
            "--output", str(out_path),
        ]
        if self_update_url:
            args.extend(["--self-update-url", self_update_url])
        if pin_digest:
            args.extend(["--pin-digest", pin_digest])
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(os.access(out_path, os.X_OK))
        return out_path

    def test_systemd_emits_unit_with_label_name(self):
        binary = self._build_binary(
            "svc.bin",
            labels={"oci2bin.name": "vaultwarden"},
        )
        result = subprocess.run(
            [str(OCI2BIN), "systemd", str(binary), "--restart", "always"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ExecStart=", result.stdout)
        self.assertIn("Restart=always", result.stdout)
        self.assertIn("Description=oci2bin test:latest", result.stdout)

    def test_healthcheck_none_short_circuits(self):
        binary = self._build_binary(
            "health-none.bin",
            healthcheck={"Test": ["NONE"]},
        )
        result = subprocess.run(
            [str(OCI2BIN), "healthcheck", str(binary)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("HEALTHCHECK NONE", result.stderr)

    def test_sign_file_and_verify_file_roundtrip(self):
        payload = self.tmpdir / "manifest.json"
        payload.write_text('{"version":"1.2.3"}', encoding="utf-8")
        key = self.tmpdir / "signing.key"
        pub = self.tmpdir / "signing.pub"
        sig = self.tmpdir / "manifest.sig"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(key)],
            check=True, capture_output=True, timeout=30,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub)],
            check=True, capture_output=True, timeout=30,
        )
        sign = subprocess.run(
            [str(OCI2BIN), "sign-file", "--key", str(key), "--in",
             str(payload), "--out", str(sig), "--hash-algorithm", "sha512"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(sign.returncode, 0, msg=sign.stderr)
        verify = subprocess.run(
            [str(OCI2BIN), "verify-file", "--key", str(pub), "--in",
             str(payload), "--sig", str(sig)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(verify.returncode, 0, msg=verify.stderr)

    def test_top_once_lists_named_process(self):
        home = self.tmpdir / "home-top"
        ctr_dir = home / ".cache" / "oci2bin" / "containers"
        ctr_dir.mkdir(parents=True, exist_ok=True)
        state = ctr_dir / "demo.json"
        state.write_text(json.dumps({
            "name": "demo",
            "pid": os.getpid(),
            "binary": str(self.loader),
            "started_at": "2026-04-17T12:00:00Z",
        }), encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(home)
        result = subprocess.run(
            [str(OCI2BIN), "top", "--once"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("NAME", result.stdout)
        self.assertIn("demo", result.stdout)

    def test_ps_rejects_symlinked_home_state_path(self):
        real_home = self.tmpdir / "home-real"
        real_home.mkdir(parents=True, exist_ok=True)
        home_link = self.tmpdir / "home-link"
        home_link.symlink_to(real_home, target_is_directory=True)
        env = os.environ.copy()
        env["HOME"] = str(home_link)
        result = subprocess.run(
            [str(OCI2BIN), "ps"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("state path contains symlink component", result.stderr)

    def test_stop_refuses_mismatched_process_identity(self):
        home = self.tmpdir / "home-stop"
        ctr_dir = home / ".cache" / "oci2bin" / "containers"
        ctr_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(["sleep", "60"])
        try:
            state = ctr_dir / "demo.json"
            state.write_text(json.dumps({
                "name": "demo",
                "pid": proc.pid,
                "binary": str(self.loader),
                "started_at": "2026-04-17T12:00:00Z",
                "start_ticks": 1,
            }), encoding="utf-8")
            env = os.environ.copy()
            env["HOME"] = str(home)
            result = subprocess.run(
                [str(OCI2BIN), "stop", "demo"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to signal", result.stderr)
            self.assertIsNone(proc.poll())
            self.assertFalse(state.exists())
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    def test_check_update_uses_signed_manifest(self):
        key = self.tmpdir / "update.key"
        pub = self.tmpdir / "update.pub"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(key)],
            check=True, capture_output=True, timeout=30,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub)],
            check=True, capture_output=True, timeout=30,
        )

        new_binary = self._build_binary("new.bin")
        manifest = self.tmpdir / "update.json"
        manifest.write_text(json.dumps({
            "version": "9.9.9",
            "url": new_binary.resolve().as_uri(),
            "digest": "sha512:" + hashlib.sha512(
                new_binary.read_bytes()
            ).hexdigest(),
        }), encoding="utf-8")
        subprocess.run(
            [str(OCI2BIN), "sign-file", "--key", str(key), "--in",
             str(manifest), "--out", str(manifest) + ".sig",
             "--hash-algorithm", "sha512"],
            check=True, capture_output=True, timeout=30,
        )

        install_root = self.tmpdir / "signed-install"
        scripts_dir = install_root / "scripts"
        bin_dir = install_root / "bin"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        (scripts_dir / "sign_binary.py").write_bytes(
            (ROOT / "scripts" / "sign_binary.py").read_bytes()
        )

        binary = self._build_binary(
            "signed-install/bin/current.bin",
            self_update_url=manifest.resolve().as_uri(),
            pin_digest="sha512:auto",
        )
        subprocess.run(
            [str(OCI2BIN), "sign", "--key", str(key), "--in", str(binary),
             "--hash-algorithm", "sha512"],
            check=True, capture_output=True, timeout=30,
        )
        result = subprocess.run(
            [str(binary), "--check-update", "--verify-key", str(pub)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 10, msg=result.stderr)
        self.assertIn("update available", result.stderr)


if __name__ == "__main__":
    unittest.main()
