import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
OCI2BIN = ROOT / "oci2bin"
BASH = shutil.which("bash") or "/bin/bash"


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


def _userns_available():
    """Can this user create a user + mount namespace (rootless runtime)?"""
    try:
        result = subprocess.run(
            ["unshare", "-Urm", "true"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


_WRITER_SRC = r"""
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void)
{
    int fd = open("/leak.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { if (write(fd, "leak\n", 5) < 0) { return 3; } close(fd); }
    printf("writer ran leak_fd=%d\n", fd);
    return fd >= 0 ? 0 : 2;
}
"""


_TRAP_SRC = r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char** argv)
{
    /* Ignore SIGTERM so only SIGKILL ends us; exit code from argv[1]. */
    signal(SIGTERM, SIG_IGN);
    printf("trap ran\n");
    fflush(stdout);
    if (argc > 1) { return atoi(argv[1]); }
    for (;;) { sleep(1); }
}
"""


def _program_oci_tar(program_bytes):
    """A one-layer image whose /bin/sh is a static program."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w:") as tf:
        for name in ("bin", "etc"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(info)
        info = tarfile.TarInfo("bin/sh")
        info.size = len(program_bytes)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(program_bytes))
        info = tarfile.TarInfo("bin/sh-link")
        info.type = tarfile.SYMTYPE
        info.linkname = "sh"
        tf.addfile(info)
        marker = b"cached-image\n"
        info = tarfile.TarInfo("etc/marker")
        info.size = len(marker)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(marker))
    layer_raw = layer.getvalue()
    layer_sha = hashlib.sha256(layer_raw).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Cmd": ["/bin/sh"], "Env": ["PATH=/bin"]},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_sha}"]},
    }
    config_raw = json.dumps(config, separators=(",", ":")).encode()
    config_sha = hashlib.sha256(config_raw).hexdigest()
    manifest = [{"Config": f"blobs/sha256/{config_sha}",
                 "RepoTags": ["cache-test:latest"],
                 "Layers": [f"blobs/sha256/{layer_sha}"]}]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, data in [
            ("manifest.json", json.dumps(manifest).encode()),
            (f"blobs/sha256/{config_sha}", config_raw),
            (f"blobs/sha256/{layer_sha}", layer_raw),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue(), config_raw


def _proc_start_ticks(pid):
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").strip()
    rparen = raw.rfind(")")
    fields = raw[rparen + 2:].split()
    return int(fields[19])


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

    def _fake_tool_path(self, tool_dir):
        tool_dir.mkdir(parents=True, exist_ok=True)
        for tool in ("python3", "readlink", "dirname", "basename", "mkdir"):
            tool_path = shutil.which(tool)
            self.assertIsNotNone(tool_path)
            tool_link = tool_dir / tool
            if not tool_link.exists():
                tool_link.symlink_to(tool_path)
        return str(tool_dir)

    def _build_writer_binary(self, name):
        """Polyglot whose workload writes /leak.txt; returns (path, config)."""
        writer_src = self.tmpdir / "writer.c"
        writer_src.write_text(_WRITER_SRC, encoding="utf-8")
        writer = self.tmpdir / "writer"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(writer),
             str(writer_src)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        tar_bytes, config_raw = _program_oci_tar(writer.read_bytes())
        tar_path = self.tmpdir / f"{name}.tar"
        tar_path.write_bytes(tar_bytes)
        out_path = self.tmpdir / name
        result = subprocess.run(
            ["python3", str(ROOT / "scripts" / "build_polyglot.py"),
             "--loader", str(self.loader), "--tar", str(tar_path),
             "--image-name", "cache-test:latest", "--output", str(out_path)],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return out_path, config_raw

    def _run_cached(self, binary, xdg, tmp, *extra, env_extra=None):
        env = dict(os.environ, XDG_CACHE_HOME=str(xdg),
                   OCI2BIN_TMPDIR=str(tmp), TMPDIR=str(tmp))
        env.pop("OCI2BIN_ROOTFS_CACHE", None)
        env.pop("OCI2BIN_ROOTFS_LAYER", None)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [str(binary), "--debug", "--net", "none", *extra],
            capture_output=True, text=True, timeout=120, env=env)

    def test_rootfs_cache_reuses_extraction_and_isolates_writes(self):
        if not _userns_available():
            self.skipTest("user namespaces unavailable; cannot run binaries")
        binary, config_raw = self._build_writer_binary("cached.bin")
        xdg = self.tmpdir / "xdg-cache"
        tmp = self.tmpdir / "runtime-tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        expected_key = hashlib.sha256(
            b"oci2bin-rootfs-cache-v1\n" + config_raw).hexdigest()
        entry = xdg / "oci2bin" / "rootfs" / expected_key

        first = self._run_cached(binary, xdg, tmp)
        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertIn("writer ran leak_fd=", first.stdout)
        self.assertIn("event=cache.miss", first.stderr)
        self.assertIn("event=extract.done", first.stderr)
        self.assertIn("event=cache.stored", first.stderr)
        self.assertIn(f"key={expected_key}", first.stderr)
        self.assertTrue((entry / "meta").is_file(), "entry published")
        self.assertTrue((entry / "rootfs" / "etc" / "marker").is_file())

        second = self._run_cached(binary, xdg, tmp)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertIn("event=cache.hit", second.stderr)
        self.assertNotIn("event=extract.begin", second.stderr)
        self.assertNotIn("event=extract.done", second.stderr)
        self.assertIn("event=rootfs.layer kind=", second.stderr)

        # The workload wrote /leak.txt on both runs; the shared tree must
        # not have it, and the run's tmpdir must be gone.
        self.assertFalse((entry / "rootfs" / "leak.txt").exists(),
                         "workload write leaked into the cached tree")
        self.assertEqual([p for p in tmp.iterdir()
                          if p.name.startswith("oci2bin.")], [])

        # The copy fallback isolates writes just the same.
        copied = self._run_cached(binary, xdg, tmp,
                                  env_extra={"OCI2BIN_ROOTFS_LAYER": "copy"})
        self.assertEqual(copied.returncode, 0, msg=copied.stderr)
        self.assertIn("event=rootfs.layer kind=copy", copied.stderr)
        self.assertFalse((entry / "rootfs" / "leak.txt").exists())

        # A corrupted entry is detected and rebuilt, never trusted.
        marker = entry / "rootfs" / "etc" / "marker"
        marker.write_bytes(b"tampered\n")
        third = self._run_cached(binary, xdg, tmp)
        self.assertEqual(third.returncode, 0, msg=third.stderr)
        self.assertIn("result=fingerprint-mismatch", third.stderr)
        self.assertIn("event=cache.corrupt", third.stderr)
        self.assertIn("event=cache.stored", third.stderr)
        self.assertEqual(marker.read_bytes(), b"cached-image\n")

        # Opting out extracts per run and leaves the cache alone.
        before = (entry / "meta").stat().st_mtime_ns
        off = self._run_cached(binary, xdg, tmp, "--rootfs-cache", "off")
        self.assertEqual(off.returncode, 0, msg=off.stderr)
        self.assertIn("event=cache.disabled reason=mode-off", off.stderr)
        self.assertIn("event=extract.done", off.stderr)
        self.assertEqual((entry / "meta").stat().st_mtime_ns, before)

        # prune sees the entry and evicts it on request.
        prune = subprocess.run(
            ["bash", str(OCI2BIN), "prune", "--all"],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, XDG_CACHE_HOME=str(xdg),
                     HOME=str(self.tmpdir / "prune-home")))
        self.assertEqual(prune.returncode, 0, msg=prune.stderr)
        self.assertIn("1 rootfs cache entry removed", prune.stdout)
        self.assertFalse(entry.exists())

    def test_stop_timeout_escalates_and_restart_policy_counts(self):
        """--stop-timeout SIGKILLs a workload that ignores SIGTERM, and
        --restart on-failure:N relaunches exactly N times."""
        if not _userns_available():
            self.skipTest("user namespaces unavailable; cannot run binaries")
        trap_src = self.tmpdir / "trap.c"
        trap_src.write_text(_TRAP_SRC, encoding="utf-8")
        trap = self.tmpdir / "trap"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(trap), str(trap_src)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        tar_bytes, _config = _program_oci_tar(trap.read_bytes())
        tar_path = self.tmpdir / "trap.tar"
        tar_path.write_bytes(tar_bytes)
        binary = self.tmpdir / "trap.bin"
        result = subprocess.run(
            ["python3", str(ROOT / "scripts" / "build_polyglot.py"),
             "--loader", str(self.loader), "--tar", str(tar_path),
             "--image-name", "trap:latest", "--output", str(binary)],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        xdg = self.tmpdir / "xdg-trap"
        tmp = self.tmpdir / "runtime-trap"
        tmp.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, XDG_CACHE_HOME=str(xdg),
                   OCI2BIN_TMPDIR=str(tmp), TMPDIR=str(tmp))

        # Stop escalation: SIGTERM to the loader is forwarded, ignored by
        # the workload, and followed by SIGKILL after one second.
        proc = subprocess.Popen(
            [str(binary), "--net", "none", "--stop-timeout", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env)
        line = proc.stdout.readline()
        self.assertEqual(line.strip(), "trap ran")
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        try:
            _out, err = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("loader did not exit after --stop-timeout")
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 137, msg=err)
        self.assertIn("sending SIGKILL", err)
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 8.0)

        # Restart policy: three runs for on-failure:2, last exit code kept.
        started = time.monotonic()
        run = subprocess.run(
            [str(binary), "--net", "none", "--restart", "on-failure:2",
             "--", "/bin/sh", "4"],
            capture_output=True, text=True, timeout=60, env=env)
        elapsed = time.monotonic() - started
        self.assertEqual(run.returncode, 4, msg=run.stderr)
        self.assertEqual(run.stdout.count("trap ran"), 3)
        self.assertEqual(run.stderr.count("restarting container"), 2)
        self.assertGreaterEqual(elapsed, 2.0)

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

    def test_systemd_without_user_env(self):
        # cron, CI and `env -i` run without $USER; set -u used to abort.
        binary = self._build_binary("svc-nouser.bin")
        env = {k: v for k, v in os.environ.items() if k != "USER"}
        result = subprocess.run(
            [str(OCI2BIN), "systemd", str(binary)],
            capture_output=True, text=True, timeout=30, env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ExecStart=", result.stdout)

    def test_unknown_option_before_image_is_rejected(self):
        result = subprocess.run(
            [str(OCI2BIN), "--no-such-option", "alpine:latest"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown option: --no-such-option", result.stderr)

    def test_option_after_image_is_not_taken_as_output(self):
        result = subprocess.run(
            [str(OCI2BIN), "--oci-dir", "/nonexistent-oci2bin", "img",
             "--bogus"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected argument: --bogus", result.stderr)

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

    def test_run_forwards_new_build_options(self):
        missing_oci = self.tmpdir / "missing-oci-layout"
        result = subprocess.run(
            [str(OCI2BIN), "run",
             "--pull-with", "skopeo",
             "--reproducible",
             "--rootfs-format", "tar",
             "--oci-dir", str(missing_oci),
             "alpine:latest", "--", "/bin/true"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("unknown build option before IMAGE", result.stderr)
        self.assertIn("--oci-dir: directory not found", result.stderr)

    def test_layer_compression_requires_squash(self):
        result = subprocess.run(
            [str(OCI2BIN), "--compress", "gzip", "alpine:latest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--compress requires --squash", result.stderr)

    def test_squashfs_rootfs_rejects_encryption_before_build(self):
        result = subprocess.run(
            [str(OCI2BIN), "--rootfs-format", "squashfs",
             "--encrypt", "--recipient", "age1example",
             "alpine:latest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be combined with age encryption", result.stderr)
        self.assertIn("would expose the plaintext image", result.stderr)

    def test_rootfs_format_rejects_unknown_value(self):
        result = subprocess.run(
            [str(OCI2BIN), "--rootfs-format", "ext4", "alpine:latest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported format 'ext4'", result.stderr)

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

    def test_stop_uses_supervisor_identity_and_stops_container_pid(self):
        home = self.tmpdir / "home-stop-supervisor"
        ctr_dir = home / ".cache" / "oci2bin" / "containers"
        ctr_dir.mkdir(parents=True, exist_ok=True)
        supervisor = subprocess.Popen(["sleep", "60"])
        container = subprocess.Popen(["sleep", "60"])
        try:
            state = ctr_dir / "demo.json"
            state.write_text(json.dumps({
                "name": "demo",
                "pid": container.pid,
                "binary": os.readlink(f"/proc/{supervisor.pid}/exe"),
                "started_at": "2026-04-17T12:00:00Z",
                "start_ticks": _proc_start_ticks(container.pid),
                "supervisor_pid": supervisor.pid,
                "supervisor_start_ticks": _proc_start_ticks(supervisor.pid),
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
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            supervisor.wait(timeout=5)
            container.wait(timeout=5)
            self.assertFalse(state.exists())
        finally:
            for proc in (supervisor, container):
                if proc.poll() is None:
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
        verifier_script = scripts_dir / "sign_binary.py"
        verifier_script.write_bytes(
            (ROOT / "scripts" / "sign_binary.py").read_bytes()
        )
        # The loader refuses to exec a group/world-writable verifier helper
        # (loader.c). `make install` stages it 0644; mirror that here so the
        # test does not depend on the runner's umask (e.g. 0002 on Debian).
        verifier_script.chmod(0o644)

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

    def test_checkpoint_requires_criu_when_missing(self):
        env = os.environ.copy()
        env["HOME"] = str(self.tmpdir / "home-no-criu")
        env["PATH"] = self._fake_tool_path(self.tmpdir / "tools-no-criu")
        result = subprocess.run(
            [BASH, str(OCI2BIN), "checkpoint", "demo"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("criu", result.stderr)
        self.assertIn("not found in PATH", result.stderr)

    def test_checkpoint_and_restore_invoke_criu(self):
        home = self.tmpdir / "home-criu"
        ctr_dir = home / ".cache" / "oci2bin" / "containers"
        ctr_dir.mkdir(parents=True, exist_ok=True)

        with open(f"/proc/{os.getpid()}/stat", encoding="utf-8") as f:
            raw = f.read().strip()
        rparen = raw.rfind(")")
        start_ticks = raw[rparen + 2:].split()[19]

        state = ctr_dir / "demo.json"
        state.write_text(json.dumps({
            "name": "demo",
            "pid": os.getpid(),
            "binary": os.readlink("/proc/self/exe"),
            "started_at": "2026-04-18T12:00:00Z",
            "start_ticks": int(start_ticks),
        }), encoding="utf-8")

        tool_dir = Path(self._fake_tool_path(self.tmpdir / "tools-criu"))
        criu_log = self.tmpdir / "criu.log"
        criu = tool_dir / "criu"
        criu.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> {shlex.quote(str(criu_log))}\n",
            encoding="utf-8",
        )
        criu.chmod(0o755)

        env = os.environ.copy()
        env["HOME"] = str(home)
        env["PATH"] = str(tool_dir)

        checkpoint = subprocess.run(
            [BASH, str(OCI2BIN), "checkpoint", "demo"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(checkpoint.returncode, 0, msg=checkpoint.stderr)

        checkpoint_dir = home / ".local" / "share" / "oci2bin" / "checkpoints" / "demo"
        self.assertTrue(checkpoint_dir.is_dir())

        restore = subprocess.run(
            [BASH, str(OCI2BIN), "restore", "demo"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(restore.returncode, 0, msg=restore.stderr)

        logged = criu_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            logged[0],
            f"dump --tree {os.getpid()} --images-dir {checkpoint_dir}",
        )
        self.assertEqual(
            logged[1],
            f"restore --images-dir {checkpoint_dir} --shell-job",
        )


if __name__ == "__main__":
    unittest.main()
