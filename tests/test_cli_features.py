import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import struct
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


_NETPROBE_SRC = r"""
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int try_bind(int type)
{
    int s = socket(AF_INET, type, 0);
    if (s < 0) { return errno; }
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int e = bind(s, (struct sockaddr*)&a, sizeof a) < 0 ? errno : 0;
    close(s); return e;
}
static int try_connect(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { return errno; }
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(9);
    int e = connect(s, (struct sockaddr*)&a, sizeof a) < 0 ? errno : 0;
    close(s); return e;
}
int main(void)
{
    printf("tcp_bind=%d tcp_connect=%d udp_bind=%d\n",
           try_bind(SOCK_STREAM), try_connect(), try_bind(SOCK_DGRAM));
    return 0;
}
"""


def _landlock_abi():
    """The running kernel's Landlock ABI, or -1."""
    import ctypes
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.syscall(444, None, 0, 1)   # landlock_create_ruleset
    except (OSError, AttributeError):
        return -1


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
        return self._build_program_binary(name, _WRITER_SRC)

    def _build_program_binary(self, name, source):
        """Polyglot whose /bin/sh is the static C program `source`;
        returns (path, config)."""
        prog_src = self.tmpdir / f"{name}.c"
        prog_src.write_text(source, encoding="utf-8")
        prog = self.tmpdir / f"{name}.prog"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(prog),
             str(prog_src)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        tar_bytes, config_raw = _program_oci_tar(prog.read_bytes())
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

    def test_signed_and_pinned_binary_verifies_natively(self):
        """--require-signed + --pin-digest are checked in-process.

        The launch must succeed with the native events in --debug output and
        refuse a tampered copy; python3/openssl are only used here to build
        and sign the artifact.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl needed to sign the test binary")
        if not _userns_available():
            self.skipTest("user namespaces unavailable; cannot run binaries")
        key = self.tmpdir / "native-sign.key"
        pub = self.tmpdir / "native-sign.pub"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(key)],
            check=True, capture_output=True, timeout=30)
        subprocess.run(
            ["openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub)],
            check=True, capture_output=True, timeout=30)

        writer_src = self.tmpdir / "writer-native.c"
        writer_src.write_text(_WRITER_SRC, encoding="utf-8")
        writer = self.tmpdir / "writer-native"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(writer),
             str(writer_src)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        tar_bytes, _config = _program_oci_tar(writer.read_bytes())
        tar_path = self.tmpdir / "native-signed.tar"
        tar_path.write_bytes(tar_bytes)
        binary = self.tmpdir / "native-signed.bin"
        result = subprocess.run(
            ["python3", str(ROOT / "scripts" / "build_polyglot.py"),
             "--loader", str(self.loader), "--tar", str(tar_path),
             "--image-name", "native:latest", "--output", str(binary),
             "--pin-digest", "sha512:auto", "--require-signed", str(pub)],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sign = subprocess.run(
            [str(OCI2BIN), "sign", "--key", str(key), "--in", str(binary)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(sign.returncode, 0, msg=sign.stderr)

        xdg = self.tmpdir / "xdg-native"
        tmp = self.tmpdir / "runtime-native"
        tmp.mkdir(parents=True, exist_ok=True)
        run = self._run_cached(binary, xdg, tmp, "--verify-key", str(pub))
        self.assertEqual(run.returncode, 0, msg=run.stderr)
        self.assertIn("writer ran", run.stdout)
        self.assertIn("event=pin.native algo=sha512 result=ok", run.stderr)
        self.assertIn("event=require_signed.native result=1", run.stderr)
        self.assertIn("event=verify_key.native result=1", run.stderr)

        # Flip a byte inside the payload: pin and signature both fail, and
        # the pin is checked first.
        tampered = self.tmpdir / "native-tampered.bin"
        data = bytearray(binary.read_bytes())
        data[len(data) // 2] ^= 0x01
        tampered.write_bytes(bytes(data))
        tampered.chmod(0o755)
        bad = self._run_cached(tampered, xdg, tmp)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("pinned digest mismatch", bad.stderr)
        self.assertNotIn("writer ran", bad.stdout)

        # The wrong verify key is refused natively as well.
        other_pub = self.tmpdir / "other.pub"
        other_key = self.tmpdir / "other.key"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(other_key)],
            check=True, capture_output=True, timeout=30)
        subprocess.run(
            ["openssl", "ec", "-in", str(other_key), "-pubout", "-out",
             str(other_pub)],
            check=True, capture_output=True, timeout=30)
        wrong = self._run_cached(binary, xdg, tmp, "--verify-key",
                                 str(other_pub))
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("signature does not match", wrong.stderr)

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

    def test_net_deny_tcp_cuts_tcp_without_a_netns(self):
        """--net deny-tcp on a real binary: the workload keeps the host
        network namespace, yet TCP bind and connect fail with EACCES while
        a UDP bind still works.  Without the flag TCP works."""
        if not _userns_available():
            self.skipTest("user namespaces unavailable; cannot run binaries")
        if _landlock_abi() < 4:
            self.skipTest("kernel Landlock ABI < 4; no network rules")
        binary, _ = self._build_program_binary("netprobe.bin", _NETPROBE_SRC)
        env = dict(os.environ, XDG_CACHE_HOME=str(self.tmpdir / "xdg"),
                   OCI2BIN_TMPDIR=str(self.tmpdir), TMPDIR=str(self.tmpdir))

        def run(*args):
            return subprocess.run([str(binary), *args], capture_output=True,
                                  text=True, timeout=120, env=env)

        denied = run("--net", "deny-tcp")
        self.assertEqual(denied.returncode, 0, msg=denied.stderr)
        self.assertIn("tcp_bind=13 tcp_connect=13 udp_bind=0", denied.stdout)

        plain = run("--net", "host")
        self.assertEqual(plain.returncode, 0, msg=plain.stderr)
        self.assertIn("tcp_bind=0 ", plain.stdout)
        self.assertIn(" udp_bind=0", plain.stdout)
        self.assertNotIn("tcp_connect=13", plain.stdout)

        # The mode is enforced by Landlock: refusing the sandbox refuses
        # the run, before anything starts.
        refused = run("--net", "deny-tcp", "--no-landlock")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("cannot be combined with --no-landlock", refused.stderr)
        self.assertEqual(refused.stdout, "")
        published = run("--net", "deny-tcp", "-p", "8080:80")
        self.assertNotEqual(published.returncode, 0)
        self.assertIn("-p cannot be combined with --net deny-tcp",
                      published.stderr)

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


def _write_oci_layout(dest, layer_files, cmd=("/bin/true",)):
    """A one-layer OCI image layout at `dest` (no engine needed to build)."""
    blobs = dest / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def put(data):
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return digest, len(data)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in layer_files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    layer = buf.getvalue()
    layer_digest, layer_size = put(layer)
    config = json.dumps({
        "architecture": "amd64", "os": "linux",
        "config": {"Cmd": list(cmd)},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + layer_digest]},
    }).encode()
    config_digest, config_size = put(config)
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": "sha256:" + config_digest, "size": config_size},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + layer_digest, "size": layer_size}],
    }).encode()
    manifest_digest, manifest_size = put(manifest)
    (dest / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": "sha256:" + manifest_digest,
                       "size": manifest_size,
                       "annotations": {"org.opencontainers.image.ref.name":
                                       "latest"}}]}))
    (dest / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')


class TestBuildArgsReplay(unittest.TestCase):
    """The wrapper records its build options and `update` replays them.

    Builds go through the real `oci2bin` CLI from a local OCI layout, so
    no container engine is needed; the loader compiled by TestCliFeatures
    is reused through a private OCI2BIN_HOME.
    """

    @classmethod
    def setUpClass(cls):
        if os.uname().machine != "x86_64":
            raise unittest.SkipTest("wrapper build test assumes x86_64")
        cls._tmp = tempfile.TemporaryDirectory(prefix="oci2bin-replay-")
        cls.tmpdir = Path(cls._tmp.name)
        # A stand-in install tree: the repo's scripts and sources, plus a
        # prebuilt loader so the wrapper does not compile one.
        cls.home = cls.tmpdir / "home"
        (cls.home / "build").mkdir(parents=True)
        for entry in ("scripts", "src", "VERSION"):
            if (ROOT / entry).exists():
                os.symlink(ROOT / entry, cls.home / entry)
        loader = cls.home / "build" / "loader-x86_64"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(loader),
             str(ROOT / "src" / "loader.c")],
            capture_output=True, text=True, timeout=300)
        if build.returncode != 0:
            raise unittest.SkipTest(f"failed to build loader: {build.stderr}")
        cls.layout = cls.tmpdir / "layout"
        _write_oci_layout(cls.layout, [("hello.txt", b"hello\n")])
        cls.env = dict(os.environ, OCI2BIN_HOME=str(cls.home),
                       XDG_CACHE_HOME=str(cls.tmpdir / "xdg"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _wrapper(self, *args, cwd=None):
        return subprocess.run([str(OCI2BIN), *args], capture_output=True,
                              text=True, timeout=300, env=self.env,
                              cwd=cwd or self.tmpdir)

    def _meta(self, binary):
        return _load_module("inspect_image",
                            ROOT / "scripts" / "inspect_image.py"
                            ).read_meta_block(str(binary)) or {}

    def test_build_records_options_and_update_replays_them(self):
        out = self.tmpdir / "app.bin"
        build = self._wrapper("--oci-dir", str(self.layout), "--no-libkrun",
                              "--label", "demo=one",
                              "--label", "spaced=a b",
                              "replay-test:latest", str(out))
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        recorded = self._meta(out).get("build_args")
        self.assertEqual(recorded, ["--arch", "x86_64",
                                    "--oci-dir", str(self.layout),
                                    "--no-libkrun",
                                    "--label", "demo=one",
                                    "--label", "spaced=a b"])
        for name in ("replay-test:latest", str(out)):
            self.assertNotIn(name, recorded)

        shown = self._wrapper("inspect", str(out))
        self.assertEqual(shown.returncode, 0, msg=shown.stderr)
        self.assertIn("Build args: --arch x86_64 --oci-dir", shown.stdout)
        self.assertIn("--label 'spaced=a b'", shown.stdout)
        as_json = self._wrapper("inspect", "--json", str(out))
        self.assertEqual(as_json.returncode, 0, msg=as_json.stderr)
        self.assertIn('"build_args"', as_json.stdout)

        # `update` rebuilds through the recorded list: the labels survive
        # and, since --oci-dir is part of it, no engine is consulted.
        before = self._meta(out)
        update = self._wrapper("update", str(out))
        self.assertEqual(update.returncode, 0, msg=update.stderr)
        self.assertIn("with the recorded options:", update.stderr)
        self.assertIn("--label 'spaced=a b'", shlex.join(recorded))
        after = self._meta(out)
        self.assertEqual(after.get("build_args"), before.get("build_args"))
        shown = self._wrapper("inspect", str(out))
        self.assertIn("demo=one", shown.stdout)
        self.assertIn("spaced=a b", shown.stdout)

    def test_update_says_when_no_options_were_recorded(self):
        """A binary from an older builder carries no build_args: update
        must say so and fall back to defaults rather than guess."""
        out = self.tmpdir / "legacy.bin"
        build = self._wrapper("--oci-dir", str(self.layout), "--no-libkrun",
                              "legacy-test:latest", str(out))
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        # Strip build_args from the metadata block in place (same length).
        blob = bytearray(out.read_bytes())
        magic = blob.rfind(b"OCI2BIN_META\x00")
        total = struct.unpack_from("<I", blob, magic - 4)[0]
        start, end = magic + 13, (magic - 4) + total
        raw = bytes(blob[start:end]).rstrip(b"\x00")
        meta = json.loads(raw)
        del meta["build_args"]
        rewritten = json.dumps(meta).encode().ljust(len(raw), b"\x00")
        blob[start:start + len(rewritten)] = rewritten
        out.write_bytes(blob)
        self.assertNotIn("build_args", self._meta(out))
        # The default rebuild needs a container engine for a bare image
        # name; with none in PATH the replay fails after the message.
        env = dict(self.env, PATH=str(self.tmpdir / "empty-bin")
                   + os.pathsep + os.path.dirname(shutil.which("python3"))
                   + os.pathsep + "/usr/bin:/bin")
        update = subprocess.run([str(OCI2BIN), "update", str(out)],
                                capture_output=True, text=True, timeout=300,
                                env=env, cwd=self.tmpdir)
        self.assertIn("no build options recorded", update.stderr)
        self.assertNotIn("with the recorded options", update.stderr)

    def test_update_refuses_a_record_that_is_not_options(self):
        """build_args is data from the binary: a token that could act as a
        positional (a different image or output) is refused outright."""
        out = self.tmpdir / "tampered.bin"
        build = self._wrapper("--oci-dir", str(self.layout), "--no-libkrun",
                              "tamper-test:latest", str(out))
        self.assertEqual(build.returncode, 0, msg=build.stderr)
        for bad in (["--strip", "evil:latest", "--squash"],
                    ["--", "x"],
                    ["evil:latest"],
                    ["--label"],
                    ["--not-a-build-option"]):
            blob = bytearray(out.read_bytes())
            magic = blob.rfind(b"OCI2BIN_META\x00")
            total = struct.unpack_from("<I", blob, magic - 4)[0]
            start, end = magic + 13, (magic - 4) + total
            raw = bytes(blob[start:end]).rstrip(b"\x00")
            meta = json.loads(raw)
            meta["build_args"] = bad
            rewritten = json.dumps(meta, separators=(",", ":")).encode()
            self.assertLessEqual(len(rewritten), len(raw) + 1)
            # The block is NUL padded; a shorter JSON is re-padded to size.
            blob[start:end] = rewritten.ljust(end - start, b"\x00")
            tampered = self.tmpdir / "tampered-copy.bin"
            tampered.write_bytes(blob)
            self.assertEqual(self._meta(tampered).get("build_args"), bad)
            update = self._wrapper("update", str(tampered))
            self.assertNotEqual(update.returncode, 0)
            self.assertIn("malformed build_args record", update.stderr)
            self.assertNotIn("rebuilding from", update.stderr)
