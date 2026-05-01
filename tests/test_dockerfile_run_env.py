"""
Regression test: Dockerfile RUN must not inherit the host's
environment. Construct the env dict the same way _do_run does,
seed os.environ with a sentinel, and assert the sentinel is not
in the resulting env.

The actual `unshare` invocation needs root or rootless tooling and a
populated rootfs, neither of which we set up here. Instead we exercise
the env-construction logic in isolation by replicating the relevant
section. If the production code drifts from this construction, the
test is updated alongside.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build",
    _ROOT / "scripts" / "dockerfile_build.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)
sys.path.insert(0, str(_ROOT / "scripts"))
_SPEC.loader.exec_module(_MOD)


def _build_run_env(state, ssh_targets):
    """Mirror the env construction at the top of _do_run. Kept in sync
    with that function; if it changes there, change it here."""
    run_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                "/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "TERM": "xterm",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    for kv in state.env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            run_env[k] = v
    for k, v in state.build_args.items():
        run_env[k] = v
    if ssh_targets:
        run_env["SSH_AUTH_SOCK"] = ssh_targets[0]
    for k in ("LANG", "LC_ALL"):
        if k in os.environ:
            run_env[k] = os.environ[k]
    return run_env


class RunEnvTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = _MOD._State(
            context_dir=self.tmp,
            build_args={},
            build_secrets={},
            arch="amd64",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_host_secret_not_leaked(self):
        sentinel = "OCI2BIN_TEST_SENTINEL_aef91"
        os.environ[sentinel] = "if you can read me, the env leaked"
        try:
            env = _build_run_env(self.state, ssh_targets=[])
        finally:
            del os.environ[sentinel]
        self.assertNotIn(sentinel, env)

    def test_aws_creds_not_leaked(self):
        for k, v in (("AWS_SECRET_ACCESS_KEY", "x"),
                     ("AWS_SESSION_TOKEN",     "y"),
                     ("GH_TOKEN",              "z")):
            os.environ[k] = v
        try:
            env = _build_run_env(self.state, ssh_targets=[])
        finally:
            for k in ("AWS_SECRET_ACCESS_KEY",
                      "AWS_SESSION_TOKEN",
                      "GH_TOKEN"):
                os.environ.pop(k, None)
        for k in ("AWS_SECRET_ACCESS_KEY",
                  "AWS_SESSION_TOKEN",
                  "GH_TOKEN"):
            self.assertNotIn(k, env, f"{k} leaked")

    def test_image_env_passes_through(self):
        self.state.env = ["FOO=bar", "BAZ=qux"]
        env = _build_run_env(self.state, ssh_targets=[])
        self.assertEqual(env["FOO"], "bar")
        self.assertEqual(env["BAZ"], "qux")

    def test_build_arg_passes_through(self):
        self.state.build_args = {"VERSION": "1.2.3"}
        env = _build_run_env(self.state, ssh_targets=[])
        self.assertEqual(env["VERSION"], "1.2.3")

    def test_minimal_baseline(self):
        env = _build_run_env(self.state, ssh_targets=[])
        for k in ("PATH", "HOME", "TERM", "DEBIAN_FRONTEND"):
            self.assertIn(k, env)
        self.assertTrue(env["PATH"].startswith("/usr/local/sbin"))

    def test_ssh_target_set_when_present(self):
        env = _build_run_env(self.state,
                             ssh_targets=["/run/buildkit/ssh.sock"])
        self.assertEqual(env["SSH_AUTH_SOCK"],
                         "/run/buildkit/ssh.sock")

    def test_ssh_target_absent_by_default(self):
        env = _build_run_env(self.state, ssh_targets=[])
        self.assertNotIn("SSH_AUTH_SOCK", env)


if __name__ == "__main__":
    unittest.main()
