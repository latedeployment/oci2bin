"""Regression tests for Dockerfile RUN parsing.

The parser may inspect leading BuildKit options, but it must not reconstruct
the shell command: shell operators, redirections, variable expansion and
quoting belong to /bin/sh.
"""

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build",
    ROOT / "scripts" / "dockerfile_build.py",
)
MOD = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MOD)


class RunParseTest(unittest.TestCase):
    def _parse(self, line):
        return MOD._parse_run_line(line)

    def test_plain_shell_operators_preserved(self):
        cmd = "echo hi && echo bye | sed 's/bye/done/' > /tmp/out"
        parsed, mounts, unsupported = self._parse(cmd)
        self.assertEqual(parsed, cmd)
        self.assertEqual(mounts, [])
        self.assertEqual(unsupported, [])

    def test_variable_expansion_preserved(self):
        cmd = 'printf "%s\\n" "$HOME" && echo ${PATH:-missing}'
        parsed, mounts, unsupported = self._parse(cmd)
        self.assertEqual(parsed, cmd)
        self.assertEqual(mounts, [])
        self.assertEqual(unsupported, [])

    def test_mount_equals_stripped_command_preserved(self):
        line = ("--mount=type=cache,target=/root/.cache "
                "echo hi && echo bye")
        parsed, mounts, unsupported = self._parse(line)
        self.assertEqual(parsed, "echo hi && echo bye")
        self.assertEqual(mounts, [{"type": "cache",
                                   "target": "/root/.cache"}])
        self.assertEqual(unsupported, [])

    def test_mount_space_form_stripped_command_preserved(self):
        line = ("--mount type=secret,id=token,target=/run/secrets/token "
                "cat /run/secrets/token && echo ok")
        parsed, mounts, unsupported = self._parse(line)
        self.assertEqual(parsed, "cat /run/secrets/token && echo ok")
        self.assertEqual(mounts, [{"type": "secret", "id": "token",
                                   "target": "/run/secrets/token"}])
        self.assertEqual(unsupported, [])

    def test_quoted_mount_value(self):
        line = ('--mount "type=bind,source=my dir,target=/src" '
                'printf "%s\\n" "a b"')
        parsed, mounts, unsupported = self._parse(line)
        self.assertEqual(parsed, 'printf "%s\\n" "a b"')
        self.assertEqual(mounts, [{"type": "bind", "source": "my dir",
                                   "target": "/src"}])
        self.assertEqual(unsupported, [])

    def test_network_and_security_options_reported_unsupported(self):
        line = "--network=none --security sandbox echo $HOME && id"
        parsed, mounts, unsupported = self._parse(line)
        self.assertEqual(parsed, "echo $HOME && id")
        self.assertEqual(mounts, [])
        self.assertEqual(unsupported, ["--network=none",
                                       "--security sandbox"])

    def test_unknown_option_like_command_preserved(self):
        cmd = "--not-a-buildkit-option echo still-a-command"
        parsed, mounts, unsupported = self._parse(cmd)
        self.assertEqual(parsed, cmd)
        self.assertEqual(mounts, [])
        self.assertEqual(unsupported, [])

    def test_malformed_command_after_mount_preserved(self):
        line = "--mount=type=cache,target=/c \"unterminated"
        parsed, mounts, unsupported = self._parse(line)
        self.assertEqual(parsed, '"unterminated')
        self.assertEqual(mounts, [{"type": "cache", "target": "/c"}])
        self.assertEqual(unsupported, [])


if __name__ == "__main__":
    unittest.main()
