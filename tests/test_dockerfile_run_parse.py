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


class DockerfileParserTest(unittest.TestCase):
    """_parse_dockerfile: continuations, comments, CRLF and heredocs."""

    def _parse_text(self, text):
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, newline="",
                                         suffix=".Dockerfile") as f:
            f.write(text)
            path = f.name
        try:
            return MOD._parse_dockerfile(path)
        finally:
            import os
            os.unlink(path)

    def test_comment_inside_continuation_is_skipped(self):
        ins = self._parse_text("FROM scratch\nRUN a && \\\n# note\n    b\n")
        self.assertEqual(ins[1][0], "RUN")
        self.assertIn("a && b", ins[1][1])
        self.assertEqual(len(ins), 2)

    def test_crlf_continuation(self):
        ins = self._parse_text("FROM scratch\r\nRUN a \\\r\n  b\r\n")
        self.assertEqual(ins[1], ("RUN", "a b", []))

    def test_heredoc_body_is_not_parsed_as_instructions(self):
        ins = self._parse_text("FROM scratch\nRUN <<EOF\nFROM evil\n"
                               "echo hi\nEOF\nCMD x\n")
        self.assertEqual([i[0] for i in ins], ["FROM", "RUN", "CMD"])
        self.assertEqual(ins[1][2], [("EOF", "FROM evil\necho hi\n")])

    def test_dash_heredoc_strips_tabs(self):
        ins = self._parse_text("FROM scratch\nRUN <<-E\n\techo x\n\tE\n")
        self.assertEqual(ins[1][2], [("E", "echo x\n")])


class ExpandVarsTest(unittest.TestCase):
    def test_no_prefix_substitution(self):
        self.assertEqual(MOD._expand_vars("$FOO $FOOBAR", {"FOO": "x"}),
                         "x ")

    def test_braces_and_defaults(self):
        v = {"A": "1", "E": ""}
        self.assertEqual(MOD._expand_vars("${A}-${B:-d}-${E:-e}", v),
                         "1-d-e")
        self.assertEqual(MOD._expand_vars("${A:+set}${B:+unset}", v), "set")

    def test_escaped_dollar(self):
        self.assertEqual(MOD._expand_vars("\\$A", {"A": "1"}), "$A")

    def test_nested_defaults(self):
        """${A:-${B}}: the first `}` used to end the expansion, leaving
        `${B` in the output and a stray `}` after it."""
        v = {"A": "a", "B": "b", "E": ""}
        self.assertEqual(MOD._expand_vars("${A:-${B}}", v), "a")
        self.assertEqual(MOD._expand_vars("${X:-${B}}", v), "b")
        self.assertEqual(MOD._expand_vars("${E:-${B}}", v), "b")
        self.assertEqual(MOD._expand_vars("${X:-${Y:-c}}", v), "c")
        self.assertEqual(MOD._expand_vars("${X:-${Y:-${B}}}x", v), "bx")
        self.assertEqual(MOD._expand_vars("pre${X:-${B}}post", v),
                         "prebpost")
        self.assertEqual(MOD._expand_vars("${A:+${B}}${X:+${B}}", v), "b")
        self.assertEqual(MOD._expand_vars("${X:-${Y}}", v), "")
        # Literal braces inside the word, and an unterminated expansion.
        self.assertEqual(MOD._expand_vars("${X:-{lit}}", v), "{lit}")
        self.assertEqual(MOD._expand_vars("${X:-unterminated", v),
                         "${X:-unterminated")
        self.assertEqual(MOD._expand_vars("${X:-${B}", v), "${X:-${B}")

    def test_matching_brace(self):
        self.assertEqual(MOD._matching_brace("${A}", 1), 3)
        self.assertEqual(MOD._matching_brace("${A:-${B}}", 1), 9)
        self.assertEqual(MOD._matching_brace("${A:-${B}", 1), -1)
        self.assertEqual(MOD._matching_brace("${A:-\\}}", 1), 7)

    def test_run_is_not_expanded_by_the_builder(self):
        self.assertNotIn("RUN", MOD._EXPANDED_INSTRUCTIONS)
        self.assertIn("ENV", MOD._EXPANDED_INSTRUCTIONS)


class FromParseTest(unittest.TestCase):
    def _state(self):
        return MOD._State(".", {}, {}, "amd64")

    def test_stage_name(self):
        self.assertEqual(MOD._parse_from(self._state(), "alpine AS Build"),
                         ("alpine", "build"))

    def test_platform_matching_arch_accepted(self):
        self.assertEqual(
            MOD._parse_from(self._state(),
                            "--platform=linux/amd64 alpine"),
            ("alpine", None))

    def test_platform_other_arch_rejected(self):
        with self.assertRaises(SystemExit):
            MOD._parse_from(self._state(), "--platform=linux/arm64 alpine")


if __name__ == "__main__":
    unittest.main()
