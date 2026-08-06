"""
The launch policy (markers + pinned digest + --require-signed) must gate every
entry point that touches the embedded payload.

These assert on the structure of main() in src/loader.c rather than on runtime
behaviour, because the bug they guard against is an *ordering* bug: the policy
check sat at step 3 of main()'s dispatcher while OCI2BIN_INSPECT and mcp-serve
were dispatched at step 1, so both extracted and acted on untrusted layer data
with the policy never consulted. A dispatcher gains new branches over time, and
a runtime test only covers the branches someone remembered to write.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOADER_C = ROOT / "src" / "loader.c"

GATE = "enforce_launch_policy"

# Entry points that read or act on the embedded OCI payload. Anything added
# here must be preceded by a GATE call inside main().
PAYLOAD_ENTRY_POINTS = (
    "inspect_image_main(",
    "mcp_serve_main(",
)

# Individual checks that make up the gate. They must be reached *through*
# enforce_launch_policy so no caller can run a partial policy.
GATE_INTERNALS = (
    "verify_pinned_digest(",
    "enforce_require_signed(",
)


def _function_body(source, signature):
    """Return the brace-balanced body of the function starting at signature."""
    start = source.index(signature)
    open_brace = source.index("{", start)
    depth = 0
    for i in range(open_brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace:i + 1]
    raise AssertionError(f"unbalanced braces in {signature}")


class LaunchPolicyGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LOADER_C.read_text()
        cls.main = _function_body(cls.source, "int main(int argc, char* argv[])")

    def test_gate_exists(self):
        self.assertIn(f"static int {GATE}(", self.source)

    def test_payload_entry_points_are_gated(self):
        """Every payload entry point in main() is preceded by a gate call."""
        for entry in PAYLOAD_ENTRY_POINTS:
            with self.subTest(entry=entry):
                pos = self.main.find(entry)
                self.assertNotEqual(pos, -1,
                                    f"{entry} no longer called from main()")
                preceding = self.main[:pos]
                self.assertIn(
                    f"{GATE}(", preceding,
                    f"{entry} is dispatched before the launch policy gate — "
                    f"this is the OCI2BIN_INSPECT/mcp-serve bypass")

    def test_inspect_is_gated_inside_its_own_branch(self):
        """The gate is in the OCI2BIN_INSPECT branch, not merely earlier.

        A gate that happens to appear before the branch for unrelated reasons
        would satisfy the ordering check above without protecting anything.
        """
        m = re.search(r'getenv\("OCI2BIN_INSPECT"\)\s*\)\s*\{(.*?)\n    \}',
                      self.main, re.S)
        self.assertIsNotNone(m, "OCI2BIN_INSPECT branch not found in main()")
        branch = m.group(1)
        self.assertIn(f"{GATE}(", branch)
        self.assertLess(branch.index(f"{GATE}("),
                        branch.index("inspect_image_main("),
                        "gate must run before extraction")

    def test_gate_internals_are_not_called_directly(self):
        """The policy's parts are only reachable through the gate itself."""
        gate_body = _function_body(self.source, f"static int {GATE}(")
        for check in GATE_INTERNALS:
            with self.subTest(check=check):
                self.assertIn(check, gate_body,
                              f"{check} is not part of {GATE}")
                self.assertNotIn(
                    check, self.main,
                    f"{check} is called directly from main() — route it "
                    f"through {GATE} so every entry point gets the full "
                    f"policy")

    def test_marker_check_is_part_of_the_gate(self):
        gate_body = _function_body(self.source, f"static int {GATE}(")
        self.assertIn("OCI_PATCHED != 1", gate_body)
        self.assertNotIn("OCI_PATCHED != 1", self.main,
                         "marker check must live in the gate, not in main()")

    def test_help_is_not_gated(self):
        """--help must keep working without a signature or openssl.

        It reads no payload, and gating it would make an unverifiable binary
        undiagnosable. parse_opts handles --help and exits, so the gate must
        stay below option parsing on the normal path.
        """
        gate_pos = self.main.rfind(f"{GATE}(")
        parse_pos = self.main.index("parse_opts(")
        self.assertLess(parse_pos, gate_pos,
                        "the normal-path gate moved above parse_opts, which "
                        "makes --help require verification")


if __name__ == "__main__":
    unittest.main()
