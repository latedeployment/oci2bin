"""The build options are recorded in the metadata block and replayed.

Structural checks over the oci2bin wrapper (the build path needs Docker, so
the replay itself cannot run here) plus the builder-side round trip.
"""

import importlib.util
import json
import pathlib
import re
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "oci2bin"
META_MAGIC = b"OCI2BIN_META\x00"


def _load_bp():
    spec = importlib.util.spec_from_file_location(
        "build_polyglot", ROOT / "scripts" / "build_polyglot.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_meta(block):
    m = block.rfind(META_MAGIC)
    total = struct.unpack_from("<I", block, m - 4)[0]
    js = m + len(META_MAGIC)
    je = (m - 4) + total
    return json.loads(block[js:je].rstrip(b"\x00"))


def _function_body(source, name):
    start = source.index(f"{name}() {{")
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise AssertionError(f"unbalanced braces in {name}")


class MetaBlockBuildArgsTest(unittest.TestCase):
    def test_recorded_verbatim(self):
        bp = _load_bp()
        args = ["--arch", "x86_64", "--strip", "--label", "a=b c"]
        meta = _parse_meta(bp.build_meta_block("img:1", build_args=args))
        self.assertEqual(meta["build_args"], args)

    def test_absent_when_not_given(self):
        bp = _load_bp()
        self.assertNotIn("build_args", _parse_meta(bp.build_meta_block("i")))

    def test_rejects_non_string_items(self):
        bp = _load_bp()
        with self.assertRaises(ValueError):
            bp.build_meta_block("i", build_args=["--strip", 3])


class WrapperReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = WRAPPER.read_text(encoding="utf-8")

    def test_every_build_option_is_forwarded(self):
        """Any build option the `run` subcommand accepts must be reproduced
        by build_forward_args_for_arch_all(), or a recorded build (and
        --arch all, and the --cache key) silently drops it."""
        # The main build parser: from its state initialisation up to the
        # forwarding function itself.
        start = self.src.index("\nSTRIP_PREFIX_ARGS=()\n")
        end = self.src.index("build_forward_args_for_arch_all() {")
        parser = self.src[start:end]
        build_opts = set()
        for line in parser.splitlines():
            if not line.startswith("        "):
                continue
            pattern, closing, _ = line[8:].partition(")")
            if not closing:
                continue
            options = pattern.split("|")
            if (not re.fullmatch(r"--[a-z0-9-]+", options[-1])
                    or not all(re.fullmatch(r"--?[a-zA-Z0-9-]+", option)
                               for option in options[:-1])):
                continue
            build_opts.update(o for o in options if o.startswith("--"))
        self.assertIn("--strip", build_opts)
        self.assertIn("--pin-digest", build_opts)
        self.assertGreater(len(build_opts), 30)
        body = _function_body(self.src, "build_forward_args_for_arch_all")
        # --arch is added by the caller (per-arch forwarding / the record);
        # --help and -- are not build options; --no-auto-tmpfs is a runtime
        # pass-through the parser only skips.
        skip = {"--arch", "--help", "--", "--no-auto-tmpfs"}
        missing = sorted(o for o in build_opts - skip
                         if f"({o}" not in body and f'"{o}"' not in body
                         and o.upper().strip("-").replace("-", "_") + "_ARGS"
                         not in body)
        self.assertEqual(missing, [],
                         f"build options not forwarded/recorded: {missing}")
        # ... and classified, so `run` accepts it and `update` replays it.
        arity = _function_body(self.src, "build_option_arity")
        unclassified = sorted(o for o in build_opts - skip
                              if not re.search(rf"(?<![\w-]){re.escape(o)}(?=[|)])",
                                               arity))
        self.assertEqual(unclassified, [],
                         f"build options build_option_arity does not know: "
                         f"{unclassified}")

    def test_build_records_the_option_list(self):
        self.assertIn("--build-args-json", self.src)
        # Recorded from the canonical list, with the target arch first.
        self.assertRegex(self.src,
                         r"printf '%s\\0' --arch \"\$TARGET_ARCH\" "
                         r"\"\$\{ARCH_ALL_FORWARD_ARGS\[@\]\}\"")
        # Both builder invocations carry EMBED_LOADER_ARG, which holds it.
        invocations = re.findall(
            r'python3 "\$OCI2BIN_HOME/scripts/build_polyglot\.py" \\\n'
            r'(?:.*\\\n)*?.*--output', self.src)
        self.assertGreaterEqual(len(invocations), 2)
        for inv in invocations:
            self.assertIn('"${EMBED_LOADER_ARG[@]}"', inv)

    def test_update_replays_recorded_options(self):
        start = self.src.index('if [[ "${1:-}" == "update" ]]; then')
        end = self.src.index("# ── ps subcommand", start)
        body = self.src[start:end]
        self.assertIn('meta.get("build_args")', body)
        self.assertIn('build_option_arity', body)
        self.assertIn("malformed build_args record", body)
        self.assertRegex(
            body, r'"\$0" "\$\{UPDATE_BUILD_ARGS\[@\]\}" "\$IMAGE_NAME" '
                  r'"\$UPDATE_TMP"')
        self.assertIn("no build options", body)


if __name__ == "__main__":
    unittest.main()
