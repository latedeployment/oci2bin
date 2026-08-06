"""
End-to-end tests for the --require-signed self-enforcing policy.

These run the *actual* embedded verifier script extracted from
src/loader.c (the C string inside enforce_require_signed), so the test cannot
drift from what the loader ships. A real EC key + sign_binary.py + openssl
exercise the full cryptographic round trip.
"""

import hashlib
import importlib.util
import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOADER_C = ROOT / "src" / "loader.c"
SIGN_PY = ROOT / "scripts" / "sign_binary.py"
META_MAGIC = b"OCI2BIN_META\x00"


OPENSSL_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


def _have(tool):
    return subprocess.run(["sh", "-c", f"command -v {tool}"],
                          capture_output=True).returncode == 0


def _openssl_path():
    """Resolve openssl the way the loader does — fixed dirs, never PATH."""
    for d in OPENSSL_DIRS:
        candidate = os.path.join(d, "openssl")
        if os.access(candidate, os.X_OK):
            return candidate
    return "openssl"


def extract_embedded_script(c_source, func_name):
    """Pull the `static const char script[] = "...";` literal out of the
    named C function and decode it back to the Python source the loader runs."""
    fn = c_source.index(f"static int {func_name}(")
    seg = c_source[fn:]
    # Match the full `static const char script[] = "..." "..." ... ;`
    # initializer: one or more string literals (which cannot contain an
    # unescaped quote) followed by the terminating semicolon. This avoids
    # stopping at a ';' that appears *inside* the embedded script text.
    m = re.search(
        r'static const char script\[\]\s*=\s*'
        r'((?:"(?:\\.|[^"\\])*"\s*)+);', seg)
    if not m:
        raise AssertionError(f"could not find script[] in {func_name}")
    # The regex stops at anything that is not another string literal — a C
    # comment placed *between* literals ends the match, and re.search would
    # then happily return the next function's script instead. Silently
    # verifying the wrong script is the worst outcome here, so require the
    # match to fall inside this function's own body.
    body_end = seg.find("\nstatic ", 1)
    if body_end != -1 and m.start() > body_end:
        raise AssertionError(
            f"script[] match for {func_name} lies outside its body — most "
            f"likely a comment between string literals ended the match "
            f"early. Move the comment above the declaration.")
    parts = re.findall(r'"((?:\\.|[^"\\])*)"', m.group(1))
    raw = "".join(parts)
    # Decode C escapes that matter here: \n \t \\ \" \'
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append({"n": "\n", "t": "\t", "\\": "\\",
                        '"': '"', "'": "'"}.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def meta_block(meta_dict):
    import json
    jb = json.dumps(meta_dict, separators=(",", ":")).encode() + b"\x00"
    total = 4 + len(META_MAGIC) + len(jb)
    return struct.pack("<I", total) + META_MAGIC + jb


@unittest.skipUnless(_have("openssl"), "openssl not installed")
class RequireSignedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = extract_embedded_script(
            LOADER_C.read_text(), "enforce_require_signed")
        cls.tmp = tempfile.mkdtemp()
        cls.priv = os.path.join(cls.tmp, "priv.pem")
        cls.pub = os.path.join(cls.tmp, "pub.pem")
        subprocess.run(["openssl", "ecparam", "-genkey", "-name",
                        "prime256v1", "-noout", "-out", cls.priv], check=True)
        subprocess.run(["openssl", "ec", "-in", cls.priv, "-pubout",
                        "-out", cls.pub], check=True,
                       capture_output=True)
        cls.pub_pem = pathlib.Path(cls.pub).read_text()

    def _run_script(self, binary_path, openssl=None, env=None):
        return subprocess.run(
            [sys.executable, "-c", self.script, binary_path,
             openssl or _openssl_path()],
            capture_output=True, text=True, env=env)

    def _sign(self, in_path):
        subprocess.run([sys.executable, str(SIGN_PY), "sign",
                        "--key", self.priv, "--in", in_path],
                       check=True, capture_output=True)

    def _make_binary(self, require_signed, sign=True, tamper=False):
        body = b"NOT-A-REAL-LOADER-BODY" * 100
        meta = {"image": "test:latest", "version": "0",
                "require_signed": require_signed}
        if require_signed:
            meta["verify_pubkey"] = self.pub_pem
        data = body + meta_block(meta)
        path = os.path.join(self.tmp, f"bin-{require_signed}-{sign}-{tamper}")
        with open(path, "wb") as f:
            f.write(data)
        if sign:
            self._sign(path)
        if tamper:
            with open(path, "r+b") as f:
                f.seek(10)
                f.write(b"\xff")
        return path

    def test_parser_disagreement_refuses(self):
        """The script refuses when it cannot re-derive the policy itself.

        enforce_require_signed() only reaches this script after the C side has
        already found require_signed in the metadata block, so a binary the
        script reads as unpoliced means the two parsers disagree about the
        same bytes — refuse, never fall back to "there is no policy". The
        genuine no-policy case returns 0 in C and never runs this script; see
        test_c_returns_early_without_running_script.
        """
        p = self._make_binary(require_signed=False, sign=False)
        r = self._run_script(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("parsers disagree", r.stderr)

    def _corrupt(self, mutate):
        p = self._make_binary(require_signed=True, sign=True)
        data = bytearray(pathlib.Path(p).read_bytes())
        out = os.path.join(self.tmp, f"corrupt-{mutate.__name__}")
        pathlib.Path(out).write_bytes(bytes(mutate(data)))
        return out

    def test_missing_metadata_refuses(self):
        def strip_magic(data):
            i = data.rfind(META_MAGIC)
            data[i:i + len(META_MAGIC)] = b"XXXXXXXXXXXXX"
            return data
        r = self._run_script(self._corrupt(strip_magic))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_inconsistent_framing_refuses(self):
        def blow_up_length(data):
            i = data.rfind(META_MAGIC)
            struct.pack_into("<I", data, i - 4, 0xFFFFFF)
            return data
        r = self._run_script(self._corrupt(blow_up_length))
        self.assertEqual(r.returncode, 1)
        self.assertIn("framing is inconsistent", r.stderr)

    def test_malformed_json_refuses(self):
        def break_json(data):
            i = data.rfind(META_MAGIC) + len(META_MAGIC)
            data[i:i + 1] = b"~"
            return data
        r = self._run_script(self._corrupt(break_json))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not valid JSON", r.stderr)

    def test_c_returns_early_without_running_script(self):
        """A binary with no policy must not pay for (or reach) the verifier.

        The fail-closed script above is only correct because C decides the
        "no policy at all" case itself. Assert that structurally: the early
        return sits between the marker lookup and the script.
        """
        src = LOADER_C.read_text()
        start = src.index("static int enforce_require_signed(")
        body = src[start:src.index("static const char script[]", start)]
        self.assertIn("has_require_signed_marker(self_path)", body)
        self.assertIn("return 0;", body,
                      "no early return for the no-policy case — the "
                      "fail-closed script would then reject unpoliced "
                      "binaries")

    def test_signed_and_valid_passes(self):
        p = self._make_binary(require_signed=True, sign=True)
        r = self._run_script(p)
        self.assertEqual(r.returncode, 0, msg=r.stderr)

    def test_policy_but_unsigned_refuses(self):
        p = self._make_binary(require_signed=True, sign=False)
        r = self._run_script(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no valid signature", r.stderr)

    def test_tampered_refuses(self):
        # Sign, then flip a byte in the signed content → verify must fail.
        p = self._make_binary(require_signed=True, sign=True, tamper=True)
        r = self._run_script(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("verification failed", r.stderr)

    def _openssl_stub(self):
        """An `openssl` that accepts everything, as an attacker would plant."""
        d = tempfile.mkdtemp(dir=self.tmp)
        stub = os.path.join(d, "openssl")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(stub, 0o755)
        return d, stub

    def test_hostile_path_does_not_defeat_verification(self):
        """A stub `openssl` earlier in PATH must not make a bad binary pass.

        The verifier is handed an absolute openssl path by the loader, so
        PATH is never consulted. The control assertion below proves the stub
        really would accept the same binary if it were ever reached.
        """
        stub_dir, stub = self._openssl_stub()
        p = self._make_binary(require_signed=True, sign=True, tamper=True)

        env = dict(os.environ)
        env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
        r = self._run_script(p, env=env)
        self.assertEqual(r.returncode, 1, msg=r.stderr)
        self.assertIn("verification failed", r.stderr)

        # Control: the stub is effective when it *is* the verifier, so the
        # assertion above is testing PATH resistance and not a dud stub.
        self.assertEqual(self._run_script(p, openssl=stub).returncode, 0)

    def test_missing_openssl_refuses(self):
        """An unusable verifier is refused, never treated as 'verified'."""
        p = self._make_binary(require_signed=True, sign=True)
        r = self._run_script(p, openssl=os.path.join(self.tmp, "no-such-ssl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot run openssl", r.stderr)


class BuildMetaRequireSignedTest(unittest.TestCase):
    def _bp(self):
        spec = importlib.util.spec_from_file_location(
            "build_polyglot", ROOT / "scripts" / "build_polyglot.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _parse_meta(self, block):
        import json
        m = block.rfind(META_MAGIC)
        total = struct.unpack_from("<I", block, m - 4)[0]
        js = m + len(META_MAGIC)
        je = (m - 4) + total
        return json.loads(block[js:je].rstrip(b"\x00"))

    def test_meta_without_policy_has_no_require_signed(self):
        bp = self._bp()
        meta = self._parse_meta(bp.build_meta_block("img:1"))
        self.assertNotIn("require_signed", meta)
        self.assertNotIn("verify_pubkey", meta)

    def test_meta_with_policy_embeds_key(self):
        bp = self._bp()
        pem = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n"
        meta = self._parse_meta(
            bp.build_meta_block("img:1", require_signed_pubkey=pem))
        self.assertTrue(meta["require_signed"])
        self.assertEqual(meta["verify_pubkey"], pem)


if __name__ == "__main__":
    unittest.main()
