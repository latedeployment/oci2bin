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


def _have(tool):
    return subprocess.run(["sh", "-c", f"command -v {tool}"],
                          capture_output=True).returncode == 0


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

    def _run_script(self, binary_path):
        return subprocess.run([sys.executable, "-c", self.script, binary_path],
                              capture_output=True, text=True)

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

    def test_no_policy_passes(self):
        p = self._make_binary(require_signed=False, sign=False)
        self.assertEqual(self._run_script(p).returncode, 0)

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
