"""
Unit tests for build-side age encryption (build_polyglot.age_encrypt).

`age` is not assumed to be installed: a fake `age` shim is placed on PATH so
the argv construction and stdin/stdout plumbing are exercised deterministically.
The fake mirrors age's framing closely enough (binary magic header) that the
loader's blob_is_age_encrypted() detection — covered by the C unit tests —
would recognise the output.
"""

import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bp = _load_module('build_polyglot', ROOT / 'scripts' / 'build_polyglot.py')

# A fake `age` that prepends the real age magic header on --encrypt and strips
# it on --decrypt, so the round trip is verifiable without the real binary.
_FAKE_AGE = textwrap.dedent("""\
    #!/usr/bin/env python3
    import sys
    MAGIC = b"age-encryption.org/v1\\n"
    args = sys.argv[1:]
    # honor -o OUT and a trailing positional input file like the real age
    out_path = None
    in_path = None
    i = 0
    while i < len(args):
        if args[i] == "-o":
            out_path = args[i + 1]; i += 2; continue
        if args[i] in ("-r", "-R", "-i"):
            i += 2; continue
        if not args[i].startswith("-"):
            in_path = args[i]
        i += 1
    data = open(in_path, "rb").read() if in_path else sys.stdin.buffer.read()
    if "--encrypt" in args:
        if not any(a in ("-r", "-R") for a in args):
            sys.stderr.write("no recipients\\n"); sys.exit(2)
        result = MAGIC + data
    elif "--decrypt" in args:
        result = data[len(MAGIC):]
    else:
        sys.exit(1)
    if out_path and out_path != "-":
        open(out_path, "wb").write(result)
    else:
        sys.stdout.buffer.write(result)
""")


class AgeEncryptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        age_path = os.path.join(self.tmp, "age")
        with open(age_path, "w") as f:
            f.write(_FAKE_AGE)
        os.chmod(age_path, 0o755)
        self._orig_path = os.environ["PATH"]
        os.environ["PATH"] = self.tmp + os.pathsep + self._orig_path

    def tearDown(self):
        os.environ["PATH"] = self._orig_path

    def test_encrypt_adds_age_magic(self):
        out = bp.age_encrypt(b"hello-oci-tar", ["age1fakeRECIPIENT"], [])
        self.assertTrue(out.startswith(b"age-encryption.org/v1\n"))
        self.assertIn(b"hello-oci-tar", out)

    def test_round_trip_via_fake_age(self):
        plain = b"the original tar bytes"
        ct = bp.age_encrypt(plain, ["age1r"], [])
        # decrypt the way the loader would: age --decrypt -i id -o out in
        with tempfile.NamedTemporaryFile(delete=False) as cf:
            cf.write(ct)
            ct_path = cf.name
        out_path = ct_path + ".dec"
        subprocess.run(
            ["age", "--decrypt", "-i", "/dev/null", "-o", out_path, ct_path],
            input=b"", check=True)
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), plain)
        os.unlink(ct_path)
        os.unlink(out_path)

    def test_no_recipients_exits(self):
        with self.assertRaises(SystemExit):
            bp.age_encrypt(b"x", [], [])


class AgeMissingTest(unittest.TestCase):
    def test_missing_age_exits_cleanly(self):
        # Point PATH at an empty dir so `age` cannot be found.
        empty = tempfile.mkdtemp()
        orig = os.environ["PATH"]
        os.environ["PATH"] = empty
        try:
            with self.assertRaises(SystemExit):
                bp.age_encrypt(b"x", ["age1r"], [])
        finally:
            os.environ["PATH"] = orig


if __name__ == "__main__":
    unittest.main()
