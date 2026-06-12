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


# A fake `age` that emulates passphrase (scrypt) mode over a pty: it prompts on
# the terminal (stderr), reads the passphrase from stdin, and stores it inside
# the ciphertext so --decrypt can verify it. Mirrors the real prompt wording
# closely enough that _age_pty_run's prompt detection fires.
_FAKE_AGE_PASS = textwrap.dedent("""\
    #!/usr/bin/env python3
    import sys
    MAGIC = b"age-encryption.org/v1\\n-> scrypt FAKESALT 18\\n"
    args = sys.argv[1:]
    out_path = None; in_path = None; i = 0
    while i < len(args):
        if args[i] == "-o": out_path = args[i + 1]; i += 2; continue
        if args[i] in ("-r", "-R", "-i"): i += 2; continue
        if not args[i].startswith("-"): in_path = args[i]
        i += 1
    def read_pass(prompt):
        sys.stderr.write(prompt); sys.stderr.flush()
        return sys.stdin.readline().rstrip("\\n").rstrip("\\r")
    if "--passphrase" in args or "-p" in args:
        p1 = read_pass("Enter passphrase: ")
        p2 = read_pass("Confirm passphrase: ")
        if p1 != p2: sys.stderr.write("no match\\n"); sys.exit(2)
        data = open(in_path, "rb").read()
        open(out_path, "wb").write(MAGIC + p1.encode() + b"\\n" + data)
    elif "--decrypt" in args:
        p = read_pass("Enter passphrase: ")
        raw = open(in_path, "rb").read()
        stored, _, data = raw[len(MAGIC):].partition(b"\\n")
        if stored.decode() != p:
            sys.stderr.write("incorrect passphrase\\n"); sys.exit(2)
        open(out_path, "wb").write(data)
    else:
        sys.exit(1)
""")


class AgePassphraseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        age_path = os.path.join(self.tmp, "age")
        with open(age_path, "w") as f:
            f.write(_FAKE_AGE_PASS)
        os.chmod(age_path, 0o755)
        self._orig_path = os.environ["PATH"]
        os.environ["PATH"] = self.tmp + os.pathsep + self._orig_path

    def tearDown(self):
        os.environ["PATH"] = self._orig_path

    def test_passphrase_encrypt_is_scrypt_age(self):
        ct = bp.age_passphrase_encrypt(b"hello-oci-tar", b"hunter2")
        self.assertTrue(ct.startswith(b"age-encryption.org/v1\n"))
        self.assertIn(b"scrypt", ct[:120])

    def test_passphrase_round_trip(self):
        plain = b"the original tar bytes" * 50
        ct = bp.age_passphrase_encrypt(plain, b"correct-horse")
        with tempfile.TemporaryDirectory() as td:
            cf = os.path.join(td, "c.age"); of = os.path.join(td, "o")
            with open(cf, "wb") as f:
                f.write(ct)
            rc = bp._age_pty_run(
                ["age", "--decrypt", "-o", of, cf], b"correct-horse", 1)
            self.assertEqual(rc, 0)
            with open(of, "rb") as f:
                self.assertEqual(f.read(), plain)

    def test_passphrase_wrong_fails(self):
        ct = bp.age_passphrase_encrypt(b"data", b"right")
        with tempfile.TemporaryDirectory() as td:
            cf = os.path.join(td, "c.age"); of = os.path.join(td, "o")
            with open(cf, "wb") as f:
                f.write(ct)
            rc = bp._age_pty_run(
                ["age", "--decrypt", "-o", of, cf], b"wrong", 1)
            self.assertNotEqual(rc, 0)

    def test_empty_passphrase_exits(self):
        with self.assertRaises(SystemExit):
            bp.age_passphrase_encrypt(b"x", b"")

    def test_missing_age_returns_127(self):
        empty = tempfile.mkdtemp()
        orig = os.environ["PATH"]
        os.environ["PATH"] = empty
        try:
            rc = bp._age_pty_run(["age", "--decrypt"], b"x", 1)
            self.assertEqual(rc, 127)
        finally:
            os.environ["PATH"] = orig


class ResolveBuildPassphraseTest(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop("OCI2BIN_PASSWORD", None)

    def tearDown(self):
        if self._env is not None:
            os.environ["OCI2BIN_PASSWORD"] = self._env
        else:
            os.environ.pop("OCI2BIN_PASSWORD", None)

    def test_password_file_first_line(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"line-one-pass\nsecond line\n")
            path = f.name
        try:
            self.assertEqual(
                bp.resolve_build_passphrase(path), b"line-one-pass")
        finally:
            os.unlink(path)

    def test_env_var(self):
        os.environ["OCI2BIN_PASSWORD"] = "env-secret"
        self.assertEqual(bp.resolve_build_passphrase(None), b"env-secret")

    def test_empty_password_file_exits(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\n")
            path = f.name
        try:
            with self.assertRaises(SystemExit):
                bp.resolve_build_passphrase(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
