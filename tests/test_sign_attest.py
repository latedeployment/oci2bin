"""Tests for sign_binary.py: v3 signature block with optional in-toto
attestation.  Uses real openssl via the script; skipped if not available."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent.parent
SIGN_PY = ROOT / "scripts" / "sign_binary.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sb = _load_module("sign_binary", SIGN_PY)


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestSignAttestRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-sign-test-"))
        self.priv = self.tmpdir / "priv.pem"
        self.pub = self.tmpdir / "pub.pem"
        # Generate a P-256 ECDSA keypair via openssl.
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(self.priv)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(self.priv),
             "-pubout", "-out", str(self.pub)],
            check=True, capture_output=True,
        )
        self.binary = self.tmpdir / "demo.bin"
        self.binary.write_bytes(b"\x7fELFstub-binary-content\x00\x01\x02\x03")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _sign(self, *extra):
        result = subprocess.run(
            ["python3", str(SIGN_PY), "sign",
             "--key", str(self.priv),
             "--in", str(self.binary), *extra],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0,
                         msg=f"sign failed: {result.stderr}")
        return result

    def _verify(self, *extra):
        return subprocess.run(
            ["python3", str(SIGN_PY), "verify",
             "--key", str(self.pub),
             "--in", str(self.binary), *extra],
            capture_output=True, text=True,
        )

    def test_sign_without_attestation_keeps_v2_layout(self):
        self._sign()
        data = self.binary.read_bytes()
        # v2 second byte (after MAGIC) is VERSION_ALGO = 2
        block_start, *_ = sb._find_sig_block(data)
        self.assertIsNotNone(block_start)
        self.assertEqual(data[block_start + len(sb.MAGIC)], sb.VERSION_ALGO)
        r = self._verify()
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("Verified OK", r.stdout)
        self.assertNotIn("attestation", r.stdout)

    def test_sign_attest_auto_embeds_provenance(self):
        self._sign("--attest", "auto",
                   "--source-image-digest", "sha256:cafe")
        data = self.binary.read_bytes()
        block_start, sig, _keyid, _alg, att, attsig = sb._find_sig_block(data)
        self.assertIsNotNone(block_start)
        self.assertEqual(data[block_start + len(sb.MAGIC)],
                         sb.VERSION_ATTESTED)
        self.assertGreater(len(att), 0)
        self.assertGreater(len(attsig), 0)
        # Attestation must be valid in-toto Statement v1 with SLSA v1
        # predicate carrying our injected source-image-digest.
        statement = json.loads(att.decode("utf-8"))
        self.assertEqual(statement["_type"], sb.INTOTO_STATEMENT_TYPE)
        self.assertEqual(statement["predicateType"], sb.SLSA_PREDICATE_TYPE)
        self.assertEqual(
            statement["predicate"]["buildDefinition"]["externalParameters"][
                "sourceImageDigest"],
            "sha256:cafe",
        )
        # Subject digest must equal the binary content hash (excluding sig).
        content = data[:block_start]
        self.assertEqual(
            statement["subject"][0]["digest"]["sha512"],
            sb._hash_bytes(content, "sha512").hex(),
        )

    def test_verify_attestation_succeeds_and_is_announced(self):
        self._sign("--attest", "auto")
        r = self._verify()
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("attestation: ok", r.stdout)

    def test_verify_detects_tampered_attestation(self):
        self._sign("--attest", "auto")
        data = bytearray(self.binary.read_bytes())
        # Find the attestation bytes and flip a single byte inside them.
        block_start, _sig, _keyid, _alg, att, _attsig = (
            sb._find_sig_block(bytes(data)))
        idx = data.index(att)
        # Flip a byte in the middle of the JSON.
        data[idx + 5] ^= 0xFF
        self.binary.write_bytes(bytes(data))
        r = self._verify()
        self.assertEqual(r.returncode, 2, msg=r.stdout)
        self.assertIn("attestation", r.stderr.lower())

    def test_verify_require_attestation_fails_without_one(self):
        self._sign()  # no attestation
        r = self._verify("--require-attestation")
        self.assertEqual(r.returncode, 2, msg=r.stdout)
        self.assertIn("--require-attestation", r.stderr)

    def test_attest_show_emits_pretty_json(self):
        self._sign("--attest", "auto")
        r = subprocess.run(
            ["python3", str(SIGN_PY), "attest-show",
             "--in", str(self.binary)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        parsed = json.loads(r.stdout)
        self.assertEqual(parsed["_type"], sb.INTOTO_STATEMENT_TYPE)

    def test_attest_show_errors_when_no_attestation(self):
        self._sign()
        r = subprocess.run(
            ["python3", str(SIGN_PY), "attest-show",
             "--in", str(self.binary)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("no attestation", r.stderr)

    def test_attest_from_file_is_embedded_verbatim(self):
        provenance = {
            "_type":         sb.INTOTO_STATEMENT_TYPE,
            "subject":       [{"name": "binary", "digest": {"sha512": "x"}}],
            "predicateType": sb.SLSA_PREDICATE_TYPE,
            "predicate":     {"customField": "from-file"},
        }
        path = self.tmpdir / "prov.json"
        path.write_text(json.dumps(provenance))
        self._sign("--attest", str(path))
        data = self.binary.read_bytes()
        _block, _sig, _keyid, _alg, att, _attsig = sb._find_sig_block(data)
        loaded = json.loads(att.decode("utf-8"))
        self.assertEqual(loaded["predicate"]["customField"], "from-file")


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestAttestVerifyCosign(unittest.TestCase):
    """Cover the cosign-verification metadata embedded by --attest auto and
    re-checked by `attest-verify`.  No real cosign needed for these cases."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="oci2bin-cosign-"))
        self.priv = self.tmpdir / "priv.pem"
        self.pub = self.tmpdir / "pub.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(self.priv)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(self.priv),
             "-pubout", "-out", str(self.pub)],
            check=True, capture_output=True,
        )
        self.binary = self.tmpdir / "demo.bin"
        self.binary.write_bytes(b"\x7fELF-cosign-test\x00")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _sign_with_cosign_meta(self, **flags):
        cmd = ["python3", str(SIGN_PY), "sign",
               "--key", str(self.priv),
               "--in", str(self.binary),
               "--attest", "auto"]
        for k, v in flags.items():
            cmd += [f"--{k.replace('_', '-')}", v]
        r = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, msg=r.stderr)

    def test_cli_flags_recorded_in_provenance(self):
        self._sign_with_cosign_meta(
            cosign_image_ref="redis@sha256:" + ("a" * 64),
            cosign_key_path="/tmp/vendor.pub",
            cosign_result="verified",
            source_image_digest="redis@sha256:" + ("a" * 64),
        )
        data = self.binary.read_bytes()
        _block, _sig, _keyid, _alg, att, _attsig = sb._find_sig_block(data)
        parsed = json.loads(att.decode("utf-8"))
        cosign = parsed["predicate"]["runDetails"]["metadata"][
            "cosignVerification"]
        self.assertEqual(cosign["imageRef"], "redis@sha256:" + ("a" * 64))
        self.assertEqual(cosign["keyPath"], "/tmp/vendor.pub")
        self.assertEqual(cosign["result"], "verified")
        deps = parsed["predicate"]["buildDefinition"]["resolvedDependencies"]
        self.assertTrue(any("sha256" in (d.get("digest") or {})
                            for d in deps),
                        "resolvedDependencies should carry the source digest")

    def test_env_var_fallback_records_cosign(self):
        env = os.environ.copy()
        env["OCI2BIN_COSIGN_REF"] = "alpine:3.19"
        env["OCI2BIN_COSIGN_KEY"] = "/etc/keys/alpine.pub"
        env["OCI2BIN_COSIGN_RESULT"] = "verified"
        r = subprocess.run(
            ["python3", str(SIGN_PY), "sign",
             "--key", str(self.priv),
             "--in", str(self.binary),
             "--attest", "auto"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        data = self.binary.read_bytes()
        _block, _sig, _keyid, _alg, att, _attsig = sb._find_sig_block(data)
        parsed = json.loads(att.decode("utf-8"))
        cosign = parsed["predicate"]["runDetails"]["metadata"][
            "cosignVerification"]
        self.assertEqual(cosign["imageRef"], "alpine:3.19")
        self.assertEqual(cosign["keyPath"], "/etc/keys/alpine.pub")
        self.assertEqual(cosign["result"], "verified")

    def test_attest_verify_prints_recorded_result(self):
        self._sign_with_cosign_meta(
            cosign_image_ref="redis:7-alpine",
            cosign_key_path="/etc/vendor.pub",
            cosign_result="verified",
        )
        r = subprocess.run(
            ["python3", str(SIGN_PY), "attest-verify",
             "--in", str(self.binary)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("redis:7-alpine", r.stdout)
        self.assertIn("verified", r.stdout)

    def test_attest_verify_failed_recorded_result_exits_two(self):
        self._sign_with_cosign_meta(
            cosign_image_ref="bad:image",
            cosign_result="failed",
        )
        r = subprocess.run(
            ["python3", str(SIGN_PY), "attest-verify",
             "--in", str(self.binary)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 2, msg=r.stdout)

    def test_attest_verify_missing_cosign_field_exits_one(self):
        # Sign WITHOUT cosign metadata.
        subprocess.run(
            ["python3", str(SIGN_PY), "sign",
             "--key", str(self.priv),
             "--in", str(self.binary),
             "--attest", "auto"],
            capture_output=True, text=True, check=True,
        )
        r = subprocess.run(
            ["python3", str(SIGN_PY), "attest-verify",
             "--in", str(self.binary)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("cosignVerification", r.stderr)


def _fallback_read_att(path):
    """Read attestation directly via _find_sig_block (used when sb has no
    _read_attestation helper, e.g. older sign_binary versions)."""
    data = open(path, "rb").read()
    _block, _sig, _keyid, _alg, att, _attsig = sb._find_sig_block(data)
    return att.decode("utf-8") if att else "{}"


def _read_att_via_subprocess(binary):
    """Last-resort: invoke attest-show to read the attestation as JSON."""
    r = subprocess.run(
        ["python3", str(SIGN_PY), "attest-show", "--in", str(binary)],
        capture_output=True, text=True,
    )
    return r.stdout


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestSigBlockParser(unittest.TestCase):
    def test_oversized_attestation_length_is_rejected(self):
        # Build a fake v3 block whose attestation length exceeds
        # MAX_ATTESTATION_BYTES — the parser must refuse.
        import struct
        magic = sb.MAGIC
        version = sb.VERSION_ATTESTED
        keyid = b"\x00" * 32
        sig = b"\x00" * 64
        att_len_field = struct.pack(">I", sb.MAX_ATTESTATION_BYTES + 1)
        body = (
            magic + bytes([version, sb.HASH_ALGORITHMS["sha512"]]) + keyid
            + struct.pack(">H", len(sig)) + sig
            + att_len_field
        )
        total = len(body) + len(sb.TRAILER) + 4
        block = body + sb.TRAILER + struct.pack(">I", total)
        result = sb._find_sig_block(b"junk-binary-content" + block)
        self.assertEqual(result, (None, None, None, None, None, None))


if __name__ == "__main__":
    unittest.main()
