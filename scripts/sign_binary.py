#!/usr/bin/env python3
"""
sign_binary.py — Sign and verify oci2bin polyglot binaries.

Embedded signature block formats (appended to end of binary):
  v1 legacy:
    magic:    b"OCI2BIN_SIG\x00"      (12 bytes)
    version:  uint8 = 1               (1 byte)
    keyid:    SHA-256 of DER public key (32 bytes)
    siglen:   uint16 big-endian       (2 bytes)
    sig:      DER-encoded ECDSA signature (siglen bytes)
    trailer:  b"OCI2BIN_SIG_END\x00"  (16 bytes)
    totallen: uint32 big-endian

  v2:
    magic:    b"OCI2BIN_SIG\x00"
    version:  uint8 = 2
    hash_alg: uint8 (1=sha256, 3=sha512)
    keyid:    SHA-256 of DER public key
    siglen:   uint16 big-endian
    sig:      DER-encoded ECDSA signature
    trailer:  b"OCI2BIN_SIG_END\x00"
    totallen: uint32 big-endian

  v3 current — adds optional in-toto/SLSA attestation:
    magic:    b"OCI2BIN_SIG\x00"
    version:  uint8 = 3
    hash_alg: uint8
    keyid:    SHA-256 of DER public key
    siglen:   uint16 big-endian
    sig:      DER-encoded ECDSA signature over the binary content
    attlen:   uint32 big-endian      — 0 if no attestation embedded
    att:      attlen bytes (UTF-8 in-toto Statement v1 JSON)
    attsiglen:uint16 big-endian      — 0 if no attestation embedded
    attsig:   attsiglen bytes (DER ECDSA signature over att)
    trailer:  b"OCI2BIN_SIG_END\x00"
    totallen: uint32 big-endian

Detached signature files:
  legacy:
    raw DER ECDSA signature over SHA-256(file)

  current:
    magic:    b"OCI2BIN_DSIG\x00"
    version:  uint8 = 1
    hash_alg: uint8 (1=sha256, 3=sha512)
    siglen:   uint16 big-endian
    sig:      DER-encoded ECDSA signature

Usage:
  sign_binary.py sign --key KEY.pem --in BINARY [--out BINARY]
                      [--hash-algorithm sha256|sha512]
                      [--attest auto|FILE] [--source-image-digest DIGEST]
  sign_binary.py verify --key PUB.pem --in BINARY [--require-attestation]
  sign_binary.py attest-show --in BINARY
  sign_binary.py sign-file --key KEY.pem --in FILE --out SIG
                           [--hash-algorithm sha256|sha512]
  sign_binary.py verify-file --key PUB.pem --in FILE --sig SIG
"""

import argparse
import datetime
import hashlib
import json
import platform
import socket
import struct
import subprocess
import sys
import os
import tempfile
import uuid

MAGIC = b"OCI2BIN_SIG\x00"
TRAILER = b"OCI2BIN_SIG_END\x00"
DETACHED_MAGIC = b"OCI2BIN_DSIG\x00"
VERSION_LEGACY = 1
VERSION_ALGO = 2
VERSION_ATTESTED = 3
DETACHED_VERSION = 1
# Cap embedded attestation at 256 KiB so we never read an attacker-controlled
# uint32 length without bound.
MAX_ATTESTATION_BYTES = 256 * 1024
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
OCI2BIN_BUILD_TYPE = "https://oci2bin.dev/build/v1"
OCI2BIN_BUILDER_ID = "https://oci2bin.dev/builders/local"
HASH_ALGORITHMS = {
    "sha256": 1,
    "sha512": 3,
}
HASH_ALGORITHM_HEX_LENGTHS = {
    "sha256": 64,
    "sha512": 128,
}
HASH_ALGORITHMS_BY_ID = {
    ident: name for name, ident in HASH_ALGORITHMS.items()
}
DEFAULT_SIGNATURE_HASH = "sha512"

# Total trailing bytes: TRAILER(16) + totallen(4) = 20
FOOTER_SIZE = len(TRAILER) + 4


def _read_file_limited(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{path}: file too large")
    return data


def _normalize_hash_algorithm(name: str) -> str:
    algorithm = (name or "").lower()
    if algorithm not in HASH_ALGORITHMS:
        supported = ", ".join(sorted(HASH_ALGORITHMS))
        raise ValueError(
            f"unsupported hash algorithm {name!r}; use {supported}"
        )
    return algorithm


def _hash_bytes(data: bytes, algorithm: str) -> bytes:
    digest = hashlib.new(_normalize_hash_algorithm(algorithm))
    digest.update(data)
    return digest.digest()


def _hash_file(path: str, algorithm: str) -> bytes:
    digest = hashlib.new(_normalize_hash_algorithm(algorithm))
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.digest()


def _format_digest_spec(algorithm: str, hex_digest: str,
                        default_algorithm: str = "sha256") -> str:
    algorithm = _normalize_hash_algorithm(algorithm)
    hex_digest = hex_digest.lower()
    if algorithm == default_algorithm:
        return hex_digest
    return f"{algorithm}:{hex_digest}"


def _parse_digest_spec(value: str, *, default_algorithm: str = "sha256",
                       allow_auto: bool = False):
    if value is None:
        raise ValueError("missing digest value")
    if not isinstance(value, str):
        raise ValueError("digest value must be a string")
    if value == "auto":
        if not allow_auto:
            raise ValueError('digest value must not be "auto" here')
        return default_algorithm, "auto"
    algorithm = default_algorithm
    digest_value = value
    if ":" in value:
        algorithm, digest_value = value.split(":", 1)
        algorithm = _normalize_hash_algorithm(algorithm)
        if digest_value == "auto":
            if not allow_auto:
                raise ValueError('digest value must not be "auto" here')
            return algorithm, "auto"
    expected_len = HASH_ALGORITHM_HEX_LENGTHS[algorithm]
    if len(digest_value) != expected_len:
        raise ValueError(
            f"digest for {algorithm} must be {expected_len} hex chars"
        )
    try:
        int(digest_value, 16)
    except ValueError as exc:
        raise ValueError(
            f"digest for {algorithm} must be valid hexadecimal"
        ) from exc
    return algorithm, digest_value.lower()


def _compute_keyid(pubkey_pem: bytes) -> bytes:
    """Return the SHA-256 of the DER-encoded public key."""
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(pubkey_pem)
        f.flush()
        tmpname = f.name
    try:
        result = subprocess.run(
            ["openssl", "ec", "-pubin", "-in", tmpname,
             "-outform", "DER"],
            capture_output=True,
        )
        if result.returncode != 0:
            # Try as a private key and extract the public key
            result2 = subprocess.run(
                ["openssl", "ec", "-in", tmpname,
                 "-pubout", "-outform", "DER"],
                capture_output=True,
            )
            if result2.returncode != 0:
                raise RuntimeError(
                    "openssl ec failed: " + result2.stderr.decode(errors="replace")
                )
            der = result2.stdout
        else:
            der = result.stdout
    finally:
        os.unlink(tmpname)
    return hashlib.sha256(der).digest()


def _read_pubkey_der_from_privkey(privkey_pem: bytes) -> bytes:
    """Extract DER public key from a PEM private key."""
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(privkey_pem)
        f.flush()
        tmpname = f.name
    try:
        result = subprocess.run(
            ["openssl", "ec", "-in", tmpname, "-pubout", "-outform", "DER"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "Cannot extract public key: " + result.stderr.decode(errors="replace")
            )
        return result.stdout
    finally:
        os.unlink(tmpname)


def _find_sig_block(data: bytes):
    """
    Locate and parse the signature block at the end of data.
    Returns a 6-tuple:
        (content_end, sig_bytes, keyid, hash_algorithm,
         attestation_bytes, attestation_sig_bytes)
    or (None,)*6 if not signed. content_end is the offset where the sig block
    begins.  attestation_bytes / attestation_sig_bytes are non-empty only when
    a v3 block embeds an in-toto attestation.
    """
    not_signed = (None, None, None, None, None, None)
    if len(data) < FOOTER_SIZE:
        return not_signed
    trailer_pos = len(data) - FOOTER_SIZE
    if data[trailer_pos:trailer_pos + len(TRAILER)] != TRAILER:
        return not_signed
    total_len = struct.unpack(">I", data[-4:])[0]
    min_legacy_len = len(MAGIC) + 1 + 32 + 2 + len(TRAILER) + 4
    min_v2_len = len(MAGIC) + 1 + 1 + 32 + 2 + len(TRAILER) + 4
    min_v3_len = min_v2_len + 4 + 2  # attlen + attsiglen
    if total_len > len(data) or total_len < min_legacy_len:
        return not_signed
    block_start = len(data) - total_len
    if data[block_start:block_start + len(MAGIC)] != MAGIC:
        return not_signed
    block_end_excl_footer = trailer_pos
    off = block_start + len(MAGIC)
    version = data[off]
    if version == VERSION_LEGACY:
        algorithm = "sha256"
    elif version in (VERSION_ALGO, VERSION_ATTESTED):
        min_required = (min_v3_len if version == VERSION_ATTESTED
                        else min_v2_len)
        if total_len < min_required:
            return not_signed
        off += 1
        algorithm = HASH_ALGORITHMS_BY_ID.get(data[off])
        if algorithm is None:
            return not_signed
    else:
        return not_signed
    off += 1
    keyid = data[off:off + 32]
    off += 32
    siglen = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    sig = data[off:off + siglen]
    if len(sig) != siglen:
        return not_signed
    off += siglen

    att_bytes = b""
    att_sig = b""
    if version == VERSION_ATTESTED:
        if off + 4 > block_end_excl_footer:
            return not_signed
        attlen = struct.unpack(">I", data[off:off + 4])[0]
        off += 4
        if attlen > MAX_ATTESTATION_BYTES:
            return not_signed
        if off + attlen > block_end_excl_footer:
            return not_signed
        att_bytes = data[off:off + attlen]
        off += attlen
        if off + 2 > block_end_excl_footer:
            return not_signed
        attsiglen = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        if off + attsiglen > block_end_excl_footer:
            return not_signed
        att_sig = data[off:off + attsiglen]
        off += attsiglen
    if off != block_end_excl_footer:
        # Trailing junk between sig payload and the trailer — refuse rather
        # than silently accept extra bytes that aren't covered by either sig.
        return not_signed
    return block_start, sig, keyid, algorithm, att_bytes, att_sig


def _encode_detached_signature(algorithm: str, sig_bytes: bytes) -> bytes:
    algorithm = _normalize_hash_algorithm(algorithm)
    return (
        DETACHED_MAGIC
        + bytes([DETACHED_VERSION, HASH_ALGORITHMS[algorithm]])
        + struct.pack(">H", len(sig_bytes))
        + sig_bytes
    )


def _decode_detached_signature(data: bytes):
    if not data.startswith(DETACHED_MAGIC):
        return "sha256", data
    header_len = len(DETACHED_MAGIC) + 1 + 1 + 2
    if len(data) < header_len:
        raise ValueError("detached signature header truncated")
    version = data[len(DETACHED_MAGIC)]
    if version != DETACHED_VERSION:
        raise ValueError("unsupported detached signature version")
    algorithm = HASH_ALGORITHMS_BY_ID.get(data[len(DETACHED_MAGIC) + 1])
    if algorithm is None:
        raise ValueError("unsupported detached signature hash algorithm")
    siglen = struct.unpack(">H", data[len(DETACHED_MAGIC) + 2:header_len])[0]
    sig = data[header_len:]
    if len(sig) != siglen:
        raise ValueError("detached signature length mismatch")
    return algorithm, sig


def _utc_now_iso() -> str:
    return datetime.datetime.now(
        tz=datetime.timezone.utc).isoformat(timespec="seconds")


def _read_oci2bin_version() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.normpath(os.path.join(here, "..", "pyproject.toml"))
    try:
        with open(candidate, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("version") and "=" in line:
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return "unknown"


COSIGN_RESULTS = {"verified", "failed", "skipped", "unavailable"}


def _build_auto_provenance(content_hash: bytes, algorithm: str,
                           source_image_digest: str = "",
                           cosign_image_ref: str = "",
                           cosign_key_path: str = "",
                           cosign_result: str = "") -> dict:
    """
    Build an in-toto Statement v1 with a SLSA provenance v1 predicate
    describing the just-built binary.  No external tools are required.

    When the build pipeline ran `cosign verify` on the source image, the
    outcome is recorded under predicate.runDetails.metadata.cosignVerification
    AND the source image is added to predicate.buildDefinition
    .resolvedDependencies.  oci2bin attest verify re-verifies the signature
    using the recorded image ref + key path.
    """
    subject_digest = {algorithm: content_hash.hex()}
    started_on = _utc_now_iso()
    invocation_id = str(uuid.uuid4())
    external_params: dict = {}
    resolved_deps: list = []
    if source_image_digest:
        external_params["sourceImageDigest"] = source_image_digest
        resolved_deps.append({
            "uri":    f"docker://{source_image_digest}"
                      if "/" in source_image_digest
                      else source_image_digest,
            "digest": _digest_dict_from_ref(source_image_digest),
        })
    metadata = {
        "invocationId": invocation_id,
        "startedOn":    started_on,
        "finishedOn":   started_on,
    }
    if cosign_image_ref:
        cosign_info = {
            "imageRef": cosign_image_ref,
            "result":   cosign_result or "unknown",
        }
        if cosign_key_path:
            cosign_info["keyPath"] = cosign_key_path
        metadata["cosignVerification"] = cosign_info
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{
            "name":   "binary",
            "digest": subject_digest,
        }],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType":          OCI2BIN_BUILD_TYPE,
                "externalParameters": external_params,
                "internalParameters": {
                    "oci2binVersion": _read_oci2bin_version(),
                    "hostArch":       platform.machine() or "unknown",
                    "hostKernel":     platform.release() or "unknown",
                    "hostname":       socket.gethostname() or "unknown",
                },
                "resolvedDependencies": resolved_deps,
            },
            "runDetails": {
                "builder": {"id": OCI2BIN_BUILDER_ID},
                "metadata": metadata,
            },
        },
    }


def _digest_dict_from_ref(ref: str) -> dict:
    """Convert a docker-style ref like `image@sha256:hex` into a SLSA
    digest dict.  Returns an empty dict if the ref has no @sha-prefix."""
    at = ref.rfind("@")
    if at < 0:
        return {}
    digest_part = ref[at + 1:]
    colon = digest_part.find(":")
    if colon < 0:
        return {}
    algo = digest_part[:colon].lower()
    hex_digest = digest_part[colon + 1:].lower()
    if algo not in ("sha256", "sha512"):
        return {}
    expected_len = HASH_ALGORITHM_HEX_LENGTHS.get(algo)
    if expected_len and len(hex_digest) != expected_len:
        return {}
    return {algo: hex_digest}


def _load_provenance_file(path: str) -> dict:
    try:
        size = os.stat(path).st_size
    except OSError as e:
        raise RuntimeError(f"--attest: cannot stat {path}: {e}") from e
    if size > MAX_ATTESTATION_BYTES:
        raise RuntimeError(
            f"--attest: file too large ({size} > {MAX_ATTESTATION_BYTES})"
        )
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"--attest: {path} is not valid JSON: {e}") from e


def _attestation_bytes(att_json: dict) -> bytes:
    """Canonical UTF-8 JSON encoding for the attestation embedded in the
    binary.  Sorted keys + no extraneous whitespace gives a stable input to
    the signature so the same JSON object always produces the same bytes."""
    return json.dumps(att_json, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def cmd_sign(args):
    in_path = args.input
    out_path = args.output if args.output else in_path

    with open(args.key, "rb") as f:
        key_pem = f.read()
    if len(key_pem) > 65536:
        print("sign_binary: key file too large", file=sys.stderr)
        sys.exit(1)

    with open(in_path, "rb") as f:
        data = f.read()

    # Strip any existing sig block
    block_start, _, _, _, _, _ = _find_sig_block(data)
    if block_start is not None:
        data = data[:block_start]

    # Compute key ID from private key's public part
    keyid = _compute_keyid(key_pem)

    algorithm = _normalize_hash_algorithm(args.hash_algorithm)
    content_hash = _hash_bytes(data, algorithm)

    sig_bytes = _sign_hash_with_key(args.key, content_hash, algorithm)
    if len(sig_bytes) > 65535:
        print("sign_binary: signature too large", file=sys.stderr)
        sys.exit(1)

    # Build optional in-toto attestation (v3 only).
    att_bytes = b""
    att_sig = b""
    attest_arg = getattr(args, "attest", None)
    source_image_digest = getattr(args, "source_image_digest", None) or ""
    if attest_arg:
        try:
            if attest_arg == "auto":
                # Cosign metadata: prefer explicit CLI flags, fall back to
                # env vars set by the bash build pipeline so users don't
                # need to thread the same info twice.
                cosign_ref = (getattr(args, "cosign_image_ref", None)
                              or os.environ.get("OCI2BIN_COSIGN_REF", ""))
                cosign_key = (getattr(args, "cosign_key_path", None)
                              or os.environ.get("OCI2BIN_COSIGN_KEY", ""))
                cosign_res = (getattr(args, "cosign_result", None)
                              or os.environ.get("OCI2BIN_COSIGN_RESULT", ""))
                att_json = _build_auto_provenance(
                    content_hash, algorithm, source_image_digest,
                    cosign_image_ref=cosign_ref,
                    cosign_key_path=cosign_key,
                    cosign_result=cosign_res)
            else:
                att_json = _load_provenance_file(attest_arg)
        except RuntimeError as e:
            print(f"sign_binary: {e}", file=sys.stderr)
            sys.exit(1)
        att_bytes = _attestation_bytes(att_json)
        if len(att_bytes) > MAX_ATTESTATION_BYTES:
            print("sign_binary: attestation too large "
                  f"({len(att_bytes)} > {MAX_ATTESTATION_BYTES})",
                  file=sys.stderr)
            sys.exit(1)
        att_digest = _hash_bytes(att_bytes, algorithm)
        att_sig = _sign_hash_with_key(args.key, att_digest, algorithm)
        if len(att_sig) > 65535:
            print("sign_binary: attestation signature too large",
                  file=sys.stderr)
            sys.exit(1)

    siglen = len(sig_bytes)
    if att_bytes or att_sig:
        version_byte = VERSION_ATTESTED
        body = (
            MAGIC
            + bytes([version_byte, HASH_ALGORITHMS[algorithm]])
            + keyid
            + struct.pack(">H", siglen)
            + sig_bytes
            + struct.pack(">I", len(att_bytes))
            + att_bytes
            + struct.pack(">H", len(att_sig))
            + att_sig
        )
    else:
        version_byte = VERSION_ALGO
        body = (
            MAGIC
            + bytes([version_byte, HASH_ALGORITHMS[algorithm]])
            + keyid
            + struct.pack(">H", siglen)
            + sig_bytes
        )
    total_len = len(body) + len(TRAILER) + 4
    block = body + TRAILER + struct.pack(">I", total_len)

    with open(out_path, "wb") as f:
        f.write(data + block)

    # Make output executable
    st = os.stat(out_path)
    os.chmod(out_path, st.st_mode | 0o111)

    suffix = " +attestation" if att_bytes else ""
    print(f"Signed: {out_path} (keyid: {keyid.hex()[:16]}...{suffix})")
    return 0


def cmd_verify(args):
    try:
        pub_pem = _read_file_limited(args.key, 65536)
    except ValueError:
        print("sign_binary: key file too large", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        data = f.read()

    (block_start, sig_bytes, keyid, algorithm,
     att_bytes, att_sig) = _find_sig_block(data)
    if block_start is None:
        print(f"sign_binary: {args.input}: not signed", file=sys.stderr)
        sys.exit(1)

    content = data[:block_start]

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(pub_pem)
        key_path = kf.name
    try:
        binary_ok = _verify_hash_with_key(
            key_path, _hash_bytes(content, algorithm), sig_bytes, algorithm)
        attestation_ok = None
        if att_bytes or att_sig:
            attestation_ok = bool(att_bytes) and bool(att_sig) and \
                _verify_hash_with_key(
                    key_path, _hash_bytes(att_bytes, algorithm),
                    att_sig, algorithm)
    finally:
        os.unlink(key_path)

    require_att = bool(getattr(args, "require_attestation", False))
    if require_att and not att_bytes:
        print(f"sign_binary: {args.input}: --require-attestation set but"
              " no attestation embedded", file=sys.stderr)
        sys.exit(2)

    if not binary_ok:
        print(f"Verification FAILED: {args.input}", file=sys.stderr)
        sys.exit(2)

    if attestation_ok is False:
        print(f"Verification FAILED (attestation): {args.input}",
              file=sys.stderr)
        sys.exit(2)

    suffix = ""
    if attestation_ok is True:
        suffix = ", attestation: ok"
    elif att_bytes and not attestation_ok:
        # unreachable — guarded by branch above, but kept for safety.
        suffix = ", attestation: BAD"
    print(
        f"Verified OK: {args.input} "
        f"(keyid: {keyid.hex()[:16]}..., hash: {algorithm}{suffix})"
    )
    return 0


def _read_attestation(binary_path):
    """Read the embedded attestation JSON from a signed binary.  Returns
    the parsed dict.  Raises RuntimeError if the binary isn't signed or
    has no attestation."""
    with open(binary_path, "rb") as f:
        data = f.read()
    block_start, _sig, _keyid, _algorithm, att_bytes, _att_sig = \
        _find_sig_block(data)
    if block_start is None:
        raise RuntimeError(f"{binary_path}: not signed")
    if not att_bytes:
        raise RuntimeError(f"{binary_path}: no attestation embedded")
    try:
        return json.loads(att_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RuntimeError(
            f"{binary_path}: corrupt attestation: {e}") from e


def cmd_attest_verify(args):
    """
    Verify the embedded attestation's recorded cosign verification by
    re-running cosign verify against the source image referenced in the
    provenance.  This complements `oci2bin verify`, which checks that
    the attestation is signed by the trusted key — `attest verify`
    additionally checks that the image the attestation describes still
    has a valid cosign signature today.
    """
    try:
        att = _read_attestation(args.input)
    except RuntimeError as e:
        print(f"sign_binary: {e}", file=sys.stderr)
        sys.exit(1)
    cosign = (att.get("predicate", {}).get("runDetails", {})
              .get("metadata", {}).get("cosignVerification"))
    if not cosign:
        print(f"sign_binary: {args.input}: attestation has no "
              "cosignVerification field — was the binary built with "
              "--verify-cosign?", file=sys.stderr)
        sys.exit(1)
    image_ref = cosign.get("imageRef")
    if not image_ref:
        print(f"sign_binary: {args.input}: cosignVerification is missing "
              "imageRef", file=sys.stderr)
        sys.exit(1)
    recorded_result = cosign.get("result", "unknown")
    key_path = cosign.get("keyPath", "")
    print(f"Source image:        {image_ref}")
    print(f"Recorded result:     {recorded_result}")
    if key_path:
        print(f"Recorded key path:   {key_path}")

    if not args.recheck:
        # No re-check requested — just print the recorded outcome.
        if recorded_result == "verified":
            return 0
        if recorded_result in ("failed",):
            sys.exit(2)
        sys.exit(1)

    # Re-run cosign verify with the recorded image ref + key.
    cosign_bin = shutil_which("cosign")
    if not cosign_bin:
        print("sign_binary: cosign not installed; cannot --recheck",
              file=sys.stderr)
        sys.exit(1)
    cosign_argv = [cosign_bin, "verify"]
    chosen_key = args.key or key_path
    if chosen_key:
        cosign_argv += ["--key", chosen_key]
    cosign_argv.append(image_ref)
    proc = subprocess.run(cosign_argv, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr_tail = proc.stderr.splitlines()[-3:]
        print("\nLive cosign verify FAILED:", file=sys.stderr)
        for line in stderr_tail:
            print(f"  {line}", file=sys.stderr)
        sys.exit(2)
    print("\nLive cosign verify: OK")
    return 0


def shutil_which(prog):
    """Stdlib-only shutil.which shim — kept here so the test stubs can
    monkey-patch this single hook to inject a fake cosign binary."""
    import shutil as _shutil
    return _shutil.which(prog)


def cmd_attest_show(args):
    with open(args.input, "rb") as f:
        data = f.read()
    (block_start, _sig, _keyid, _algorithm,
     att_bytes, _att_sig) = _find_sig_block(data)
    if block_start is None:
        print(f"sign_binary: {args.input}: not signed", file=sys.stderr)
        sys.exit(1)
    if not att_bytes:
        print(f"sign_binary: {args.input}: no attestation embedded",
              file=sys.stderr)
        sys.exit(1)
    try:
        parsed = json.loads(att_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"sign_binary: {args.input}: corrupt attestation: {e}",
              file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(json.dumps(parsed, indent=2, sort_keys=True))
    sys.stdout.write("\n")
    return 0


def _sign_hash_with_key(key_path: str, digest: bytes, algorithm: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as hashf:
        hashf.write(digest)
        hash_path = hashf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sigf:
        sig_path = sigf.name
    try:
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign",
             "-inkey", key_path,
             "-in", hash_path,
             "-out", sig_path,
             "-pkeyopt", f"digest:{algorithm}"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "openssl sign failed: "
                + result.stderr.decode(errors="replace")
            )
        with open(sig_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(hash_path)
        os.unlink(sig_path)


def _verify_hash_with_key(key_path: str, digest: bytes, sig_bytes: bytes,
                          algorithm: str) -> bool:
    try:
        key_data = _read_file_limited(key_path, 65536)
    except ValueError:
        return False
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_data)
        key_tmp = kf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as hf:
        hf.write(digest)
        hash_path = hf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sf:
        sf.write(sig_bytes)
        sig_path = sf.name
    try:
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify",
             "-pubin", "-inkey", key_tmp,
             "-in", hash_path,
             "-sigfile", sig_path,
             "-pkeyopt", f"digest:{algorithm}"],
            capture_output=True,
        )
        return result.returncode == 0
    finally:
        os.unlink(key_tmp)
        os.unlink(hash_path)
        os.unlink(sig_path)


def cmd_sign_file(args):
    algorithm = _normalize_hash_algorithm(args.hash_algorithm)
    digest = _hash_file(args.input, algorithm)
    sig_bytes = _sign_hash_with_key(args.key, digest, algorithm)
    with open(args.output, "wb") as f:
        f.write(_encode_detached_signature(algorithm, sig_bytes))
    print(f"Signed file: {args.input} -> {args.output} ({algorithm})")
    return 0


def cmd_verify_file(args):
    try:
        sig_data = _read_file_limited(args.sig, 65535 + 32)
    except ValueError:
        print("sign_binary: signature too large", file=sys.stderr)
        sys.exit(1)
    try:
        algorithm, sig_bytes = _decode_detached_signature(sig_data)
    except ValueError as exc:
        print(f"sign_binary: {args.sig}: {exc}", file=sys.stderr)
        sys.exit(1)
    digest = _hash_file(args.input, algorithm)
    if _verify_hash_with_key(args.key, digest, sig_bytes, algorithm):
        print(f"Verified file OK: {args.input}")
        return 0
    print(f"File verification FAILED: {args.input}", file=sys.stderr)
    sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Sign and verify oci2bin binaries")
    sub = parser.add_subparsers(dest="cmd")

    p_sign = sub.add_parser("sign", help="Sign a binary")
    p_sign.add_argument("--key", required=True, help="PEM private key")
    p_sign.add_argument("--in", dest="input", required=True, help="Input binary")
    p_sign.add_argument("--out", dest="output", help="Output binary (default: in-place)")
    p_sign.add_argument("--hash-algorithm", default=DEFAULT_SIGNATURE_HASH,
                        choices=sorted(HASH_ALGORITHMS),
                        help="Digest used before signing (default: %(default)s)")
    p_sign.add_argument("--attest", default=None,
                        help="Embed an in-toto/SLSA provenance attestation. "
                        "Pass 'auto' to auto-generate one, or a path to a "
                        "JSON file containing a Statement v1 to embed.")
    p_sign.add_argument("--source-image-digest", default=None,
                        help="Source OCI image digest, recorded in the auto-"
                        "generated attestation as externalParameters.")
    p_sign.add_argument("--cosign-image-ref", default=None,
                        help="Source image reference passed to cosign verify "
                        "during the build.  Recorded in the attestation so "
                        "`oci2bin attest verify` can re-check the signature.")
    p_sign.add_argument("--cosign-key-path", default=None,
                        help="Public key path used by cosign verify.  "
                        "Recorded alongside --cosign-image-ref.")
    p_sign.add_argument("--cosign-result", default=None,
                        choices=sorted(COSIGN_RESULTS),
                        help="Outcome of the build-time cosign verification "
                        "(verified|failed|skipped|unavailable).")

    p_verify = sub.add_parser("verify", help="Verify a binary signature")
    p_verify.add_argument("--key", required=True, help="PEM public key")
    p_verify.add_argument("--in", dest="input", required=True, help="Binary to verify")
    p_verify.add_argument("--require-attestation", action="store_true",
                          help="Fail if no in-toto attestation is embedded")

    p_attest = sub.add_parser("attest-show",
                              help="Print the embedded in-toto attestation")
    p_attest.add_argument("--in", dest="input", required=True,
                          help="Signed binary to inspect")

    p_atv = sub.add_parser("attest-verify",
                           help="Verify the embedded attestation's "
                                "cosign-verification record")
    p_atv.add_argument("--in", dest="input", required=True,
                       help="Signed binary to verify")
    p_atv.add_argument("--recheck", action="store_true",
                       help="Re-run cosign verify against the source image "
                            "referenced in the attestation (requires cosign)")
    p_atv.add_argument("--key", default=None,
                       help="Override the cosign public key path "
                            "(default: use the path recorded in the "
                            "attestation, if any)")

    p_sign_file = sub.add_parser("sign-file", help="Sign an arbitrary file")
    p_sign_file.add_argument("--key", required=True, help="PEM private key")
    p_sign_file.add_argument("--in", dest="input", required=True, help="Input file")
    p_sign_file.add_argument("--out", dest="output", required=True,
                             help="Detached signature output path")
    p_sign_file.add_argument("--hash-algorithm",
                             default=DEFAULT_SIGNATURE_HASH,
                             choices=sorted(HASH_ALGORITHMS),
                             help="Digest used before signing "
                                  "(default: %(default)s)")

    p_verify_file = sub.add_parser("verify-file",
                                   help="Verify a detached file signature")
    p_verify_file.add_argument("--key", required=True, help="PEM public key")
    p_verify_file.add_argument("--in", dest="input", required=True, help="Input file")
    p_verify_file.add_argument("--sig", required=True,
                               help="Detached signature path")

    args = parser.parse_args()
    if args.cmd == "sign":
        sys.exit(cmd_sign(args))
    elif args.cmd == "verify":
        sys.exit(cmd_verify(args))
    elif args.cmd == "attest-show":
        sys.exit(cmd_attest_show(args))
    elif args.cmd == "attest-verify":
        sys.exit(cmd_attest_verify(args))
    elif args.cmd == "sign-file":
        sys.exit(cmd_sign_file(args))
    elif args.cmd == "verify-file":
        sys.exit(cmd_verify_file(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
