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

  v2 current:
    magic:    b"OCI2BIN_SIG\x00"
    version:  uint8 = 2
    hash_alg: uint8 (1=sha256, 3=sha512)
    keyid:    SHA-256 of DER public key
    siglen:   uint16 big-endian
    sig:      DER-encoded ECDSA signature
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
  sign_binary.py verify --key PUB.pem --in BINARY
  sign_binary.py sign-file --key KEY.pem --in FILE --out SIG
                           [--hash-algorithm sha256|sha512]
  sign_binary.py verify-file --key PUB.pem --in FILE --sig SIG
"""

import argparse
import hashlib
import struct
import subprocess
import sys
import os
import tempfile

MAGIC = b"OCI2BIN_SIG\x00"
TRAILER = b"OCI2BIN_SIG_END\x00"
DETACHED_MAGIC = b"OCI2BIN_DSIG\x00"
VERSION_LEGACY = 1
VERSION_ALGO = 2
DETACHED_VERSION = 1
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
    Returns (content_end, sig_bytes, keyid, hash_algorithm) or
    (None, None, None, None) if not signed. content_end is the offset where
    the sig block begins.
    """
    if len(data) < FOOTER_SIZE:
        return None, None, None, None
    trailer_pos = len(data) - FOOTER_SIZE
    if data[trailer_pos:trailer_pos + len(TRAILER)] != TRAILER:
        return None, None, None, None
    total_len = struct.unpack(">I", data[-4:])[0]
    min_legacy_len = len(MAGIC) + 1 + 32 + 2 + len(TRAILER) + 4
    min_current_len = len(MAGIC) + 1 + 1 + 32 + 2 + len(TRAILER) + 4
    if total_len > len(data) or total_len < min_legacy_len:
        return None, None, None, None
    block_start = len(data) - total_len
    if data[block_start:block_start + len(MAGIC)] != MAGIC:
        return None, None, None, None
    off = block_start + len(MAGIC)
    version = data[off]
    if version == VERSION_LEGACY:
        algorithm = "sha256"
    elif version == VERSION_ALGO:
        if total_len < min_current_len:
            return None, None, None, None
        off += 1
        algorithm = HASH_ALGORITHMS_BY_ID.get(data[off])
        if algorithm is None:
            return None, None, None, None
    else:
        return None, None, None, None
    off += 1
    keyid = data[off:off + 32]
    off += 32
    siglen = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    sig = data[off:off + siglen]
    if len(sig) != siglen:
        return None, None, None, None
    return block_start, sig, keyid, algorithm


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
    block_start, _, _, _ = _find_sig_block(data)
    if block_start is not None:
        data = data[:block_start]

    # Compute key ID from private key's public part
    keyid = _compute_keyid(key_pem)

    algorithm = _normalize_hash_algorithm(args.hash_algorithm)
    content_hash = _hash_bytes(data, algorithm)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as hashf:
        hashf.write(content_hash)
        hash_path = hashf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sigf:
        sig_path = sigf.name

    try:
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign",
             "-inkey", args.key,
             "-in", hash_path,
             "-out", sig_path,
             "-pkeyopt", f"digest:{algorithm}"],
            capture_output=True,
        )
        if result.returncode != 0:
            print("sign_binary: openssl sign failed:",
                  result.stderr.decode(errors="replace"), file=sys.stderr)
            sys.exit(1)
        with open(sig_path, "rb") as f:
            sig_bytes = f.read()
    finally:
        os.unlink(hash_path)
        os.unlink(sig_path)

    if len(sig_bytes) > 65535:
        print("sign_binary: signature too large", file=sys.stderr)
        sys.exit(1)

    # Build block
    siglen = len(sig_bytes)
    total_len = len(MAGIC) + 1 + 1 + 32 + 2 + siglen + len(TRAILER) + 4
    block = (
        MAGIC
        + bytes([VERSION_ALGO, HASH_ALGORITHMS[algorithm]])
        + keyid
        + struct.pack(">H", siglen)
        + sig_bytes
        + TRAILER
        + struct.pack(">I", total_len)
    )

    with open(out_path, "wb") as f:
        f.write(data + block)

    # Make output executable
    st = os.stat(out_path)
    os.chmod(out_path, st.st_mode | 0o111)

    print(f"Signed: {out_path} (keyid: {keyid.hex()[:16]}...)")
    return 0


def cmd_verify(args):
    try:
        pub_pem = _read_file_limited(args.key, 65536)
    except ValueError:
        print("sign_binary: key file too large", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        data = f.read()

    block_start, sig_bytes, keyid, algorithm = _find_sig_block(data)
    if block_start is None:
        print(f"sign_binary: {args.input}: not signed", file=sys.stderr)
        sys.exit(1)

    content = data[:block_start]
    content_hash = _hash_bytes(content, algorithm)

    # Verify using openssl pkeyutl
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(pub_pem)
        key_path = kf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as hf:
        hf.write(content_hash)
        hash_path = hf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sf:
        sf.write(sig_bytes)
        sig_path = sf.name

    try:
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify",
             "-pubin", "-inkey", key_path,
             "-in", hash_path,
             "-sigfile", sig_path,
             "-pkeyopt", f"digest:{algorithm}"],
            capture_output=True,
        )
        verified = result.returncode == 0
    finally:
        os.unlink(key_path)
        os.unlink(hash_path)
        os.unlink(sig_path)

    if verified:
        print(
            f"Verified OK: {args.input} "
            f"(keyid: {keyid.hex()[:16]}..., hash: {algorithm})"
        )
        return 0
    else:
        print(f"Verification FAILED: {args.input}", file=sys.stderr)
        sys.exit(2)


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

    p_verify = sub.add_parser("verify", help="Verify a binary signature")
    p_verify.add_argument("--key", required=True, help="PEM public key")
    p_verify.add_argument("--in", dest="input", required=True, help="Binary to verify")

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
    elif args.cmd == "sign-file":
        sys.exit(cmd_sign_file(args))
    elif args.cmd == "verify-file":
        sys.exit(cmd_verify_file(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
