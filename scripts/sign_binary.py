#!/usr/bin/env python3
"""
sign_binary.py — Sign and verify oci2bin polyglot binaries.

Signature block format (appended to end of binary):
  magic:    b"OCI2BIN_SIG\x00"  (12 bytes)
  version:  uint8 = 1            (1 byte)
  keyid:    SHA-256 of DER public key (32 bytes)
  siglen:   uint16 big-endian   (2 bytes)
  sig:      DER-encoded ECDSA signature (siglen bytes)
  trailer:  b"OCI2BIN_SIG_END\x00" (16 bytes)
  totallen: uint32 big-endian total block length including magic+trailer+totallen (4 bytes)

Usage:
  sign_binary.py sign --key KEY.pem --in BINARY [--out BINARY]
  sign_binary.py verify --key PUB.pem --in BINARY
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
VERSION = 1

# Total trailing bytes: TRAILER(16) + totallen(4) = 20
FOOTER_SIZE = len(TRAILER) + 4


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
    Returns (content_end, sig_bytes, keyid) or (None, None, None) if not signed.
    content_end is the offset where the sig block begins.
    """
    if len(data) < FOOTER_SIZE:
        return None, None, None
    trailer_pos = len(data) - FOOTER_SIZE
    if data[trailer_pos:trailer_pos + len(TRAILER)] != TRAILER:
        return None, None, None
    total_len = struct.unpack(">I", data[-4:])[0]
    if total_len > len(data) or total_len < len(MAGIC) + 1 + 32 + 2 + len(TRAILER) + 4:
        return None, None, None
    block_start = len(data) - total_len
    if data[block_start:block_start + len(MAGIC)] != MAGIC:
        return None, None, None
    off = block_start + len(MAGIC)
    version = data[off]
    if version != VERSION:
        return None, None, None
    off += 1
    keyid = data[off:off + 32]
    off += 32
    siglen = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    sig = data[off:off + siglen]
    if len(sig) != siglen:
        return None, None, None
    return block_start, sig, keyid


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
    block_start, _, _ = _find_sig_block(data)
    if block_start is not None:
        data = data[:block_start]

    # Compute key ID from private key's public part
    keyid = _compute_keyid(key_pem)

    # Sign SHA-256 of the content
    content_hash = hashlib.sha256(data).digest()

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
             "-pkeyopt", "digest:sha256"],
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
    # total = MAGIC(12) + version(1) + keyid(32) + siglen(2) + sig + TRAILER(16) + totallen(4)
    total_len = len(MAGIC) + 1 + 32 + 2 + siglen + len(TRAILER) + 4
    block = (
        MAGIC
        + bytes([VERSION])
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
    with open(args.key, "rb") as f:
        pub_pem = f.read()
    if len(pub_pem) > 65536:
        print("sign_binary: key file too large", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        data = f.read()

    block_start, sig_bytes, keyid = _find_sig_block(data)
    if block_start is None:
        print(f"sign_binary: {args.input}: not signed", file=sys.stderr)
        sys.exit(1)

    content = data[:block_start]
    content_hash = hashlib.sha256(content).digest()

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
             "-pkeyopt", "digest:sha256"],
            capture_output=True,
        )
        verified = result.returncode == 0
    finally:
        os.unlink(key_path)
        os.unlink(hash_path)
        os.unlink(sig_path)

    if verified:
        print(f"Verified OK: {args.input} (keyid: {keyid.hex()[:16]}...)")
        return 0
    else:
        print(f"Verification FAILED: {args.input}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Sign and verify oci2bin binaries")
    sub = parser.add_subparsers(dest="cmd")

    p_sign = sub.add_parser("sign", help="Sign a binary")
    p_sign.add_argument("--key", required=True, help="PEM private key")
    p_sign.add_argument("--in", dest="input", required=True, help="Input binary")
    p_sign.add_argument("--out", dest="output", help="Output binary (default: in-place)")

    p_verify = sub.add_parser("verify", help="Verify a binary signature")
    p_verify.add_argument("--key", required=True, help="PEM public key")
    p_verify.add_argument("--in", dest="input", required=True, help="Binary to verify")

    args = parser.parse_args()
    if args.cmd == "sign":
        sys.exit(cmd_sign(args))
    elif args.cmd == "verify":
        sys.exit(cmd_verify(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
