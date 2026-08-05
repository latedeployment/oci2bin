#!/usr/bin/env bash
# End-to-end check for --secret tpm2:NAME.
#
# The loader never talks to the TPM itself — it execs `systemd-creds decrypt`,
# which does. So this script exercises the whole oci2bin path (credential
# lookup, safety check, stdin plumbing, ramfs staging, read-only bind mount)
# and works with or without a TPM:
#
#   with a TPM2 device  -> seals with --with-key=tpm2   (full TPM path)
#   without one         -> seals with --with-key=host   (identical code path
#                                                        in oci2bin)
#
# Requires root: systemd-creds needs /var/lib/systemd/credential.secret and,
# for TPM2-bound credentials, /dev/tpmrm0.
#
# Usage: sudo bash scripts/test_tpm2_secret.sh ./app.bin
set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "usage: sudo bash $0 /path/to/oci2bin-built-binary" >&2
    exit 2
fi

if [[ "$(id -u)" != "0" ]]; then
    echo "FAIL: must run as root (systemd-creds needs the host credential key)" >&2
    exit 2
fi

command -v systemd-creds >/dev/null || { echo "FAIL: systemd-creds not in PATH" >&2; exit 2; }

CRED_NAME="oci2bin-selftest"
CRED_DIR="/etc/credstore.encrypted"
CRED_FILE="$CRED_DIR/$CRED_NAME"
PLAINTEXT="oci2bin-tpm2-selftest-$RANDOM$RANDOM"
FAILED=0

cleanup() { rm -f "$CRED_FILE"; }
trap cleanup EXIT

# ── 1. what key can we seal with? ────────────────────────────────────────────
if systemd-analyze has-tpm2 >/dev/null 2>&1; then
    KEY=tpm2
    echo "== TPM2 present: sealing with --with-key=tpm2 (full TPM path)"
else
    KEY=host
    echo "== no TPM2 device: sealing with --with-key=host"
    echo "   (same oci2bin code path; only the systemd key type differs)"
    echo "   to get a real TPM here, add an emulated one to the VM — see below"
fi

# ── 2. seal a credential into the system credential store ────────────────────
mkdir -p "$CRED_DIR"
chmod 0700 "$CRED_DIR"
[[ -f /var/lib/systemd/credential.secret ]] || systemd-creds setup >/dev/null
printf '%s' "$PLAINTEXT" \
    | systemd-creds encrypt --with-key="$KEY" --name="$CRED_NAME" - "$CRED_FILE"
chmod 0400 "$CRED_FILE"
echo "== sealed $CRED_FILE ($(stat -c '%s bytes, mode %a' "$CRED_FILE"))"

check() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == *"$expected"* ]]; then
        echo "ok   - $desc"
    else
        echo "FAIL - $desc"
        echo "       expected to contain: $expected"
        echo "       got: $actual"
        FAILED=1
    fi
}

# ── 3. the credential is delivered, and matches ──────────────────────────────
out="$("$BIN" --secret "tpm2:$CRED_NAME" /bin/cat "/run/secrets/$CRED_NAME" 2>/dev/null || true)"
check "credential decrypts and lands at /run/secrets/$CRED_NAME" "$PLAINTEXT" "$out"

# ── 4. custom container path ─────────────────────────────────────────────────
out="$("$BIN" --secret "tpm2:$CRED_NAME:/run/secrets/custom" \
        /bin/cat /run/secrets/custom 2>/dev/null || true)"
check "custom container path honored" "$PLAINTEXT" "$out"

# ── 5. it is read-only inside the container ──────────────────────────────────
out="$("$BIN" --secret "tpm2:$CRED_NAME" \
        /bin/sh -c "echo overwrite > /run/secrets/$CRED_NAME 2>&1 || echo WRITE_REFUSED" 2>/dev/null || true)"
check "secret is read-only inside the container" "WRITE_REFUSED" "$out"

# ── 6. the plaintext is memory-backed, not on disk ───────────────────────────
out="$("$BIN" --secret "tpm2:$CRED_NAME" \
        /bin/sh -c "grep -E ' /run/secrets/$CRED_NAME ' /proc/self/mountinfo || echo NO_MOUNT" 2>/dev/null || true)"
check "secret is a mount, not a plain file in the rootfs" "/run/secrets/$CRED_NAME" "$out"
case "$out" in
    *ramfs*) echo "ok   - staged on ramfs (never swapped)" ;;
    *tmpfs*) echo "ok   - staged on tmpfs (ramfs unavailable; may reach swap)" ;;
    *)       echo "note - could not identify staging fs from: $out" ;;
esac

# ── 7. a missing credential fails closed (and does not hang on stdin) ────────
set +e
timeout 20 "$BIN" --secret "tpm2:definitely-not-present" /bin/true >/dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 124 ]]; then
    echo "FAIL - missing credential HUNG (regression: helper is reading our stdin)"
    FAILED=1
elif [[ $rc -eq 0 ]]; then
    echo "FAIL - missing credential did not abort the run"
    FAILED=1
else
    echo "ok   - missing credential fails closed (exit $rc, no hang)"
fi

# ── 8. a group/world-writable credential is refused ──────────────────────────
chmod 0460 "$CRED_FILE"
set +e
out="$("$BIN" --secret "tpm2:$CRED_NAME" /bin/true 2>&1)"
rc=$?
set -e
chmod 0400 "$CRED_FILE"
if [[ $rc -ne 0 && "$out" == *"group- or world-writable"* ]]; then
    echo "ok   - group-writable credential refused"
else
    echo "FAIL - group-writable credential was not refused (exit $rc)"
    FAILED=1
fi

# ── 9. --vm is rejected rather than silently dropping the secret ─────────────
set +e
out="$("$BIN" --vm --secret "tpm2:$CRED_NAME" /bin/true 2>&1)"
rc=$?
set -e
if [[ $rc -ne 0 && "$out" == *"not supported with --vm"* ]]; then
    echo "ok   - --secret with --vm is rejected"
else
    echo "FAIL - --secret with --vm was not rejected (exit $rc)"
    FAILED=1
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "All --secret tpm2 checks passed (key type: $KEY)."
else
    echo "Some --secret tpm2 checks FAILED." >&2
fi
exit $FAILED
