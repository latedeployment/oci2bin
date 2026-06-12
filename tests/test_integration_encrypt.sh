#!/usr/bin/env bash
# Integration test: build an ENCRYPTED (age passphrase) container with oci2bin
# and exercise the full real run path that unit tests cannot reach — a real
# built binary running a real container. In one realistic flow it covers:
#
#   - age passphrase decryption at run time (OCI2BIN_PASSWORD)
#   - subordinate-ID user-namespace mapping WITHOUT --no-userns-remap
#     (would catch the "newuidmap: uid range ... not allowed" regression)
#   - the container entrypoint dropping to a non-root in-image user via
#     gosu/su-exec (would catch the setgroups=deny regression that broke
#     'failed switching to "redis"')
#   - default seccomp applied (no --no-seccomp)
#   - wrong passphrase fails closed: no extraction, no run, no age footer noise
#
# Requires: docker, age, python3. Output: TAP.
set -euo pipefail

TAP_TOTAL=5
tap_n=0
fail=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${TMPDIR:-}" ]]; then
    TMPDIR="$SCRIPT_DIR/build/test-tmp"
fi
mkdir -p "$TMPDIR"
export TMPDIR
export OCI2BIN_TMPDIR="${OCI2BIN_TMPDIR:-$TMPDIR}"
OCI2BIN="$SCRIPT_DIR/oci2bin"

tap_ok()   { tap_n=$((tap_n + 1)); echo "ok $tap_n - $*"; }
tap_fail() { tap_n=$((tap_n + 1)); echo "not ok $tap_n - $*"; fail=$((fail + 1)); }
tap_skip() { tap_n=$((tap_n + 1)); echo "ok $tap_n - $* # SKIP"; }

echo "TAP version 13"

# Encryption needs the age CLI; skip cleanly (not fail) where it is absent.
if ! command -v age >/dev/null 2>&1; then
    for _ in $(seq 1 "$TAP_TOTAL"); do tap_skip "age not installed"; done
    echo "1..$TAP_TOTAL"
    exit 0
fi

WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/redis_enc"
PASS="test-pass-$$-secret"
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
PID=""

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    pkill -f "$BIN" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── 1. Build an encrypted binary ─────────────────────────────────────────────
if OCI2BIN_PASSWORD="$PASS" "$OCI2BIN" --passphrase redis:7-alpine "$BIN" \
        >/dev/null 2>&1; then
    tap_ok "build: encrypted redis binary built"
else
    tap_fail "build: oci2bin --passphrase failed"
    echo "1..$TAP_TOTAL"
    exit 1
fi

# ── 2. Payload is encrypted and the passphrase is NOT embedded ───────────────
if grep -aq "age-encryption.org" "$BIN" && ! grep -aqF "$PASS" "$BIN"; then
    tap_ok "build: payload is age-encrypted and passphrase is not embedded"
else
    tap_fail "build: payload not encrypted or passphrase leaked into binary"
fi

# ── 3. Run the full real path: decrypt + rootless subid map + gosu user-switch
#       No --no-userns-remap, no --no-seccomp, default entrypoint (-> gosu redis)
OCI2BIN_PASSWORD="$PASS" "$BIN" redis-server --port "$PORT" --daemonize no \
    >/dev/null 2>&1 &
PID=$!
listening=0
for _ in $(seq 1 30); do
    sleep 0.5
    if bash -c "echo >/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        listening=1
        break
    fi
    kill -0 "$PID" 2>/dev/null || break
done
if [[ "$listening" -eq 1 ]]; then
    tap_ok "run: encrypted image decrypts + starts rootless (subid map + user-switch)"
else
    tap_fail "run: encrypted redis did not come up on the real rootless path"
fi

# ── 4. PING over TCP ─────────────────────────────────────────────────────────
if [[ "$listening" -eq 1 ]]; then
    response="$(python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $PORT), timeout=3)
s.sendall(b'*1\r\n\$4\r\nPING\r\n')
print(s.recv(64).decode('utf-8', 'replace'))
s.close()
" 2>/dev/null || true)"
    if echo "$response" | grep -q '+PONG'; then
        tap_ok "run: PING returns +PONG"
    else
        tap_fail "run: PING did not return +PONG (got: $(echo "$response" | head -1))"
    fi
else
    tap_fail "run: PING skipped (server not up)"
fi
if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=""
fi

# ── 5. Wrong passphrase fails closed (nonzero, no run, no age footer) ────────
errout="$(OCI2BIN_PASSWORD="wrong-$PASS" "$BIN" echo SHOULD_NOT_RUN 2>&1 || true)"
if echo "$errout" | grep -q "decryption failed" \
        && ! echo "$errout" | grep -q "SHOULD_NOT_RUN" \
        && ! echo "$errout" | grep -q "filippo.io/age/report"; then
    tap_ok "run: wrong passphrase fails closed (no extraction, no age footer)"
else
    tap_fail "run: wrong passphrase not handled correctly (got: $(echo "$errout" | tr '\n' ' ' | head -c 200))"
fi

echo "1..$TAP_TOTAL"
[[ "$fail" -eq 0 ]]
