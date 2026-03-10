#!/usr/bin/env bash
# Integration test: run a Redis container built with oci2bin and verify
# basic PING / SET / GET operations work over TCP.
#
# Requires: docker, nc (netcat), oci2bin wrapper in PATH or CWD
# Output: TAP format

set -euo pipefail

TAP_TOTAL=3
tap_n=0
fail=0

tap_ok()  { tap_n=$((tap_n + 1)); echo "ok $tap_n - $*"; }
tap_fail(){ tap_n=$((tap_n + 1)); echo "not ok $tap_n - $*"; fail=$((fail + 1)); }

echo "TAP version 13"

WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/redis_test"
REDIS_PORT=16379   # use non-standard port to avoid conflicts
REDIS_PID=""

cleanup() {
    if [[ -n "$REDIS_PID" ]] && kill -0 "$REDIS_PID" 2>/dev/null; then
        kill "$REDIS_PID" 2>/dev/null || true
        wait "$REDIS_PID" 2>/dev/null || true
    fi
    rm -f "$BIN"
    rmdir "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Build the redis binary ────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OCI2BIN="${SCRIPT_DIR}/oci2bin"

if ! "$OCI2BIN" redis:7-alpine "$BIN" 2>/dev/null; then
    tap_fail "redis: oci2bin build failed"
    echo "1..$TAP_TOTAL"
    exit 1
fi
tap_ok "redis: oci2bin build succeeded"

# ── 2. Start redis-server in the background ───────────────────────────────────

"$BIN" --no-seccomp --entrypoint /usr/local/bin/redis-server \
    -- --port "$REDIS_PORT" --daemonize no \
    2>/dev/null &
REDIS_PID=$!

# Wait up to 8 seconds for the port to be listening
ok=0
for _ in $(seq 1 16); do
    sleep 0.5
    if bash -c "echo >/dev/tcp/127.0.0.1/$REDIS_PORT" 2>/dev/null; then
        ok=1
        break
    fi
done

if [[ "$ok" -eq 0 ]]; then
    tap_fail "redis: server did not listen on port $REDIS_PORT"
    echo "1..$TAP_TOTAL"
    exit 1
fi

# ── 3. PING ───────────────────────────────────────────────────────────────────

response="$(python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $REDIS_PORT), timeout=3)
s.sendall(b'*1\r\n\$4\r\nPING\r\n')
r = s.recv(256).decode(errors='replace')
s.close()
print(r)
" 2>/dev/null || true)"
if echo "$response" | grep -q '+PONG'; then
    tap_ok "redis: PING returns +PONG"
else
    tap_fail "redis: PING did not return +PONG (got: $(echo "$response" | head -1))"
fi

# ── 4. SET and GET ────────────────────────────────────────────────────────────

response="$(python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $REDIS_PORT), timeout=3)
s.sendall(b'*3\r\n\$3\r\nSET\r\n\$3\r\nfoo\r\n\$3\r\nbar\r\n*2\r\n\$3\r\nGET\r\n\$3\r\nfoo\r\n')
r = s.recv(256).decode(errors='replace')
s.close()
print(r)
" 2>/dev/null || true)"
if echo "$response" | grep -q '+OK' && echo "$response" | grep -q 'bar'; then
    tap_ok "redis: SET foo bar / GET foo returns bar"
else
    tap_fail "redis: SET/GET failed (got: $(echo "$response" | tr -d '\r' | head -3 | tr '\n' ' '))"
fi

echo "1..$TAP_TOTAL"
[[ "$fail" -eq 0 ]]
