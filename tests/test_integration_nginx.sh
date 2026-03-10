#!/usr/bin/env bash
# Integration test: run an nginx container built with oci2bin and verify
# it serves HTTP 200 on /.
#
# Requires: docker, curl, oci2bin wrapper in PATH or CWD
# Output: TAP format

set -euo pipefail

TAP_TOTAL=2
tap_n=0
fail=0

tap_ok()  { tap_n=$((tap_n + 1)); echo "ok $tap_n - $*"; }
tap_fail(){ tap_n=$((tap_n + 1)); echo "not ok $tap_n - $*"; fail=$((fail + 1)); }

echo "TAP version 13"

WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/nginx_test"
# Pick a random free port in the ephemeral range to avoid conflicts
NGINX_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
NGINX_PID=""

cleanup() {
    if [[ -n "$NGINX_PID" ]] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    rm -f "$BIN"
    rmdir "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Build the nginx binary ─────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OCI2BIN="${SCRIPT_DIR}/oci2bin"

if ! "$OCI2BIN" nginx:alpine "$BIN" 2>/dev/null; then
    tap_fail "nginx: oci2bin build failed"
    echo "1..$TAP_TOTAL"
    exit 1
fi
tap_ok "nginx: oci2bin build succeeded"

# ── 2. Start nginx in the background ─────────────────────────────────────────

# Write a minimal nginx config that listens on NGINX_PORT
NGINX_CONF="$WORKDIR/nginx.conf"
cat >"$NGINX_CONF" <<EOF
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 16; }
http {
    access_log /dev/stdout;
    server {
        listen $NGINX_PORT;
        location / { return 200 "ok\n"; }
    }
}
EOF

"$BIN" --no-seccomp \
    -v "$NGINX_CONF:/etc/nginx/nginx.conf" \
    -- nginx -g "daemon off;" \
    2>/dev/null &
NGINX_PID=$!

# Wait up to 8 seconds for the port to respond
ok=0
for _ in $(seq 1 16); do
    sleep 0.5
    if bash -c "echo >/dev/tcp/127.0.0.1/$NGINX_PORT" 2>/dev/null; then
        ok=1
        break
    fi
done

if [[ "$ok" -eq 0 ]]; then
    tap_fail "nginx: server did not listen on port $NGINX_PORT"
    echo "1..$TAP_TOTAL"
    exit 1
fi

# ── 3. HTTP GET / ─────────────────────────────────────────────────────────────

status="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$NGINX_PORT/" 2>/dev/null || true)"
if [[ "$status" == "200" ]]; then
    tap_ok "nginx: GET / returns HTTP 200"
else
    tap_fail "nginx: GET / returned HTTP $status (expected 200)"
fi

echo "1..$TAP_TOTAL"
[[ "$fail" -eq 0 ]]
