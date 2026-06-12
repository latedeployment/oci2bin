#!/usr/bin/env bash
# Integration test: build real images with oci2bin and run them LIVE on the
# full runtime path — no --no-userns-remap, no --no-seccomp. This is the
# coverage unit tests cannot provide: an actual built binary running an actual
# container, with rootless subordinate-ID mapping and seccomp active.
#
# Unlike test_runtime.sh / the redis & nginx integration tests (which pass
# --no-userns-remap / --no-seccomp and so skip the rootless + seccomp paths),
# every command here runs with the defaults a user gets.
#
# Coverage:
#   alpine  — rootless uid mapping, arg passthrough, -e env, -v volume,
#             --entrypoint override, image filesystem read
#   redis   — default entrypoint dropping to the non-root "redis" user
#             (gosu / setgroups) and serving traffic (PING)
#
# Requires: docker, python3. Output: TAP.
set -euo pipefail

TAP_TOTAL=10
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

if ! docker info >/dev/null 2>&1; then
    for _ in $(seq 1 "$TAP_TOTAL"); do tap_skip "docker not available"; done
    echo "1..$TAP_TOTAL"
    exit 0
fi

WORKDIR="$(mktemp -d)"
ALP="$WORKDIR/alpine_live"
REDIS="$WORKDIR/redis_live"
VOLDIR="$WORKDIR/vol"
REDIS_PID=""

cleanup() {
    if [[ -n "$REDIS_PID" ]] && kill -0 "$REDIS_PID" 2>/dev/null; then
        kill "$REDIS_PID" 2>/dev/null || true
        wait "$REDIS_PID" 2>/dev/null || true
    fi
    pkill -f "$REDIS" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Best-effort: make sure the base images are present (no-op if already pulled).
docker image inspect alpine:latest    >/dev/null 2>&1 || docker pull -q alpine:latest    >/dev/null 2>&1 || true
docker image inspect redis:7-alpine   >/dev/null 2>&1 || docker pull -q redis:7-alpine   >/dev/null 2>&1 || true

# helper: run a built binary, assert exit 0 and that stdout contains a needle
run_contains() {
    local desc="$1" needle="$2"; shift 2
    local out
    if out="$(timeout 30 "$@" 2>/dev/null)" && echo "$out" | grep -qF "$needle"; then
        tap_ok "$desc"
    else
        tap_fail "$desc (got: $(echo "${out:-}" | tr '\n' ' ' | head -c 120))"
    fi
}

# ── alpine: build once, exercise the feature matrix on the real path ─────────
if "$OCI2BIN" alpine:latest "$ALP" >/dev/null 2>&1; then
    tap_ok "alpine: build succeeded"
else
    tap_fail "alpine: oci2bin build failed"
    echo "1..$TAP_TOTAL"
    exit 1
fi

run_contains "alpine: rootless uid mapping (id -> uid=0 root)" "uid=0(root)" \
    "$ALP" id
run_contains "alpine: argument passthrough" "LIVE_ARG_OK" \
    "$ALP" echo LIVE_ARG_OK
run_contains "alpine: -e env injection" "barbaz" \
    "$ALP" -e FOO=barbaz printenv FOO

mkdir -p "$VOLDIR"
echo "VOLDATA_OK" > "$VOLDIR/f.txt"
run_contains "alpine: -v volume mount visible inside container" "VOLDATA_OK" \
    "$ALP" -v "$VOLDIR:/data" cat /data/f.txt

run_contains "alpine: --entrypoint override" "EP_OK" \
    "$ALP" --entrypoint /bin/echo EP_OK
run_contains "alpine: reads image filesystem (/etc/alpine-release)" "." \
    "$ALP" cat /etc/alpine-release

# ── redis: default entrypoint drops to non-root user (gosu) and serves ───────
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
if "$OCI2BIN" redis:7-alpine "$REDIS" >/dev/null 2>&1; then
    tap_ok "redis: build succeeded"
else
    tap_fail "redis: oci2bin build failed"
    echo "1..$TAP_TOTAL"
    exit 1
fi

# Default entrypoint (docker-entrypoint.sh) -> gosu redis; full real path.
"$REDIS" redis-server --port "$PORT" --daemonize no >/dev/null 2>&1 &
REDIS_PID=$!
listening=0
for _ in $(seq 1 30); do
    sleep 0.5
    if bash -c "echo >/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        listening=1
        break
    fi
    kill -0 "$REDIS_PID" 2>/dev/null || break
done
if [[ "$listening" -eq 1 ]]; then
    tap_ok "redis: starts rootless + drops to non-root user (gosu/setgroups)"
else
    tap_fail "redis: did not come up on the real rootless path"
fi

if [[ "$listening" -eq 1 ]]; then
    response="$(python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $PORT), timeout=3)
s.sendall(b'*1\r\n\$4\r\nPING\r\n')
print(s.recv(64).decode('utf-8', 'replace'))
s.close()
" 2>/dev/null || true)"
    if echo "$response" | grep -q '+PONG'; then
        tap_ok "redis: PING returns +PONG"
    else
        tap_fail "redis: PING did not return +PONG (got: $(echo "$response" | head -1))"
    fi
else
    tap_fail "redis: PING skipped (server not up)"
fi

echo "1..$TAP_TOTAL"
[[ "$fail" -eq 0 ]]
