#!/usr/bin/env bash
# test_runtime.sh — Shell TAP runtime integration tests for oci2bin.img
#
# Tests the three new loader features:
#   1. Argument passthrough
#   2. --entrypoint override
#   3. -v volume mounts
# Plus docker load compatibility and error handling.
#
# Output: TAP (Test Anything Protocol)
# Run:    bash tests/test_runtime.sh

set -euo pipefail

IMG="./oci2bin.img"
TAP_COUNT=15
FAIL=0
T=0

# ── TAP helpers ───────────────────────────────────────────────────────────

ok() {
    T=$(( T + 1 ))
    echo "ok $T - $1"
}

not_ok() {
    T=$(( T + 1 ))
    echo "not ok $T - $1"
    echo "# $2"
    FAIL=$(( FAIL + 1 ))
}

# Run a test: run_test "description" <expected_exit> "pattern" cmd...
run_test() {
    local desc="$1"
    local expected_exit="$2"
    local pattern="$3"
    shift 3
    local out
    local exit_code=0
    out=$(timeout 15 "$@" 2>/dev/null) || exit_code=$?

    if [[ "$expected_exit" == "nonzero" ]]; then
        if [[ "$exit_code" -ne 0 ]]; then
            ok "$desc"
        else
            not_ok "$desc" "Expected non-zero exit, got 0. Output: $out"
        fi
        return
    fi

    if [[ "$exit_code" -ne "$expected_exit" ]]; then
        not_ok "$desc" "Exit $exit_code (expected $expected_exit). Output: $out"
        return
    fi

    if [[ -n "$pattern" ]] && ! echo "$out" | grep -q "$pattern"; then
        not_ok "$desc" "Pattern '$pattern' not found in output: $out"
        return
    fi

    ok "$desc"
}

# ── Setup ─────────────────────────────────────────────────────────────────

echo "TAP version 13"
echo "1..$TAP_COUNT"

if [[ ! -f "$IMG" ]]; then
    for i in $(seq 1 $TAP_COUNT); do
        echo "not ok $i - SKIP: $IMG not found"
    done
    exit 1
fi

if [[ ! -x "$IMG" ]]; then
    for i in $(seq 1 $TAP_COUNT); do
        echo "not ok $i - SKIP: $IMG not executable"
    done
    exit 1
fi

# ── Test 1: Arg passthrough — simple echo ─────────────────────────────────

run_test "arg passthrough: /bin/echo hello_from_container" \
    0 "hello_from_container" \
    "$IMG" /bin/echo hello_from_container

# ── Test 2: Shell -c passthrough ─────────────────────────────────────────

run_test "arg passthrough: /bin/sh -c echo polydocker_ok" \
    0 "polydocker_ok" \
    "$IMG" /bin/sh -c 'echo polydocker_ok'

# ── Test 3: Exit code passthrough ────────────────────────────────────────

T=$(( T + 1 ))
exit_code=0
timeout 15 "$IMG" /bin/sh -c 'exit 42' 2>/dev/null || exit_code=$?
if [[ "$exit_code" -eq 42 ]]; then
    echo "ok $T - exit code passthrough (exit 42)"
else
    echo "not ok $T - exit code passthrough (exit 42)"
    echo "# Got exit code $exit_code, expected 42"
    FAIL=$(( FAIL + 1 ))
fi

# ── Test 4: --entrypoint override ────────────────────────────────────────

run_test "--entrypoint /bin/echo with arg" \
    0 "ep_arg" \
    "$IMG" --entrypoint /bin/echo ep_arg

# ── Test 5: --entrypoint with shell -c ───────────────────────────────────

run_test "--entrypoint /bin/sh -- -c 'echo ep_sh_ok'" \
    0 "ep_sh_ok" \
    "$IMG" --entrypoint /bin/sh -- -c "echo ep_sh_ok"

# ── Test 6: -v volume mount ───────────────────────────────────────────────

TMPDIR_V=$(mktemp -d)
echo "host_content_ok" > "$TMPDIR_V/testfile.txt"

T=$(( T + 1 ))
out=""
exit_code=0
out=$(timeout 15 "$IMG" -v "$TMPDIR_V:/mnt" /bin/cat /mnt/testfile.txt 2>/dev/null) \
    || exit_code=$?

if [[ "$exit_code" -eq 0 ]] && echo "$out" | grep -q "host_content_ok"; then
    echo "ok $T - -v volume mount: host file visible inside container"
else
    echo "not ok $T - -v volume mount: host file visible inside container"
    echo "# exit=$exit_code output='$out'"
    FAIL=$(( FAIL + 1 ))
fi

rm -rf "$TMPDIR_V"

# ── Test 7: -v auto-creates non-existent mountpoint ──────────────────────

TMPDIR_V2=$(mktemp -d)
echo "auto_mnt_ok" > "$TMPDIR_V2/data.txt"

T=$(( T + 1 ))
out=""
exit_code=0
out=$(timeout 15 "$IMG" -v "$TMPDIR_V2:/newmnt" /bin/cat /newmnt/data.txt 2>/dev/null) \
    || exit_code=$?

if [[ "$exit_code" -eq 0 ]] && echo "$out" | grep -q "auto_mnt_ok"; then
    echo "ok $T - -v auto-creates non-existent mountpoint"
else
    echo "not ok $T - -v auto-creates non-existent mountpoint"
    echo "# exit=$exit_code output='$out'"
    FAIL=$(( FAIL + 1 ))
fi

rm -rf "$TMPDIR_V2"

# ── Test 8: Multiple -v flags ─────────────────────────────────────────────

TMPDIR_A=$(mktemp -d)
TMPDIR_B=$(mktemp -d)
echo "vol_a_ok" > "$TMPDIR_A/a.txt"
echo "vol_b_ok" > "$TMPDIR_B/b.txt"

T=$(( T + 1 ))
out=""
exit_code=0
out=$(timeout 15 "$IMG" \
    -v "$TMPDIR_A:/mnt/a" \
    -v "$TMPDIR_B:/mnt/b" \
    /bin/sh -c 'cat /mnt/a/a.txt && cat /mnt/b/b.txt' 2>/dev/null) \
    || exit_code=$?

if [[ "$exit_code" -eq 0 ]] \
    && echo "$out" | grep -q "vol_a_ok" \
    && echo "$out" | grep -q "vol_b_ok"; then
    echo "ok $T - multiple -v flags: both volumes visible"
else
    echo "not ok $T - multiple -v flags: both volumes visible"
    echo "# exit=$exit_code output='$out'"
    FAIL=$(( FAIL + 1 ))
fi

rm -rf "$TMPDIR_A" "$TMPDIR_B"

# ── Test 9: docker load compatibility ────────────────────────────────────

T=$(( T + 1 ))
if command -v docker &>/dev/null; then
    out=""
    exit_code=0
    out=$(docker load < "$IMG" 2>&1) || exit_code=$?
    if [[ "$exit_code" -eq 0 ]] && echo "$out" | grep -qi "Loaded image"; then
        echo "ok $T - docker load < oci2bin.img succeeds"
    else
        echo "not ok $T - docker load < oci2bin.img succeeds"
        echo "# exit=$exit_code output='$out'"
        FAIL=$(( FAIL + 1 ))
    fi
else
    echo "ok $T - SKIP: docker not available"
fi

# ── Test 10: Unknown flag → non-zero exit ─────────────────────────────────

T=$(( T + 1 ))
exit_code=0
timeout 15 "$IMG" --no-such-flag 2>/dev/null || exit_code=$?
if [[ "$exit_code" -ne 0 ]]; then
    echo "ok $T - unknown flag returns non-zero exit"
else
    echo "not ok $T - unknown flag returns non-zero exit"
    echo "# Got exit 0, expected non-zero"
    FAIL=$(( FAIL + 1 ))
fi

# ── Test 11: -v missing arg → non-zero exit ───────────────────────────────

T=$(( T + 1 ))
exit_code=0
timeout 15 "$IMG" -v 2>/dev/null || exit_code=$?
if [[ "$exit_code" -ne 0 ]]; then
    echo "ok $T - -v missing arg returns non-zero exit"
else
    echo "not ok $T - -v missing arg returns non-zero exit"
    echo "# Got exit 0, expected non-zero"
    FAIL=$(( FAIL + 1 ))
fi

# ── Test 12: -v without colon → non-zero exit ────────────────────────────

T=$(( T + 1 ))
exit_code=0
timeout 15 "$IMG" -v nocolon 2>/dev/null || exit_code=$?
if [[ "$exit_code" -ne 0 ]]; then
    echo "ok $T - -v without colon returns non-zero exit"
else
    echo "not ok $T - -v without colon returns non-zero exit"
    echo "# Got exit 0, expected non-zero"
    FAIL=$(( FAIL + 1 ))
fi

# ── Test 13: PATH set inside container ───────────────────────────────────

run_test "PATH set inside container contains /usr/bin" \
    0 "/usr/bin" \
    "$IMG" /bin/sh -c 'echo $PATH'

# ── Test 14: HOME set to /root ────────────────────────────────────────────

run_test "HOME set to /root inside container" \
    0 "/root" \
    "$IMG" /bin/sh -c 'echo $HOME'

# ── Test 15: Binary runs without docker in PATH ───────────────────────────

T=$(( T + 1 ))
out=""
exit_code=0
out=$(env PATH="$(echo "$PATH" | tr ':' '\n' | grep -v docker | tr '\n' ':')" \
    timeout 15 "$IMG" /bin/echo no_docker_needed 2>/dev/null) || exit_code=$?
if [[ "$exit_code" -eq 0 ]] && echo "$out" | grep -q "no_docker_needed"; then
    echo "ok $T - binary runs without docker in PATH"
else
    echo "not ok $T - binary runs without docker in PATH"
    echo "# exit=$exit_code output='$out'"
    FAIL=$(( FAIL + 1 ))
fi

# ── Summary ───────────────────────────────────────────────────────────────

if [[ "$FAIL" -gt 0 ]]; then
    echo "# $FAIL of $TAP_COUNT tests FAILED" >&2
    exit 1
fi

exit 0
