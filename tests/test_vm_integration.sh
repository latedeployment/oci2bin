#!/usr/bin/env bash
# VM integration tests — require /dev/kvm.
# Usage: bash tests/test_vm_integration.sh [LOADER_BINARY]
set -euo pipefail

LOADER="${1:-./alpine_latest}"

if [ ! -e /dev/kvm ]; then
    echo "SKIP: /dev/kvm not available"
    exit 0
fi

if [ ! -x "$LOADER" ]; then
    echo "SKIP: $LOADER not found or not executable"
    echo "      Run: oci2bin alpine $LOADER  to build it first"
    exit 0
fi

echo "=== VM integration tests ==="

echo "Test 1: basic echo"
OUT=$("$LOADER" --vm /bin/echo hello)
[ "$OUT" = "hello" ] || { echo "FAIL: echo output: $OUT"; exit 1; }
echo "PASS: basic echo"

echo "Test 2: exit code propagation"
set +e
"$LOADER" --vm /bin/sh -c 'exit 42'
CODE=$?
set -e
[ "$CODE" = "42" ] || { echo "FAIL: exit code $CODE != 42"; exit 1; }
echo "PASS: exit code propagation"

echo "Test 3: --overlay-persist"
TMPSTATE=$(mktemp -d)
trap 'rm -rf "$TMPSTATE"' EXIT
"$LOADER" --vm --overlay-persist "$TMPSTATE" \
    /bin/sh -c 'echo persisted > /mnt/persist/test.txt'
"$LOADER" --vm --overlay-persist "$TMPSTATE" \
    /bin/cat /mnt/persist/test.txt | grep -q persisted \
    || { echo "FAIL: overlay-persist"; exit 1; }
echo "PASS: overlay-persist"

echo "=== All VM integration tests PASSED ==="
