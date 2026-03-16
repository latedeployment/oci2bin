#!/usr/bin/env bash
# fuzz_run.sh — run all libFuzzer harnesses in parallel and report findings.
#
# Usage:
#   bash scripts/fuzz_run.sh [SECONDS]   # default: 300
#
# Each harness runs in its own process.  Artifacts (crash-*, leak-*, oom-*)
# land in build/fuzz-out/<harness>/.  Any findings are printed at the end.

set -euo pipefail

DURATION=${1:-300}
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ROOT="$REPO_ROOT/build/fuzz-out"

cd "$REPO_ROOT"

# ── Build if needed ────────────────────────────────────────────────────────────
echo "=== Building fuzz targets ==="
make fuzz-all

# ── Launch each harness ────────────────────────────────────────────────────────
TARGETS=(
    "fuzz_json:tests/fuzz/corpus/json:-max_len=65536"
    "fuzz_seccomp:tests/fuzz/corpus/seccomp:-max_len=65536"
    "fuzz_parse_opts:tests/fuzz/corpus/parse_opts:-max_len=4096"
)

PIDS=()
LOG_FILES=()

echo "=== Starting fuzzers (${DURATION}s each) ==="
for entry in "${TARGETS[@]}"; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    corpus="${rest%%:*}"
    extra_flags="${rest#*:}"

    mkdir -p "$OUT_ROOT/$name"

    log="$OUT_ROOT/$name/fuzz.log"
    LOG_FILES+=("$log")

    # libFuzzer writes artifacts to the CWD; use artifact_prefix to redirect
    ./build/"$name" \
        "$corpus" \
        -max_total_time="$DURATION" \
        $extra_flags \
        -artifact_prefix="$OUT_ROOT/$name/" \
        -jobs=1 \
        -workers=1 \
        >"$log" 2>&1 &

    PIDS+=($!)
    echo "  [$name] PID $! — log: $log"
done

# ── Wait and show live tail ────────────────────────────────────────────────────
echo ""
echo "Fuzzing for ${DURATION}s — tailing logs (Ctrl-C to abort)..."
echo "────────────────────────────────────────────────────────────"

# Tail all logs until all child processes exit
tail -f "${LOG_FILES[@]}" &
TAIL_PID=$!

for pid in "${PIDS[@]}"; do
    wait "$pid" || true
done

# Give tail a moment to flush, then kill it
sleep 1
kill "$TAIL_PID" 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo "=== Fuzzing complete — scanning for artifacts ==="
echo ""

# ── Report ─────────────────────────────────────────────────────────────────────
FOUND=0
for entry in "${TARGETS[@]}"; do
    name="${entry%%:*}"
    dir="$OUT_ROOT/$name"

    crashes=( "$dir"/crash-* )
    leaks=(   "$dir"/leak-*   )
    ooms=(    "$dir"/oom-*    )
    timeouts=("$dir"/timeout-* )

    has_crash=0
    [[ -e "${crashes[0]}" ]]  && has_crash=1
    has_leak=0
    [[ -e "${leaks[0]}" ]]    && has_leak=1
    has_oom=0
    [[ -e "${ooms[0]}" ]]     && has_oom=1
    has_timeout=0
    [[ -e "${timeouts[0]}" ]] && has_timeout=1

    if (( has_crash + has_leak + has_oom + has_timeout == 0 )); then
        echo "  [$name] CLEAN — no findings"
    else
        FOUND=1
        echo "  [$name] FINDINGS:"
        (( has_crash ))   && printf '    CRASH:   %s\n' "${crashes[@]}"
        (( has_leak ))    && printf '    LEAK:    %s\n' "${leaks[@]}"
        (( has_oom ))     && printf '    OOM:     %s\n' "${ooms[@]}"
        (( has_timeout )) && printf '    TIMEOUT: %s\n' "${timeouts[@]}"
    fi
done

echo ""
if (( FOUND )); then
    echo "Replay a finding:"
    echo "  ./build/fuzz_json      build/fuzz-out/fuzz_json/crash-<hash>"
    echo "  ./build/fuzz_seccomp   build/fuzz-out/fuzz_seccomp/leak-<hash>"
    echo "  ./build/fuzz_parse_opts build/fuzz-out/fuzz_parse_opts/leak-<hash>"
    echo ""
    echo "Add confirmed fixes to the regression corpus:"
    echo "  cp build/fuzz-out/<harness>/crash-<hash> tests/fuzz/corpus/<harness>/regression_<n>"
    exit 1
else
    echo "All harnesses clean."
    exit 0
fi
