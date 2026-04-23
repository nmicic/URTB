#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# run_all_tests.sh — single end-to-end test driver for URTB.
#
# Three tiers:
#   no-hw  (default) — host-only, ~40s. Build + frame_test + AC-03 pyte +
#                       heltec socat sim + fragmentation runtime + hygiene.
#   hw              — Heltec V3 hardware tier, ~3min. Auto-skipped if <2
#                       Heltec ports detected via tools/ports.sh.
#   all             — no-hw followed by hw.
#
# Wraps the existing per-test scripts in tools/. Adds NO new test logic.
#
#   tools/run_all_tests.sh                  # default = no-hw
#   tools/run_all_tests.sh --tier no-hw     # explicit
#   tools/run_all_tests.sh --tier hw
#   tools/run_all_tests.sh --tier all
#   tools/run_all_tests.sh --quick          # frame_test only smoke (~10s)
#   tools/run_all_tests.sh --json out.json  # also write machine summary
#   tools/run_all_tests.sh --help
#
# Exit codes:
#   0  all tests PASS
#   1  one or more tests FAIL (soft fail — kept going)
#   2  hard error (build broke) — execution stopped early

set -uo pipefail
cd "$(dirname "$0")/.."

TIER=no-hw
QUICK=0
JSON_OUT=
INCLUDE_FI02_DOC=0

print_help() {
    sed -n '3,21p' "$0"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)
            TIER=$2; shift 2
            case "$TIER" in
                no-hw|hw|all) ;;
                *) echo "error: --tier must be no-hw|hw|all (got: $TIER)" >&2; exit 2;;
            esac
            ;;
        --quick) QUICK=1; shift ;;
        --json) JSON_OUT=$2; shift 2 ;;
        --include-fi02-doc) INCLUDE_FI02_DOC=1; shift ;;
        --help|-h) print_help; exit 0 ;;
        *) echo "error: unknown arg '$1' (try --help)" >&2; exit 2 ;;
    esac
done

TS=$(date -u +%Y%m%dT%H%M%SZ)
RUNDIR=${URTB_REPORTS_DIR:-test-reports}/run_all/$TS
mkdir -p "$RUNDIR"

# --- result table ---------------------------------------------------------
# Parallel arrays: id, tier, verdict (PASS/FAIL/SKIP/HARDFAIL), seconds, log
RESULT_ID=()
RESULT_TIER=()
RESULT_VERDICT=()
RESULT_SECS=()
RESULT_LOG=()

record() {
    local id=$1 tier=$2 verdict=$3 secs=$4 log=$5
    RESULT_ID+=("$id")
    RESULT_TIER+=("$tier")
    RESULT_VERDICT+=("$verdict")
    RESULT_SECS+=("$secs")
    RESULT_LOG+=("$log")
}

# Run a single labeled step. $1=id, $2=tier, $3=hard|soft, rest=command.
# Captures full stdout+stderr to $RUNDIR/<id>.log, prints a one-line
# PASS/FAIL with elapsed seconds. If hard and the step fails, exits 2 with
# a HARDFAIL record so the caller can stop the world.
run_step() {
    local id=$1 tier=$2 mode=$3; shift 3
    local logfile="$RUNDIR/$id.log"
    local t0=$(date +%s)
    printf '  [%-10s] %-32s ... ' "$tier" "$id"
    if "$@" >"$logfile" 2>&1; then
        local secs=$(( $(date +%s) - t0 ))
        printf 'PASS (%ds)\n' "$secs"
        record "$id" "$tier" PASS "$secs" "$logfile"
        return 0
    else
        local rc=$?
        local secs=$(( $(date +%s) - t0 ))
        if [[ "$mode" == "hard" ]]; then
            printf 'HARDFAIL rc=%d (%ds) — see %s\n' "$rc" "$secs" "$logfile"
            record "$id" "$tier" HARDFAIL "$secs" "$logfile"
            return 2
        fi
        printf 'FAIL rc=%d (%ds) — see %s\n' "$rc" "$secs" "$logfile"
        record "$id" "$tier" FAIL "$secs" "$logfile"
        return 1
    fi
}

skip_step() {
    local id=$1 tier=$2 reason=$3
    printf '  [%-10s] %-32s ... SKIP (%s)\n' "$tier" "$id" "$reason"
    record "$id" "$tier" SKIP 0 "(skipped: $reason)"
}

# --- step bodies ----------------------------------------------------------

step_make_clean() { make clean; }
step_make_build() { make CC=cc CFLAGS="-Wall -Wextra -std=c11 -O2"; }
step_urtb_help()  { ./urtb --help; }
step_platform_libs() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        otool -L urtb
    else
        ldd urtb || true
    fi
}
step_make_test()      { make test; }
step_ac03_pyte()      { python3 tools/ac03_pyte_test.py; }
step_heltec_socat()   { bash tools/heltec_socat_test.sh; }
step_frag_runtime()   { bash tools/frag_runtime_test.sh; }
step_musl_static()    { make urtb-static && file urtb-static | grep -q 'statically linked'; }
step_hygiene() {
    # Production binary must contain ZERO inject symbols. The inject phase
    # report (D-37, report_inject_phase.md §5) calls this the load-bearing
    # gate that keeps test-only RF failure injection out of shipped builds.
    local count
    count=$(nm urtb 2>/dev/null | grep -c inject; true)
    count=${count:-0}
    echo "nm urtb | grep -c inject = $count"
    [[ "$count" -eq 0 ]]
}

# --- no-hw tier -----------------------------------------------------------

run_no_hw() {
    echo "== no-hw tier =="
    run_step make-clean   no-hw hard step_make_clean   || return 2
    run_step make-build   no-hw hard step_make_build   || return 2
    run_step urtb-help    no-hw soft step_urtb_help
    run_step platform-libs no-hw soft step_platform_libs
    run_step frame-test   no-hw hard step_make_test    || return 2
    run_step ac03-pyte    no-hw soft step_ac03_pyte
    run_step heltec-socat no-hw soft step_heltec_socat
    run_step frag-runtime no-hw soft step_frag_runtime
    if [[ "$(uname -s)" != "Darwin" ]] && command -v musl-gcc >/dev/null 2>&1; then
        run_step musl-static no-hw soft step_musl_static
    else
        skip_step musl-static no-hw "musl-gcc not present (Darwin or Linux without musl-tools)"
    fi
    run_step hygiene      no-hw soft step_hygiene
}

run_quick() {
    echo "== quick smoke =="
    run_step make-clean no-hw hard step_make_clean || return 2
    run_step make-build no-hw hard step_make_build || return 2
    run_step frame-test no-hw hard step_make_test  || return 2
}

# --- hw tier --------------------------------------------------------------

run_hw() {
    echo "== hw tier =="
    local ports_out
    ports_out=$(bash tools/ports.sh 2>/dev/null || true)
    eval "$ports_out" || true
    if [[ -z "${DEVICE_A:-}" || -z "${DEVICE_B:-}" ]]; then
        echo "  hw tier SKIPPED: <2 Heltec V3 ports detected (tools/ports.sh)"
        skip_step ports         hw "<2 Heltec V3 ports"
        skip_step build-test    hw "no hardware"
        skip_step build-prod    hw "no hardware"
        skip_step flash-test    hw "no hardware"
        skip_step inject-acs    hw "no hardware"
        skip_step reflash-prod  hw "no hardware"
        return 0
    fi
    echo "  ports: DEVICE_A=$DEVICE_A DEVICE_B=$DEVICE_B"

    # build-test: inject-enabled binary MUST contain inject symbols
    # (load-bearing gate proves URTB_TEST_INJECT=1 actually wired in).
    # The inject-phase report records exactly 7 inject symbols in the
    # test build; assert >= 7 to allow growth without regressing presence.
    run_step build-test hw hard \
        bash -c 'set -e
                 make clean
                 make urtb URTB_TEST_INJECT=1
                 mv urtb urtb-test
                 c=$(nm urtb-test | grep -c inject; true); c=${c:-0}
                 echo "nm urtb-test | grep -c inject = $c"
                 [ "$c" -ge 7 ] || { echo "FAIL: expected >=7 inject symbols, got $c" >&2; exit 1; }' \
        || return 2

    # build-prod: production binary MUST contain ZERO inject symbols
    # (the symbol-audit half of D-37).
    run_step build-prod hw hard \
        bash -c 'set -e
                 make clean
                 make urtb
                 c=$(nm urtb | grep -c inject; true); c=${c:-0}
                 echo "nm urtb | grep -c inject = $c"
                 [ "$c" -eq 0 ] || { echo "FAIL: prod binary has $c inject symbols" >&2; exit 1; }' \
        || return 2

    run_step flash-test hw hard \
        bash -c "cd firmware && pio run -e heltec_wifi_lora_32_V3_test -t upload --upload-port $DEVICE_A && pio run -e heltec_wifi_lora_32_V3_test -t upload --upload-port $DEVICE_B" \
        || return 2

    DEV_A=$DEVICE_A DEV_B=$DEVICE_B \
        run_step inject-acs hw soft \
            bash tools/run_inject_acs.sh all

    run_step reflash-prod hw soft \
        bash -c "cd firmware && pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port $DEVICE_A && pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port $DEVICE_B"

    if [[ $INCLUDE_FI02_DOC -eq 1 ]]; then
        skip_step fi02-physical hw "interactive-manual: see TESTING.md §FI-02"
    fi
}

# --- main -----------------------------------------------------------------

T0=$(date +%s)
HARD_ERROR=0

if [[ $QUICK -eq 1 ]]; then
    run_quick || HARD_ERROR=1
else
    case "$TIER" in
        no-hw) run_no_hw || HARD_ERROR=1 ;;
        hw)    run_hw   || HARD_ERROR=1 ;;
        all)
            run_no_hw || HARD_ERROR=1
            if [[ $HARD_ERROR -eq 0 ]]; then
                run_hw || HARD_ERROR=1
            else
                echo "  hw tier SKIPPED: hard failure in no-hw tier"
            fi
            ;;
    esac
fi

T1=$(date +%s)
ELAPSED=$(( T1 - T0 ))

# --- summary --------------------------------------------------------------

SUMMARY="$RUNDIR/summary.txt"
n=${#RESULT_ID[@]}
pass=0; fail=0; skip=0; hard=0
for ((i=0; i<n; i++)); do
    case "${RESULT_VERDICT[i]}" in
        PASS) pass=$((pass+1));;
        FAIL) fail=$((fail+1));;
        SKIP) skip=$((skip+1));;
        HARDFAIL) hard=$((hard+1));;
    esac
done

{
    printf '== run_all_tests summary (%s) ==\n' "$TS"
    printf '%-15s %-8s %-12s %8s\n' "TEST" "TIER" "VERDICT" "SECS"
    printf '%s\n' "----------------------------------------------------"
    for ((i=0; i<n; i++)); do
        printf '%-15s %-8s %-12s %8s\n' \
            "${RESULT_ID[i]}" "${RESULT_TIER[i]}" "${RESULT_VERDICT[i]}" "${RESULT_SECS[i]}"
    done
    printf '%s\n' "----------------------------------------------------"
    printf 'totals: %d PASS, %d FAIL, %d SKIP, %d HARDFAIL  (wall %ds)\n' \
        "$pass" "$fail" "$skip" "$hard" "$ELAPSED"
    printf 'logs: %s\n' "$RUNDIR"
} | tee "$SUMMARY"

# --- json (optional) ------------------------------------------------------

if [[ -n "$JSON_OUT" ]]; then
    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$TS"
        printf '  "tier": "%s",\n' "$TIER"
        printf '  "elapsed_secs": %d,\n' "$ELAPSED"
        printf '  "logs_dir": "%s",\n' "$RUNDIR"
        printf '  "results": [\n'
        n=${#RESULT_ID[@]}
        for ((i=0; i<n; i++)); do
            sep=,
            [[ $i -eq $((n-1)) ]] && sep=
            printf '    {"id":"%s","tier":"%s","verdict":"%s","secs":%s,"log":"%s"}%s\n' \
                "${RESULT_ID[i]}" "${RESULT_TIER[i]}" "${RESULT_VERDICT[i]}" "${RESULT_SECS[i]}" "${RESULT_LOG[i]}" "$sep"
        done
        printf '  ],\n'
        printf '  "totals": {"pass": %d, "fail": %d, "skip": %d, "hardfail": %d}\n' \
            "$pass" "$fail" "$skip" "$hard"
        printf '}\n'
    } > "$JSON_OUT"
fi

# --- exit -----------------------------------------------------------------

if [[ $hard -gt 0 ]]; then exit 2; fi
if [[ $fail -gt 0 ]]; then exit 1; fi
exit 0
