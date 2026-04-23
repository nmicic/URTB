#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# doctor.sh — environment readiness check for URTB.
#
# Required:    cc/clang, make, python3, pyte module, socat
# Recommended: pio (PlatformIO, for hardware tier), 2 Heltec V3 ports
# Optional:    musl-gcc (Linux only)

set -uo pipefail
cd "$(dirname "$0")/.."

REQ_FAIL=0

row() {
    # row STATUS NAME DESC
    printf '[%-4s] %-16s %s\n' "$1" "$2" "$3"
}

short_ver() {
    # Extract a clean one-liner from arbitrary --version output.
    head -1 "$@" 2>/dev/null
}

echo "== URTB doctor =="

# ---- compiler -----------------------------------------------------------
if command -v cc >/dev/null 2>&1; then
    ver=$(cc --version 2>/dev/null | head -1 || echo "unknown")
    row OK compiler "$ver"
elif command -v clang >/dev/null 2>&1; then
    ver=$(clang --version 2>/dev/null | head -1 || echo "unknown")
    row OK compiler "$ver"
elif command -v gcc >/dev/null 2>&1; then
    ver=$(gcc --version 2>/dev/null | head -1 || echo "unknown")
    row OK compiler "$ver"
else
    row FAIL compiler "no cc/clang/gcc on PATH"
    REQ_FAIL=1
fi

# ---- make ---------------------------------------------------------------
if command -v make >/dev/null 2>&1; then
    ver=$(make --version 2>/dev/null | head -1 || echo "unknown")
    row OK make "$ver"
else
    row FAIL make "no make on PATH"
    REQ_FAIL=1
fi

# ---- python3 + pyte -----------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    pyver=$(python3 --version 2>&1 || echo "unknown")
    row OK python3 "$pyver"
    if python3 -c 'import pyte' >/dev/null 2>&1; then
        pytever=$(python3 -c 'import pyte; print(getattr(pyte, "__version__", "(no __version__ attr)"))' 2>/dev/null)
        row OK "pyte module" "$pytever (used by tools/ac03_pyte_test.py)"
    else
        row FAIL "pyte module" "missing — install with: pip3 install pyte"
        REQ_FAIL=1
    fi
else
    row FAIL python3 "no python3 on PATH"
    REQ_FAIL=1
    row FAIL "pyte module" "python3 missing"
fi

# ---- socat --------------------------------------------------------------
if command -v socat >/dev/null 2>&1; then
    ver=$(socat -V 2>&1 | awk '/^socat version/ {print "socat "$3; exit}')
    [[ -z "$ver" ]] && ver="(version unknown)"
    row OK socat "$ver (used by heltec_socat_test.sh + frag_runtime_test.sh)"
else
    row FAIL socat "missing — install with: brew install socat (mac) / apt-get install socat (linux)"
    REQ_FAIL=1
fi

# ---- perl ---------------------------------------------------------------
# heltec_socat_test.sh and frag_runtime_test.sh use a perl fork+alarm shim
# as the macOS-portable replacement for GNU timeout(1). A bare `alarm; exec`
# is broken because POSIX clears pending alarms on exec(), so the timer
# must run in a parent process that is NOT the child being timed.
if command -v perl >/dev/null 2>&1; then
    ver=$(perl -e 'printf "perl %vd", $^V' 2>/dev/null || echo "perl present")
    row OK perl "$ver (timeout shim for socat tests on macOS)"
else
    row FAIL perl "missing — required by heltec_socat_test.sh / frag_runtime_test.sh on macOS"
    REQ_FAIL=1
fi

# ---- vim / htop (AC-03 pyte sub-tests) ----------------------------------
# AC-03-02 drives `vim` and AC-03-03 drives `htop` through the PTY.
# When either is missing, tools/ac03_pyte_test.py records that sub-test
# as SKIP (not FAIL) — warn here so the cause is visible upfront.
for bin in vim htop; do
    if command -v "$bin" >/dev/null 2>&1; then
        row OK "$bin" "present (AC-03 pyte sub-test)"
    else
        row WARN "$bin" "missing — ac03_pyte_test.py will SKIP the $bin sub-test"
    fi
done

# ---- pio (recommended) --------------------------------------------------
if command -v pio >/dev/null 2>&1; then
    ver=$(pio --version 2>/dev/null || echo "unknown")
    row OK pio "$ver (firmware build/upload, hardware tier)"
else
    row WARN pio "missing — only required for hardware tier (pipx install platformio)"
fi

# ---- Heltec ports -------------------------------------------------------
ports_out=$(bash tools/ports.sh 2>/dev/null || true)
if grep -q '^DEVICE_B=' <<<"$ports_out" 2>/dev/null; then
    a=$(grep '^DEVICE_A=' <<<"$ports_out" | cut -d= -f2)
    b=$(grep '^DEVICE_B=' <<<"$ports_out" | cut -d= -f2)
    row OK "Heltec ports" "2 detected ($a, $b)"
elif grep -q '^DEVICE_A=' <<<"$ports_out" 2>/dev/null; then
    a=$(grep '^DEVICE_A=' <<<"$ports_out" | cut -d= -f2)
    row WARN "Heltec ports" "only 1 detected ($a) — hardware tier needs 2"
else
    row WARN "Heltec ports" "0 detected — hardware tier will skip"
fi

# ---- musl-gcc (optional, Linux only) ------------------------------------
if [[ "$(uname -s)" == "Linux" ]]; then
    if command -v musl-gcc >/dev/null 2>&1; then
        row OK musl-gcc "present (enables make urtb-static)"
    else
        row WARN musl-gcc "not found — install musl-tools to enable urtb-static"
    fi
else
    row "--" musl-gcc "Linux-only, skipped on $(uname -s)"
fi

# ---- urtb binary --------------------------------------------------------
if [[ -x ./urtb ]]; then
    row OK "urtb binary" "built ($(ls -la urtb | awk '{print $5}') bytes)"
else
    row "--" "urtb binary" "not built (run: make)"
fi

# ---- urtb-test binary (informational) -----------------------------------
# The hardware tier renames the URTB_TEST_INJECT=1 build to ./urtb-test so
# the inject subcommand stays out of the production ./urtb path. If both
# exist side-by-side on disk this is normal — ./urtb-test is for AC-05
# inject scenarios only and never gets shipped.
if [[ -x ./urtb-test ]]; then
    row OK "urtb-test" "present (URTB_TEST_INJECT=1 build, used by hw tier)"
else
    row "--" "urtb-test" "not built (built on demand by make check-hw)"
fi

if [[ $REQ_FAIL -eq 0 ]]; then
    echo "== ready: yes =="
    exit 0
else
    echo "== ready: NO  (one or more required components missing) =="
    exit 1
fi
