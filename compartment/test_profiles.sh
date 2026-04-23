#!/bin/bash
# test_profiles.sh — Verify compartment profiles work with urtb.
# Tests both connect and listen profiles, including OTP path.
# Requires: compartment-user in PATH or ~/compartment/compartment-user
# Usage: ./compartment/test_profiles.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
URTB_DIR="$(dirname "$SCRIPT_DIR")"
CAP="/tmp/urtb_compartment_test_$$.cap"
OTP_KEY="/tmp/urtb_compartment_test_otp_$$.key"
PASS=0
FAIL=0

CU=""
for p in compartment-user "$HOME/compartment/compartment-user" /usr/local/bin/compartment-user; do
    if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then
        CU="$p"
        break
    fi
done
if [ -z "$CU" ]; then
    echo "SKIP: compartment-user not found" >&2
    exit 0
fi

cleanup() { rm -f "$CAP" "$OTP_KEY"; }
trap cleanup EXIT

cd "$URTB_DIR"

export URTB_PASSPHRASE=test
./urtb keygen --out "$CAP" 2>/dev/null

run_test() {
    local name="$1" profile="$2" listen_extra="${3:-}" log="/tmp/urtb_ctest_$$.log"
    local listen_cmd="./urtb listen --transport stdio --capsule $CAP $listen_extra"

    timeout 5 "$CU" --profile "$profile" -- \
        bash -c "./urtb connect \
            --exec \"$listen_cmd\" \
            --capsule $CAP" >"$log" 2>&1 || true

    if grep -q 'ESTABLISHED' "$log" && grep -q 'raw mode' "$log" && ! grep -q 'Segmentation' "$log"; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name"
        cat "$log" >&2
        FAIL=$((FAIL + 1))
    fi
    rm -f "$log"
}

run_otp_test() {
    local name="$1" profile="$2" log="/tmp/urtb_ctest_$$.log"

    ./urtb otp-init --type totp --out "$OTP_KEY" --force >/dev/null 2>&1
    local code
    code=$(./urtb otp-verify --otp "$OTP_KEY" --print 2>&1)

    local listen_cmd="./urtb listen --transport stdio --capsule $CAP --otp $OTP_KEY"
    timeout 5 "$CU" --profile "$profile" -- \
        bash -c "./urtb connect \
            --exec \"$listen_cmd\" \
            --capsule $CAP <<< '$code'" >"$log" 2>&1 || true

    if grep -q 'OTP verified' "$log" && grep -q 'ESTABLISHED' "$log" && ! grep -q 'Segmentation' "$log"; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name"
        cat "$log" >&2
        FAIL=$((FAIL + 1))
    fi
    rm -f "$log"
}

echo "--- Compartment profile tests ---"

echo "# Connect profiles"
run_test "connect deny-list"  "$SCRIPT_DIR/urtb-connect.conf"
run_test "connect strict"     "$SCRIPT_DIR/urtb-connect-strict.conf"

echo "# Listen profiles"
run_test "listen deny-list"   "$SCRIPT_DIR/urtb-listen.conf"
run_test "listen strict"      "$SCRIPT_DIR/urtb-listen-strict.conf"

echo "# Listen + OTP"
run_otp_test "listen deny-list + OTP" "$SCRIPT_DIR/urtb-listen.conf"
run_otp_test "listen strict + OTP"    "$SCRIPT_DIR/urtb-listen-strict.conf"

echo "--- $PASS passed, $FAIL failed ---"
[ "$FAIL" -eq 0 ]
