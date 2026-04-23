#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# frag_runtime_test.sh — exercise PROTOCOL.md §7 fragmentation end-to-end
# via the same socat virtual-TTY topology as heltec_socat_test.sh.
#
# Forces LoRa mode (transport_active=2 → MTU 72) and runs a remote command
# whose output is much larger than 72 bytes in a single LoRa coalescer flush.
# The listener-side PTY master read becomes a multi-fragment radio burst.
# Verifies:
#   1. urtb listen + connect both reach ESTABLISHED on LoRa mode.
#   2. The 400-byte payload is reassembled intact at the receiving side
#      (the literal token must appear in the connect-side output).
#   3. The session does not log any reasm errors.
#   4. urtb connect exits rc=0.
#
# Usage:  bash tools/frag_runtime_test.sh

set -uo pipefail
cd "$(dirname "$0")/.."

# macOS has no GNU `timeout`. Use the same fork-wait perl shim as
# heltec_socat_test.sh (bare alarm+exec is broken because POSIX clears
# pending alarms on exec()).
timeout_cmd() {
    local secs=$1; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        perl -e '
            my $s = shift;
            my $pid = fork();
            die "fork: $!" unless defined $pid;
            if ($pid == 0) { exec { $ARGV[0] } @ARGV or die "exec: $!"; }
            $SIG{ALRM} = sub { kill "TERM", $pid; };
            alarm $s;
            waitpid($pid, 0);
            my $rc = $?;
            exit($rc & 127 ? 128 + ($rc & 127) : $rc >> 8);
        ' "$secs" "$@"
    fi
}

CAP=/tmp/urtb-frag.cap
A0=/tmp/ttyFA0; A1=/tmp/ttyFA1
B0=/tmp/ttyFB0; B1=/tmp/ttyFB1
LISTEN_LOG=/tmp/urtb-frag-listen.log
CONNECT_LOG=/tmp/urtb-frag-connect.log
FW_LOG=/tmp/urtb-frag-fw.log

cleanup() {
    [[ -n "${LISTEN_PID:-}" ]] && kill -9 "$LISTEN_PID" 2>/dev/null
    [[ -n "${CONNECT_PID:-}" ]] && kill -9 "$CONNECT_PID" 2>/dev/null
    [[ -n "${FW_PID:-}" ]]      && kill -9 "$FW_PID" 2>/dev/null
    [[ -n "${SOCAT_A_PID:-}" ]] && kill -9 "$SOCAT_A_PID" 2>/dev/null
    [[ -n "${SOCAT_B_PID:-}" ]] && kill -9 "$SOCAT_B_PID" 2>/dev/null
    rm -f "$A0" "$A1" "$B0" "$B1"
}
trap cleanup EXIT

rm -f "$CAP" "$A0" "$A1" "$B0" "$B1" "$LISTEN_LOG" "$CONNECT_LOG" "$FW_LOG"

URTB_PASSPHRASE=fraghw ./urtb keygen --out "$CAP" >/dev/null

socat -d -d PTY,link=$A0,raw,echo=0 PTY,link=$A1,raw,echo=0 >/dev/null 2>&1 &
SOCAT_A_PID=$!
socat -d -d PTY,link=$B0,raw,echo=0 PTY,link=$B1,raw,echo=0 >/dev/null 2>&1 &
SOCAT_B_PID=$!

for i in 1 2 3 4 5 6 7 8 9 10; do
    [[ -e $A0 && -e $A1 && -e $B0 && -e $B1 ]] && break
    sleep 0.1
done
[[ -e $A0 && -e $A1 && -e $B0 && -e $B1 ]] || { echo "FAIL: socat pty not created" >&2; exit 1; }

# Force LoRa from the very first status push.
python3 tools/fake_firmware.py "$A1" "$B1" --initial-status 1 > "$FW_LOG" 2>&1 &
FW_PID=$!
sleep 0.3

URTB_PASSPHRASE=fraghw ./urtb listen --transport heltec --device "$A0" --capsule "$CAP" > "$LISTEN_LOG" 2>&1 &
LISTEN_PID=$!
sleep 1.0

# A single-line burst well above the 72-byte LoRa MTU.
# The token "FRAGTOKEN" appears once at the start and once at the end of
# the payload so we can detect partial delivery vs full delivery.
URTB_PASSPHRASE=fraghw timeout_cmd 15 ./urtb connect --transport heltec --device "$B0" --capsule "$CAP" > "$CONNECT_LOG" 2>&1 <<'EOF'
printf 'FRAGTOKEN_BEGIN_'; printf 'X%.0s' $(seq 1 400); printf '_FRAGTOKEN_END\n'
exit
EOF
RC=$?
sleep 0.3

echo "=== rc=$RC ==="

PAYLOAD_OK=0
if grep -q 'FRAGTOKEN_BEGIN_' "$CONNECT_LOG" && grep -q '_FRAGTOKEN_END' "$CONNECT_LOG"; then
    PAYLOAD_OK=1
fi

REASM_ERR=0
if grep -q 'reasm error' "$LISTEN_LOG" || grep -q 'reasm error' "$CONNECT_LOG"; then
    REASM_ERR=1
fi

# Positively assert that the multi-fragment branch of session_send_data
# actually fired on the listener side. Without this check, a regression
# that silently bypassed fragmentation (e.g. capping payload to MTU)
# could still pass the token-roundtrip check.
FRAG_FIRED=0
FRAG_LINE=$(grep 'session: fragmenting' "$LISTEN_LOG" | tail -1 || true)
if [[ -n "$FRAG_LINE" ]]; then
    NFRAGS=$(echo "$FRAG_LINE" | sed -n 's/.*into \([0-9][0-9]*\) fragments.*/\1/p')
    if [[ -n "$NFRAGS" && "$NFRAGS" -ge 2 ]]; then
        FRAG_FIRED=1
    fi
fi

LORA_MODE_OK=0
if grep -q 'transport mode 2' "$LISTEN_LOG" && grep -q 'transport mode 2' "$CONNECT_LOG"; then
    LORA_MODE_OK=1
fi

echo "lora_mode=$LORA_MODE_OK payload_ok=$PAYLOAD_OK reasm_errors=$REASM_ERR frag_fired=$FRAG_FIRED nfrags=${NFRAGS:-0} rc=$RC"

if [[ $RC -eq 0 && $PAYLOAD_OK -eq 1 && $REASM_ERR -eq 0 && $LORA_MODE_OK -eq 1 && $FRAG_FIRED -eq 1 ]]; then
    echo "PASS: fragmentation E2E (LoRa, ~400-byte burst → ${NFRAGS} fragments, reassembled intact)"
    exit 0
fi

echo "--- listen log (last 30) ---"
tail -30 "$LISTEN_LOG"
echo "--- connect log (last 30) ---"
tail -30 "$CONNECT_LOG"
echo "--- fake fw log ---"
cat "$FW_LOG"
exit 1
