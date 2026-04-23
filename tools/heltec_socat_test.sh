#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# heltec_socat_test.sh — drive Heltec USB framing over two socat PTY pairs
# bridged by tools/fake_firmware.py. Validates transport_heltec.c end-to-end
# without real hardware.
#
# See tools/fake_firmware.py for topology details.

set -uo pipefail
cd "$(dirname "$0")/.."

# macOS portability: ship-with-OS bash is 3.2 (no `${arr[@]+...}` shortcut
# is needed but `${ARR[@]}` on an empty array under `set -u` errors here),
# and macOS has no GNU `timeout`. Provide a fallback via perl alarm.
timeout_cmd() {
    local secs=$1; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        # POSIX explicitly clears any pending alarm() on exec() (see
        # "alarm" in IEEE Std 1003.1), so a naive `alarm $s; exec @ARGV`
        # lets the child run indefinitely. Fork the child, keep perl
        # alive as the timer parent, SIGTERM on alarm, then propagate
        # the child's exit status.
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

CAP=/tmp/heltec-cap.bin
A0=/tmp/ttyA0; A1=/tmp/ttyA1
B0=/tmp/ttyB0; B1=/tmp/ttyB1
LISTEN_LOG=/tmp/heltec-listen.log
CONNECT_LOG=/tmp/heltec-connect.log
FW_LOG=/tmp/heltec-fw.log
SOCAT_A_LOG=/tmp/heltec-socat-a.log
SOCAT_B_LOG=/tmp/heltec-socat-b.log

cleanup() {
    [[ -n "${LISTEN_PID:-}" ]] && kill -9 "$LISTEN_PID" 2>/dev/null
    [[ -n "${CONNECT_PID:-}" ]] && kill -9 "$CONNECT_PID" 2>/dev/null
    [[ -n "${FW_PID:-}" ]]      && kill -9 "$FW_PID" 2>/dev/null
    [[ -n "${SOCAT_A_PID:-}" ]] && kill -9 "$SOCAT_A_PID" 2>/dev/null
    [[ -n "${SOCAT_B_PID:-}" ]] && kill -9 "$SOCAT_B_PID" 2>/dev/null
    rm -f "$A0" "$A1" "$B0" "$B1"
}
trap cleanup EXIT

rm -f "$CAP" "$A0" "$A1" "$B0" "$B1" "$LISTEN_LOG" "$CONNECT_LOG" "$FW_LOG" "$SOCAT_A_LOG" "$SOCAT_B_LOG"

# DECISIONS.md D-40: keygen with a distinctive channel (11,
# not the default 6) so the fake-firmware-side log assertion below proves
# the capsule-selected channel actually reached USB_CONFIG byte 18. The
# `${ESPNOW_CHANNEL:-11}` form lets callers override but defaults to 11
# so the assertion is meaningful when the script runs stand-alone.
ESPNOW_CHANNEL="${ESPNOW_CHANNEL:-11}"
URTB_PASSPHRASE=heltec ./urtb keygen --out "$CAP" \
    --espnow-channel "$ESPNOW_CHANNEL" >/dev/null

socat -d -d PTY,link=$A0,raw,echo=0 PTY,link=$A1,raw,echo=0 > "$SOCAT_A_LOG" 2>&1 &
SOCAT_A_PID=$!
socat -d -d PTY,link=$B0,raw,echo=0 PTY,link=$B1,raw,echo=0 > "$SOCAT_B_LOG" 2>&1 &
SOCAT_B_PID=$!

# Wait for both PTY pairs.
for i in 1 2 3 4 5 6 7 8 9 10; do
    [[ -e $A0 && -e $A1 && -e $B0 && -e $B1 ]] && break
    sleep 0.1
done
if [[ ! -e $A0 || ! -e $A1 || ! -e $B0 || ! -e $B1 ]]; then
    echo "FAIL: socat did not create all four PTY symlinks" >&2
    exit 1
fi

INITIAL_STATUS="${INITIAL_STATUS:-0}"
# macOS bash 3.2 errors on `${EMPTY[@]}` under set -u; branch on whether
# STATUS_FLAP is set instead of building an empty array.
if [[ -n "${STATUS_FLAP:-}" ]]; then
    python3 tools/fake_firmware.py "$A1" "$B1" \
        --initial-status "$INITIAL_STATUS" \
        --status-flap "$STATUS_FLAP" > "$FW_LOG" 2>&1 &
else
    python3 tools/fake_firmware.py "$A1" "$B1" \
        --initial-status "$INITIAL_STATUS" > "$FW_LOG" 2>&1 &
fi
FW_PID=$!
sleep 0.3

URTB_PASSPHRASE=heltec ./urtb listen --transport heltec --device "$A0" --capsule "$CAP" > "$LISTEN_LOG" 2>&1 &
LISTEN_PID=$!
sleep 1.0

DWELL="${DWELL:-0}"
if [[ "$DWELL" != "0" ]]; then
    URTB_PASSPHRASE=heltec timeout_cmd $((DWELL + 12)) ./urtb connect --transport heltec --device "$B0" --capsule "$CAP" > "$CONNECT_LOG" 2>&1 <<EOF
id
tty
sleep $DWELL
exit
EOF
else
    URTB_PASSPHRASE=heltec timeout_cmd 12 ./urtb connect --transport heltec --device "$B0" --capsule "$CAP" > "$CONNECT_LOG" 2>&1 <<EOF
id
tty
exit
EOF
fi
RC=$?
sleep 0.5

echo "=== exit code: $RC ==="
echo
echo "=== listen log (last 40) ==="
tail -40 "$LISTEN_LOG"
echo
echo "=== connect log (last 40) ==="
tail -40 "$CONNECT_LOG"
echo
echo "=== fake firmware log ==="
cat "$FW_LOG"

# DECISIONS.md D-40: assert the chosen ESP-NOW channel
# reached USB_CONFIG byte 18 on BOTH sides (A and B). fake_firmware.py
# logs one line per side of the form:
#   [fake_fw] A: USB_CONFIG (pair_id=..., espnow_channel=11, ...) ...
#   [fake_fw] B: USB_CONFIG (pair_id=..., espnow_channel=11, ...) ...
CHAN_A=$(grep -Eo "^\[fake_fw\] A: USB_CONFIG \([^)]*espnow_channel=[0-9-]+" "$FW_LOG" \
    | grep -Eo 'espnow_channel=[0-9-]+' | head -n1 | cut -d= -f2)
CHAN_B=$(grep -Eo "^\[fake_fw\] B: USB_CONFIG \([^)]*espnow_channel=[0-9-]+" "$FW_LOG" \
    | grep -Eo 'espnow_channel=[0-9-]+' | head -n1 | cut -d= -f2)
echo
echo "=== channel assertion (D-40) ==="
echo "expected espnow_channel=$ESPNOW_CHANNEL on both sides"
echo "  side A saw: ${CHAN_A:-<none>}"
echo "  side B saw: ${CHAN_B:-<none>}"
if [[ "$CHAN_A" != "$ESPNOW_CHANNEL" || "$CHAN_B" != "$ESPNOW_CHANNEL" ]]; then
    echo "FAIL: USB_CONFIG byte 18 (espnow_channel) mismatch — expected $ESPNOW_CHANNEL on both sides" >&2
    # Only promote to hard fail if the session itself reached USB_CONFIG
    # (otherwise the upstream failure is the real signal, not this check).
    if [[ "$RC" -eq 0 ]]; then
        exit 1
    fi
fi

exit $RC
