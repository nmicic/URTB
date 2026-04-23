#!/bin/sh
# URTB hardware test — phase 2: keygen, run listen+connect, check for
# ESTABLISHED state on both sides.
# Exit codes:
#   0 — both sides reached ESTABLISHED on ESP-NOW and stayed ≥5s
#   1 — session failed (timeout, LoRa fallback during handshake, etc.)
#   2 — setup failure (no boards, capsule failed, etc.)
set -u

cd "$(dirname "$0")/.."   # repo root

# Assumes ./urtb already built.
if [ ! -x ./urtb ]; then
    echo "ERROR: ./urtb binary not found — run make first" >&2
    exit 2
fi

DEVS=$(pio device list 2>/dev/null | grep usbserial | grep ^/dev)
DEV1=$(echo "$DEVS" | head -1)
DEV2=$(echo "$DEVS" | tail -1)

if [ -z "$DEV1" ] || [ -z "$DEV2" ] || [ "$DEV1" = "$DEV2" ]; then
    echo "ERROR: expected two distinct usbserial devices" >&2
    exit 2
fi

CAP=/tmp/urtb_hw_test.capsule
LOG_LISTEN=/tmp/urtb_hw_listen.log
LOG_CONNECT=/tmp/urtb_hw_connect.log

rm -f "$CAP" "$LOG_LISTEN" "$LOG_CONNECT"

URTB_PASSPHRASE=test123 ./urtb keygen --out "$CAP" || exit 2

# Start listen in background
URTB_PASSPHRASE=test123 ./urtb listen \
    --transport heltec --capsule "$CAP" --device "$DEV1" \
    >"$LOG_LISTEN" 2>&1 &
LISTEN_PID=$!

sleep 2   # let listen open USB and send USB_CONFIG before connect starts

# Start connect in background with a 45s wall clock
URTB_PASSPHRASE=test123 ./urtb connect \
    --transport heltec --capsule "$CAP" --device "$DEV2" \
    >"$LOG_CONNECT" 2>&1 &
CONNECT_PID=$!

# Wait up to 45s for both sides to show ESTABLISHED
OK=0
for i in $(seq 1 45); do
    if grep -q '→ ESTABLISHED' "$LOG_LISTEN" 2>/dev/null \
    && grep -q 'transport mode 1' "$LOG_CONNECT" 2>/dev/null \
    && grep -q 'sent CTRL_READY' "$LOG_CONNECT" 2>/dev/null; then
        OK=1; break
    fi
    sleep 1
done

# If both sides reached ESTABLISHED, give it 5s to make sure it holds
if [ "$OK" = "1" ]; then
    sleep 5
    # If the connect side timed out during those 5s, fail
    if grep -q 'KEY_DERIVING timeout\|liveness timeout\|→ IDLE' \
         "$LOG_CONNECT" 2>/dev/null; then
        OK=0
    fi
    # If either peer ever shows mode 2 (LoRa), fail. Ship gate proves
    # the session stays on ESP-NOW on BOTH sides — any mode-2 mention
    # (transient or persistent) masks the e279c05 / b33899c regression
    # class. Investigate the bounce before re-running.
    if grep -q 'transport mode 2' "$LOG_LISTEN" 2>/dev/null; then
        OK=0
    fi
    if grep -q 'transport mode 2' "$LOG_CONNECT" 2>/dev/null; then
        OK=0
    fi
fi

# Cleanup
kill "$LISTEN_PID" 2>/dev/null || true
kill "$CONNECT_PID" 2>/dev/null || true
wait 2>/dev/null

echo "=== listen log ==="
cat "$LOG_LISTEN"
echo "=== connect log ==="
cat "$LOG_CONNECT"

if [ "$OK" = "1" ]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
