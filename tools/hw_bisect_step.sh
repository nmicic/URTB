#!/bin/sh
# tools/hw_bisect_step.sh — called per commit by `git bisect run`.
# Exit: 0 = good, 1 = bad, 125 = skip (doesn't build / missing firmware).
set -u

cd "$(git rev-parse --show-toplevel)"

# 1. Build host binary
make clean >/dev/null 2>&1
if ! make >/tmp/urtb_build.log 2>&1; then
    echo "skip: host build failed at $(git rev-parse --short HEAD)"
    cat /tmp/urtb_build.log | tail -20
    exit 125
fi

# 2. Build firmware
if [ ! -d firmware ]; then
    echo "skip: no firmware dir at $(git rev-parse --short HEAD)"
    exit 125
fi
(cd firmware && pio run -e heltec_wifi_lora_32_V3 >/tmp/urtb_fw_build.log 2>&1)
if [ $? -ne 0 ]; then
    echo "skip: firmware build failed"
    cat /tmp/urtb_fw_build.log | tail -20
    exit 125
fi

# 3. Flash both boards
if ! tools/hw_test_flash.sh >/tmp/urtb_flash.log 2>&1; then
    echo "skip: flash failed at $(git rev-parse --short HEAD)"
    cat /tmp/urtb_flash.log | tail -20
    exit 125
fi

# 4. Run the test twice (retry once for transient RF glitches)
if tools/hw_test_run.sh; then
    exit 0
fi
sleep 3
if tools/hw_test_run.sh; then
    exit 0
fi
exit 1
