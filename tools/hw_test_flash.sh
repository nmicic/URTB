#!/bin/sh
# URTB hardware test — phase 1: erase + reflash both Heltec V3 boards.
# Requires pio on PATH and two boards visible as /dev/cu.usbserial-*.
set -eu

cd "$(dirname "$0")/.."   # repo root

cd firmware

DEVS=$(pio device list 2>/dev/null | grep usbserial | grep ^/dev)
DEV1=$(echo "$DEVS" | head -1)
DEV2=$(echo "$DEVS" | tail -1)

echo "Board 1: $DEV1"
echo "Board 2: $DEV2"

if [ -z "$DEV1" ] || [ -z "$DEV2" ] || [ "$DEV1" = "$DEV2" ]; then
    echo "ERROR: expected two distinct usbserial devices" >&2
    exit 2
fi

pio run -e heltec_wifi_lora_32_V3 -t erase  --upload-port "$DEV1"
pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port "$DEV1"

pio run -e heltec_wifi_lora_32_V3 -t erase  --upload-port "$DEV2"
pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port "$DEV2"

# Let USB settle after the last reboot
sleep 3
pio device list | grep usbserial | grep ^/dev
cd ..
echo "flash OK"
