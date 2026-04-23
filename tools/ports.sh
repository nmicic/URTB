#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# ports.sh — auto-detect attached Heltec V3 USB-serial ports.
#
# CP2102 USB-UART bridge (VID 10c4 PID ea60) on macOS appears as
# /dev/cu.usbserial-* and on Linux as /dev/ttyUSB*. Output is
# eval-friendly:
#
#   eval $(tools/ports.sh)
#   echo "$DEVICE_A $DEVICE_B"
#
# Exit code 0 when ≥2 ports are detected, 1 otherwise.

set -uo pipefail

uname_s=$(uname -s)

mapfile_compat() {
    # macOS bash 3.2 has no `mapfile`. Read newline-separated stdin into
    # the named array.
    local __name=$1
    local __line
    eval "$__name=()"
    while IFS= read -r __line; do
        [[ -z "$__line" ]] && continue
        eval "$__name+=(\"\$__line\")"
    done
}

PORTS=()

if [[ "$uname_s" == "Darwin" ]]; then
    # Prefer pio device list (richest source: filters by VID/PID) when pio
    # is installed. Fall back to the /dev glob.
    if command -v pio >/dev/null 2>&1; then
        # `pio device list` prints stanzas; lines starting with /dev/cu... are
        # the device path; filter those whose VID:PID block contains 10C4:EA60.
        pio_out=$(pio device list 2>/dev/null || true)
        if [[ -n "$pio_out" ]]; then
            mapfile_compat PORTS < <(
                awk '
                    /^\/dev\// { dev=$0; next }
                    /VID:PID/ {
                        if (toupper($0) ~ /10C4:EA60/) print dev
                    }
                ' <<<"$pio_out"
            )
        fi
    fi
    if [[ ${#PORTS[@]} -eq 0 ]]; then
        # Plain glob fallback. Any /dev/cu.usbserial-* device.
        for p in /dev/cu.usbserial-*; do
            [[ -e "$p" ]] || continue
            PORTS+=("$p")
        done
    fi
else
    # Linux: prefer /dev/serial/by-id symlinks that reference CP2102, else
    # plain /dev/ttyUSB* glob.
    if [[ -d /dev/serial/by-id ]]; then
        for link in /dev/serial/by-id/*CP210*; do
            [[ -e "$link" ]] || continue
            real=$(readlink -f "$link" 2>/dev/null || echo "$link")
            PORTS+=("$real")
        done
    fi
    if [[ ${#PORTS[@]} -eq 0 ]]; then
        for p in /dev/ttyUSB*; do
            [[ -e "$p" ]] || continue
            PORTS+=("$p")
        done
    fi
fi

# Deduplicate while preserving order (a device may appear via both pio and
# the by-id symlink).
DEDUPED=()
for p in "${PORTS[@]:-}"; do
    [[ -z "$p" ]] && continue
    skip=0
    for q in "${DEDUPED[@]:-}"; do
        if [[ "$q" == "$p" ]]; then skip=1; break; fi
    done
    [[ $skip -eq 0 ]] && DEDUPED+=("$p")
done

case ${#DEDUPED[@]} in
    0)
        echo "# no Heltec V3 ports detected"
        exit 1
        ;;
    1)
        echo "# only 1 Heltec V3 port detected"
        echo "DEVICE_A=${DEDUPED[0]}"
        exit 1
        ;;
    *)
        echo "DEVICE_A=${DEDUPED[0]}"
        echo "DEVICE_B=${DEDUPED[1]}"
        exit 0
        ;;
esac
