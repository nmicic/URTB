#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# fi_inject.py — programmable RF failure injection helper (test build only)
#
# Standalone Python USB framing tool that opens a Heltec V3 serial port
# directly and sends a single USB_TEST_INJECT (type 0x0B) frame, then reads
# the firmware's echo ack and prints OK/ERR. Use this when the urtb session
# is NOT running on this device — for in-isolation flag-mechanism tests.
# For mid-session injection while urtb owns the serial port, use the
# `urtb test-inject --pid <pid>` subcommand instead, which goes through the
# control unix socket /tmp/urtb-inject-<pid>.sock.
#
# Sticky semantics: each invocation of this tool persists state in
# /tmp/urtb-fi-inject-<basename(device)>.state so that incremental verbs
# (espnow-down then lora-down) compose correctly.
#
# Usage:
#   fi_inject.py <device> <verb> [hex]
#
# Verbs:
#   espnow-down       set bits 0|1 (DROP_ESPNOW_TX|RX)
#   espnow-up         clear bits 0|1
#   lora-down         set bits 2|3 (DROP_LORA_TX|RX)
#   lora-up           clear bits 2|3
#   all-down          set bits 0..3
#   reset             clear all bits
#   lora-low-power    set bit 4
#   lora-full-power   clear bit 4
#   raw <hex>         replace flags with <hex>

import os
import struct
import sys
import time

import serial

USB_MAGIC = b"\xAB\xCD"
USB_VER = 0x01
USB_TEST_INJECT = 0x0B

VERBS = {
    "espnow-down":     (0x03, 0x00),
    "espnow-up":       (0x00, 0x03),
    "lora-down":       (0x0C, 0x00),
    "lora-up":         (0x00, 0x0C),
    "all-down":        (0x0F, 0x00),
    "reset":           (0x00, 0x1F),
    "lora-low-power":  (0x10, 0x00),
    "lora-full-power": (0x00, 0x10),
}
TI_VALID_MASK = 0x1F


def crc16_ccitt_false(buf):
    crc = 0xFFFF
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def usb_encode(type_b, body):
    hdr = USB_MAGIC + bytes([USB_VER, type_b, 0]) + struct.pack("<H", len(body))
    crc = crc16_ccitt_false(hdr + body)
    return hdr + body + struct.pack("<H", crc)


def state_path(device):
    return f"/tmp/urtb-fi-inject-{os.path.basename(device)}.state"


def load_state(device):
    try:
        with open(state_path(device), "rb") as f:
            v = f.read(1)
            return v[0] if len(v) == 1 else 0
    except FileNotFoundError:
        return 0


def save_state(device, val):
    # Open with explicit 0600 so the state byte is not world-readable under a
    # default 022 umask. The state file leaks current RF inject flags otherwise.
    path = state_path(device)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, bytes([val & TI_VALID_MASK]))
    finally:
        os.close(fd)


def main():
    if len(sys.argv) < 3:
        print(__doc__.split("Usage:")[1].split("\n\n")[0], file=sys.stderr)
        sys.exit(2)
    device = sys.argv[1]
    verb = sys.argv[2]

    current = load_state(device)
    if verb == "raw":
        if len(sys.argv) < 4:
            print("raw <hex> requires hex argument", file=sys.stderr)
            sys.exit(2)
        new = int(sys.argv[3], 0) & TI_VALID_MASK
    elif verb in VERBS:
        set_mask, clear_mask = VERBS[verb]
        new = ((current & ~clear_mask) | set_mask) & TI_VALID_MASK
    else:
        print(f"unknown verb: {verb}", file=sys.stderr)
        sys.exit(2)

    ser = serial.Serial(device, 115200, timeout=1.0)
    # DTR/RTS reset is intentionally NOT done here — that would reboot the
    # device and clear flags. We just open the port and write.
    frame = usb_encode(USB_TEST_INJECT, bytes([new]))
    ser.write(frame)
    ser.flush()

    # Wait briefly for the firmware echo (USB_TEST_INJECT, body=1B with new flags).
    deadline = time.time() + 1.0
    acc = b""
    saw_ack = False
    while time.time() < deadline:
        chunk = ser.read(64)
        if chunk:
            acc += chunk
        # Scan for our echo
        i = 0
        while i + 9 <= len(acc):
            if acc[i:i + 2] != USB_MAGIC or acc[i + 2] != USB_VER:
                i += 1
                continue
            (body_len,) = struct.unpack("<H", acc[i + 5:i + 7])
            total = 7 + body_len + 2
            if i + total > len(acc):
                break
            type_b = acc[i + 3]
            if type_b == USB_TEST_INJECT and body_len == 1:
                ack = acc[i + 7]
                if ack == new:
                    saw_ack = True
                acc = acc[i + total:]
                break
            i += total
        if saw_ack:
            break
    ser.close()

    if saw_ack:
        save_state(device, new)
        print(f"OK flags=0x{new:02X}")
        sys.exit(0)
    print(f"ERR no ack (sent 0x{new:02X})")
    sys.exit(1)


if __name__ == "__main__":
    main()
