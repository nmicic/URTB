#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# fi05_pair_id_inject.py — FI-05 / AC-05-07 PAIR_ID gate verification
#
# Configures both Heltec V3 firmwares with PAIR_ID=AAAAAAAA. Then from
# DEVICE_A injects two USB_DATA_TX frames over serial:
#   1. WRONG pair_id (BBBBBBBB) — firmware on DEVICE_B should drop at the
#      ESP-NOW ingress gate (firmware/src/main.cpp:366), so DEVICE_B emits
#      no USB_DATA_RX.
#   2. CORRECT pair_id (AAAAAAAA) — firmware on DEVICE_B should accept,
#      forward to host as USB_DATA_RX (positive control).
#
# Usage: python3 tools/fi05_pair_id_inject.py DEVICE_A DEVICE_B

import serial
import struct
import sys
import time

USB_MAGIC = b"\xAB\xCD"
USB_VER = 0x01

USB_HELLO = 0x05
USB_HELLO_ACK = 0x06
USB_CONFIG = 0x07
USB_CONFIG_ACK = 0x08
USB_DATA_TX = 0x01
USB_DATA_RX = 0x02
USB_STATUS_RSP = 0x04

PAIR_ID_OK = bytes.fromhex("AAAAAAAA")
PAIR_ID_BAD = bytes.fromhex("BBBBBBBB")
PEER_MAC_BCAST = b"\xFF" * 6
ESPNOW_CHANNEL = 6
LORA_FREQ = 869_875_000  # EU


def crc16_ccitt_false(buf):
    crc = 0xFFFF
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def usb_encode(type_b, body, flags=0):
    hdr = USB_MAGIC + bytes([USB_VER, type_b, flags]) + struct.pack("<H", len(body))
    crc = crc16_ccitt_false(hdr + body)
    return hdr + body + struct.pack("<H", crc)


class FrameReader:
    """Stateful USB frame reader that preserves leftover bytes across reads.

    sonnet-F MAJOR-F05-2: the previous implementation discarded the read
    accumulator on every call, which would lose any USB_DATA_RX that arrived
    in the same ser.read() chunk as a preceding frame and cause a false PASS
    on the negative test. Keep the accumulator on self so leftover bytes from
    one call carry to the next."""

    def __init__(self, ser):
        self.ser = ser
        self.acc = b""

    def read_one(self, timeout_s):
        """Return (type_b, body) for the next valid USB frame, or (None, None)
        on timeout."""
        deadline = time.time() + timeout_s
        while True:
            # try parsing from current accumulator first
            i = 0
            while i + 9 <= len(self.acc):
                if self.acc[i:i + 2] != USB_MAGIC:
                    i += 1
                    continue
                if self.acc[i + 2] != USB_VER:
                    i += 1
                    continue
                (body_len,) = struct.unpack("<H", self.acc[i + 5:i + 7])
                total = 7 + body_len + 2
                if i + total > len(self.acc):
                    break
                crc_calc = crc16_ccitt_false(self.acc[i:i + 7 + body_len])
                (crc_wire,) = struct.unpack("<H",
                                            self.acc[i + 7 + body_len:i + total])
                if crc_calc != crc_wire:
                    i += 1
                    continue
                frame = self.acc[i:i + total]
                self.acc = self.acc[i + total:]
                return frame[3], frame[7:7 + body_len]
            if i > 0:
                self.acc = self.acc[i:]
            if time.time() >= deadline:
                return None, None
            chunk = self.ser.read(256)
            if chunk:
                self.acc += chunk
            else:
                time.sleep(0.01)


def drain_for(reader, dur_s):
    """Drain frames for dur_s wall-clock seconds, returning [(type_b, body)]."""
    out = []
    deadline = time.time() + dur_s
    while time.time() < deadline:
        rem = max(0.05, deadline - time.time())
        type_b, body = reader.read_one(rem)
        if type_b is None:
            continue
        out.append((type_b, body))
    return out


def setup_firmware(reader, label):
    ser = reader.ser
    print(f"[{label}] sending USB_HELLO")
    ser.write(usb_encode(USB_HELLO, bytes([0x01, 0x00])))
    ser.flush()
    # USB_HELLO_ACK may be preceded by USB_STATUS_RSP — skip until ACK
    deadline = time.time() + 5
    while time.time() < deadline:
        type_b, body = reader.read_one(1.0)
        if type_b == USB_HELLO_ACK:
            print(f"[{label}] got USB_HELLO_ACK ({len(body)} body bytes)")
            break
        elif type_b is not None:
            print(f"[{label}] (skip type=0x{type_b:02x})")
    else:
        raise RuntimeError(f"{label}: USB_HELLO_ACK timeout")

    cfg_body = bytearray(20)
    cfg_body[0:4] = PAIR_ID_OK
    cfg_body[4:8] = struct.pack("<I", LORA_FREQ)
    cfg_body[8] = 7   # sf
    cfg_body[9] = 7   # bw
    cfg_body[10] = 5  # cr
    cfg_body[11] = 17  # txpower
    cfg_body[12:18] = PEER_MAC_BCAST
    cfg_body[18] = ESPNOW_CHANNEL
    cfg_body[19] = 0
    print(f"[{label}] sending USB_CONFIG (pair_id={PAIR_ID_OK.hex()})")
    ser.write(usb_encode(USB_CONFIG, bytes(cfg_body)))
    ser.flush()

    deadline = time.time() + 3
    while time.time() < deadline:
        type_b, body = reader.read_one(1.0)
        if type_b == USB_CONFIG_ACK:
            print(f"[{label}] got USB_CONFIG_ACK")
            return
        elif type_b is not None:
            print(f"[{label}] (skip type=0x{type_b:02x})")
    raise RuntimeError(f"{label}: USB_CONFIG_ACK timeout")


def make_radio_frame(pair_id, seq=0, chan=0x10, type_b=0x04):
    """Minimal radio frame: pair_id(4) seq(4) chan(1) type(1) ct_len(2) ct(16).
    chan=0x10 → chan_id=1 (PTY), ct=16 zero bytes (won't decrypt but the
    PAIR_ID gate runs before any decryption attempt)."""
    ct = b"\x00" * 16
    return pair_id + struct.pack("<I", seq) + bytes([chan, type_b]) + struct.pack("<H", len(ct)) + ct


def main():
    if len(sys.argv) != 3:
        print("usage: fi05_pair_id_inject.py DEVICE_A DEVICE_B", file=sys.stderr)
        sys.exit(2)
    dev_a = sys.argv[1]
    dev_b = sys.argv[2]

    ser_a = serial.Serial(dev_a, 115200, timeout=0.1)
    ser_b = serial.Serial(dev_b, 115200, timeout=0.1)

    # Reset both via DTR/RTS, give the boot banner time to settle
    for s in (ser_a, ser_b):
        s.dtr = False
        s.rts = False
        time.sleep(0.1)
        s.dtr = True
        s.rts = True
    time.sleep(2.0)
    ser_a.reset_input_buffer()
    ser_b.reset_input_buffer()

    reader_a = FrameReader(ser_a)
    reader_b = FrameReader(ser_b)
    setup_firmware(reader_a, "DEVICE_A")
    setup_firmware(reader_b, "DEVICE_B")
    # Drain any USB_STATUS_RSP that may have arrived after CONFIG_ACK
    drain_for(reader_a, 0.3)
    drain_for(reader_b, 0.3)

    # NEGATIVE: send wrong pair_id
    print("\n--- NEGATIVE: injecting WRONG pair_id from DEVICE_A ---")
    bad_radio = make_radio_frame(PAIR_ID_BAD, seq=42)
    ser_a.write(usb_encode(USB_DATA_TX, bad_radio))
    ser_a.flush()

    print("watching DEVICE_B for USB_DATA_RX (2.0s)...")
    seen = drain_for(reader_b, 2.0)
    rx_data = [(t, b) for t, b in seen if t == USB_DATA_RX]
    other = [(t, b) for t, b in seen if t != USB_DATA_RX]
    print(f"DEVICE_B saw {len(rx_data)} USB_DATA_RX, {len(other)} other "
          f"(types: {[hex(t) for t, _ in other]})")
    neg_pass = (len(rx_data) == 0)
    print(f"NEGATIVE: {'PASS' if neg_pass else 'FAIL'} "
          f"(expected 0 USB_DATA_RX from wrong pair_id)")

    # POSITIVE control: send correct pair_id
    print("\n--- POSITIVE control: injecting CORRECT pair_id from DEVICE_A ---")
    good_radio = make_radio_frame(PAIR_ID_OK, seq=43)
    ser_a.write(usb_encode(USB_DATA_TX, good_radio))
    ser_a.flush()

    print("watching DEVICE_B for USB_DATA_RX (2.0s)...")
    seen = drain_for(reader_b, 2.0)
    rx_data = [(t, b) for t, b in seen if t == USB_DATA_RX]
    print(f"DEVICE_B saw {len(rx_data)} USB_DATA_RX")
    # sonnet-F MAJOR-F05-1: assert the forwarded frame actually carries
    # PAIR_ID_OK in bytes 0-3, not just "≥1 frame seen".
    pos_pass = False
    if len(rx_data) >= 1:
        first = rx_data[0][1]
        if len(first) >= 4:
            print(f"  first frame pair_id (bytes 0-3) = {first[0:4].hex()}")
            pos_pass = (first[0:4] == PAIR_ID_OK)
    print(f"POSITIVE: {'PASS' if pos_pass else 'FAIL'} "
          f"(expected ≥1 USB_DATA_RX with pair_id={PAIR_ID_OK.hex()})")

    ser_a.close()
    ser_b.close()

    if neg_pass and pos_pass:
        print("\nFI-05 / AC-05-07 RESULT: PASS")
        sys.exit(0)
    print("\nFI-05 / AC-05-07 RESULT: FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
