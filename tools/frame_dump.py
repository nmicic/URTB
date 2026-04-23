#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# frame_dump.py — URTB frame decoder
#
# Reads raw bytes from stdin or a file and pretty-prints any URTB USB frames
# (and, with --radio, any radio frames) found in the byte stream.
# Skips bytes that don't look like a frame so it can be pointed at noisy
# captures (e.g. /dev/cu.usbserial-* or a file produced by `cat`).
#
# Usage:
#   cat /dev/cu.usbserial-0001 | python3 tools/frame_dump.py
#   python3 tools/frame_dump.py capture.bin
#   python3 tools/frame_dump.py --radio radio.bin

import argparse
import struct
import sys

USB_MAGIC = b"\xAB\xCD"
USB_VER = 0x01
USB_HEADER_LEN = 7
USB_TRAILER_LEN = 2
USB_OVERHEAD = USB_HEADER_LEN + USB_TRAILER_LEN
USB_MAX_BODY = 510

USB_TYPES = {
    0x01: "USB_DATA_TX",
    0x02: "USB_DATA_RX",
    0x03: "USB_STATUS_REQ",
    0x04: "USB_STATUS_RSP",
    0x05: "USB_HELLO",
    0x06: "USB_HELLO_ACK",
    0x07: "USB_CONFIG",
    0x08: "USB_CONFIG_ACK",
    0x09: "USB_ERROR",
    0x0A: "USB_RESET",
}

CHAN_NAMES = {
    0: "ctrl",
    1: "pty",
}

CTRL_TYPES = {
    0x01: "CTRL_HELLO",
    0x02: "CTRL_HELLO_ACK",
    0x03: "CTRL_READY",
    0x04: "CTRL_CLOSE",
    0x05: "CTRL_KEEPALIVE",
    0x06: "CTRL_KEEPALIVE_ACK",
    0x08: "CTRL_ERROR",
}

PTY_TYPES = {
    0x01: "PTY_OPEN",
    0x02: "PTY_OPEN_ACK",
    0x03: "PTY_OPEN_ERR",
    0x04: "PTY_DATA",
    0x05: "PTY_RESIZE",
    0x06: "PTY_SIGNAL",
    0x07: "PTY_CLOSE",
    0x08: "PTY_EOF",
}


def crc16_ccitt_false(buf: bytes) -> int:
    crc = 0xFFFF
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def hexdump(buf: bytes, indent: str = "    ", width: int = 16) -> str:
    out = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{indent}{i:04x}  {hexpart:<{width * 3}}  {ascpart}")
    return "\n".join(out)


def chan_label(chan_byte: int) -> str:
    cid = (chan_byte >> 4) & 0x0F
    name = CHAN_NAMES.get(cid, f"ch{cid}")
    flags = []
    if chan_byte & 0x02:
        flags.append("FF")
    if chan_byte & 0x01:
        flags.append("MF")
    if flags:
        return f"{name}[{','.join(flags)}]"
    return name


def type_label(chan_byte: int, type_byte: int) -> str:
    cid = (chan_byte >> 4) & 0x0F
    if cid == 0:
        return CTRL_TYPES.get(type_byte, f"0x{type_byte:02x}")
    if cid == 1:
        return PTY_TYPES.get(type_byte, f"0x{type_byte:02x}")
    return f"0x{type_byte:02x}"


def dump_radio_frame(body: bytes, indent: str = "    ") -> None:
    if len(body) < 12:
        print(f"{indent}<radio frame too short: {len(body)} bytes>")
        return
    pair_id = body[0:4]
    seq = struct.unpack("<I", body[4:8])[0]
    chan = body[8]
    type_b = body[9]
    ct_len = struct.unpack("<H", body[10:12])[0]
    print(f"{indent}radio: pair_id={pair_id.hex()} seq={seq} "
          f"chan={chan_label(chan)} type={type_label(chan, type_b)} "
          f"ct_len={ct_len}")
    if 12 + ct_len <= len(body):
        print(hexdump(body[12:12 + ct_len], indent=indent + "  "))
    else:
        print(f"{indent}  <truncated: header says {ct_len} ct bytes, "
              f"have {len(body) - 12}>")


def dump_usb_frame(frame: bytes) -> None:
    type_b = frame[3]
    flags = frame[4]
    body_len = struct.unpack("<H", frame[5:7])[0]
    body = frame[7:7 + body_len]
    type_name = USB_TYPES.get(type_b, f"0x{type_b:02x}")
    print(f"USB {type_name} flags=0x{flags:02x} body_len={body_len}")
    if type_b in (0x01, 0x02) and body_len >= 12:
        dump_radio_frame(body)
    elif body_len:
        print(hexdump(body, indent="    "))


def scan_usb_frames(buf: bytes):
    valid = 0
    invalid = 0
    i = 0
    while i + USB_OVERHEAD <= len(buf):
        if buf[i:i + 2] != USB_MAGIC:
            i += 1
            invalid += 1
            continue
        if i + USB_HEADER_LEN > len(buf):
            break
        if buf[i + 2] != USB_VER:
            i += 1
            invalid += 1
            continue
        body_len = struct.unpack("<H", buf[i + 5:i + 7])[0]
        if body_len > USB_MAX_BODY:
            i += 1
            invalid += 1
            continue
        total = USB_HEADER_LEN + body_len + USB_TRAILER_LEN
        if i + total > len(buf):
            break
        crc_calc = crc16_ccitt_false(buf[i:i + USB_HEADER_LEN + body_len])
        crc_wire = struct.unpack("<H",
                                 buf[i + USB_HEADER_LEN + body_len:
                                     i + USB_HEADER_LEN + body_len + 2])[0]
        if crc_calc != crc_wire:
            i += 1
            invalid += 1
            continue
        dump_usb_frame(buf[i:i + total])
        valid += 1
        i += total
    print(f"\n{valid} valid USB frames, {invalid} skipped non-frame bytes",
          file=sys.stderr)


def scan_radio_frames(buf: bytes):
    """In --radio mode, we assume each line is one length-prefixed radio
    frame, OR a tightly-packed stream of radio frames. Best-effort: print
    any 12+ byte chunks separated by line breaks."""
    valid = 0
    if not buf:
        print("0 radio frames", file=sys.stderr)
        return
    # If file looks like it has length prefixes (alternating <H>+frame), use them.
    # Otherwise just dump it as one frame.
    i = 0
    while i + 12 <= len(buf):
        ct_len_field = struct.unpack("<H", buf[i + 10:i + 12])[0]
        frame_len = 12 + ct_len_field
        if i + frame_len > len(buf):
            break
        dump_radio_frame(buf[i:i + frame_len])
        valid += 1
        i += frame_len
    print(f"\n{valid} radio frames", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="URTB frame dumper")
    ap.add_argument("file", nargs="?",
                    help="input file (stdin if omitted)")
    ap.add_argument("--radio", action="store_true",
                    help="parse input as raw radio frames (not USB-wrapped)")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()

    if args.radio:
        scan_radio_frames(data)
    else:
        scan_usb_frames(data)


if __name__ == "__main__":
    main()
