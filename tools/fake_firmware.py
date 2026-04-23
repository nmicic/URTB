#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
"""
fake_firmware.py — Heltec USB-framing bridge for socat virtual TTY pairs.

Validates URTB host's transport_heltec.c USB framing (USB_HELLO,
USB_HELLO_ACK, USB_CONFIG, USB_CONFIG_ACK, USB_DATA_TX, USB_DATA_RX,
USB_STATUS_RSP, CRC-16/CCITT-FALSE) without real Heltec hardware.

Topology (the only one that actually works — see CAVEATS below):

    urtb listen          ←socat→         fake_firmware
       /tmp/ttyA0  ←==================→  /tmp/ttyA1
                                              ║
                                              ║  (radio relay: USB_DATA_TX
                                              ║   on one side becomes
                                              ║   USB_DATA_RX on the other)
                                              ║
       /tmp/ttyB0  ←==================→  /tmp/ttyB1
    urtb connect         ←socat→         fake_firmware

Two distinct socat PTY pairs are required. Each pair is point-to-point;
the fake firmware sits at the firmware-side end of each pair (ttyA1,
ttyB1) and:
  1. Replies to each side's USB_HELLO with USB_HELLO_ACK (pair_id = 0
     so the host's "fw_zero → proceed" path runs regardless of the
     host capsule pair_id).
  2. Replies to each side's USB_CONFIG with USB_CONFIG_ACK.
  3. Forwards USB_DATA_TX bodies as USB_DATA_RX bodies on the other
     end — the simulated over-the-air radio relay.
  4. Optionally emits unsolicited USB_STATUS_RSP frames to drive
     failover testing (--initial-status / --status-flap modes).

CAVEATS:
  - A single socat PTY pair is point-to-point. You CANNOT have
    fake_firmware open one end of the same pair as urtb — both
    processes would race to read each other's writes via the shared
    slave end, and nothing useful happens. (The author of this script
    learned this the hard way; see git history.)
  - This bridge does NOT validate the radio-frame PAIR_ID gating or
    LoRa duty-cycle behavior — those live in real firmware. What it
    does validate is the full USB-side wire format end-to-end:
    framing, CRC, type dispatch, pair_id propagation, body relay,
    USB_STATUS_RSP transition handling.

Usage:
  # listener-side cable
  socat -d -d PTY,link=/tmp/ttyA0,raw,echo=0 PTY,link=/tmp/ttyA1,raw,echo=0 &
  # connector-side cable
  socat -d -d PTY,link=/tmp/ttyB0,raw,echo=0 PTY,link=/tmp/ttyB1,raw,echo=0 &
  # bridge
  python3 tools/fake_firmware.py /tmp/ttyA1 /tmp/ttyB1 &
  # peers
  urtb listen  --transport heltec --device /tmp/ttyA0 --capsule cap.bin
  urtb connect --transport heltec --device /tmp/ttyB0 --capsule cap.bin
"""

import argparse
import os
import select
import struct
import sys
import termios
import time

USB_MAGIC0 = 0xAB
USB_MAGIC1 = 0xCD
USB_VER = 0x01
USB_HEADER_LEN = 7
USB_OVERHEAD = 9
USB_MAX_BODY = 510
USB_MAX_FRAME = 519

USB_DATA_TX = 0x01
USB_DATA_RX = 0x02
USB_STATUS_REQ = 0x03
USB_STATUS_RSP = 0x04
USB_HELLO = 0x05
USB_HELLO_ACK = 0x06
USB_CONFIG = 0x07
USB_CONFIG_ACK = 0x08
USB_ERROR = 0x09

TYPE_NAMES = {
    USB_DATA_TX: "USB_DATA_TX",
    USB_DATA_RX: "USB_DATA_RX",
    USB_STATUS_REQ: "USB_STATUS_REQ",
    USB_STATUS_RSP: "USB_STATUS_RSP",
    USB_HELLO: "USB_HELLO",
    USB_HELLO_ACK: "USB_HELLO_ACK",
    USB_CONFIG: "USB_CONFIG",
    USB_CONFIG_ACK: "USB_CONFIG_ACK",
    USB_ERROR: "USB_ERROR",
}


def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly=0x1021, init=0xFFFF, no reflect, no xorout."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def encode_frame(typ: int, body: bytes, flags: int = 0) -> bytes:
    if len(body) > USB_MAX_BODY:
        raise ValueError(f"body too long: {len(body)}")
    header = bytes(
        [
            USB_MAGIC0,
            USB_MAGIC1,
            USB_VER,
            typ,
            flags,
            len(body) & 0xFF,
            (len(body) >> 8) & 0xFF,
        ]
    )
    crc = crc16_ccitt_false(header + body)
    crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return header + body + crc_bytes


class FrameAccumulator:
    """Stateful USB-frame decoder. Feed bytes; iterate complete frames."""

    def __init__(self, label: str):
        self.label = label
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf.extend(data)

    def __iter__(self):
        return self

    def __next__(self):
        # Drop leading garbage until magic.
        while len(self.buf) >= 2 and not (
            self.buf[0] == USB_MAGIC0 and self.buf[1] == USB_MAGIC1
        ):
            del self.buf[0]
        if len(self.buf) < USB_HEADER_LEN:
            raise StopIteration
        body_len = self.buf[5] | (self.buf[6] << 8)
        if body_len > USB_MAX_BODY:
            del self.buf[0]
            return ("BAD_LEN", 0, b"")
        total = USB_OVERHEAD + body_len
        if len(self.buf) < total:
            raise StopIteration
        typ = self.buf[3]
        flags = self.buf[4]
        body = bytes(self.buf[USB_HEADER_LEN : USB_HEADER_LEN + body_len])
        crc_lo = self.buf[USB_HEADER_LEN + body_len]
        crc_hi = self.buf[USB_HEADER_LEN + body_len + 1]
        got_crc = crc_lo | (crc_hi << 8)
        want_crc = crc16_ccitt_false(bytes(self.buf[: USB_HEADER_LEN + body_len]))
        del self.buf[:total]
        if got_crc != want_crc:
            return ("BAD_CRC", typ, body)
        return ("OK", typ, body)


def open_pty(path: str) -> int:
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    # Set raw mode just in case socat didn't.
    attr = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attr
    iflag &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
               | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
    oflag &= ~termios.OPOST
    lflag &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
    cflag &= ~(termios.CSIZE | termios.PARENB)
    cflag |= termios.CS8
    cc[termios.VMIN] = 1
    cc[termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])
    return fd


def make_hello_ack(pair_id: bytes = b"\x00\x00\x00\x00") -> bytes:
    # 32-byte body: fw_major, fw_minor, fw_patch, caps, pair_id[4], reserved[24]
    body = bytes([0, 1, 0, 0x03]) + pair_id + b"\x00" * 24
    return encode_frame(USB_HELLO_ACK, body)


def make_config_ack() -> bytes:
    return encode_frame(USB_CONFIG_ACK, b"")


def make_status_rsp(transport_active: int, rssi: int = -50) -> bytes:
    # 16-byte body per PROTOCOL.md §1
    body = struct.pack(
        "<BbbbHHHH4s",
        transport_active & 0xFF,
        rssi if -128 <= rssi <= 127 else 0,  # espnow_rssi
        rssi,  # lora_rssi
        100,  # lora_snr (tenths)
        10,   # espnow_tx_ok
        0,    # espnow_tx_fail
        5,    # lora_tx_ok
        0,    # lora_tx_fail
        b"\x00" * 4,  # reserved
    )
    return encode_frame(USB_STATUS_RSP, body)


class Side:
    def __init__(self, label: str, path: str):
        self.label = label
        self.fd = open_pty(path)
        self.acc = FrameAccumulator(label)
        self.hello_seen = False
        self.config_seen = False
        self.tx_data = 0
        self.rx_data = 0
        self.espnow_channel = -1  # filled in on USB_CONFIG receipt


def log(msg, verbose=True):
    if verbose:
        print(f"[fake_fw] {msg}", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description="Heltec fake-firmware bridge")
    parser.add_argument("dev_a")
    parser.add_argument("dev_b")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--status-flap", type=float, default=0.0,
                        help="seconds between USB_STATUS_RSP transport_active flips (0=off)")
    parser.add_argument("--initial-status", type=int, default=-1,
                        help="if 0/1, send initial USB_STATUS_RSP with this transport_active")
    parser.add_argument("--idle-exit", type=float, default=0.0,
                        help="exit after this many seconds of inactivity (0=off)")
    args = parser.parse_args()

    verbose = not args.quiet
    side_a = Side("A", args.dev_a)
    side_b = Side("B", args.dev_b)
    sides = [side_a, side_b]

    log(f"opened {args.dev_a} (fd={side_a.fd}) and {args.dev_b} (fd={side_b.fd})", verbose)

    last_activity = time.monotonic()
    last_flap = time.monotonic()
    flap_state = 0
    initial_status_pending = args.initial_status in (0, 1)

    try:
        while True:
            timeout = 0.5
            r, _, _ = select.select([side_a.fd, side_b.fd], [], [], timeout)
            now = time.monotonic()

            if r:
                last_activity = now

            for side in sides:
                if side.fd in r:
                    try:
                        chunk = os.read(side.fd, 4096)
                    except OSError as exc:
                        log(f"{side.label}: read error: {exc}", verbose)
                        chunk = b""
                    if not chunk:
                        continue
                    side.acc.feed(chunk)
                    other = side_b if side is side_a else side_a
                    while True:
                        try:
                            status, typ, body = next(side.acc)
                        except StopIteration:
                            break
                        if status == "BAD_LEN":
                            log(f"{side.label}: dropping byte (BAD_LEN)", verbose)
                            continue
                        if status == "BAD_CRC":
                            log(f"{side.label}: BAD_CRC for {TYPE_NAMES.get(typ, hex(typ))}", verbose)
                            continue
                        name = TYPE_NAMES.get(typ, f"0x{typ:02X}")
                        if typ == USB_HELLO:
                            log(f"{side.label}: USB_HELLO ({len(body)}B) → reply USB_HELLO_ACK", verbose)
                            os.write(side.fd, make_hello_ack())
                            side.hello_seen = True
                        elif typ == USB_CONFIG:
                            pid = body[:4].hex().upper()
                            # DECISIONS.md D-40: log USB_CONFIG byte 18
                            # (espnow_channel) so shell-level integration
                            # tests can assert the chosen channel actually
                            # reached the wire.
                            ch = body[18] if len(body) > 18 else -1
                            log(f"{side.label}: USB_CONFIG (pair_id={pid}, espnow_channel={ch}, {len(body)}B) → reply USB_CONFIG_ACK", verbose)
                            os.write(side.fd, make_config_ack())
                            side.config_seen = True
                            side.espnow_channel = ch
                        elif typ == USB_STATUS_REQ:
                            log(f"{side.label}: USB_STATUS_REQ → reply USB_STATUS_RSP(active=0)", verbose)
                            os.write(side.fd, make_status_rsp(0))
                        elif typ == USB_DATA_TX:
                            side.tx_data += 1
                            other.rx_data += 1
                            log(f"{side.label}: USB_DATA_TX ({len(body)}B) → relay USB_DATA_RX to {other.label} (#{side.tx_data})", verbose and side.tx_data <= 5)
                            os.write(other.fd, encode_frame(USB_DATA_RX, body))
                        else:
                            log(f"{side.label}: ignoring {name} ({len(body)}B)", verbose)

            # Initial status push (after both sides have completed setup).
            if initial_status_pending and side_a.config_seen and side_b.config_seen:
                log(f"sending initial USB_STATUS_RSP(active={args.initial_status}) to both sides", verbose)
                os.write(side_a.fd, make_status_rsp(args.initial_status))
                os.write(side_b.fd, make_status_rsp(args.initial_status))
                initial_status_pending = False
                last_activity = now

            # Periodic transport_active flap.
            if args.status_flap > 0 and side_a.config_seen and side_b.config_seen:
                if now - last_flap >= args.status_flap:
                    flap_state ^= 1
                    log(f"flap: USB_STATUS_RSP(active={flap_state}) to both sides", verbose)
                    os.write(side_a.fd, make_status_rsp(flap_state))
                    os.write(side_b.fd, make_status_rsp(flap_state))
                    last_flap = now

            if args.idle_exit > 0 and (now - last_activity) > args.idle_exit:
                log(f"idle exit after {args.idle_exit}s", verbose)
                break
    except KeyboardInterrupt:
        pass
    finally:
        log(f"shutting down. A: tx={side_a.tx_data} rx={side_a.rx_data}, B: tx={side_b.tx_data} rx={side_b.rx_data}", verbose)
        os.close(side_a.fd)
        os.close(side_b.fd)


if __name__ == "__main__":
    main()
