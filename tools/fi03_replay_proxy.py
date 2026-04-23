#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
# fi03_replay_proxy.py — FI-03 replay-injection harness
#
# Sits between `urtb connect` and `urtb listen` over the unix transport,
# forwards bytes both ways, and re-injects the FIRST chan=1 (PTY) frame
# observed in the listen→connect direction one second after first delivery.
#
# Expected behavior: connect's session.c replay_check() drops the duplicate
# (already-seen SEQ in the additive-form replay window). Session continues
# normally — no error frames, no state change.
#
# Wire format (transport_unix): 2-byte LE length prefix + raw radio frame.
# Radio frame layout (PROTOCOL.md §3): pair_id(4) seq(4) chan(1) type(1)
# ct_len(2) ciphertext(ct_len). chan high nibble is the channel id;
# 0=ctrl, 1=pty.
#
# Usage:
#   python3 tools/fi03_replay_proxy.py PROXY_SOCK REAL_SOCK [--log FILE]

import argparse
import os
import socket
import struct
import sys
import threading
import time

REPLAY_DELAY_S = 1.0


def log(msg, fh=None):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, file=sys.stderr, flush=True)
    if fh is not None:
        fh.write(line + "\n")
        fh.flush()


def parse_radio_frame(body):
    """Return (chan_id, type_b, seq) or (None, None, None) if too short."""
    if len(body) < 12:
        return None, None, None
    seq = struct.unpack("<I", body[4:8])[0]
    chan = body[8]
    type_b = body[9]
    chan_id = (chan >> 4) & 0x0F
    return chan_id, type_b, seq


def relay_with_replay(src, dst, label, slot_key, replay_state, lock, log_fh):
    """Forward length-prefixed frames from src to dst. Capture and re-inject
    the first chan=1 frame seen in this direction (per-direction slot in
    replay_state). sonnet-F MAJOR-F03-1: both directions are now exercised
    so we hit both per-direction replay windows."""
    try:
        while True:
            hdr = b""
            while len(hdr) < 2:
                chunk = src.recv(2 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            (length,) = struct.unpack("<H", hdr)
            body = b""
            while len(body) < length:
                chunk = src.recv(length - len(body))
                if not chunk:
                    return
                body += chunk
            chan_id, type_b, seq = parse_radio_frame(body)
            log(f"{label}: len={length} seq={seq} chan={chan_id} type=0x{type_b:02x}",
                log_fh)
            dst.sendall(hdr + body)

            with lock:
                if (chan_id == 1
                        and replay_state[slot_key]["captured"] is None):
                    replay_state[slot_key]["captured"] = hdr + body
                    replay_state[slot_key]["captured_seq"] = seq
                    replay_state[slot_key]["captured_dst"] = dst
                    log(f"FI-03: captured {label} frame (seq={seq}, chan=1)",
                        log_fh)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log(f"{label}: relay ended ({e})", log_fh)


def replay_thread(slot_key, label, replay_state, lock, log_fh):
    """Wait until a frame is captured for slot_key, sleep, then re-inject."""
    while True:
        with lock:
            captured = replay_state[slot_key]["captured"]
        if captured is not None:
            break
        time.sleep(0.05)
    time.sleep(REPLAY_DELAY_S)
    with lock:
        seq = replay_state[slot_key]["captured_seq"]
        dst = replay_state[slot_key]["captured_dst"]
    try:
        log(f"FI-03: REPLAYING {label} frame (seq={seq})", log_fh)
        dst.sendall(captured)
        log(f"FI-03: {label} replay sent — peer should drop via replay_check",
            log_fh)
    except OSError as e:
        log(f"FI-03: {label} replay send failed ({e})", log_fh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("proxy_sock", help="path connect will dial (we listen here)")
    ap.add_argument("real_sock", help="path of urtb listen's actual socket")
    ap.add_argument("--log", help="append log file")
    args = ap.parse_args()

    log_fh = open(args.log, "a") if args.log else None

    try:
        os.unlink(args.proxy_sock)
    except FileNotFoundError:
        pass

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(args.proxy_sock)
    listener.listen(1)
    log(f"proxy: listening on {args.proxy_sock}, will relay to {args.real_sock}",
        log_fh)

    connect_side, _ = listener.accept()
    log("proxy: connect side attached", log_fh)

    listen_side = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.time() + 5.0
    while True:
        try:
            listen_side.connect(args.real_sock)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            if time.time() > deadline:
                log("proxy: real socket never appeared", log_fh)
                sys.exit(1)
            time.sleep(0.05)
    log("proxy: listen side attached", log_fh)

    replay_state = {
        "l2c": {"captured": None, "captured_seq": None, "captured_dst": None},
        "c2l": {"captured": None, "captured_seq": None, "captured_dst": None},
    }
    lock = threading.Lock()

    t1 = threading.Thread(
        target=relay_with_replay,
        args=(listen_side, connect_side, "listen→connect", "l2c",
              replay_state, lock, log_fh),
        daemon=True,
    )
    t2 = threading.Thread(
        target=relay_with_replay,
        args=(connect_side, listen_side, "connect→listen", "c2l",
              replay_state, lock, log_fh),
        daemon=True,
    )
    t3 = threading.Thread(
        target=replay_thread,
        args=("l2c", "listen→connect", replay_state, lock, log_fh),
        daemon=True,
    )
    t4 = threading.Thread(
        target=replay_thread,
        args=("c2l", "connect→listen", replay_state, lock, log_fh),
        daemon=True,
    )
    t1.start()
    t2.start()
    t3.start()
    t4.start()

    t1.join()
    t2.join()
    log("proxy: both relays ended", log_fh)
    if log_fh is not None:
        log_fh.close()


if __name__ == "__main__":
    main()
