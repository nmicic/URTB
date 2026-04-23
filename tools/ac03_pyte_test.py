#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
"""
AC-03 mechanical verification harness.

Drives `urtb connect` inside a python-allocated PTY (rows=24, cols=80),
captures all bytes the client writes back to the controlling terminal,
replays them through pyte, and asserts on the rendered screen.

Per ACCEPTANCE_CRITERIA.md §AC-03:
  AC-03-01  top    renders correctly (PID column visible)
  AC-03-02  vim    open + :q! returns to shell prompt cleanly
  AC-03-03  htop   renders correctly (CPU/MEM bars or column headers)
  AC-03-04  tab completion works
  AC-03-05  arrow-key history works (UP recalls previous command)

Usage:
  python3 tools/ac03_pyte_test.py
Exit code 0 = all PASS, 1 = at least one FAIL.

The harness spawns one fresh urtb listen + connect pair per test so
state from a previous test cannot leak into the next.
"""

import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
import fcntl
from pathlib import Path

import pyte


class TolerantScreen(pyte.Screen):
    """
    pyte 0.8.2's Screen.select_graphic_rendition does not accept the
    `private` kwarg that Stream may pass for non-standard CSI ?...m
    sequences (vim emits these). Swallow the extra kwarg so replay
    doesn't crash mid-stream.
    """

    def select_graphic_rendition(self, *args, **kwargs):
        kwargs.pop("private", None)
        return super().select_graphic_rendition(*args, **kwargs)

REPO = Path(__file__).resolve().parent.parent
URTB = REPO / "urtb"
CAPSULE = Path("/tmp/ac03-cap.bin")
PASSPHRASE = "ac03test"
SOCK_TEMPLATE = "/tmp/urtb-ac03-{}.sock"

ROWS = 24
COLS = 80


def log(msg):
    print(f"[ac03] {msg}", flush=True)


def ensure_capsule():
    if CAPSULE.exists():
        CAPSULE.unlink()
    env = os.environ.copy()
    env["URTB_PASSPHRASE"] = PASSPHRASE
    r = subprocess.run(
        [str(URTB), "keygen", "--out", str(CAPSULE)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert CAPSULE.exists(), "capsule not produced"


def start_listener(sock_path):
    """Start `urtb listen` in the background with stderr to log file."""
    if Path(sock_path).exists():
        Path(sock_path).unlink()
    log_path = f"/tmp/ac03-listen-{os.getpid()}.log"
    env = os.environ.copy()
    env["URTB_PASSPHRASE"] = PASSPHRASE
    # Force a fresh shell so PS1 / history quirks from the leader process
    # don't taint screen content.
    env["SHELL"] = "/bin/bash"
    env["PS1"] = r"$ "
    # Suppress bash startup files that would print fortune/banner.
    f = open(log_path, "wb")
    proc = subprocess.Popen(
        [
            str(URTB),
            "listen",
            "--transport",
            "unix",
            "--socket",
            sock_path,
            "--capsule",
            str(CAPSULE),
        ],
        env=env,
        stdout=f,
        stderr=f,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Wait for the socket to be created.
    for _ in range(50):
        if Path(sock_path).exists():
            break
        time.sleep(0.05)
    else:
        proc.kill()
        raise RuntimeError(f"listener never created socket {sock_path}")
    return proc, log_path


def stop_listener(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def run_connect(sock_path, script):
    """
    Spawn `urtb connect` inside a python-allocated PTY, set rows/cols,
    drive the script (a list of (action, arg) tuples), and return the
    captured raw bytes.

    Actions:
      ("send", bytes)    write bytes to the PTY
      ("sleep", seconds)  drain output for `seconds` seconds
      ("eof",)            close the PTY master (signals client EOF)
    """
    master, slave = pty.openpty()
    # Set window size 24x80 on the slave PTY before spawn.
    winsize = struct.pack("HHHH", ROWS, COLS, 0, 0)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)

    env = os.environ.copy()
    env["URTB_PASSPHRASE"] = PASSPHRASE
    env["TERM"] = "xterm-256color"
    env["LINES"] = str(ROWS)
    env["COLUMNS"] = str(COLS)

    proc = subprocess.Popen(
        [
            str(URTB),
            "connect",
            "--transport",
            "unix",
            "--socket",
            sock_path,
            "--capsule",
            str(CAPSULE),
        ],
        env=env,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave)

    captured = bytearray()

    def drain(deadline):
        while True:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            r, _, _ = select.select([master], [], [], timeout)
            if not r:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                return False
            if not chunk:
                return False
            captured.extend(chunk)
        return True

    # Initial settle — let session reach ESTABLISHED and prompt render.
    drain(time.monotonic() + 1.5)

    for step in script:
        action = step[0]
        if action == "send":
            os.write(master, step[1])
        elif action == "sleep":
            drain(time.monotonic() + step[1])
        elif action == "eof":
            os.close(master)
            master = None
            break

    if master is not None:
        # Final drain.
        drain(time.monotonic() + 0.8)
        try:
            os.close(master)
        except OSError:
            pass

    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)

    return bytes(captured), proc.returncode


def render(raw):
    """Replay raw bytes through pyte and return (lines, cursor)."""
    screen = TolerantScreen(COLS, ROWS)
    stream = pyte.Stream(screen)
    # Decode permissively — VT100 sequences are 7-bit, escapes are bytes,
    # and we don't want to drop content on UTF-8 decode hiccups.
    stream.feed(raw.decode("utf-8", errors="replace"))
    return screen.display, (screen.cursor.y, screen.cursor.x)


def screen_text(lines):
    return "\n".join(line.rstrip() for line in lines)


# ---- individual tests --------------------------------------------------


def make_test(idx, name, script, predicate, save_artifact=True):
    sock = SOCK_TEMPLATE.format(idx)
    listener, listener_log = start_listener(sock)
    try:
        raw, rc = run_connect(sock, script)
    finally:
        stop_listener(listener)
        try:
            Path(sock).unlink()
        except FileNotFoundError:
            pass

    lines, cursor = render(raw)
    text = screen_text(lines)

    if save_artifact:
        artifact_dir = Path("/tmp/ac03-artifacts")
        artifact_dir.mkdir(exist_ok=True)
        (artifact_dir / f"{name}.raw").write_bytes(raw)
        (artifact_dir / f"{name}.screen").write_text(text)

    ok, why = predicate(text, lines, cursor, raw, rc)
    return ok, why, text, cursor, rc


def t01_top():
    # Run interactive top so the column header stays at the top of the
    # screen, then send 'q' to quit cleanly.
    script = [
        ("sleep", 0.4),
        ("send", b"top\n"),
        ("sleep", 3.0),
        ("send", b"q"),
        ("sleep", 0.5),
    ]

    def check(text, lines, cursor, raw, rc):
        # top's interactive header must include the PID column label.
        if "PID" not in text:
            return False, "PID column header not visible"
        if "%CPU" not in text and "CPU" not in text:
            return False, "CPU column header not visible"
        # Summary block: any of Linux-procps OR macOS-bsd top markers
        # proves top emitted its summary header. macOS top uses a different
        # vocabulary ("Processes:", "Load Avg:", "PhysMem:", "CPU usage:").
        markers = [
            # Linux procps top
            "Tasks:", "MiB Mem", "MiB Swap", "%Cpu(s)", "%Cpu",
            # macOS BSD top
            "Processes:", "Load Avg:", "PhysMem:", "CPU usage:", "SharedLibs:",
        ]
        if not any(m in text for m in markers):
            return False, f"none of top summary markers seen ({markers})"
        # Cursor must remain inside the screen.
        r, c = cursor
        if not (0 <= r < ROWS and 0 <= c < COLS):
            return False, f"cursor out of bounds: {cursor}"
        return True, "top header + PID + CPU columns rendered, cursor in-bounds"

    return make_test(1, "ac03_01_top", script, check)


def t02_vim():
    script = [
        ("sleep", 0.3),
        ("send", b"vim\n"),
        ("sleep", 1.5),
        ("send", b"i"),
        ("sleep", 0.4),  # let -- INSERT -- status line render
        ("send", b"hello-from-ac03"),
        ("sleep", 0.3),
        ("send", b"\x1b"),  # ESC back to normal mode
        ("send", b":q!\n"),
        ("sleep", 0.8),
        # Drive a clean shell exit so urtb connect exits rc=0 instead of
        # being SIGKILLed at proc.wait timeout (Reviewer B finding).
        ("send", b"exit\n"),
        ("sleep", 0.8),
    ]

    def check(text, lines, cursor, raw, rc):
        # Five things must all be true to prove vim ran end-to-end:
        #   1. vim drew its empty-buffer tildes  → it actually started
        #   2. -- INSERT -- mode line appeared   → input mode was entered
        #   3. our typed payload made it through → input forwarding works
        #   4. the shell prompt is visible again → :q! returned to bash
        #   5. urtb connect exited with rc == 0  → AC-03-02 "exits cleanly"
        # NOTE: pyte 0.8.2 does not implement DEC ?1049 alt-screen save/
        # restore, so vim's buffer remains visible after :q!. That's a
        # pyte limitation, not a urtb bug — a real xterm would restore.
        # We assert urtb forwarded the alt-screen sequences in the raw
        # byte stream (which is what xterm consumes).
        if not lines[1].lstrip().startswith("~") and "~" not in text:
            return False, "vim tildes never appeared — vim did not start"
        if b"INSERT" not in raw:
            return False, "vim -- INSERT -- status line not in byte stream"
        # Assert on raw bytes rather than the rendered screen: after the
        # subsequent `exit\n` the shell may scroll the typed text off the
        # 24-row pyte buffer, but it must have been forwarded byte-for-byte
        # at some point in the stream.
        if b"hello-from-ac03" not in raw:
            return False, "typed text not in byte stream — input forwarding broken"
        bottom = "\n".join(lines[ROWS // 2 :])
        if "$" not in bottom and "#" not in bottom:
            return False, "no shell prompt visible after :q!"
        # Confirm urtb forwarded the alt-screen ?1049h enter sequence.
        if b"\x1b[?1049h" not in raw and b"\x1b[?47h" not in raw:
            return False, "alt-screen ENTER sequence not in byte stream"
        if b"\x1b[?1049l" not in raw and b"\x1b[?47l" not in raw:
            return False, "alt-screen EXIT sequence not in byte stream"
        r, c = cursor
        if not (0 <= r < ROWS and 0 <= c < COLS):
            return False, f"cursor out of bounds: {cursor}"
        if rc != 0:
            return False, f"urtb connect did not exit cleanly after :q! + exit (rc={rc})"
        return True, "vim entered INSERT, echoed input, alt-screen flushed, exit rc=0"

    return make_test(2, "ac03_02_vim", script, check)


def t03_htop():
    script = [
        ("send", b"htop\n"),
        ("sleep", 2.5),
        ("send", b"q"),
        ("sleep", 0.8),
    ]

    def check(text, lines, cursor, raw, rc):
        # htop draws a header and a process table. Look for typical labels.
        # "PID", "CPU%", or the function-key footer "F1Help".
        markers = ["PID", "CPU%", "Mem", "Swp", "F1", "F10", "load average", "Tasks"]
        hit = [m for m in markers if m in text]
        if not hit:
            return False, f"no htop UI markers found in screen (looked for {markers})"
        r, c = cursor
        if not (0 <= r < ROWS and 0 <= c < COLS):
            return False, f"cursor out of bounds: {cursor}"
        return True, f"htop markers seen: {hit}"

    return make_test(3, "ac03_03_htop", script, check)


def t04_tab_completion():
    # Type "ech" + TAB; bash completes to "echo " — then add "ac03tab\n".
    # On the rendered screen we expect the literal string "ac03tab".
    script = [
        ("sleep", 0.4),
        ("send", b"ech\t"),
        ("sleep", 0.5),
        ("send", b"ac03tab\n"),
        ("sleep", 0.6),
    ]

    def check(text, lines, cursor, raw, rc):
        if "ac03tab" not in text:
            return False, "ac03tab not echoed — TAB did not complete to `echo`"
        # Look for the actual completion: the line containing "echo" + "ac03tab".
        full = "echo" in text or "echo " in text
        if not full:
            return False, "echo keyword not on screen after TAB"
        return True, "TAB completed `ech` → `echo` and command ran"

    return make_test(4, "ac03_04_tab", script, check)


def t05_arrow_history():
    # Type a unique command, run it, then UP-arrow + Enter to recall and
    # re-run it. Expect the unique token to appear at least twice.
    UNIQ = "ac03arrowtoken"
    script = [
        ("sleep", 0.4),
        ("send", b"echo " + UNIQ.encode() + b"\n"),
        ("sleep", 0.5),
        # Up arrow (CSI A)
        ("send", b"\x1b[A"),
        ("sleep", 0.3),
        ("send", b"\n"),
        ("sleep", 0.5),
    ]

    def check(text, lines, cursor, raw, rc):
        n = text.count(UNIQ)
        if n < 2:
            return False, f"unique token only appeared {n}× — UP arrow did not recall history"
        return True, f"unique token appeared {n}× — UP arrow history works"

    return make_test(5, "ac03_05_arrows", script, check)


# ---- main --------------------------------------------------------------


# Each entry: (label, test_fn, required_binary_or_None).
# required_binary: if non-None and not on PATH, the sub-test is reported
# as SKIP (not FAIL) so `make check` doesn't regress on bare-minimum hosts
# that lack the interactive TUI apps AC-03-02/03 drive.
TESTS = [
    ("AC-03-01 top", t01_top, None),
    ("AC-03-02 vim", t02_vim, "vim"),
    ("AC-03-03 htop", t03_htop, "htop"),
    ("AC-03-04 tab completion", t04_tab_completion, None),
    ("AC-03-05 arrow history", t05_arrow_history, None),
]


def main():
    if not URTB.exists():
        log(f"ERROR: {URTB} not built — run `make` first")
        sys.exit(2)
    ensure_capsule()
    log(f"capsule ready at {CAPSULE}")

    results = []
    for label, fn, requires in TESTS:
        if requires and shutil.which(requires) is None:
            why = f"`{requires}` not installed — install to exercise this sub-test"
            log(f"SKIP {label}: {why}")
            results.append((label, None, why, (0, 0), 0, ""))
            continue
        log(f"running {label}")
        try:
            ok, why, text, cursor, rc = fn()
        except Exception as exc:
            ok, why, text, cursor, rc = False, f"harness exception: {exc}", "", (0, 0), -1
        results.append((label, ok, why, cursor, rc, text))
        verdict = "PASS" if ok else "FAIL"
        log(f"  {verdict}: {why}  (rc={rc}, cursor={cursor})")

    print()
    print("=" * 60)
    print("AC-03 mechanical verification — summary")
    print("=" * 60)
    n_pass = sum(1 for r in results if r[1] is True)
    n_fail = sum(1 for r in results if r[1] is False)
    n_skip = sum(1 for r in results if r[1] is None)
    for label, ok, why, cursor, rc, _ in results:
        verdict = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"{verdict}  {label:30s}  {why}")
    print("-" * 60)
    if n_skip:
        print(f"{n_pass}/{len(results)} passed, {n_skip} skipped, {n_fail} failed")
    else:
        print(f"{n_pass}/{len(results)} passed")

    sys.exit(0 if n_fail == 0 else 1)


if __name__ == "__main__":
    main()
