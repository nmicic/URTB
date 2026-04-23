# URTB how-to

What URTB is, how to install it, and six end-to-end use cases. Every
command in this file has been verified on macOS Darwin 24.6.0. Where
output is shown, it is captured from a real test run.

## What URTB is

URTB is an authenticated, encrypted PTY tunnel over an unreliable
backhaul. Two `urtb` processes paired with the same capsule (a
passphrase-encrypted PSK + 4-byte PAIR_ID) establish an
XChaCha20-Poly1305 session and carry an interactive shell between
them. The two end-to-end-verified transports are a local UNIX domain
socket and a Heltec WiFi LoRa 32 V3 board (ESP-NOW with automatic LoRa
fallback). A third transport, `--exec "cmd args"`, speaks the framed
protocol over an arbitrary child process's stdio; its **wire format**
is verified by `frame_test` group 6 (`tools/frame_test.c:810` —
socketpair + `execvp("cat")` round-trip), **end-to-end PTY sessions over `--exec` are validated in HOWTO_JUMPHOST.md**. See `SPEC.md` and
`PROTOCOL.md` for the wire format and state machine.

## Install

```
git clone https://github.com/nmicic/URTB
cd URTB
make doctor   # check toolchain (compiler, python3, pyte, socat, pio, ports)
make          # build ./urtb
./urtb --help
```

> **Important:** Both the listener and the connect side MUST be built for the
> same region. If one side uses `make REGION=EU` and the other uses
> `make REGION=US`, the LoRa frequencies will not match and the connection
> will fail with a handshake timeout. The default region is EU (869.875 MHz).

`./urtb --help` output (2026-04-17):

```
Usage:
  ./urtb keygen [--out PATH] [--espnow-channel N]
  ./urtb listen  --transport unix   --socket PATH [--capsule PATH] [--loop] [--burn] [--otp PATH]
  ./urtb listen  --transport heltec --device DEV  [--capsule PATH] [--loop] [--burn] [--otp PATH]
  ./urtb listen  --transport stdio               [--capsule PATH] [--loop] [--burn] [--otp PATH]
  ./urtb listen  --exec "cmd args" [--capsule PATH] [--loop] [--burn] [--otp PATH]
  ./urtb connect --transport unix   --socket PATH [--capsule PATH] [--burn]
  ./urtb connect --transport heltec --device DEV  [--capsule PATH] [--burn]
  ./urtb connect --transport stdio               [--capsule PATH] [--burn]
  ./urtb connect --exec "cmd args" [--capsule PATH] [--burn]
  ./urtb status  --device DEV [--capsule PATH]
  ./urtb otp-init   [--type hotp|totp] [--out PATH] [--force]
  ./urtb otp-verify --otp PATH [--code CODE | --print]

Default --capsule: ./pairing.capsule
URTB_PASSPHRASE env var bypasses interactive prompt (for tests).
--espnow-channel N: keygen only. Selects the ESP-NOW Wi-Fi channel
        (1..13, default 6) baked into the capsule. Both endpoints
        automatically agree because they load the same capsule.
        There is no runtime override — a typo at keygen is the
        only way to get it wrong. See DECISIONS.md D-40.
--loop: continuous listener; re-listens after each session ends
        (until SIGTERM/SIGHUP/SIGINT or transport open failure).
--burn: after loading, securely delete capsule and OTP key files.
        Key material lives in mlock'd memory only. Cannot be undone.
        With --loop: OTP counter updates are in memory only.
--transport stdio: use own stdin/stdout as transport (urtb launched as
        a subprocess, e.g. via SSH remote command). See HOWTO_JUMPHOST.md.
--otp:  require OTP code from connecting client before PTY bridge starts.
Default OTP key: ~/.config/urtb/otp.key
```

The macOS build is one `cc` invocation against `libSystem` only:

```
$ otool -L urtb
urtb:
    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current 1356.0.0)
```

(On Linux the equivalent is `ldd urtb`; the strict-static build is
`make urtb-static`, which produces a binary `ldd` reports as "not a
dynamic executable".)

## Use Case 0 — Try it in 60 seconds (no hardware)

A UNIX-domain-socket pair on the same host, two terminals, a real
interactive remote shell. No radios, no socat, no firmware. This is
the fastest path from `make` to `top` running over URTB.

```
# 1. one-time setup (passphrase: test123)
URTB_PASSPHRASE=test123 ./urtb keygen --out /tmp/urtb_demo.cap

# 2. terminal A — server
URTB_PASSPHRASE=test123 ./urtb listen --transport unix \
    --socket /tmp/urtb_demo.sock \
    --capsule /tmp/urtb_demo.cap

# 3. terminal B — interactive client
URTB_PASSPHRASE=test123 ./urtb connect --transport unix \
    --socket /tmp/urtb_demo.sock \
    --capsule /tmp/urtb_demo.cap
```

The connect side detects a TTY on stdin and enters raw mode
automatically (`urtb: entered raw mode`). Inside the shell that
opens, try:

```
id           # confirm you are inside the remote shell
top          # raw mode + alt-screen, q to quit
vim /tmp/x   # raw mode + alt-screen, :q to quit
Ctrl+C       # forwarded to the remote process via PTY_SIGNAL
exit         # clean teardown, your local terminal is restored
```

### What you should see

Listen-side log (verbatim):

```
transport_unix: listening on /tmp/urtb_demo.sock
transport_unix: accepted connection
session: server mode, waiting for CTRL_HELLO
session: → KEY_DERIVING (server)
session: sent CTRL_HELLO_ACK
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: server spawned PTY pid=... fd=... (80x24)
channel_pty: shell exited (code=0) — sending PTY_EOF + CTRL_CLOSE
session: initiating close
session: received CTRL_CLOSE
session: → IDLE
```

(The `pid` and `fd` numbers vary per run; the rest of the log is
byte-stable. The state-machine transitions match this excerpt
line for line across runs.)

Connect-side log (same capture):

```
transport_unix: connected to /tmp/urtb_demo.sock
session: → CONNECTING
session: sent CTRL_HELLO (attempt 1)
session: → KEY_DERIVING (client)
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: client sending PTY_OPEN (80x24)
channel_pty: client received PTY_OPEN_ACK
urtb: entered raw mode
```

The remote shell answered `id` with `uid=511(user) gid=20(staff)
groups=...` and `tput lines` with `24` (proving the PTY allocated by
the listener is the size the client negotiated via `PTY_OPEN`). Both
assertions are checked by `tools/ac03_pyte_test.py`.

The mechanical conformance evidence that `top`, `vim`, `htop`, tab
completion, and arrow-key history all work is `tools/ac03_pyte_test.py`
(5/5 PASS).

### Tip — tell the remote shell apart from the local one

On a single host, `urtb listen` and `urtb connect` open shells that
look identical. Two ways to make it obvious you really crossed the
bridge:

1. **Compare ttys.** Run `tty` in your *local* terminal **before**
   starting `urtb connect`, then run `tty` again **after** the remote
   shell opens. The device path differs — the local one is something
   like `/dev/ttys012`, the remote one is the PTY allocated by the
   listener (e.g. `/dev/ttys015`). Different tty = you are inside
   the URTB-tunnelled shell.

2. **Use a distinct remote prompt.** Once the remote shell is up,
   paste this so the prompt is red and shows the remote tty:

   ```
   # macOS (zsh, remote)
   export PROMPT='%F{red}%n@%m (%y) %1~ %# %f'

   # Linux (bash, remote)
   export PS1='\[\033[0;31m\]\u@\h (\l) \W \$ \[\033[0m\]'
   ```

   `%y` (zsh) and `\l` (bash) both expand to the PTY device basename,
   so the prompt itself proves which shell you are in.

3. **Make it automatic via your rcfile.** `urtb` sets the env var
   `URTB_SESSION=1` in every shell it spawns inside a PTY session.
   Drop one of the snippets below into `~/.zshrc` (macOS) or
   `~/.bashrc` (Linux) on the *listener* host. The rcfile detects
   the env var and turns the prompt red; ordinary local shells
   stay green.

   ```zsh
   # ~/.zshrc — macOS
   if [[ -n "$URTB_SESSION" ]]; then
       export PROMPT='%F{red}[urtb] %n@%m (%y) %1~ %# %f'   # via URTB
   else
       export PROMPT='%F{green}%n@%m (%y) %1~ %# %f'        # local
   fi
   ```

   ```bash
   # ~/.bashrc — Linux
   if [[ -n "$URTB_SESSION" ]]; then
       PS1='\[\033[0;33m\][urtb]\[\033[0m\] \[\033[0;31m\]\u@\h (\l) \W \$ \[\033[0m\]'
   else
       PS1='\[\033[0;32m\]\u@\h (\l) \W \$ \[\033[0m\]'
   fi
   ```

   For a minimal "prefix only" version that wraps an existing PS1:

   ```bash
   # ~/.bashrc — minimal: prepend [urtb] when inside a urtb session
   PS1='${URTB_SESSION:+\[\033[0;33m\][urtb]\[\033[0m\] }'"$PS1"
   ```

   `URTB_SESSION=1` is set by `urtb` in the child branch of `forkpty()`
   before `execl`, so it is present in every shell launched by either
   `urtb listen` or a server-spawned PTY. Detecting it is more reliable
   than walking PPID, which breaks under daemonisation or `setsid`.

## Use Case 0.5 — Try it without a Heltec V3 (socat null-modem + fake firmware)

Same interactive shell, but routed over the production
`--transport heltec` code path: USB framing, CRC, USB_HELLO/CONFIG/
STATUS_RSP handshake, transport-mode propagation, the lot. The radio
itself is replaced by `tools/fake_firmware.py`, which speaks the same
USB framing as a real Heltec board. This lets you exercise every line
of `transport_heltec.c` and the host-side mode-1/mode-2 logic without
buying hardware.

```
# terminal 1 — bring up two virtual null-modem pairs (one per "Heltec")
socat -d -d PTY,link=/tmp/ttyA0,raw,echo=0 PTY,link=/tmp/ttyA1,raw,echo=0 &
socat -d -d PTY,link=/tmp/ttyB0,raw,echo=0 PTY,link=/tmp/ttyB1,raw,echo=0 &

# terminal 1 (cont) — fake firmware bridges the two firmware-side ends.
# CLI is positional: dev_a dev_b. --initial-status 0 makes the firmware
# send a USB_STATUS_RSP at startup so the host emits the
# "transport mode 1" log line; otherwise mode 1 is the silent default.
python3 tools/fake_firmware.py --initial-status 0 /tmp/ttyA1 /tmp/ttyB1 &

# terminal 2 — server, "DEVICE_A" host side
URTB_PASSPHRASE=test123 ./urtb listen --transport heltec \
    --device /tmp/ttyA0 --capsule /tmp/urtb_demo.cap

# terminal 3 — interactive client, "DEVICE_B" host side
URTB_PASSPHRASE=test123 ./urtb connect --transport heltec \
    --device /tmp/ttyB0 --capsule /tmp/urtb_demo.cap
```

Verify the CLI before you paste:

```
$ python3 tools/fake_firmware.py --help
usage: fake_firmware.py [-h] [--quiet] [--status-flap STATUS_FLAP]
                        [--initial-status INITIAL_STATUS]
                        [--idle-exit IDLE_EXIT]
                        dev_a dev_b
```

`dev_a` and `dev_b` are positional. `--tty-a` / `--tty-b` are **not**
flags it accepts — pass the two firmware-side PTY symlinks
positionally.

### What you should see

Listen-side log (verbatim):

```
transport_heltec: opened /tmp/urtb_howto_ttyA0 at 115200 baud
transport_heltec: sent USB_HELLO
transport_heltec: sent USB_CONFIG (pair_id=...)
transport_heltec: setup complete
session: server mode, waiting for CTRL_HELLO
session: → KEY_DERIVING (server)
session: sent CTRL_HELLO_ACK
session: sent CTRL_READY
session: transport mode 1 → keepalive=2000ms liveness=8000ms mtu=222
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: server spawned PTY pid=... fd=... (80x24)
channel_pty: shell exited (code=0) — sending PTY_EOF + CTRL_CLOSE
session: initiating close
session: received CTRL_CLOSE
session: → IDLE
```

(`pair_id`, `pid`, and `fd` are run-dependent. The capsule-derived
`pair_id` is stable for a given `/tmp/urtb_demo.cap`; regenerating
the capsule will change it. The state-machine and mode lines are
byte-stable.)

Connect-side log (same capture, with `urtb: entered raw mode` after
the client receives `PTY_OPEN_ACK`):

```
transport_heltec: opened /tmp/urtb_howto_ttyB0 at 115200 baud
transport_heltec: sent USB_HELLO
transport_heltec: sent USB_CONFIG (pair_id=...)
transport_heltec: setup complete
session: → CONNECTING
session: sent CTRL_HELLO (attempt 1)
session: → KEY_DERIVING (client)
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: client sending PTY_OPEN (80x24)
channel_pty: client received PTY_OPEN_ACK
urtb: entered raw mode
```

The remote shell answered `id` with `uid=511(user)` and
`tput lines` with `24`. The `transport mode 1 → keepalive=2000ms
liveness=8000ms mtu=222` line is the host reacting to the
`USB_STATUS_RSP` that the fake firmware sent because of
`--initial-status 0` (the byte means "transport_active=0" which the
session treats as ESP-NOW = mode 1; see `src/session.c:744` in
`session_set_transport_mode`).

The fully automated form of this same setup is
`tools/heltec_socat_test.sh`, which runs the end-to-end three-scenario
sweep (default, initial LoRa, mid-session flap).

## Interactive mode

When the connect side detects a TTY on `STDIN_FILENO`
(`isatty(STDIN_FILENO)` true), it puts the local terminal into raw
mode via `cfmakeraw` and forwards keystrokes byte-for-byte to the
remote PTY allocated on the listen side. Raw mode is automatic; there
is no `--interactive` flag. If stdin is not a TTY (e.g. a heredoc in
a test), `enter_raw_mode` returns early and the connect process runs
in cooked / line mode. See `src/main.c:80` (`enter_raw_mode`) and
`src/main.c:113` (`client_on_pty_ack`).

### What works

- Full-screen apps: `top`, `htop`, `vim`, `less`, `more`, `nano` —
  alt-screen, cursor positioning, and color all round-trip cleanly.
- Tab completion in the remote shell.
- Arrow-key history.
- `Ctrl+C` (SIGINT): the local SIGINT handler sets a pending flag
  that the session tick converts into a `PTY_SIGNAL(2)` frame —
  see `src/main.c:118` `client_session_tick`.
- `Ctrl+Z` (SIGTSTP): **not** forwarded as a `PTY_SIGNAL` frame.
  Inspection of `src/main.c` confirms only `SIGINT` and `SIGWINCH`
  are pumped into the session (`src/main.c:393`–`410`); SIGHUP /
  SIGTERM / SIGQUIT trigger the signal cleanup handler that restores
  termios and `_exit`s. However, because `cfmakeraw` clears `ISIG`
  on the local terminal, Ctrl+Z is **not** intercepted locally — the
  raw byte `0x1A` is sent over the data channel to the remote PTY,
  whose line discipline (with `ISIG` enabled by default) raises
  `SIGTSTP` against the remote foreground process. The end-user
  experience is "Ctrl+Z stops the remote command", but the
  forwarding is byte-level via the PTY, not signal-level via
  `PTY_SIGNAL`. If you ever set `stty -isig` on the remote PTY,
  Ctrl+Z would no longer reach anything.
- Window resize: `SIGWINCH` on the client → `client_session_tick`
  reads the new winsize via `TIOCGWINSZ` and emits
  `PTY_RESIZE` to the remote (`src/main.c:128` `TIOCGWINSZ` →
  `src/main.c:129` `channel_pty_client_send_resize`). `tput lines`
  updates and curses apps redraw on the next paint.

### How to exit cleanly

- Type `exit` in the remote shell — the remote shell exits, the
  listener sends `PTY_EOF` + `CTRL_CLOSE`, and the connect side's
  atexit handler restores termios. This is the path the captures
  above take.
- Send `SIGTERM` to the local `urtb connect` — the signal cleanup handler
  installed at `src/main.c:408`–`410` restores termios via the
  saved snapshot, re-raises with `SA_RESETHAND` so the second hit
  is fatal, then `_exit(128+sig)`.
- Unplug the cable (Heltec) or kill the listener (UNIX) — the
  transport poll detects `POLLHUP`, the session goes to `IDLE`, and
  the same atexit handler restores the local terminal. This path is
  verified end-to-end on real Heltec hardware including a live
  USB cable yank mid-session.

### Conformance evidence

`tools/ac03_pyte_test.py` runs `top`, `vim`, `htop`, tab completion,
and arrow-key history through a real `pty.openpty()` and asserts on
the rendered screen via pyte (5/5 PASS). Both Use Case 0 and
Use Case 0.5 pass under `make check`.

### Caveats

- `tools/ac03_pyte_test.py` and `make check` are the actual
  interactive coverage.
- Over LoRa fallback (mode 2), interactive feel is poor by design —
  keepalive 30 s, liveness 90 s, mtu 72, with a 500 ms send-side
  coalescer (ESP-NOW) / **7 s coalescer (LoRa)**. Tab completion and
  arrow keys still work, but there is visible per-keystroke lag. Use
  Case 0.5 stays in mode 1 (ESP-NOW) unless you pass
  `--initial-status 2` (or wire up `--status-flap`) to
  `fake_firmware.py`.

### LoRa mode — duty-cycle warning

LoRa fallback enforces a **7-second minimum interval** between PTY data
frames (EU 869.875 MHz, 1% duty cycle ≈ 8.6 frames/min at the 72-byte
LoRa MTU). Interactive typing will feel sluggish: each keystroke can
take up to 7 s to echo. LoRa is designed for **emergency access only**
— short commands (`uptime`, `ip a`, `tail -n 5 …`) and status checks.
Avoid streaming commands (`cat`, `top`, `tail -f`) in LoRa mode; the
1% budget will be exhausted in minutes and the link becomes useless
until the regulatory window resets.

CTRL+C always reaches the remote shell **immediately** regardless of
the throttle: the client-side `PTY_SIGNAL` path (`channel_pty.c
:channel_pty_client_send_signal`) calls `send_pty()` → `send_frame()`
directly, bypassing the LoRa coalescer. So even if the budget is
saturated and the buffered output is sitting in `lora_buf`, you can
still abort a runaway process and recover the session.

## Pairing two terminals on one host (UNIX socket)

The fastest path is one passphrase, two terminals, one socket.
Captured fresh from the working tree on this run:

```
$ URTB_PASSPHRASE=test123 ./urtb keygen --out /tmp/howto-cap
keygen: capsule written to /tmp/howto-cap

$ ls -la /tmp/howto-cap
-rw-------  1 user  wheel  173 Apr 15 17:22 /tmp/howto-cap

$ URTB_PASSPHRASE=test123 ./urtb listen --transport unix \
      --socket /tmp/howto.sock --capsule /tmp/howto-cap &

$ URTB_PASSPHRASE=test123 ./urtb connect --transport unix \
      --socket /tmp/howto.sock --capsule /tmp/howto-cap <<'EOF'
id
exit
EOF
```

Listen-side log (verbatim):

```
transport_unix: listening on /tmp/howto.sock
transport_unix: accepted connection
session: server mode, waiting for CTRL_HELLO
session: → KEY_DERIVING (server)
session: sent CTRL_HELLO_ACK
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: server spawned PTY pid=25521 fd=5 (80x24)
channel_pty: shell exited (code=0) — sending PTY_EOF + CTRL_CLOSE
session: initiating close
session: received CTRL_CLOSE
session: → IDLE
```

Connect-side captured `id` output:

```
uid=511(user) gid=20(staff) groups=20(staff),12(everyone),...
```

AC IDs covered:
AC-01-02 (capsule produced), AC-01-06 (mode 0600), AC-02-01..03
(unix listen/connect/handshake), AC-02-04 (typing visible),
AC-02-05 (rc=0 propagation), AC-08-01 (transport abstraction over
unix).

## Use case 1: pair two URTBs over a Heltec V3 USB-framing simulator

Production code path of `transport_heltec.c` validated end-to-end on
the host with no real radio. Driven by
`tools/heltec_socat_test.sh`; two `socat`
PTY pairs feed into `tools/fake_firmware.py`, which speaks the same
USB framing as a real Heltec board. One command runs the whole
scenario:

```
$ bash tools/heltec_socat_test.sh
=== exit code: 0 ===
```

Listen log excerpt (the log below shows `liveness=8000ms`; earlier
test runs showed `liveness=6000ms` because they predate the
mode-1 liveness bump from 6 s → 8 s):

```
session: transport mode 1 → keepalive=2000ms liveness=8000ms mtu=222
session: → ESTABLISHED
channel_pty: server spawned PTY pid=... fd=... (80x24)
```

The fake firmware logs `USB_HELLO_ACK`, `USB_CONFIG_ACK`,
`USB_STATUS_RSP`, and relays `USB_DATA_TX → USB_DATA_RX` in both
directions — exercising the host-side USB framing (HELLO/CONFIG/STATUS
handshake, CRC-16/CCITT-FALSE, capsule→USB_CONFIG pair_id propagation,
wire-byte mapping, USB_STATUS_RSP unsolicited handling).

Three scenarios all pass against this bridge:

```
$ bash tools/heltec_socat_test.sh                   # default ESP-NOW
=== exit code: 0 ===
$ INITIAL_STATUS=2 bash tools/heltec_socat_test.sh  # initial LoRa
=== exit code: 0 ===
$ STATUS_FLAP=2 bash tools/heltec_socat_test.sh     # mid-session flap
=== exit code: 0 ===
```

AC IDs covered: AC-08-03 (heltec transport abstraction), partial
AC-05-02 (mode propagation surface) and AC-06-05 (keepalive 2 s
ESP-NOW) at the host-side wire-format layer. The radio physics itself
is **not** exercised here — that needs the next use case.

## Use case 2: real Heltec V3 over ESP-NOW

What you need:
- Two Heltec WiFi LoRa 32 V3 boards. The CP2102 USB-UART bridge
  enumerates as `/dev/cu.usbserial-*` on macOS and `/dev/ttyUSB*` on
  Linux. `make ports` (or `tools/ports.sh`) detects them.
- PlatformIO Core (`pipx install platformio` puts `pio` in
  `~/.local/bin/`). Verified working: PlatformIO Core 6.1.19.
- Wiring: a USB cable between each board and your host.

Flash both boards with the production firmware:

```
$ (cd firmware && pio run -e heltec_wifi_lora_32_V3 -t upload \
    --upload-port /dev/cu.usbserial-0001)
…
Wrote 723424 bytes (470486 compressed) at 0x00010000 in 12.2 seconds
   (effective 473.7 kbit/s)...
Hash of data verified.
========================= [SUCCESS] Took 20.59 seconds =========================

$ (cd firmware && pio run -e heltec_wifi_lora_32_V3 -t upload \
    --upload-port /dev/cu.usbserial-4)
…
========================= [SUCCESS] Took 20.86 seconds =========================
```

> **Upgrading firmware alongside a new `urtb` binary: erase first.**
> A plain `pio run -t upload` writes the new image but leaves the
> previous NVS / ESP-NOW partitions intact. If the wire format or
> capsule layout changed between versions, `urtb` will log a clean
> `[SUCCESS]` from PlatformIO and then fail the handshake with stale
> state still on the board. Run a full erase + upload per board — this
> is exactly what `tools/hw_test_flash.sh` does:
>
> ```
> $ pio run -e heltec_wifi_lora_32_V3 -t erase  --upload-port <dev>
> $ pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port <dev>
> ```
>
> Rule of thumb: if you just pulled a new `urtb` HEAD, assume the
> firmware needs erase+upload, not upload alone.

Generate a capsule and run the pair:

```
$ URTB_PASSPHRASE=test123 ./urtb keygen --out /tmp/urtb_hw.capsule
$ ./urtb listen  --transport heltec --device /dev/cu.usbserial-0001 \
                 --capsule /tmp/urtb_hw.capsule
$ ./urtb connect --transport heltec --device /dev/cu.usbserial-4 \
                 --capsule /tmp/urtb_hw.capsule
```

Query device counters (RSSI, TX ok/fail, ring-drop) from a separate terminal:

```
$ ./urtb status --device /dev/cu.usbserial-0001 --capsule /tmp/urtb_hw.capsule
```

Note: `espnow_ring_drop` (firmware TX ring overflow count) is only visible via
`urtb status`. During a live session the host accumulates the other TX counters
internally but does not print a periodic summary.

> **Note:** `urtb status` opens the device directly and cannot be used
> while an active session is running on the same Heltec device. Both
> processes would compete for frames on the same serial port. Stop the
> session first, run `urtb status`, then reconnect.

Expected listen-side log (expected output):

```
session: server mode, waiting for CTRL_HELLO
session: → KEY_DERIVING (server)
session: sent CTRL_HELLO_ACK
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: server spawned PTY pid=97007 fd=4 (80x24)
session: transport mode 1 → keepalive=2000ms liveness=6000ms mtu=222
```

(Mode-1 liveness is 8000 ms in current builds; this log predates
that change.)

Connect-side log (verbatim):

```
session: → CONNECTING
session: sent CTRL_HELLO (attempt 1)
session: → KEY_DERIVING (client)
session: sent CTRL_READY
session: received CTRL_READY
session: → ESTABLISHED
channel_pty: client sending PTY_OPEN (80x24)
channel_pty: client received PTY_OPEN_ACK
urtb: entered raw mode
```

Driving the session with `echo MARK_A; hostname; uname -s; date; exit`
on the connect side:

```
echo MARK_A   → MARK_A
hostname      → remote.local
uname -s      → Darwin
date          → Wed Apr 15 13:42:38 CEST 2026
exit          → clean PTY_EOF + CTRL_CLOSE on both sides → IDLE
```

AC IDs covered: AC-05-01 (real-radio session), AC-05-02 (transport
mode = ESPNOW), AC-05-06 (mode-switch events visible), AC-06-05
(keepalive 2 s ESP-NOW), AC-06-06 (CTRL_CLOSE clean exit).

## Use case 3: forced LoRa fallback for testing

Real Heltec hardware, with the test build that exposes the
`urtb test-inject` subcommand. See `tools/run_inject_acs.sh` for the
exhaustive harness:

```
$ make clean && make urtb URTB_TEST_INJECT=1 && mv urtb urtb-test
$ (cd firmware && pio run -e heltec_wifi_lora_32_V3_test \
    -t erase --upload-port /dev/cu.usbserial-0001 && \
  pio run -e heltec_wifi_lora_32_V3_test \
    -t upload --upload-port /dev/cu.usbserial-0001)
$ (cd firmware && pio run -e heltec_wifi_lora_32_V3_test \
    -t erase --upload-port /dev/cu.usbserial-4 && \
  pio run -e heltec_wifi_lora_32_V3_test \
    -t upload --upload-port /dev/cu.usbserial-4)
```

> **Why erase first:** you are switching the board from the prod env
> (`heltec_wifi_lora_32_V3`) to the test env (`_test`). NVS/partition
> state from the prod image will be read by the test image and can
> break the handshake. See §Use case 2 for the full rationale.

Then in two terminals:

```
$ ./urtb-test listen  --transport heltec \
      --device /dev/cu.usbserial-0001 --capsule /tmp/urtb_hw.capsule
$ ./urtb-test connect --transport heltec \
      --device /dev/cu.usbserial-4    --capsule /tmp/urtb_hw.capsule
```

Both sides reach `transport mode 1 → keepalive=2000ms liveness=8000ms
mtu=222` (ESP-NOW). Then in a third terminal, force the failover:

```
$ ./urtb-test test-inject --pid <listen-pid> espnow-down
applied flags=0x03
```

Within ~14 s both sides should log:

```
session: transport mode 1 → keepalive=2000ms liveness=8000ms mtu=222
session: transport mode 2 → keepalive=30000ms liveness=90000ms mtu=72
```

This is the real-hardware code path that closes AC-05-03 (failover),
AC-05-04 (PTY survives over LoRa), and AC-05-05 (recovery via
`espnow-up`). The exhaustive harness `tools/run_inject_acs.sh all`
runs all six inject ACs back-to-back. After running, **always
reflash production firmware** — erase first, since you are swapping
the env back from `_test` to prod (see §Use case 2):

```
$ (cd firmware && pio run -e heltec_wifi_lora_32_V3 -t erase  --upload-port /dev/cu.usbserial-0001 \
                && pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port /dev/cu.usbserial-0001)
$ (cd firmware && pio run -e heltec_wifi_lora_32_V3 -t erase  --upload-port /dev/cu.usbserial-4 \
                && pio run -e heltec_wifi_lora_32_V3 -t upload --upload-port /dev/cu.usbserial-4)
$ make clean && make urtb && make hygiene
nm urtb | grep -c inject = 0
```

Production builds must contain zero inject symbols — that gate is
load-bearing (DECISIONS.md D-37).

## Use case 4: capsule generation, file mode, and rotation

```
$ URTB_PASSPHRASE=test123 ./urtb keygen --out /tmp/howto-cap
keygen: capsule written to /tmp/howto-cap

$ ls -la /tmp/howto-cap
-rw-------  1 user  wheel  173 Apr 15 17:22 /tmp/howto-cap
```

What is fixed (capsule implementation):

- File size is exactly 173 bytes. The format is documented in
  `PROTOCOL.md` (capsule layout) and the magic is the first four
  bytes `0x55 0x52 0x54 0x42` — ASCII `URTB`.
- File mode is `0600`, created with `O_EXCL`. `keygen` refuses to
  overwrite an existing file (AC-01-06).
- The PSK is encrypted at rest with XChaCha20-Poly1305, keyed from
  your passphrase via Argon2id (64 MiB, 3 passes, parallelism 1 —
  hardcoded cost params, see `src/capsule.c`).
- Two `keygen` runs against the same passphrase produce different
  capsules — fresh nonce + salt every time (AC-01-07).
- The `URTB_PASSPHRASE` env var bypasses the interactive double-prompt
  (`./urtb --help` documents this as for-tests-only). For interactive
  use, `keygen` reads the passphrase twice from `/dev/tty` via
  `termios` raw-no-echo mode (AC-01-01).
- Rotate by generating a fresh capsule on one host and copying it to
  the peer over a trusted channel (e.g. `scp` after verifying a
  fingerprint by phone). Never copy the capsule over the radio link
  URTB itself creates — the capsule **is** the root secret.

### Running multiple URTB pairs in the same radio space

ESP-NOW shares the 2.4 GHz band. To coexist, generate one capsule per
pair with a distinct Wi-Fi channel:

```sh
# Pair A — channel 1
./urtb keygen --out pair_a.capsule --espnow-channel 1

# Pair B — default channel 6
./urtb keygen --out pair_b.capsule

# Pair C — channel 11
./urtb keygen --out pair_c.capsule --espnow-channel 11
```

Each pair's two endpoints use that pair's capsule. The channel is
baked into the capsule and cannot be overridden at runtime — this is
by design, so the two endpoints cannot mismatch. Both ends always
agree because they load the same capsule.

See DECISIONS.md D-40 for why the channel lives in the capsule
rather than a runtime flag, and `references/capsule_format.md` for
the v2 wire delta.

## Use case 5: URTB as an SSH jump host (out-of-band bastion)

The motivating use case in `PRIOR_ART.md` is "an out-of-band terminal
between two laptops you own that does not touch the IP layer of either
one." Once the URTB session is up, the remote shell behaves like any
other interactive shell — so anything you can do from a normal jump
host you can do from inside URTB, you just reach the jump host over
the radio (or the UNIX socket, or the heltec USB framing) instead of
over TCP.

### Topology

```
[client laptop] ─USB─ [Heltec V3 A]  ⟿ ESP-NOW ⟿  [Heltec V3 B] ─USB─ [home server]
     │                                                                    │
     │                                                          ssh internal-host
     │                                                                    │
   urtb connect ────────── encrypted URTB session ───────────── /bin/zsh on home server
```

The client laptop never gets an IP route to anything inside the home
network. A VPN on the client machine, if any, sees zero new interfaces. The
"jump" happens *inside* the URTB-tunnelled shell — you `ssh` from
the home server, and the home server's network is the network you
land on.

> **Warning:** This does **not** mean the setup is acceptable on an
> employer-managed or policy-restricted device. Attaching an unapproved USB
> radio or running unapproved software may violate local policy and can carry
> real consequences. This use case is **not recommended** on corporate-managed
> devices unless your security or IT team has explicitly approved it. You are
> responsible for complying with your organization's rules.

### Procedure

```
# client laptop — open the URTB session
URTB_PASSPHRASE=test123 ./urtb connect --transport heltec \
    --device /dev/cu.usbserial-0001 \
    --capsule /tmp/urtb_demo.cap

# you now have a shell on the home server; from there:
ssh internal-host.lan          # a host only the home server can route to
ssh -L 5432:db.lan:5432 db-admin@bastion.lan   # forward a port
git -C ~/repos/urtb pull       # do work on the home server itself
exit                            # back to the URTB shell, then exit again to tear down
```

### What the SSH client sees

`ssh internal-host.lan` from inside the URTB shell is an ordinary
SSH session — TCP from the home server's IP to the internal host's
IP, full SSH crypto, full key auth, full feature set (port
forwards, `scp`, `rsync`, `sftp`, `Match host`, the lot). URTB is
**not** in the SSH crypto path; it is the encrypted PTY tunnel that
delivered you to the home server's command line. Two layers,
composed cleanly:

| Layer | What it secures | How |
|---|---|---|
| URTB | client laptop ↔ home server, the wire | XChaCha20-Poly1305 + Argon2id capsule + dual-radio |
| SSH (inside) | home server ↔ internal host | OpenSSH defaults (Ed25519 host key + your key) |

### Limits of the model

URTB does not expose a SOCKS proxy or a TCP listener you could feed
to `ssh -J` or `ProxyJump`. The "jump" is not a transport-layer
jump; it is "a shell on the bastion, opened over URTB instead of
over SSH-on-TCP." That distinction matters in two ways:

- **No `ssh -J urtb target` form.** You log into the URTB shell
  first, then `ssh` from there. Multi-hop chains compose by
  re-running `ssh` inside each hop's shell, the same way you would
  on any non-IP bastion.
- **No `scp client-laptop:file urtb:remote`.** To move files, either
  use the URTB PTY itself (paste short text), or run `scp
  internal-host:file ~` *from inside* the URTB shell to stage the
  file on the home server, then move it the rest of the way out of
  band.

Inside-out (client laptop → home network) is what URTB is built for.
Outside-in (home network → client laptop) is the same trick with the
roles reversed: run `urtb listen` on the client laptop and `urtb
connect` on the home server.

### Side-by-side: URTB jump vs. `socat + openssl` jump

The same jump-host pattern works without URTB if your two endpoints
already share an IP path. The prior-art reference is
`tools/prior-art-demo.sh` (full discussion in `PRIOR_ART.md`
§"Prior art II"). Both forms terminate at a real PTY shell on the
bastion and let you `ssh` onward from there. The only things that
change are the wire and the auth model.

**Bastion side (run on the home server)**

```
# URTB form — wire is ESP-NOW + LoRa fallback, auth is Argon2id capsule
URTB_PASSPHRASE=test123 ./urtb listen --transport heltec \
    --device /dev/ttyUSB0 --capsule /tmp/urtb_demo.cap

# socat+openssl form — wire is TCP, auth is mutual TLS cert
./tools/prior-art-demo.sh setup     # one-time: generate urtb.pem + urtb.key
./tools/prior-art-demo.sh server    # binds 127.0.0.1:9443
```

**Client side (run on the client laptop)**

```
# URTB form
URTB_PASSPHRASE=test123 ./urtb connect --transport heltec \
    --device /dev/cu.usbserial-0001 --capsule /tmp/urtb_demo.cap

# socat+openssl form
URTB_HOST=home.example.com ./tools/prior-art-demo.sh client
```

**Then in either resulting shell, the jump itself is identical**

```
ssh internal-host.lan                          # plain jump
ssh -L 5432:db.lan:5432 db@bastion.lan         # port-forward through the bastion
scp internal-host.lan:/etc/foo.conf ~          # stage a file on the bastion
```

**Comparison**

| Property | URTB jump | `socat + openssl` jump |
|---|---|---|
| Wire | ESP-NOW primary, LoRa fallback | TCP |
| Encryption | XChaCha20-Poly1305 (URTB AEAD) | TLS 1.2/1.3 (OpenSSL) |
| Mutual auth | PSK in Argon2id capsule | Self-signed cert + key, both sides |
| Touches the IP layer? | **No** — USB ↔ radio ↔ USB | Yes — needs a routable TCP path |
| Survives transport switch mid-session? | Yes (ESP-NOW ↔ LoRa) | N/A (single TCP conn) |
| Custom code to audit | ~2000 lines (`urtb`) | 0 (off-the-shelf socat + openssl) |
| Setup complexity | `keygen` once, copy capsule once | `openssl req` once, copy cert once |
| Right answer when... | you cannot or do not want an IP path between the two hosts (restrictive VPN-managed network, no port forward, out-of-band by design) | you already have a clean IP path and just want an encrypted PTY |

Pick the row your situation actually matches. `PRIOR_ART.md` is
explicit that URTB does not compete with `socat + openssl` on TCP —
it competes only on the radio + dual-radio failover slot. If your
jump host is reachable on TCP, the prior-art form is simpler, has
forward secrecy, and uses zero custom code. URTB is the answer
when the *point* is that there is no IP route to introduce.

**Single-host smoke test** of the prior-art form (handy for
verifying TLS + PTY work before running it across the network):

```
./tools/prior-art-demo.sh setup
./tools/prior-art-demo.sh loopback   # server in background, client against it, one host
```

`./tools/prior-art-demo.sh cable /tmp/tty-a /tmp/tty-b` creates a
virtual null-modem pair, the same way Use Case 0.5 does for the
heltec transport — useful if you want to chain two prior-art-demo
instances over a fake serial cable instead of TCP.

## Second factor authentication (OTP)

URTB supports optional HOTP/TOTP as a second factor. Even if your capsule file
is compromised, an attacker cannot get a shell without the current OTP code.

### Setup (listener side, one time)

    ./urtb otp-init --type hotp

Scan the printed URI with Google Authenticator, Proton Authenticator,
Microsoft Authenticator, Aegis, or FreeOTP+. The key is saved to
`~/.config/urtb/otp.key` — keep it on this machine only, never transfer it.

TOTP (time-based) is available via `--type totp` but requires the listener
clock to be within ±30 seconds of the authenticator app clock. HOTP
(counter-based, default) works without NTP sync.

### Listening with OTP

    ./urtb listen --transport heltec --device $DEVICE --capsule pairing.capsule \
                  --otp ~/.config/urtb/otp.key --loop

Or with UNIX sockets (no hardware):

    ./urtb listen --transport unix --socket /tmp/urtb.sock \
                  --otp ~/.config/urtb/otp.key

### Connecting (no change)

    ./urtb connect --transport heltec --device $DEVICE --capsule pairing.capsule

After connecting, you will see an `OTP: ` prompt. Type the current 6-digit
code from your authenticator app and press Enter. Three wrong attempts
close the session.

### Disabling OTP

Omit `--otp` from the listen command. To disable permanently, delete the
key file:

    rm ~/.config/urtb/otp.key

### Building without OTP support

    make OTP=0

This produces a binary with zero OTP code or SHA1 symbols — the same binary
as pre-OTP builds. Useful for constrained environments or if OTP is not
wanted.

## Troubleshooting

- **"no Heltec V3 ports detected" from `make ports`** — the CP2102
  bridge (VID `10c4` PID `ea60`) is not enumerating. `pio device
  list` is the easiest second opinion; on macOS the device should
  show up as `/dev/cu.usbserial-*`, on Linux `/dev/ttyUSB*`. Try a
  different USB cable — the Heltec V3 ships with USB-C cables that
  are sometimes power-only. `pyserial` (which PlatformIO installs
  as a transitive dep, so `pio` users already have it) gives the
  same information in a grep-friendly form on both macOS and Linux:
  ```
  python3 -m serial.tools.list_ports -v
  # or, filtered to just CP2102 device paths:
  python3 -m serial.tools.list_ports -v 2>/dev/null \
      | awk '/^\/dev\//{dev=$1} /VID:PID=10C4:EA60/{print dev}'
  ```
- **"session won't establish on real Heltec"** — check that **both**
  boards are on production firmware, current build. Three real
  hardware bugs were found and fixed during bring-up: firmware
  SX1262 self-loopback over the shared FIFO, host sending
  all-zero `peer_mac` causing ESP-NOW to silently drop everything,
  and a half-duplex CTRL_READY collision over LoRa (fixed with a
  250 ms server-side stagger). Reflash both
  boards and rebuild the host before assuming a new bug.
- **`tools/heltec_socat_test.sh` or `tools/frag_runtime_test.sh`
  fails on macOS** — these scripts need `socat` and a working
  `timeout(1)`. macOS has no `timeout`; both scripts ship with a
  perl `fork+alarm` shim baked in (naive
  `alarm; exec` is broken because POSIX clears pending alarms on
  exec). If the shim is failing, check that `perl` is on the PATH.
- **`python3 tools/ac03_pyte_test.py` fails with "no module named
  pyte"** — install with `pip3 install pyte` (or `pip3 install
  --break-system-packages pyte` on a PEP-668 distro). Tested with pyte 0.8.2.
- **`make` says `forkpty undefined` on macOS** — `LDLIBS=-lutil` is
  the Linux path; macOS ships `forkpty` in `libSystem` and has no
  `libutil`. The Makefile already auto-detects this via
  `UNAME_S := Darwin`; if a custom invocation is forcing `LDLIBS`
  manually, drop `-lutil` from it.

## Where to look next

- `PROTOCOL.md` — wire format, frame types, crypto, state machine,
  channels, keepalive, fragmentation, USB_TEST_INJECT (test build).
- `SPEC.md` — system scope, components, data flow.
- `SECURITY.md` — threat model and key-handling rules.
- `TESTING.md` — full test inventory, tiers, CI guidance.
- `KNOWN_ISSUES.md` — what is deferred and why.
- `DECISIONS.md` — design-decision log (D-37 covers test-only RF
  injection).
