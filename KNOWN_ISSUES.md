# urtb — Known Issues

Known limitations, deferred features, and items not addressed in the current
release. These are tracked here for contributors; none affect normal use.

## Protocol

### §1 USB_STATUS_RSP body[2..11] fields — RESOLVED
Status: closed.
Resolution: `transport_heltec.c` now stashes the full 16-byte body via
`have_status_rsp` / `last_status_body`, and `session_run` applies wrap-
safe uint16 delta reconciliation into `session_t`'s
`espnow_tx_ok_total` / `espnow_tx_fail_total` / `lora_tx_ok_total` /
`lora_tx_fail_total` (uint32) plus `espnow_rssi_last`, `lora_rssi_last`,
`lora_snr_last_decideb` (int8). New `urtb status --device DEV` subcommand
prints the parsed table (sentinel-zero RSSI rendered as `--`). The
firmware OLED (Heltec V3, U8g2 SW I2C) draws once at boot — `URTB`,
the 7-char git SHA, build date, and last 3 bytes of the STA MAC — and
performs **no I2C traffic from `loop()` or any RX/TX callback**.
Software I2C on GPIO17/18 blocks ~10–50 ms per redraw, which broke
symmetric ESP-NOW RX in the e279c05 regression; runtime redraws are
intentionally not supported. See PROTOCOL.md and `firmware/src/display.h`
for details.

### Post-setup USB_HELLO_ACK renegotiation — deferred
Status: deferred.
Reason: `transport_heltec.c` silently discards late `USB_HELLO_ACK`
frames. A proper reconnect path needs firmware-initiated
renegotiation design.
Follow-up: define renegotiation semantics, then wire the host side.

## Operation

### Session recovery after suspend / wake / screen-lock — deferred
Status: deferred.
Reason: the host has no mid-session recovery path when either
laptop suspends, wakes, the screen locks, or the USB link is
cycled. In most of these cases one side closes cleanly while the
other stays wedged (or vice versa), and restoring the tunnel
means killing the connect side and reconnecting.
Recommendation: run the server side under `urtb listen --loop` so
each connect-side restart is accepted transparently. In `--loop`
the server returns to IDLE after a session closes and waits for
the next `CTRL_HELLO` without dropping the capsule keys (mlock'd
and MADV_DONTDUMP across iterations — see SECURITY.md and
FUTURE.md S-1/S-2).
Follow-up: FUTURE.md C-14 tracks a client-side escape sequence so
the connect side is cleanly killable without a second terminal. A
proper mid-session resync path is deferred pending more field
data (see also FUTURE.md I-6).

## Platforms

### macOS build — RESOLVED
Status: resolved. `make clean && make` runs green under Apple
`cc -Wall -Wextra -std=c11 -O2`; AC-07-02 and AC-07-05 verified.

---

## Resolved items

The following entries previously appeared here and have now been closed
out. They are listed so future readers can find what changed:

- **USB cable disconnect mid-session** — RESOLVED. Operator physically
  yanked DEVICE_B's USB cable mid-session. Connect side
  detected via poll HUP/ERR and exited cleanly (`transport poll
  hup/err — closing → IDLE`); listen side recovered via firmware
  failover ESPNOW→LoRa + mode-2 liveness 90s + CTRL_CLOSE retransmit
  → force close. No fd leak, no zombie, no stuck PTY.
- **Heltec V3 AC-05-* / AC-09-01 needs-hw** — RESOLVED. Replaced
  Faraday-cage shielding with build-flag-gated RF failure injection
  (`URTB_TEST_INJECT=1` test build, USB_TEST_INJECT frame type 0x0B,
  `urtb test-inject` host subcommand, `tools/run_inject_acs.sh`
  harness). All six inject-driven ACs (AC-05-03/04/05/08/09, AC-09-01)
  PASS deterministically on real Heltec V3 hardware. Two latent bugs
  surfaced and fixed: (1) `maybe_send_probe()` bypassed
  `DROP_ESPNOW_TX`, (2) host mode-1 liveness 6s raced firmware
  failover 6s. See DECISIONS.md D-37 and PROTOCOL.md §1 USB_TEST_INJECT.

- **§7 fragmentation/reassembly on channel 1** — RESOLVED. Implemented
  in `src/reasm.{h,c}` + `session_send_data()` + `process_frame()`
  reasm interception. Unit tests `tools/frame_test.c` group 7 (11
  tests, all pass). Runtime end-to-end test
  `tools/frag_runtime_test.sh` exercises a real ~420-byte LoRa burst
  → 6 fragments → reassembled intact. AC-06-03 and AC-06-04 now PASS
  mechanically.
- **PlatformIO firmware compile-check** — RESOLVED. `pio run` succeeds
  on first invocation, RAM 14.4% / Flash 21.6%, only cosmetic
  RadioLib BuildOpt.h warnings.
- **Static musl build (AC-07-04 strict)** — RESOLVED. `make
  urtb-static` builds via `musl-gcc -static`. `ldd urtb-static` →
  "not a dynamic executable". Full keygen + listen + connect + PTY
  E2E green.
- **AC-03-01..05 (top/vim/htop/tab/arrows)** — RESOLVED. Mechanical
  pyte-based harness `tools/ac03_pyte_test.py` runs each test inside
  a real `pty.openpty()` PTY at 24×80, drives input, drains output,
  replays through pyte 0.8.2, asserts on screen. 5/5 PASS in ~17s.
