# URTB testing

This document is the operator's reference for the URTB test surface. Every
command below has been run on macOS Darwin 24.6.0 against the working tree
at the head of `main`.

## Overview — three test tiers

URTB has three tiers of evidence:

1. **No-hardware tier.** Host-only: builds, frame_test (52 wire-format
   and crypto cases), the `pyte`-driven AC-03 PTY harness, the `socat +
   fake_firmware.py` Heltec USB-framing simulator, the `frag_runtime`
   end-to-end fragmentation runtime test, and the prod-binary symbol
   audit. ~50 s wall.
2. **Hardware tier.** Two Heltec V3 boards on USB. Builds the
   `URTB_TEST_INJECT=1` test binary and test-firmware, flashes both
   boards, runs `tools/run_inject_acs.sh all` (six inject-driven ACs),
   then reflashes prod firmware. ~3 min wall.
3. **Interactive tier.** A single test — FI-02 USB cable yank — that
   only a human can drive. Documented procedure, no automation.

## Quick start

```
make doctor   # check toolchain + ports
make check    # no-hw tier (~50s, expect 9 PASS / 1 SKIP on macOS)
make check-hw # hardware tier (requires 2 Heltec V3 attached)
make check-all # both
```

`make smoke` is the ~2 s sanity build + frame_test for tight inner loops.

## Test inventory

Wide table — every PASS in this repository against the script that emits
it and the AC IDs the report says it covers.

| Test ID         | Tier   | Command                                | What it covers (AC IDs)                                         | Runtime | HW required |
|-----------------|--------|----------------------------------------|-----------------------------------------------------------------|---------|-------------|
| make-clean      | no-hw  | `make clean`                           | (build hygiene)                                                 | <1 s    | no          |
| make-build      | no-hw  | `make CC=cc CFLAGS="-Wall -Wextra -std=c11 -O2"` | AC-07-02 (macOS build), AC-07-03 (Linux build, reused) | 1–2 s | no |
| urtb-help       | no-hw  | `./urtb --help`                        | AC-07-01 (subcommand inventory)                                 | <1 s    | no          |
| platform-libs   | no-hw  | `otool -L urtb` (mac) / `ldd urtb` (linux) | AC-07-05 (macOS libSystem only)                              | <1 s    | no          |
| frame-test      | no-hw  | `make test`                            | AC-04-01..05 (replay/AEAD), AC-06-01 (CRC), AC-06-03/04 (§7 reasm), AC-08-01..03 (transports), FI-04 | <1 s | no |
| capsule-version | no-hw  | `make test` (includes `tools/capsule_version_test`) | AC-01-09 (v2 capsule format: round-trip on ch 1/6/13, generate-reject on 0/14, v1 forward-compat via URTB_TEST_V1_EMIT shim, pre-AEAD accept-list gate) | <1 s | no |
| ac03-pyte       | no-hw  | `python3 tools/ac03_pyte_test.py`      | AC-03-01 top, AC-03-02 vim, AC-03-03 htop, AC-03-04 tab completion, AC-03-05 arrow history | ~42 s | no |
| heltec-socat    | no-hw  | `bash tools/heltec_socat_test.sh`      | Host-side `transport_heltec.c`: USB framing, CRC, USB_HELLO/CONFIG/STATUS, ESPNOW↔LoRa mode flap | 2–3 s | no |
| frag-runtime    | no-hw  | `bash tools/frag_runtime_test.sh`      | AC-06-03 PTY fragmentation runtime path (~400 B → 7 fragments → reassembled intact, LoRa mode) | 2–3 s | no |
| musl-static     | no-hw  | `make urtb-static`                     | AC-07-04 (Linux musl-static, "not a dynamic executable") — Linux-only, SKIP on macOS | ~5 s | no (Linux) |
| hygiene         | no-hw  | `make hygiene`                         | Prod binary contains zero `inject` symbols (D-37 build-flag gate) | <1 s | no          |
| heltec-e2e      | hw     | `./urtb listen --transport heltec --device <A> --capsule <c>` + matching `connect` on `<B>` | AC-05-01 real-radio session, AC-05-02 transport_active=ESPNOW, AC-05-06 mode-switch events, AC-06-05 keepalive 2 s ESP-NOW, AC-06-06 CTRL_CLOSE clean exit | ~30 s | 2× Heltec V3 |
| inject-acs      | hw     | `tools/run_inject_acs.sh all`          | AC-05-03/04/05 failover/recovery, AC-05-08 both-radios-down liveness, AC-05-09 LoRa low-power asym, AC-09-01 LoRa coalescing | ~3 min | 2× Heltec V3 |
| FI-02 (manual)  | manual | physical USB cable yank, see §Interactive | FI-02 — peer-loss recovery via firmware failover + mode-2 liveness + CTRL_CLOSE retransmit ladder | ~99 s | 2× Heltec V3 + human |

The 42-AC / 8-FI rollup grid is maintained alongside the test runs. The "No-hardware path"
section below describes what this no-hw tier covers vs. what only the
hardware tier or the interactive tier can reach.

A note on **PASS-L** rows in the rollup grid: a non-trivial
fraction of the 42-AC grid is marked "PASS-L" (Linux PASS reused) —
e.g. AC-01-01/05/06/07, AC-02-06/07, AC-03-06/07, AC-04-01/05/06/07,
AC-06-07, FI-04/06/07/08. PASS-L items have been verified on Linux
and are marked to distinguish them from macOS-verified runs.

A note on `tools/fi03_replay_proxy.py` and `tools/fi05_pair_id_inject.py`:
these are one-shot harnesses that produced the FI-03 and FI-05 PASS
evidence.
They are intentionally **not** wired into `tools/run_all_tests.sh` —
fi03 expects a stable unix-transport scenario and fi05 needs the
specific real-Heltec USB framing handshake. To re-run them, invoke
them directly from the repo root.

## No-hardware path

`make check` on macOS produces (recent run, 2026-04-15):

```
== no-hw tier ==
  [no-hw     ] make-clean                       ... PASS (0s)
  [no-hw     ] make-build                       ... PASS (2s)
  [no-hw     ] urtb-help                        ... PASS (0s)
  [no-hw     ] platform-libs                    ... PASS (0s)
  [no-hw     ] frame-test                       ... PASS (0s)
  [no-hw     ] ac03-pyte                        ... PASS (41s)
  [no-hw     ] heltec-socat                     ... PASS (3s)
  [no-hw     ] frag-runtime                     ... PASS (3s)
  [no-hw     ] musl-static                      ... SKIP (musl-gcc not present)
  [no-hw     ] hygiene                          ... PASS (0s)
totals: 9 PASS, 0 FAIL, 1 SKIP, 0 HARDFAIL  (wall 49s)
```

What the no-hardware path fully verifies:
- the entire host-side state machine (`src/session.c`),
- the wire format (USB + radio framing, AEAD, replay window, BLAKE2b
  KDF) — `frame_test` 52/52,
- channel-1 PTY plumbing including raw-mode / SIGWINCH / EOF handling
  via the `pyte`-backed AC-03 harness (real `pty.openpty()` 24×80 inside
  the test process),
- the `transport_heltec.c` USB framing (HELLO/CONFIG/STATUS handshake,
  PAIR_ID propagation, mid-session ESPNOW↔LoRa flap) via
  `tools/fake_firmware.py` bridging two `socat` PTY pairs,
- the §7 reassembler from sender split through receiver reassembly on
  a forced LoRa MTU of 72 — `tools/frag_runtime_test.sh`,
- prod-binary symbol hygiene (`make hygiene` → `nm urtb | grep -c
  inject == 0`).

What the no-hardware path **cannot** verify:
- ESP-NOW failover at the radio layer — there is no real radio. The
  `socat + fake_firmware.py` bridge models USB but not RF physics.
  Covered by the `URTB_TEST_INJECT=1` build-flag-gated inject path in
  the hardware tier.
- Real LoRa duty-cycle or SX1262 timing.
- Physical USB cable disconnect on a real device — covered only by the
  interactive FI-02 procedure.
- `tools/frag_runtime_test.sh` and `tools/heltec_socat_test.sh` need
  `socat` on the PATH; macOS without a working `timeout(1)` falls back
  to a perl `fork+alarm` shim baked into both scripts (POSIX clears
  pending alarms on exec, so a naive `alarm; exec` is broken).

## Hardware path

Requirements:
- Two Heltec V3 boards each connected over USB. The CP2102 USB-UART
  bridge enumerates as `/dev/cu.usbserial-*` on macOS and `/dev/ttyUSB*`
  on Linux. Run `make ports` (or `tools/ports.sh`) to verify.
- PlatformIO Core (`pipx install platformio`) on the PATH.
- The repo's `firmware/platformio.ini` defines two envs:
  - `heltec_wifi_lora_32_V3` — production firmware,
    `URTB_TEST_INJECT=0`.
  - `heltec_wifi_lora_32_V3_test` — test firmware,
    `URTB_TEST_INJECT=1`, exposes the `0x0B USB_TEST_INJECT` frame.

`make check-hw` runs the following sequence (full driver:
`tools/run_all_tests.sh --tier hw`):

1. `tools/ports.sh` detects two Heltec ports. If <2, the entire hw tier
   is SKIPped — never half-run.
2. Build the test binary: `make clean && make urtb URTB_TEST_INJECT=1`,
   rename to `urtb-test`. Symbol audit: `nm urtb-test | grep -c inject`
   should be 7.
3. Build the production binary again: `make clean && make urtb`. Symbol
   audit: `nm urtb | grep -c inject == 0` is the load-bearing gate that
   keeps test-only RF inject code out of shipped binaries (D-37).
4. Flash the test firmware to both boards:
   `cd firmware && pio run -e heltec_wifi_lora_32_V3_test -t erase
   --upload-port <DEVICE_A> && pio run -e heltec_wifi_lora_32_V3_test
   -t upload --upload-port <DEVICE_A>`, and again for `<DEVICE_B>`.
   The erase step is required because the prior image is the prod env
   (`heltec_wifi_lora_32_V3`); crossing envs without erase can leave
   stale partitions that break the handshake — see HOWTO.md §Use case 2.
5. `bash tools/run_inject_acs.sh all` — six inject-driven ACs:
   - **AC-05-03** failover ESP-NOW→LoRa via `inject espnow-down`
   - **AC-05-04** PTY survives over LoRa
   - **AC-05-05** recovery LoRa→ESP-NOW via `inject espnow-up`
   - **AC-09-01** LoRa coalescing ≤ 10 fpm
   - **AC-05-08** both radios down → liveness watchdog ≤ 110 s
   - **AC-05-09** asymmetric LoRa low-power link
6. Reflash production firmware to both boards: `pio run -e
   heltec_wifi_lora_32_V3 -t erase && pio run -e
   heltec_wifi_lora_32_V3 -t upload` per board. Erase is required for
   the same reason as step 4 (env swap `_test` → prod). Boards are
   left in shippable state.

What to look for in the logs:

- Listen side, after both sides reach ESTABLISHED:
  `session: transport mode 1 → keepalive=2000ms liveness=8000ms mtu=222`
  (mode 1 == ESP-NOW). After `inject espnow-down`, both sides should
  show `transport mode 2 → keepalive=30000ms liveness=90000ms mtu=72`
  within ~14 s.
- Connect side:
  `session: → ESTABLISHED`,
  `channel_pty: client received PTY_OPEN_ACK`,
  `urtb: entered raw mode`.
- Final harness summary: `=== summary: 0 failures ===`.

## Pre-push hardware ship gate

Before pushing any change that touches `src/session.c`, `src/transport_*`,
`firmware/`, or `tools/hw_test_*.sh` to the public repo, run the
hardware ship gate on two physical Heltec V3 boards:

```sh
make                                            # production binary
bash tools/hw_test_flash.sh                     # flash production firmware
for i in 1 2 3; do bash tools/hw_test_run.sh || exit 1; done   # 3× back-to-back
```

The gate fails if either peer ever reports `transport mode 2` (LoRa
fallback) during the run — that masks the e279c05 / b33899c regression
class where the ESP-NOW handshake succeeds but the link silently
degrades. The 3× back-to-back requirement catches first-run-only
flukes; for a release tag, also run a 5-minute idle soak (`sleep 300`
after the third PASS, then re-grep the log for `→ IDLE` / `liveness
timeout`).

### Bisect scope

Regressions that present as a wire-protocol or handshake failure can
originate in *either* `src/` (host) or `firmware/`. When bisecting such
a symptom, the candidate set must include both — restricting `git
bisect` to one tree (e.g. `git bisect start -- firmware/`) is what let
b33899c slip past the original regression hunt. Default to a full
bisect; narrow only when the symptom is unambiguously one-sided.

## Failure injection mechanism

The `URTB_TEST_INJECT=1` build links `src/test_inject.c` and exposes
the `urtb test-inject --pid <pid> <verb>` subcommand on the host, plus
the `0x0B USB_TEST_INJECT` frame between host and firmware. Both are
absent from production builds — `make hygiene` is the gate.

Verbs (per PROTOCOL.md §1 "Test-only frames"):

- `espnow-down` / `espnow-up` — drop or restore ESP-NOW TX (sticky).
- `lora-down` / `lora-up` — drop or restore LoRa TX.
- `all-down` — drop both radios; combined with mode-2 liveness this
  drives AC-05-08.
- `lora-low-power` — emulate asymmetric low-power LoRa link
  (AC-05-09).

The host control socket lives at `/tmp/urtb-inject-<pid>.sock` (mode
0600, SO_PEERCRED check on Linux, LOCAL_PEERCRED + cr_version on
macOS), with 2 s rcv/snd timeouts on accepted connections. Inject
commands are sticky; the firmware acks each as
`USB_TEST_INJECT_ACK applied flags=0xNN`.

Background: see DECISIONS.md D-37 ("test-only RF failure injection")
and PROTOCOL.md §1 ("Test-only frames (URTB_TEST_INJECT build only)").

The inject path replaced an earlier Faraday-cage / cookie-tin shielding
plan; it is more deterministic and also surfaced two real bugs that
shielding would have masked (firmware `maybe_send_probe()` bypassing
`DROP_ESPNOW_TX`, host mode-1 liveness racing firmware failover —
both fixed and documented in DECISIONS.md).

## The interactive tier — FI-02 USB cable yank

Procedure:

1. Both boards on production firmware (`pio run -e
   heltec_wifi_lora_32_V3 -t upload` on each device — prepend
   `-t erase &&` when upgrading firmware alongside the host binary;
   see HOWTO.md §Use case 2).
2. Generate a capsule: `URTB_PASSPHRASE=test123 ./urtb keygen --out
   /tmp/fi02_capsule`.
3. Start listen on DEVICE_A:
   `./urtb listen --transport heltec --device /dev/cu.usbserial-0001
   --capsule /tmp/fi02_capsule </dev/null >/tmp/fi02-listen.log 2>&1 &`
4. Start connect on DEVICE_B:
   `./urtb connect --transport heltec --device /dev/cu.usbserial-4
   --capsule /tmp/fi02_capsule </dev/null >/tmp/fi02-connect.log 2>&1 &`
5. Wait until both logs show `→ ESTABLISHED` and `transport mode 1 →
   keepalive=2000ms liveness=8000ms mtu=222`.
6. **Physically pull DEVICE_B's USB cable.**

Expected outcome:

- Connect side (`/tmp/fi02-connect.log`) closes immediately on the next
  poll iteration:
  `session: transport poll hup/err — closing` → `session: → IDLE`.
  No crash, no stuck PTY, no leaked fd
  (`lsof | grep usbserial-4` empty post-yank).
- Listen side (`/tmp/fi02-listen.log`) recovers via firmware failover
  ESP-NOW→LoRa (~6 s = `FAILOVER_EMPTY_WINDOWS × WINDOW_MS`), then
  mode-2 liveness watchdog (90 s), then CTRL_CLOSE 2/3 → 3/3 → `force
  close after CTRL_CLOSE retransmits` → `channel_pty: PTY closed
  (exit=1)` → `→ IDLE`. Wall time ~99 s from yank to listen exit.
- `pgrep -fl "urtb (connect|listen) --transport heltec"` empty within
  the timeout window. No defunct urtb processes.

Why this is interactive-only: this test requires a physical cable
yank and cannot be automated (a cable yank is a physical action with
no clean software analogue, and `tools/run_inject_acs.sh all-down` already
covers the firmware-side recovery path on the listen side via
inject — FI-02 specifically validates the `transport poll hup/err`
path on the yanked side, which can only be reached by removing the
USB device).

## Adding a new test

Convention used by every script under `tools/`:

- Live in `tools/<test-id>.sh` (or `.py` for tests that need
  `pty.openpty()`).
- Exit code `0` on PASS, non-zero on FAIL. The driver
  (`tools/run_all_tests.sh`) uses the exit code as the verdict.
- Print enough context on stderr that a glance at the log is enough
  to triage.
- Clean up `/tmp/<test>-*` on exit, including on signal — the existing
  scripts use a `trap cleanup EXIT` pattern.
- Hook it into the desired tier by adding a `run_step <id> <tier>
  <hard|soft> <function>` line in the appropriate `run_no_hw` /
  `run_hw` section of `tools/run_all_tests.sh`. `hard` aborts the rest
  of the tier; `soft` records FAIL and continues.

## CI guidance

The no-hardware tier is intended to be the GitHub Actions matrix gate:
`{ubuntu-latest, macos-latest} × make doctor && make check`. On Linux,
the `musl-static` step builds and `ldd`s when `musl-tools` is in the
runner image; on macOS it is correctly SKIPped. The hardware tier is
not CI-friendly and should run on a dedicated bench host with two
Heltec V3 boards on USB. The CI workflow is at `.github/workflows/test.yml`
with the ubuntu+macos matrix, a separate `test-asan` ubuntu job, and
per-OS dynamic-library whitelists. The matrix gate runs `make` plus
`make test`; the doctor step is not in CI today (it is still
recommended for local pre-flight).

## Reference — per-test evidence

| AC group              | Evidence                                                              |
|-----------------------|-----------------------------------------------------------------------|
| AC-01 keygen          | code paths in `src/main.c` + `src/capsule.c`                         |
| AC-02 unix transport  | `make check` no-hw tier                                               |
| AC-03 PTY apps        | `tools/ac03_pyte_test.py` (5/5 PASS)                                  |
| AC-04 crypto/replay   | `frame_test` group 4                                                  |
| AC-05 Heltec radio    | real-hw bringup + `tools/run_inject_acs.sh` (inject ACs)              |
| AC-06 framing         | `frame_test` groups 1/6/7 + `tools/frag_runtime_test.sh`              |
| AC-07 build/portable  | `otool -L` / `ldd` checks, `make urtb-static` (musl)                 |
| AC-08 transport mux   | `tools/heltec_socat_test.sh` + `frame_test` group 6                   |
| AC-09 coalescing      | `tools/run_inject_acs.sh` AC-09-01                                    |
| FI-01..FI-08          | `tools/run_inject_acs.sh` + FI-02 manual procedure                    |
