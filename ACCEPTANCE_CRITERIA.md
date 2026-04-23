# URTB — Acceptance Criteria
# All criteria are testable pass/fail. No "works correctly" without specifics.

---

## AC-01  Pairing / keygen

  AC-01-01  `urtb keygen` prompts for a passphrase (twice, must match)
  AC-01-02  `urtb keygen` produces a pairing.capsule file
  AC-01-03  pairing.capsule begins with magic bytes 0x55 0x52 0x54 0x42
  AC-01-04  pairing.capsule is readable by `urtb listen` and `urtb connect` with correct passphrase
  AC-01-05  Wrong passphrase at startup: process exits with non-zero code and error message
  AC-01-06  pairing.capsule file permissions are 0600 after creation
  AC-01-07  Two separate `urtb keygen` runs produce different capsule files (different PSK)
  AC-01-08  Tampered capsule header: modify salt or time_cost in a valid capsule, attempt
             unlock with the correct passphrase → unlock fails with AEAD error, no session
             established. Verifies KDF-param AD binding from SECURITY.md §capsule.
  AC-01-09  Capsule format v2 — ESP-NOW channel binding (DECISIONS.md D-40):
             (a) `urtb keygen --espnow-channel 1 --out ch1.capsule` produces a valid
                 v2 capsule (header byte 4 = 0x02).
             (b) `urtb keygen --out default.capsule` (no flag) produces a v2 capsule
                 with channel = 6 on load.
             (c) `urtb keygen --espnow-channel 14` exits non-zero with a clear error,
                 no file written. Same for 0 and non-numeric input.
             (d) A v1 capsule (generated at test time via the `URTB_TEST_V1_EMIT`
                 shim — no v1 binary fixture checked in) loads successfully with
                 runtime channel = 6. Back-compat unchanged for existing v1 capsules.
             (e) `cmd_session` and `cmd_status` both load the channel from the
                 capsule. `git grep -n 'espnow_channel = 6' src/` returns only
                 documentation/comment matches — no assignment statements.
             (f) `git grep -n 'espnow_channel ? .* : 6' src/` returns nothing.
             (g) `urtb keygen --espnow-channel 11` + `tools/fake_firmware.py` logs
                 USB_CONFIG byte 18 == 11 for both peers (end-to-end proof the
                 chosen channel reaches the wire). Exercised by
                 `tools/heltec_socat_test.sh`.
             (h) `tools/capsule_version_test` passes all cases; `make clean && make`
                 is warning-free.

---

## AC-02  UNIX socket transport (no hardware)

  AC-02-01  `urtb listen --transport unix --socket /tmp/urtb.sock` starts without error
  AC-02-02  `urtb connect --transport unix --socket /tmp/urtb.sock` connects successfully
  AC-02-03  Session established: CTRL_HELLO + CTRL_HELLO_ACK + CTRL_READY (both directions)
             exchange completes; both client and server log "session established"
  AC-02-04  After session: typing in client terminal produces output visible in client terminal
  AC-02-05  `exit` in remote shell closes session cleanly, client urtb exits with code 0
  AC-02-06  Ctrl+C in client: SIGINT forwarded to remote shell, not kill of urtb itself
  AC-02-07  Terminal resize: remote shell sees updated rows/cols after client window resize

---

## AC-03  PTY correctness

  AC-03-01  `top` runs in the PTY session, refreshes without corruption
  AC-03-02  `vim` opens, accepts keystrokes, displays correctly, exits cleanly with :q
  AC-03-03  `htop` displays, q exits cleanly
  AC-03-04  Tab completion works in the remote shell (zsh/bash)
  AC-03-05  Arrow keys work (up/down for history, left/right for cursor)
  AC-03-06  `tty` in the remote shell returns a PTY device path (not "not a tty")
  AC-03-07  SIGWINCH forwarded on terminal resize: `tput lines` and `tput cols` reflect new size

---

## AC-04  Session security

  AC-04-01  Two urtb instances with mismatched PSK: server sends zero CTRL_HELLO_ACK frames
             (observable: capture or count TX at server side). Client transmits exactly
             5 CTRL_HELLO frames total (1 initial + 4 retries; backoff 1s/2s/4s/8s between,
             16s after 5th = 31s total), then logs "handshake timeout" and returns to IDLE.
             TX counter == 5. No ERR_AUTH_FAIL frame is ever sent by either side.
  AC-04-02  Replayed radio frame (same SEQ): frame is silently dropped (no response from
             receiver, session state unchanged, no additional TX from either peer).
             Verify: inject a captured frame twice; second injection produces no observable
             state change.
  AC-04-03  Sequence number outside replay window (old): frame is dropped
  AC-04-04  Corrupted ciphertext (1 bit flipped): AEAD decryption fails, frame is dropped
  AC-04-05  PSK never appears in any log output (grep PSK from log = 0 matches)
  AC-04-06  Capsule passphrase never appears in any log output
  AC-04-07  Session key not written to disk (lsof / /proc/fd shows no session key file)

---

## AC-05  Transport failover (requires Heltec hardware)

  AC-05-01  urtb listen + urtb connect establish session over ESP-NOW
  AC-05-02  `urtb status` (or USB_STATUS_REQ → USB_STATUS_RSP) shows transport_active=0
             (ESP-NOW). Output must include: transport name, RSSI, tx_ok, tx_fail counters.
  AC-05-03  Block ESP-NOW on BOTH devices simultaneously for 6+ seconds (e.g. RF shield or
             channel change on both) while both remain powered: both firmwares detect 3
             consecutive 2s windows with zero PAIR_ID-matching ESP-NOW frames, switch to LoRa.
             Note: blocking only one side causes asymmetric behavior — the unblocked side
             continues receiving the blocked side's transmissions and may not failover.
  AC-05-04  After switch: PTY session continues, commands execute (at LoRa latency)
  AC-05-05  Restore ESP-NOW connectivity (remove block): recovery probes succeed (2 consecutive
             2s windows with ESP-NOW frames), session switches back to ESP-NOW
  AC-05-06  Switch events appear in status output (stderr or status file)
  AC-05-07  PAIR_ID mismatch: firmware drops frame, never forwarded to host app

---

## AC-06  Protocol correctness

  AC-06-01  USB frame CRC mismatch: frame discarded, no crash
  AC-06-02  Radio frame with wrong PAIR_ID: firmware drops before USB forward
  AC-06-03  Fragmented PTY frame: reassembled correctly at receiver.
             Note: normal PTY path reads up to current_mtu (72 bytes on LoRa), so
             fragmentation is tested via a synthetic Ch1 sender: inject a multi-fragment
             Ch1 sequence (FF=1/MF=1, FF=0/MF=1, FF=0/MF=0) directly into the session
             frame pipeline and verify the reassembled payload matches the input.
  AC-06-04  Reassembly timeout (fragment never arrives): partial buffer discarded, no hang
  AC-06-05  Keepalive period: CTRL_KEEPALIVE frames observed at ~2s intervals (ESP-NOW)
  AC-06-06  Session state machine: CTRL_CLOSE from server causes client to exit cleanly
  AC-06-08  Missed keepalive: kill the remote urtb process mid-session (or block all transport
             frames) until 3 consecutive keepalive periods elapse without an authenticated
             frame. Expected: urtb logs one liveness-timeout message to status output and
             closes the session (CTRL_CLOSE or silent teardown depending on transport state).
             Terminal restored, process exits cleanly.

  AC-06-07  SEQ approaching wrap threshold (0xFFFFFFFF - 1000): sender automatically sends
             CTRL_CLOSE and initiates renegotiation before wrap. Test: artificially seed
             SEQ counter at 0xFFFFFFFF - 1001, send one frame — CTRL_CLOSE follows immediately.
             SEQ must NEVER actually wrap to 0 (nonce reuse). "Handles wrap" is not acceptable.

---

## AC-07  Single binary

  AC-07-01  `urtb --help` lists: keygen, listen, connect subcommands
  AC-07-02  Binary runs on macOS (arm64 or x86_64)
  AC-07-03  Binary runs on Linux (x86_64)
  AC-07-04  `ldd urtb` on Linux shows only libc (or fully static: "not a dynamic executable")
  AC-07-05  `otool -L urtb` on macOS shows only system frameworks (no libsodium, no Python)

---

## AC-08  Transport abstraction

  AC-08-01  Changing transport from unix to stdio (config change only) produces identical
             session_key derivation, channel dispatch, and AEAD operations. Verified by:
             `nm urtb | grep ' U '` shows no direct transport_unix_* or transport_heltec_*
             function symbol calls from session.o or channel.o. Extern references to
             `transport_unix` and `transport_heltec` (the ops structs) are permitted in
             main.c / transport_registry.c — only direct function calls are prohibited.
  AC-08-02  Swapping transport (unix → heltec → stdio) requires only config change, no recompile
  AC-08-03  transport_ops_t interface: all 5 function pointers non-NULL for each transport

---

## AC-09  LoRa duty-cycle coalescing

  AC-09-01  During LORA_FALLBACK: PTY keystroke output is batched; observe ≤ 10 LoRa frames/minute
             averaged over 60s of normal interactive typing (commands + responses; NOT
             continuous clipboard paste or synthetic key flooding — that exceeds the LoRa duty
             cycle by design and is a known limitation documented in D-36).
             Budget target is ~8.6 frames/min at SF7/BW125.
             No single 1s window may contain more than 1 LoRa frame with FIRST_FRAGMENT=1
             (i.e. new coalesced PTY batch). Fragment continuation frames (FIRST_FRAGMENT=0)
             are exempt from the burst limit — they must be delivered within the 30s reassembly
             timeout and cannot be artificially throttled.
             Verify with frame_dump.py timestamps + frame type filtering.
  AC-09-02  During ESPNOW_PRIMARY: PTY output is sent immediately (no 500ms delay).
             Verify with frame_dump.py that keystroke response latency < 100ms.

---

## AC-10  OTP second-factor authentication

  AC-10-01  `urtb otp-verify --otp PATH --code CORRECT` → exit 0; HOTP counter
             advances by 1 in file.
  AC-10-02  `urtb otp-verify --otp PATH --code WRONG` → exit 1; counter unchanged.
  AC-10-03  HOTP lookahead window: code for counter+N (N ≤ window) accepted;
             code for counter+window+1 rejected.
  AC-10-04  TOTP: code for current 30 s window ± 1 step accepted; code for
             window ± 2 steps rejected.
  AC-10-05  Session with `--otp`: wrong code → "Access denied.", re-prompts.
             After 3 wrong codes → silent session close.
  AC-10-06  `--loop` sessions have independent OTP attempt counters — failure
             in session N does not lock out session N+1.
  AC-10-07  Malformed code (non-digit, wrong length, trailing garbage) → rejected
             as if wrong code; not a crash.
  AC-10-08  Shell not reachable before OTP succeeds: PTY_SIGNAL and PTY_RESIZE
             are ignored until OTP_DONE; shell stdout is discarded (not forwarded).
  AC-10-09  `make OTP=0 && make test OTP=0` compiles clean, 0 warnings.

---

## Not yet implemented — see FUTURE.md

  File push/pull (channels 2, 3)
  Telemetry channels (4-8)
  QoS / channel priority scheduling
  Status bar / TUI overlay
  WiFi direct transport
  Multi-pair support
