# URTB — Future / Nice-to-Have / Deferred Items
# Items here are not required for the current release.
# They are tracked so they don't get lost, not so they get done now.
# Add to this file freely. Remove items when promoted to a DECISIONS.md entry.

---

## Future priorities (roughly ordered)

### C-1  X25519 ephemeral key exchange (PFS)
  Replace PSK-only session_key derivation with Noise_XX pattern:
  X25519 identity keys for mutual authentication + ephemeral X25519 per session
  for true forward secrecy. PSK becomes a pairing token for identity verification,
  not the session encryption key. Monocypher provides crypto_x25519 and
  crypto_x25519_public_key.
  Reference: DECISIONS.md D-07, D-30.

### C-2  Airtime accounting + backpressure (LoRa)
  Firmware tracks LoRa TX airtime per 1-hour rolling window.
  When budget < N ms, firmware sends USB_TX_BACKPRESSURE to host.
  Host queues and drops PTY frames accordingly, notifies user.
  Adaptive SF selection (SF9 at edge of range = fewer frames needed).
  Reference: DECISIONS.md D-36.

### C-3  File transfer channels (Ch2/Ch3)
  Binary file push/pull with checksumming and resume.
  Channel-level ACK/retry (NOT session-level retransmit).
  QoS: strict priority Control > PTY > File, rate cap on file channels.
  Reference: DECISIONS.md D-17, D-18.

### C-4  Telemetry channels (Ch4-Ch8)
  App-level stats, RSSI/SNR, duty cycle, transport state — both sides.
  Lightweight TUI overlay on client terminal (status bar).
  Reference: DECISIONS.md D-16.

### C-5  Adaptive coalescing
  Dynamic coalescing window based on link speed:
  ESP-NOW: no coalescing needed (<2ms round trip).
  LoRa: 500ms coalescing window (D-36 baseline).
  Could extend to: backoff when consecutive AEAD failures increase.

### C-6  Multi-hop relay firmware
  One Heltec as relay: receive ESP-NOW from laptop, retransmit over LoRa.
  Session layer unaffected — relay is transparent to transport_ops_t.
  Useful when laptop is indoors with another Heltec at window for LoRa range.
  No protocol changes required; only a new firmware build variant.

### C-7  PAIR_ID derived from PSK (not random)
  PAIR_ID = BLAKE2b(PSK, "urtb-pairid")[:4]
  Ensures PAIR_ID is stable and tied to the PSK, not a random separate value.
  **Implemented.** See DECISIONS.md D-38.

### C-8  hello_key nonce_a replay cache
  Server-side cache of recently-seen (PAIR_ID, nonce_a) pairs.
  Prevents a captured valid CTRL_HELLO from being replayed within same session
  to cause repeated decrypt work on server.
  Low priority: attack requires attacker in radio range, cost is one decrypt op.

### C-9  Compression layer (optional, per-channel)
  Optional LZ4 compression of PTY channel payload before AEAD.
  LoRa 72-byte MTU makes compression attractive for ASCII-heavy terminal output.
  Compression ratio for typical shell output: 2-3×, halves fragment count.
  Tradeoff: adds latency for small frames; only beneficial for LoRa path.
  Must be negotiated in CTRL_HELLO caps field (bit to add).

### C-10  WiFi direct transport
  Direct peer-to-peer WiFi (not via AP) for when ESP-NOW range is insufficient.
  Deferred: requires AP mode negotiation on both devices.

### C-11  Meshtastic interop
  If Meshtastic devices are in range, use them as LoRa relay nodes.
  Requires adapting URTB PAIR_ID routing to Meshtastic mesh addressing.
  Future exploration only — no concrete design yet.

### C-12  Per-pair RF parameters (deferred)
  The capsule loader in `src/capsule.c` dispatches on format version
  (see DECISIONS.md D-40). Future per-pair RF parameters land as a new
  capsule version:

  - ESP-NOW rate (`esp_now_set_peer_rate_config`)
  - ESP-NOW TX power (per region)
  - LoRa frequency / SF / BW override (currently compile-time constants)

  Template: add `load_v3_plaintext()`, bump `CAPSULE_VERSION_CURRENT`,
  add the new version to the pre-AEAD accept-list, add keygen flags,
  and grow `capsule_load()`'s signature with one out-param per new
  field. No new CLI runtime surface, no new dispatch logic.

  Rationale for deferring: channel alone covers the coexistence use
  case (capsule v2 / D-40). The rest should be driven by real failure data.

### C-13  Capsule transport-mode lock (AUTO / ESPNOW_ONLY / LORA_ONLY)
  Add a 1-byte transport-mode field to the capsule plaintext (next
  reserved slot after the v2 channel byte). Three values:
    AUTO          — current behavior, ESP-NOW with LoRa fallback
    ESPNOW_ONLY   — never switch to LoRa; session fails closed on ESP loss
    LORA_ONLY     — skip ESP-NOW probing entirely

  Use cases from field testing:
  - Blind-spot profiling inside a building: ESPNOW_ONLY shows where
    ESP-NOW coverage actually ends, without the link silently
    degrading to LoRa and masking the transition.
  - Long-range stationary setups: LORA_ONLY avoids wasted ESP-NOW
    probe airtime when the distance makes ESP unreachable anyway.

  Enforcement is host-side only in `session.c`'s transport-switch
  logic; firmware continues its dual-probe behavior unchanged. No
  USB_CONFIG wire-format change required. Ships as a `urtb keygen
  --transport-mode {auto,espnow,lora}` flag.

  Deferred pending more field data — see also I-6 for the
  AUTO-mode resync issue that partly motivates this.

### C-14  Client-side escape sequence for clean exit
  The connect-side client forwards Ctrl+C to the remote PTY
  (correct — Ctrl+C should interrupt the remote shell, not the
  local client). This leaves no built-in way to terminate the
  local client cleanly: the operator has to open a second
  terminal and `kill`, or Ctrl+Z then `kill %1`.

  Add a telnet/ssh-style escape sequence that the client
  intercepts in raw-mode stdin before it reaches the PTY. Candidate
  bindings: `~.` on a fresh line (ssh-style), or Ctrl+\ followed
  by `c`. Matching bytes trigger the client's existing signal
  handler — flush ring, emit CTRL_CLOSE, unwind cleanly — without
  forwarding to the remote.

  Must preserve: a bare Ctrl+C continues to reach the remote PTY
  untouched. The escape must be unambiguous enough that normal
  shell traffic cannot trigger it accidentally (fresh-line gate or
  two-key combo).

  Motivated by the KNOWN_ISSUES.md "Session recovery" note — with
  `listen --loop` on the server, the missing piece is a one-hand
  way to kill the client.

---

## Security hardening — jump host scenario

### S-1  Single-use capsule (`--burn`)
  **Implemented.** `--burn` flag for both `listen` and `connect`. After
  capsule_load() succeeds, secure_unlink() overwrites with zeros, fsyncs, and
  unlinks the file. With --loop, PSK lives in mlock'd + MADV_DONTDUMP memory
  across iterations.

### S-2  Single-use OTP key (`--burn` for OTP)
  **Implemented.** When `--burn --otp` are combined, the OTP key is pre-loaded
  into mlock'd + MADV_DONTDUMP memory, then secure_unlink'd. With --loop, the
  shared template carries HOTP counter state in memory across sessions.

### S-3  In-memory key obfuscation (defense in depth)
After loading the PSK into memory, XOR it with a random masking key (generated
from getrandom at startup). Store the mask and the masked PSK separately. Unmask
only when needed for crypto operations, re-mask immediately after.

Purpose: defense in depth against memory disclosure (core dumps,
/proc/pid/mem, cold boot, keyutils). Not a security boundary — an attacker with
arbitrary memory read can find both halves — but raises the bar above "grep for
32-byte keys in a core dump."

Implementation: mlock both the masked key and the mask. On session close or
process exit, crypto_memzero both. Optionally disable core dumps with
setrlimit(RLIMIT_CORE, 0) and prctl(PR_SET_DUMPABLE, 0).

Reference: SECURITY.md "Key material lifecycle", HOWTO_JUMPHOST.md (untrusted jump
host scenario).

---

## Infrastructure / developer experience

### I-1  GitHub Actions CI
  **Implemented.** CI runs via GitHub Actions (`.github/workflows/test.yml`)
  with an ubuntu+macos build matrix and a separate test-asan job on ubuntu.

### I-2  ASAN + leak sanitizer target
  **Implemented.** `make test ASAN=1` builds with `-fsanitize=address,leak`
  (Linux) or `-fsanitize=address,undefined` (macOS). A `make leaks` target
  runs `leaks --atExit` on macOS as leak detection fallback.

### I-3  Fuzz testing
  Fuzz the USB frame decoder and radio frame decoder with libfuzzer or AFL.
  Focus: malformed MAGIC, LEN overflow, CRC collision, zero-length body.

### I-4  Performance benchmarks
  Throughput targets per transport:
    UNIX socket: <2ms round-trip, >10 MB/s
    ESP-NOW: <10ms p50 round-trip
    LoRa: not specified (link-limited)
  Add `make bench` target.

### I-6  Expanded inject coverage for AUTO-mode transport resync
  Observed during mobility testing: pulling USB on one side forces
  that side to LoRa; re-plugging restores ESP-NOW on the recovering
  side, but the peer can remain on LoRa for a noticeable window. The
  resulting transport asymmetry stretches "out of sync" time beyond
  what a single failover would predict.

  Expand `tools/run_inject_acs.sh` (or add a sibling harness) to
  exercise this sequence deterministically using the existing
  inject primitives (`espnow-down` / `espnow-up` on one side while
  the peer stays live), and measure time-to-symmetric-ESP-NOW after
  restore. The same harness is a prerequisite for evaluating C-13
  — locked modes should fail closed quickly, not hang waiting for a
  fallback that will never arrive.

  Reference: HOWTO.md §Use case 3 (existing inject harness).

### I-5  PRIOR_ART.md sanitization
PRIOR_ART.md currently mixes examples that use non-SSH ports (socat+openssl on
port 9443) with URTB's core value proposition (encrypted channel inside a single
fd, no extra ports). This conflates two different use cases:
- URTB: works over any single fd (serial, SSH pipe, UNIX socket) — no IP path
  needed
- socat+openssl: works over TCP — requires open ports and IP path

Sanitize PRIOR_ART.md to clearly separate these. The socat+openssl comparison is
"what you'd use if you have TCP" — not a URTB feature or recommended approach.
URTB's differentiator is that it establishes encrypted channels inside existing
connections without opening new ports or sockets.

Cross-reference: HOWTO_JUMPHOST.md (untrusted jump host), HOWTO.md (core usage).

---

## Post-publish hardware testing

### HW-1  Heltec WiFi LoRa 32 V4
  Status: hardware not yet available (as of 2026-04-15).
  V4 uses ESP32-S3 + SX1262 same as V3; pin assignments may differ.
  When hardware arrives: update PORTING.md board table, add
  `firmware/boards/heltec_v4.h`, update [env:heltec_v4] in platformio.ini.
  Expect minor pin differences only — SX1262 init flags unchanged.

### HW-2  LilyGO T-Beam SX1262
  Popular Meshtastic device. ESP32 + SX1262. No display by default (optional addon).
  Pins documented in PORTING.md worked example but untested on real hardware.
  Verify pin numbers against T-Beam SX1262 schematic, run AC-05 hardware tests.

### HW-3  nRF52840-based boards (T-Echo, RAK4631) — LoRa-only mode
  ESP-NOW not available. LoRa-only mode works at protocol level but needs
  firmware porting: replace esp_now.h with no-op stubs, remove WiFi init,
  test that session starts directly in LoRa mode (transport_active=2).
  Lower priority than ESP32 boards; requires nRF52 PlatformIO toolchain.

---

## Design decisions that were explicitly rejected (document why)

### R-1  TCP transport (rejected)
  Decision: no TCP transport implementation.
  Why: TCP brings MSS/MTU/congestion control assumptions. nc/socat/openssl via
  stdio + --exec covers all TCP/TLS use cases without implementing TCP in C.
  Re-add if: a use case appears that cannot be served by `--exec nc/socat`.

### R-2  Firmware-generated keepalive frames
  Decision: firmware never generates any channel frames.
  Why: firmware has no session keys. Fake keepalives from firmware would be
  unauthenticated — indistinguishable from replay by an attacker.
  Alternative was considered (all-zero key for keepalive) and rejected (D-03).

### R-3  Fragmentation
  Decision: include fragmentation.
  Why: LoRa SF7/BW125 max plaintext 72 bytes. A single `ls -la` line is 133 bytes.
  Without fragmentation, Ch1 PTY is unusable over LoRa fallback.

### R-4  Collapse KEY_DERIVING into HANDSHAKING (3-state machine)
  Decision: keep 5 states (IDLE, CONNECTING, KEY_DERIVING, ESTABLISHED, CLOSING).
  Why: KEY_DERIVING is observable and necessary — it is the state where server has
  received CTRL_HELLO but not yet confirmed CTRL_READY. Merging loses this
  distinction and makes the server-side retransmit timeout ambiguous.

### R-5  Per-channel replay windows
  Decision: per-direction replay window only.
  Why: Ch0 and Ch1 TYPE fields are authenticated in AD — a Ch1 frame cannot be
  replayed as a Ch0 frame. Per-channel windows are an optimization for when
  file channels (Ch2/Ch3) with independent SEQ spaces are added.
