# URTB — System Specification

---

## What URTB is

A terminal link between two laptops using USB-attached Heltec V3 radios.
No shared IP network required. No VPN. Direct encrypted radio side-channel.
Also supports a stdio/pipe transport for use over SSH through untrusted jump hosts.

Primary transport: ESP-NOW (2.4 GHz, same-building range, ~ms latency).
Fallback transport: LoRa (869.875 MHz EU, km range, ~seconds latency).
stdio/pipe transport: fork subprocess (`--exec "ssh ... urtb listen --transport stdio"`)
  for URTB-over-SSH without trusting the SSH session for confidentiality.
Host app: C binary, macOS + Linux, static-linked, no runtime dependencies.
Firmware: PlatformIO C/C++, Heltec V3, RadioLib for LoRa, native ESP-NOW.

---

## What URTB is NOT

- NOT a file transfer tool (see FUTURE.md)
- NOT a mesh network (two nodes, one pair only)
- NOT compatible with Reticulum or RNode protocol (see PRIOR_ART.md)
- NOT a terminal emulator (raw PTY pipe only — user's terminal emulator renders)
- NOT bi-directional session initiation (client initiates, server listens)
- NOT multi-pair (one pairing configuration, two devices)
- NOT WiFi direct (see FUTURE.md)
- NOT a replacement for SSH over an existing network

---

## System components

### Host app (urtb)
Single C binary. Subcommands:
  urtb keygen [--espnow-channel N]
                           generate pairing capsule (PSK + PAIR_ID +
                           ESP-NOW channel 1..13, default 6)
  urtb listen              server mode (accepts PTY sessions from remote)
  urtb connect <dest>      client mode (opens PTY session to remote listener)
  urtb status --device DEV query Heltec V3 over USB (transport / RSSI / SNR / TX counters)

Handles: PTY fork+exec, channel multiplexing, AEAD encryption/decryption,
session key derivation, USB serial framing, transport selection signalling,
heartbeat monitoring, capsule unlock at startup.

### Heltec V3 firmware
PlatformIO, C/C++, single binary flashed via: pio run -t upload
Handles: USB framing, PAIR_ID routing, ESP-NOW TX/RX, LoRa TX/RX,
transport failover state machine (by counting received PAIR_ID frames),
ESP-NOW recovery probe generation (4-byte PAIR_ID-only frame every 2s during fallback).
Does NOT handle: encryption, session logic, PTY, application channels,
keepalive generation (host is sole source of authenticated keepalives).

### Pairing capsule (pairing.capsule)
Binary file, identical on both machines.
Contains: PSK (32 bytes, random), PAIR_ID (4 bytes), encrypted with user passphrase.
Capsule also binds the ESP-NOW Wi-Fi channel for the pair (1..13,
default 6). Selected at keygen time (`--espnow-channel N`). See
DECISIONS.md D-40 and references/capsule_format.md.
Generated once per pair. Transferred out-of-band (scp, gpg+base64, USB stick).

---

## Data flow (send path)

  User types keystroke
    ↓
  Host app PTY master (stdin)
    ↓ channel mux
  Host app: frame(channel=1, seq, data)
    ↓ AEAD encrypt (XChaCha20-Poly1305, session_key,
                    nonce = direction_byte || seq_le32 || zeros(19 bytes))
  Host app: usb_frame(PAIR_ID, seq, ch, type, len, ciphertext)
    ↓ USB serial
  Heltec firmware: check PAIR_ID, check hardware CRC
    ↓ active transport
  Radio TX (ESP-NOW or LoRa)
    ↓ air
  Radio RX (other Heltec)
    ↓ USB serial
  Remote host app: check hardware CRC, AEAD decrypt, verify seq
    ↓ channel demux
  Remote PTY master (write to shell stdin)

---

## Transport states

  ESPNOW_PRIMARY    ESP-NOW carries data. LoRa listen-only (no periodic probe — first
                    LoRa frame after failover establishes the fallback link).
  LORA_FALLBACK     LoRa carries data. Firmware sends ESP-NOW recovery probes every 2s.
                    In LORA_FALLBACK, host coalesces PTY_DATA writes (≤7000ms flush window) — see PROTOCOL.md §5.

Transition ESPNOW_PRIMARY → LORA_FALLBACK:
  3 consecutive 2s windows with no received ESP-NOW frame matching PAIR_ID.

Transition LORA_FALLBACK → ESPNOW_PRIMARY:
  2 consecutive 2s windows with ≥1 received ESP-NOW frame matching PAIR_ID.
  Recovery probes (4-byte PAIR_ID-only, firmware-originated) satisfy this condition.

Both sides run this state machine independently. They converge naturally — each side
detects peer recovery probes and independently triggers failback.
No explicit transport-switch control message — both sides observe received PAIR_ID frames.

---

## Session lifecycle

  1. Client: unlock capsule (user passphrase prompt)
  2. Client: send CTRL_HELLO (encrypted with hello_key = BLAKE2b_keyed(key=PSK, msg="urtb-hello"),
             contains nonce_a — only peers with PSK can decrypt)
  3. Server: reply CTRL_HELLO_ACK (encrypted with hello_key, contains nonce_b)
  4. Both sides: derive session_key = BLAKE2b_keyed(PSK, "urtb-v1"||nonce_a||nonce_b)
  5. Both sides: exchange CTRL_READY (encrypted with session_key, mutual key confirmation)
  6. ESTABLISHED: all subsequent frames encrypted with session_key,
                  nonce = direction_byte(0x00/0x01) || seq_le32 || zeros(19 bytes)
  7. Client: send PTY_OPEN → server forks PTY shell → server replies PTY_OPEN_ACK (or PTY_OPEN_ERR)
  8. Client: on PTY_OPEN_ACK, enter raw terminal mode, pipe stdin/stdout to Ch1
             On PTY_OPEN_ERR: log error, remain in ESTABLISHED (do not enter raw mode)
  9. Session ends: PTY exits, or either side sends CTRL_CLOSE, or liveness budget exhausted

**Second-factor authentication (OTP).** The listener can require a HOTP
(RFC 4226) or TOTP (RFC 6238) one-time code as a second factor. The code is
prompted after the encrypted session is established (post-PTY_OPEN_ACK),
before the shell is accessible. The OTP seed (20-byte HMAC-SHA1 key) is
stored in a mode-0600 file on the listener machine only. OTP does not change
the wire protocol — the prompt and response travel as normal PTY_DATA frames.
Enabled with `urtb listen --otp PATH`. Default algorithm: HOTP with window=20
(counter-based, no time-sync required). TOTP supported for time-synced hosts.

---

## Acceptance criteria

See ACCEPTANCE_CRITERIA.md for full testable criteria.

Functional minimums:
  [ ] urtb keygen produces a capsule file, prompts for passphrase
  [ ] urtb listen + urtb connect establish a PTY session over UNIX socket
  [ ] PTY session: keystrokes reach remote shell, output returns correctly
  [ ] VT100 programs (top, vim, htop) render correctly in the PTY session
  [ ] Session terminates cleanly when shell exits or connection drops
  [ ] Same flow works over USB-Heltec transport (ESP-NOW path)
  [ ] Transport failover: block ESP-NOW on both devices → session recovers on LoRa
  [ ] Replay packet is rejected (old seq_no)
  [ ] Wrong PSK: connection fails, no session established
  [ ] Keepalive liveness: session closes after 3× missed keepalives (see PROTOCOL.md §6, AC-06)

---

## Out of scope, explicitly

  File transfer (Ch2, Ch3)         Future
  Telemetry channels (Ch4-Ch8)     Future
  QoS / channel scheduling         Future
  Status bar / TUI overlay         Future
  WiFi direct transport            Deferred
  Multi-pair support               Not planned for v1
  Reticulum protocol compatibility Not planned
  Bi-directional session init      Not planned for v1
