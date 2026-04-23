# URTB — Protocol Specification
# All field sizes, enums, state machines, and wire formats defined here.

---

## Frame types

Two frame formats exist:
  1. USB frame     host ↔ firmware (over USB serial)
  2. Radio frame   firmware ↔ firmware (over ESP-NOW or LoRa)

These are distinct. The USB frame wraps what the firmware needs to transmit/receive.
The radio frame is what goes over the air.

---

## 1. USB frame (host ↔ firmware)

Byte layout (all multi-byte fields: little-endian):

  +--------+------+------+------+--------+-------------------+-------+
  | MAGIC  | VER  | TYPE | FLAGS| LEN    | BODY              | CRC16 |
  | 2 bytes| 1 B  | 1 B  | 1 B  | 2 bytes| 0–510 bytes       | 2 B   |
  +--------+------+------+------+--------+-------------------+-------+

  Total overhead: 9 bytes
  Max body: 510 bytes (leaves room for radio frame overhead in body)
  Max total USB frame: 519 bytes

Field definitions:

  MAGIC     0xAB 0xCD  (2 bytes, fixed)
  VER       0x01       (protocol version, 1 byte)
  TYPE      see USB frame type enum below
  FLAGS     bits 0-7 reserved, set to 0. Fragmentation state is carried exclusively
            in the radio frame's CHAN byte (AEAD-authenticated) — do not use USB FLAGS
            for fragmentation.
  LEN       body length in bytes (uint16_t, little-endian)
  BODY      payload bytes (varies by TYPE)
  CRC16     CRC-16/CCITT-FALSE over bytes [MAGIC..BODY inclusive], little-endian

USB frame types (TYPE field):

  0x01  USB_DATA_TX     host → firmware: radio frame to transmit
  0x02  USB_DATA_RX     firmware → host: received radio frame
  0x03  USB_STATUS_REQ  host → firmware: request device status
  0x04  USB_STATUS_RSP  firmware → host: device status response
  0x05  USB_HELLO       host → firmware: initial handshake on connect
  0x06  USB_HELLO_ACK   firmware → host: handshake reply with device info
  0x07  USB_CONFIG      host → firmware: set operating parameters
  0x08  USB_CONFIG_ACK  firmware → host: config acknowledged
  0x09  USB_ERROR       either direction: error notification
  0x0A  USB_RESET       host → firmware: soft reset request
  0x0B  USB_TEST_INJECT host ↔ firmware: programmable RF failure injection
                          (TEST BUILDS ONLY — see "Test-only frames" below)
  0x0C–0xFF  Reserved

USB_DATA_TX body (variable, 28–250 bytes):

  uint8_t  frame[LEN];    // complete radio frame bytes (header + ciphertext)
                          // exact byte count in LEN field; no padding
                          // min 28 = 12-byte radio header + 16-byte AEAD tag (empty plaintext)
                          // max 250 = ESP-NOW MTU; LoRa frames are smaller in practice
                          // firmware MUST reject USB_DATA_TX with LEN < 28

USB_DATA_RX body (variable, 1–250 bytes):

  uint8_t  frame[LEN];    // complete radio frame bytes as received over the air
                          // exact byte count in LEN field; no padding
                          // firmware does NOT strip header — host receives full frame

USB_STATUS_REQ body (empty, LEN=0):

  No body bytes. LEN=0. Firmware replies with USB_STATUS_RSP.

  Unsolicited USB_STATUS_RSP: Firmware MAY emit USB_STATUS_RSP without a preceding
  USB_STATUS_REQ to report a transport-active change (e.g., ESP-NOW→LoRa failover).
  Host MUST accept USB_STATUS_RSP at any time, in any session state
  (CONNECTING, KEY_DERIVING, ESTABLISHED). Receipt of an unsolicited USB_STATUS_RSP
  is not an error and MUST NOT trigger ERR_SESSION. Host processes the updated
  transport_active value and adjusts keepalive timing, PTY coalescing, and MTU cap.

USB_STATUS_RSP body (packed struct, 16 bytes):

  uint8_t  transport_active;  // 0=ESP-NOW, 1=LoRa
  int8_t   espnow_rssi;       // last heard ESP-NOW RSSI (signed dBm, 0=no data)
  int8_t   lora_rssi;         // last heard LoRa RSSI (signed dBm)
  int8_t   lora_snr;          // last heard LoRa SNR (signed, tenths of dB)
  uint16_t espnow_tx_ok;      // ESP-NOW TX success count (rolling)
  uint16_t espnow_tx_fail;    // ESP-NOW TX failure count (rolling)
  uint16_t lora_tx_ok;        // LoRa TX success count (rolling)
  uint16_t lora_tx_fail;      // LoRa TX failure count (rolling)
  uint16_t espnow_ring_drop;  // ESP-NOW TX ring overflow count (rolling, since boot)
  uint8_t  reserved[2];       // set to 0 (pads struct to 16 bytes)

USB_HELLO body (2 bytes):

  uint8_t  version;       // host protocol version = 0x01
  uint8_t  reserved;      // set to 0

USB_HELLO_ACK body (fixed 32 bytes):

  uint8_t  fw_major;          // firmware major version
  uint8_t  fw_minor;          // firmware minor version
  uint8_t  fw_patch;          // firmware patch version
  uint8_t  caps;              // capability flags (bit 0=ESP-NOW, bit 1=LoRa)
  uint8_t  pair_id[4];        // last configured PAIR_ID from flash; 0x00000000 if unconfigured (fresh device)
  uint8_t  reserved[24];      // set to 0, reserved for future use

USB_CONFIG body (20 bytes):

  uint8_t  pair_id[4];        // PAIR_ID to configure
  uint32_t lora_freq;         // LoRa frequency Hz (little-endian)
  uint8_t  lora_sf;           // LoRa spreading factor (7-12)
  uint8_t  lora_bw;           // LoRa bandwidth code (0=7.8k,1=10.4k,2=15.6k,
                              //   3=20.8k,4=31.25k,5=41.7k,6=62.5k,7=125k,
                              //   8=250k,9=500k)
  uint8_t  lora_cr;           // LoRa coding rate (5=4/5,6=4/6,7=4/7,8=4/8)
  uint8_t  lora_txpower;      // LoRa TX power dBm (2-22)
  uint8_t  mac_addr[6];       // ESP-NOW peer MAC address (6 bytes)
  uint8_t  espnow_channel;    // WiFi channel for ESP-NOW (1-13)
  uint8_t  reserved;          // set to 0

The host-side value of `espnow_channel` is read from the capsule.
v1 capsules default to 6; v2 capsules carry the operator's choice
(1..13) from `urtb keygen --espnow-channel N`. See
`references/capsule_format.md` and DECISIONS.md D-40.

USB_CONFIG_ACK body (empty, LEN=0):

  No body bytes. LEN=0. Confirms USB_CONFIG was applied.
  Ordering rule: firmware MUST NOT process USB_DATA_TX frames received before
  USB_CONFIG_ACK has been sent. If USB_DATA_TX arrives before USB_CONFIG is received,
  firmware replies USB_ERROR(ERR_SESSION) and discards the frame.

USB_ERROR body (4 bytes):

  uint16_t  error_code;       // error code (reuse radio error code table, see §4)
  uint16_t  reserved;         // set to 0

USB_RESET body (empty, LEN=0):

  No body bytes. LEN=0. Firmware performs soft reset on receipt.

### Test-only frames (URTB_TEST_INJECT build only)

  These frames exist ONLY in firmware and host binaries built with
  `URTB_TEST_INJECT=1`. Production builds (`make urtb`, the default PlatformIO
  env `heltec_wifi_lora_32_V3`) compile with `URTB_TEST_INJECT=0` and contain
  ZERO inject code or symbols (`nm urtb | grep -ci inject` MUST return 0).
  Production firmware also rejects type 0x0B with `USB_ERROR(ERR_SESSION)` via
  the dispatcher's default unknown-type fallthrough.

  USB_TEST_INJECT body (1 byte): programmable RF failure injection flags

    bit 0: DROP_ESPNOW_TX  — silently drop outgoing ESP-NOW frames
    bit 1: DROP_ESPNOW_RX  — silently drop incoming ESP-NOW frames
    bit 2: DROP_LORA_TX    — silently drop outgoing LoRa frames (with ~50ms pacing)
    bit 3: DROP_LORA_RX    — silently drop incoming LoRa frames
    bit 4: LORA_LOW_POWER  — set SX1262 TX power to +2 dBm (asymmetric link)
    bits 5-7: reserved, MUST be 0 (firmware masks with 0x1F)

  Sticky semantics: each USB_TEST_INJECT request wholesale-replaces the current
  flag byte. The host-side `urtb test-inject --pid <pid> <verb>` subcommand
  composes incremental verbs (`espnow-down` then `lora-down`) on the host using
  per-verb (set_mask, clear_mask) pairs against a cached current-flags value,
  then sends the resulting full byte. The firmware never tracks set/clear masks.

  ACK convention: firmware echoes USB_TEST_INJECT back to host with body =
  1 byte = the now-active flag value (after masking). No dedicated ACK type.

  Failover counter implications: when DROP_ESPNOW_TX or DROP_LORA_TX is set,
  the corresponding `*_tx_fail` counter in USB_STATUS_RSP IS incremented for
  parity with real radio failures. Failover from ESP-NOW → LoRa is driven by
  the empty-RX-window detector (see §5), not by the TX-fail counter directly.

---

## 2. Radio frame (over ESP-NOW or LoRa)

This is what the firmware puts on the air. The host app builds this frame,
encrypts the payload, and hands it to the firmware as USB_DATA body.

Byte layout (all multi-byte fields: little-endian):

  +----------+----------+------+------+-------+-------------------+
  | PAIR_ID  | SEQ      | CHAN | TYPE | LEN   | CIPHERTEXT        |
  | 4 bytes  | 4 bytes  | 1 B  | 1 B  | 2 B   | N bytes           |
  +----------+----------+------+------+-------+-------------------+

  Total overhead: 12 bytes
  CIPHERTEXT includes the 16-byte Poly1305 auth tag at the end.
  Minimum ciphertext length: 16 bytes (empty plaintext + tag).

  Max radio frame for ESP-NOW: 250 bytes total → max ciphertext: 238 bytes
                                              → max plaintext: 222 bytes
  Max radio frame for LoRa:    Depends on SF/BW. At SF7/BW125: ~100 bytes
                               practical total → 12 byte header, 16 byte tag
                               → max plaintext: ~72 bytes on LoRa.
                               Fragmentation required for larger payloads (CHAN bit 0).

Field definitions:

  PAIR_ID   4-byte pairing identifier (same on both devices, set during pairing)
            Not secret. Used by firmware as routing tag — discard if mismatch.
  SEQ       Monotonic 32-bit sequence number, per-direction, per-session.
            Each side maintains its own independent SEQ counter (client has one,
            server has one). Both start at 0 at session start.
            Nonce = direction_byte || SEQ || zeros — see Crypto section.
            Wraps to 0 after 0xFFFFFFFF — session must renegotiate before wrap.
  CHAN      bits 7-4: channel ID (4 bits, 0-15) — see D-16 in DECISIONS.md
            bits 3-2: reserved (set to 0)
            bit 1:    FIRST_FRAGMENT flag (1 = this is the first or only fragment of a message)
            bit 0:    MORE_FRAGMENTS flag (1 = more fragments follow, 0 = last or only fragment)
            Both flags are part of AEAD additional data (AD = PAIR_ID||SEQ||CHAN||TYPE).
            See §7 for fragmentation rules and all valid flag combinations.
  TYPE      Frame subtype within the channel (see per-channel type enums below)
  LEN       Length of CIPHERTEXT in bytes (uint16_t, little-endian)
  CIPHERTEXT  XChaCha20-Poly1305 ciphertext + 16-byte Poly1305 tag

Radio frame vs ESP-NOW vs LoRa:
  - Frame format is IDENTICAL for both transports.
  - Firmware selects the active transport and reports it via USB_STATUS_RSP.
  - Host app is transport-adaptive: it adjusts keepalive period, PTY coalescing,
    and MTU cap based on transport_active (see §6). The radio frame format itself
    is the same regardless — only host-side pacing and fragmentation thresholds differ.
  - LoRa payloads are smaller → host MUST fragment when plaintext > 72 bytes (see §7).

---

## 3. Crypto: XChaCha20-Poly1305 (Monocypher)

Key derivation:
  session_key = crypto_blake2b_keyed(
    out_len = 32,
    key     = PSK (32 bytes),
    message = "urtb-v1" || nonce_a || nonce_b    // 7 + 16 + 16 = 39 bytes
  )
  Output: 32-byte session_key.

  NOTE: Monocypher does not provide SHA-family HKDF. BLAKE2b keyed-hash provides
  equivalent domain separation using the library already chosen in D-02.

Pre-session key (for CTRL_HELLO / CTRL_HELLO_ACK only):
  hello_key = crypto_blake2b_keyed(
    out_len = 32,
    key     = PSK (32 bytes),
    message = "urtb-hello" (10 bytes)
  )
  CTRL_HELLO and CTRL_HELLO_ACK are encrypted with hello_key (not session_key).
  CTRL_READY is the first frame encrypted with session_key.
  See §4 for full handshake wire format.

  CRITICAL: hello_key is deterministic from PSK alone — two sessions with
  the same PSK produce the same hello_key. To avoid catastrophic
  XChaCha20-Poly1305 nonce reuse across sessions, CTRL_HELLO and
  CTRL_HELLO_ACK do NOT use the (direction || SEQ) nonce derivation.
  Instead, the sender samples a fresh 24-byte hello_nonce per frame and
  ships it in cleartext at the front of the frame body. The receiver
  reads the nonce from the wire and uses it directly as the XChaCha20
  nonce. All other frame types still use the (direction || SEQ) path
  because session_key is already per-session via nonce_a / nonce_b.
  See §4 "Handshake wire format" and DECISIONS.md D-39.

Nonce construction (24 bytes for XChaCha20):
  nonce[0]      = direction byte: 0x00 (client→server) or 0x01 (server→client)
  nonce[1..4]   = SEQ as uint32_t little-endian
  nonce[5..23]  = 0x00  (zero-padded)

  CRITICAL: The direction byte is mandatory. Without it, if both sides independently
  reach the same SEQ value, they would produce identical nonces with the same
  session_key — catastrophic nonce reuse for AEAD (breaks confidentiality and
  allows MAC forgery). The direction byte makes client→server and server→client
  nonces disjoint regardless of SEQ values.
  This fix was identified by comparing with NULINK's odd/even counter approach.
  (Identified during prior NULINK spec comparison.)

Encryption (per radio frame payload):
  (ciphertext, tag) = crypto_aead_lock(
    key       = session_key,
    nonce     = nonce_from_seq(SEQ),
    ad        = PAIR_ID || SEQ || CHAN || TYPE  // 10 bytes, authenticated but not encrypted
    plaintext = payload
  )

  The PAIR_ID, SEQ, CHAN, TYPE fields in the radio header are AUTHENTICATED
  (included in AD) but NOT encrypted. Firmware can read them.
  The payload (PTY data, control messages) is encrypted.

Decryption:
  plaintext = crypto_aead_unlock(
    key       = session_key,    // or hello_key for CTRL_HELLO/CTRL_HELLO_ACK
    nonce     = nonce_from_seq(SEQ),
    ad        = PAIR_ID || SEQ || CHAN || TYPE,
    ciphertext = frame.CIPHERTEXT
  )

Exception for CTRL_HELLO and CTRL_HELLO_ACK (D-39):
  The hello AEAD nonce is NOT derived from (direction, SEQ). Instead, a
  fresh 24-byte XChaCha20 nonce is sampled per send and carried in
  cleartext at the front of the frame body, so:
    nonce      = body[0..23]    // cleartext, integrity-protected by the
                                 // Poly1305 tag because it drives the
                                 // keystream (any tamper changes the
                                 // derived one-time key and the tag fails)
    ciphertext = body[24..]     // plaintext_len + 16-byte tag, AD unchanged
  See §4 "Handshake wire format" and DECISIONS.md D-39 for the rationale.
  All non-hello frames keep the (direction, SEQ) nonce path above.

AEAD failure policy (per frame type):
  CTRL_HELLO (server receiving):
    AEAD failure → discard silently, no response, remain in IDLE.
    Rationale: wrong-PSK or replayed hello should not produce any response
    (prevents amplification / oracle). Server stays ready for a valid CTRL_HELLO.
  CTRL_HELLO_ACK (client receiving):
    AEAD failure → discard silently, remain in CONNECTING, wait for retransmit.
    The client retransmit timer handles liveness; no error response needed.
  CTRL_READY (either side receiving):
    AEAD failure → send CTRL_ERROR(ERR_AUTH_FAIL), return to IDLE immediately.
    Rationale: both sides already derived what they believe is session_key.
    CTRL_READY failure means the keys diverged — this is fatal to the session.
  Data frames (all other types, ESTABLISHED state):
    AEAD failure → drop frame silently, log one line to status output,
    increment consecutive_aead_failures counter.
    AEAD_FAIL_THRESHOLD (10) consecutive AEAD data-frame failures → close session (ERR_AUTH_FAIL).

  Rationale: radio bit flips are expected on LoRa. A single corrupted data frame
  MUST NOT terminate the session — only key-mismatch at CTRL_READY and persistent
  corruption trigger session close.

Replay protection:
  Receiver maintains a sliding window of the last 256 sequence numbers per direction.
  High-water mark (HWM) = highest SEQ accepted so far.
  Accept condition: (SEQ > HWM) OR (SEQ + 256 > HWM AND bitmap[SEQ % 256] == 0)
  Reject condition: SEQ + 256 ≤ HWM (below window) OR bitmap[SEQ % 256] == 1 (seen)
  Use the additive form (SEQ + 256 > HWM) not the subtractive (SEQ > HWM - 256) to
  avoid the fencepost: when HWM=300, subtractive boundary is 44, which incorrectly
  accepts SEQ=44 (on the boundary). Additive form: 44+256=300 > 300 is false → reject.

  HWM initialization: HWM is uninitialized at session start. The first authenticated
  received frame sets HWM to its SEQ and marks bitmap[SEQ % 256] = 1. Subsequent
  frames use the standard accept/reject rule above. All SEQ comparisons use uint32_t
  modular arithmetic: SEQ is considered newer than HWM if (uint32_t)(SEQ - HWM) < 0x80000000.
  This handles wrap-around at 0xFFFFFFFF correctly.

  Bitmap slot recycling on HWM advance:
  When HWM advances from old_hwm to new_hwm (because a SEQ > old_hwm was accepted),
  clear all bitmap slots that correspond to SEQ values now below the new window floor:
    for seq = old_hwm - 255 to new_hwm - 256:
      bitmap[seq % 256] = 0
  In practice: when accepting SEQ N that advances HWM, clear bitmap[(N-256) % 256]
  for each position that slides out. Simple implementation: clear the slot for
  (new_hwm - 256) % 256 on every HWM advance — this is the slot just evicted.
  Window of 256 is sized to cover LoRa fragmentation bursts with headroom.

---

## 4. Channel 0 — Control messages

Control channel carries session lifecycle messages. All control messages are
small (<64 bytes plaintext). Always highest priority.

Control message types (TYPE field in radio frame when CHAN=0):

  0x01  CTRL_HELLO        client → server, session initiation
  0x02  CTRL_HELLO_ACK    server → client, nonce exchange
  0x03  CTRL_READY        either direction, mutual session key confirmation
  0x04  CTRL_CLOSE        either direction, graceful close
  0x05  CTRL_KEEPALIVE    either direction, heartbeat (no body required)
  0x06  CTRL_KEEPALIVE_ACK  reply to keepalive
  0x07  RESERVED          not transmitted over radio; silently drop on radio receive.
                         Transport-change notification is via unsolicited USB_STATUS_RSP
                         (see §1). No CTRL_TRANSPORT frame is ever emitted on the radio.
  0x08  CTRL_ERROR        either direction, error with code
  0x09–0xFF  Reserved

CTRL_HELLO plaintext body (32 bytes — see Handshake wire format below for
on-wire layout):

  uint8_t  version;           // protocol version = 0x02 (was 0x01 prior to D-39)
  uint8_t  caps;              // capability flags (bit 0=PTY, bit 1=file push, etc.)
  uint8_t  nonce_a[16];       // client's random nonce (16 random bytes per session)
  uint8_t  reserved[14];      // set to 0

CTRL_HELLO_ACK plaintext body (32 bytes — see Handshake wire format below
for on-wire layout):

  uint8_t  version;           // server's protocol version = 0x02 (was 0x01 prior to D-39)
  uint8_t  caps;              // server's capabilities
  uint8_t  nonce_b[16];       // server's random nonce (16 random bytes per session)
  uint8_t  reserved[14];      // set to 0

CTRL_READY body: empty plaintext (LEN=0 bytes).

  CTRL_READY is sent by BOTH sides after deriving session_key (mutual confirmation).
  Client sends CTRL_READY immediately after deriving session_key.
  Server sends CTRL_READY immediately after deriving session_key.
  Both sides independently send and independently receive — no ordering requirement.
  The AEAD tag (16 bytes) proves the sender derived the same session_key.
  On AEAD failure: receiver sends CTRL_ERROR(ERR_AUTH_FAIL) and returns to IDLE.
  CTRL_READY is the first frame encrypted under session_key.
  ESTABLISHED is entered when a valid CTRL_READY has been both SENT and RECEIVED.
  All frames after the CTRL_READY exchange use session_key.

Handshake wire format:
  CTRL_HELLO and CTRL_HELLO_ACK use hello_key (not session_key) as the AEAD key.
    hello_key = crypto_blake2b_keyed(key=PSK, message="urtb-hello", out_len=32)
  Both frames still use the standard radio frame format. The CIPHERTEXT field
  of a hello frame carries:

    BODY = hello_nonce[24] || aead_ciphertext[plaintext_len + 16]
      hello_nonce       : 24 random bytes, freshly sampled per send,
                          used directly as the XChaCha20 nonce (cleartext).
      aead_ciphertext   : AEAD output for the 32-byte plaintext body
                          (CTRL_HELLO or CTRL_HELLO_ACK), produced with
                          key=hello_key, nonce=hello_nonce, ad as below.

  AD layout is unchanged: PAIR_ID(4) || SEQ(4) || CHAN(1) || TYPE(1).
  The hello_nonce is NOT included in AD — its integrity is covered by the
  AEAD tag because any modification will derive a different keystream and
  Poly1305 key, causing decryption to fail.

  Hello-frame nonce uniqueness rule (D-39):
    Sender MUST sample hello_nonce from a CSPRNG on every send (including
    retransmits), and MUST NOT cache or reuse it. With a 192-bit random
    nonce the collision probability is negligible across the lifetime of
    any plausible deployment, so each (key=hello_key, nonce=hello_nonce)
    pair is used exactly once globally — preserving Poly1305 one-time-key
    security even though hello_key is deterministic from PSK alone.

  Why not derive the nonce from (direction || SEQ) like data frames?
    Because hello_key is deterministic from PSK alone, while session_key
    is per-session via nonce_a / nonce_b. Two sessions with the same PSK
    would otherwise reuse (key, nonce) pairs at SEQ=0, allowing Poly1305
    one-time-key forgery.

  Only peers with the PSK can produce or verify a valid CTRL_HELLO.
  A CTRL_HELLO that fails AEAD verification → discard, no response, stay in IDLE.

  After CTRL_HELLO_ACK, both sides derive:
    session_key = crypto_blake2b_keyed(key=PSK, message="urtb-v1"||nonce_a||nonce_b)

SEQ wrap renegotiation:
  When a sender's SEQ counter reaches 0xFFFFFFFF - 1000, it MUST send CTRL_CLOSE
  and re-establish a new session with a new CTRL_HELLO (new random nonces).
  No separate CTRL_RENEGOTIATE message — use the normal session lifecycle.

CTRL_ERROR body (4 bytes):

  uint16_t  error_code;       // see error code table below
  uint16_t  reserved;         // set to 0

Error codes:

  0x0001  ERR_AUTH_FAIL       AEAD verification failed
  0x0002  ERR_REPLAY          Sequence number replay detected
  0x0003  ERR_VERSION         Protocol version mismatch
  0x0004  ERR_CAPS            Required capability not available
  0x0005  ERR_SESSION         Session state error
  0x0006  ERR_RESOURCE        Out of resources (memory, fds)
  0x0007  ERR_TIMEOUT         Operation timed out
  0x0008–0xFFFF  Reserved

---

## 5. Channel 1 — PTY messages

PTY channel carries terminal I/O. Raw byte stream, no framing within the channel
beyond the outer radio frame. Multiple radio frames may carry one write.

PTY message types (TYPE field in radio frame when CHAN=1):

  0x01  PTY_OPEN        client → server, request PTY + shell spawn
  0x02  PTY_OPEN_ACK    server → client, PTY spawned OK
  0x03  PTY_OPEN_ERR    server → client, spawn failed
  0x04  PTY_DATA        either direction, raw terminal bytes
  0x05  PTY_RESIZE      client → server, terminal resize event
  0x06  PTY_SIGNAL      client → server, signal to remote shell
  0x07  PTY_CLOSE       either direction, PTY session closed
  0x08  PTY_EOF         server → client, shell process exited

PTY_OPEN body (8 bytes):

  uint16_t  rows;             // initial terminal rows
  uint16_t  cols;             // initial terminal cols
  uint16_t  xpixels;         // pixel width (0 if unknown)
  uint16_t  ypixels;         // pixel height (0 if unknown)

PTY_OPEN_ACK body (4 bytes):

  uint32_t  pid;              // PID of spawned shell (informational)

PTY_OPEN_ERR body (4 bytes):

  uint16_t  error_code;       // ERR_RESOURCE, ERR_CAPS, or ERR_SESSION
  uint16_t  reserved;         // set to 0

PTY_DATA body:

  raw bytes — terminal I/O in both directions
  No additional framing. Client → server is stdin. Server → client is stdout+stderr.
  Max per frame: limited by radio MTU. Multiple frames for larger writes.

PTY_RESIZE body (8 bytes):

  Same layout as PTY_OPEN body.

PTY_SIGNAL body (4 bytes):

  uint8_t   signum;           // POSIX signal number (SIGINT=2, SIGTSTP=20, etc.)
  uint8_t   reserved[3];      // set to 0

PTY_EOF body (4 bytes):

  int32_t   exit_code;        // remote shell exit code (signed)

A sender MAY also emit a zero-length PTY_EOF (len=0) as an early best-effort
signal before the authoritative 4-byte form. This is used by the server when
the shell EOF is detected but `waitpid` has not yet returned the real exit
code: the early zero-length frame lets the peer stop its liveness watchdog
promptly, and the subsequent 4-byte PTY_EOF carries the exit code. Receivers
MUST tolerate len=0 and treat it as exit_code=0 until the 4-byte form arrives.

### 5.1 OTP challenge (optional)

When the listener was started with `--otp PATH`, after sending PTY_OPEN_ACK
the server enters OTP_PENDING state:

1. Server sends `PTY_DATA "OTP: "` (no newline).
2. Connect side displays prompt; user types 6-digit code + Enter.
3. Server accumulates up to 6 printable characters from PTY_DATA until `\n`
   or `\r`. The resulting code must be exactly 6 ASCII decimal digits, or the
   attempt is counted as a failure.
4. Code verified against key file (HOTP lookahead counter..counter+window,
   TOTP ±window × 30 s steps).
5. On success: OTP_DONE, bridge loop starts.
6. On failure: server sends `PTY_DATA "Access denied.\n"`, re-prompts. After
   3 failures: session closed silently (no 3rd "Access denied").

While OTP_PENDING: shell stdout/stderr discarded (not forwarded to client);
PTY_SIGNAL and PTY_RESIZE ignored. If the shell exits before OTP succeeds,
PTY_EOF is sent and the session closes normally.

---

## 6. Heartbeat / keepalive

Keepalive is sent on Control channel (CTRL_KEEPALIVE, TYPE=0x05).
Body is empty (LEN=0, zero bytes of plaintext, encrypted and authenticated with session_key).
The host app is the SOLE source of CTRL_KEEPALIVE frames. Firmware never generates them.

  ESP-NOW path: host sends CTRL_KEEPALIVE every 2s
  LoRa path:    host sends CTRL_KEEPALIVE every 30s (duty cycle constraint)

Keepalive ACK (CTRL_KEEPALIVE_ACK, TYPE=0x06) is sent immediately on receipt.
Round-trip time of keepalive → ACK is the link latency measurement.

Layered liveness model (two distinct watchdogs):
  Firmware liveness (transport-level):
    Firmware counts received radio frames with matching PAIR_ID (PAIR_ID is in the
    plaintext header — firmware can read it without AEAD verification).
    Any PAIR_ID-matching frame resets the firmware's per-transport receive counter.
    3 consecutive 2-second windows with no ESP-NOW frame → firmware switches to LoRa.
    2 consecutive 2-second windows with ESP-NOW frames while on LoRa → switch back.
    Firmware notifies host of transport switch via USB_STATUS_RSP.

    ESP-NOW recovery probes (firmware-originated, below host protocol layer):
      While in LORA_FALLBACK, firmware sends a 4-byte raw ESP-NOW frame every 2s.
      Frame content: PAIR_ID[4] only — no CHAN, no TYPE, no ciphertext.
      Frame length is exactly 4 bytes. Any ESP-NOW frame with matching PAIR_ID[0..3]
      AND length == 4 is a recovery probe — count for failback, do NOT forward to host.
      Length < 12 but ≠ 4: malformed, drop without counting.
      Recovery probes are not authenticated — their sole purpose is to prove
      ESP-NOW radio-layer connectivity so the state machine can trigger failback.
      Both peers send probes during LORA_FALLBACK, so convergence is symmetric.

  Host liveness (session-level):
    Host tracks time since last received authenticated frame (any TYPE on any channel).
    Any frame that passes AEAD verification resets the host liveness timer.
    If no authenticated frame received for 4 × 2s = 8s (ESP-NOW) or 3 × 30s = 90s (LoRa):
    session closes. Counting all authenticated frames (not only CTRL_KEEPALIVE) means
    active PTY sessions remain alive even if isolated keepalives are lost in transit.

    CTRL_KEEPALIVE priority in LoRa mode: when transport_active == LORA_FALLBACK,
    CTRL_KEEPALIVE MUST be sent at its scheduled interval even if it means deferring
    or dropping a queued PTY data frame. LoRa duty-cycle budget does not protect the
    session by itself — only authenticated frame receipt does. PTY data degrading is
    acceptable; session silent-death from missed keepalives is not. Implementation:
    CTRL_KEEPALIVE goes to head of the LoRa TX queue; PTY frames go to tail.

  The two watchdogs are independent: firmware may have failed over to LoRa while the
  host session remains ESTABLISHED (if the first LoRa keepalive arrives in time).
  This is correct behavior — session survives transport failover transparently.

  On any USB_STATUS_RSP reporting a changed transport_active value, the host MUST
  immediately reset: keepalive scheduler interval, PTY coalescing timer, and MTU cap
  to the new transport's values (2s/none/222 for ESP-NOW; 30s/7000ms/72 for LoRa).

PTY write coalescing in LORA_FALLBACK:
  When transport_active == LORA_FALLBACK, the host MUST coalesce PTY_DATA writes:
    - Buffer PTY master reads instead of sending immediately.
    - Flush the buffer as one PTY_DATA frame at most every 7000ms.
    - On transition back to ESPNOW_PRIMARY, flush the buffer immediately.
  Rationale: LoRa duty-cycle budget is ~8.6 frames/minute (see D-36). 7000ms
  coalescing batches multiple keystrokes into single frames, keeping TX count
  near the duty-cycle ceiling. It does NOT guarantee staying within the 8.6 frames/min
  budget during sustained typing — LoRa fallback is designed for low-frequency
  emergency access only, not continuous interactive sessions.
  CTRL_KEEPALIVE is never coalesced — it always bypasses the PTY buffer (see above).
  Implementation: maintain a per-transport coalescing timer; reset on transport switch.
  See D-36 for duty-cycle arithmetic and AC-09 for acceptance criteria.

---

## 7. Fragmentation

When plaintext payload > transport MTU minus overhead, the host app fragments.

Fragmentation flags in the CHAN byte (see §2):
  FIRST_FRAGMENT: bit 1 — set on first (or only) fragment of a message.
  MORE_FRAGMENTS: bit 0 — set on all fragments except the last.
  Both flags are part of AEAD additional data (AD = PAIR_ID||SEQ||CHAN||TYPE):
  authenticated — receiver can trust them were set by the real sender.
  Radio frame overhead remains 12 bytes (no additional header byte needed).

Fragment reassembly:
  Sender rules:
    - Split plaintext into chunks ≤ MTU, assign the next available global SEQ to each.
    - First fragment: FIRST_FRAGMENT=1, MORE_FRAGMENTS=1.
    - Middle fragments: FIRST_FRAGMENT=0, MORE_FRAGMENTS=1.
    - Last fragment: FIRST_FRAGMENT=0, MORE_FRAGMENTS=0.
    - Single-fragment message (fits in one frame): FIRST_FRAGMENT=1, MORE_FRAGMENTS=0.
    - Fragments of the same message share CHAN and TYPE. SEQ values are NOT required to
      be consecutive — frames on other channels may consume SEQ values between fragments.
    - Sender MUST NOT interleave fragments of two messages on the same channel.

  Receiver rules (all 6 valid flag combinations):
    FF=1, MF=1  → first fragment: discard any existing buffer for this CHAN (prior burst's
                   end was lost), open a new reassembly buffer, store this fragment.
    FF=0, MF=1, buffer open   → continuation: append in arrival order.
    FF=0, MF=1, no buffer     → discard (first fragment was lost).
    FF=1, MF=0  → single-fragment message: deliver directly, no buffer needed.
    FF=0, MF=0, buffer open   → final fragment: append, deliver assembled message, close buffer.
    FF=0, MF=0, no buffer     → orphaned terminal fragment: discard.

  Fragment loss behavior:
    A lost first fragment: receiver sees FF=0, MF=1 with no open buffer → discards.
    A lost middle fragment: eventual MF=0 closes a corrupt buffer. Channel handler MUST
      validate reassembled payload length (application-level check).
    A lost terminal fragment: buffer stays open until 5s timeout fires, then discarded.
    A sender that starts a new message on the same channel after a lost terminal: the new
      message's first fragment carries FF=1, which triggers an immediate buffer reset at
      the receiver. No 5s wait required.
  No interleaving (per-channel rule): a sender MUST NOT interleave fragments from
    two different messages on the SAME channel. Frames on OTHER channels may be
    sent at any time — including during an in-progress Ch1 PTY fragment burst.
    CRITICAL: Ch0 Control frames (keepalives, CTRL_CLOSE, etc.) are NEVER blocked
    by Ch1 reassembly. A 7-fragment LoRa burst (~7 × 30s duty cycle windows) must
    not silence Ch0 — the session liveness watchdog would fire and kill the session.
  Reassembly buffer timeout (transport-dependent):
    ESP-NOW: 5 seconds from first fragment. ESP-NOW has no duty cycle; fragments
      can arrive in rapid succession.
    LoRa: 30 seconds from first fragment. LoRa duty-cycle inter-frame gap is ~7s
      (70ms TX / 1% duty cycle); the 30s timeout accommodates a burst of 4 fragments
      with slack, and matches the LoRa keepalive period for easy reasoning.
  Maximum reassembly buffer: 4 KB (prevents runaway MORE_FRAGMENTS=1 attacks).
  Drop entire message if any fragment is lost or timeout expires.

Fragmentation budget:
  ESP-NOW: 250 byte MTU, 12 byte radio header, 16 byte tag = 222 byte max plaintext.
           PTY data chunks should be ≤200 bytes for headroom. Rarely need fragmentation.
  LoRa:    SF7/BW125 practical max ~100 byte total → 12 byte header, 16 byte tag
           → 72 byte max plaintext per fragment. PTY data always fragmented on LoRa.
           Acceptable given LoRa is fallback. Design for up to ~4 fragments per
           coalesced PTY batch (4 × 72 = 288 bytes per batch; fits within the 30s
           reassembly window at one fragment per ~7s duty-cycle gap).

---

## 8. Session state machine

States:
  IDLE          no session
  CONNECTING    client only: sent CTRL_HELLO, awaiting CTRL_HELLO_ACK
                server skips this state — goes directly IDLE → KEY_DERIVING on first CTRL_HELLO
  KEY_DERIVING  both: session_key derived, CTRL_READY sent, awaiting peer's CTRL_READY
  ESTABLISHED   session active, PTY may be open
  CLOSING       graceful close in progress

Client transitions:
  IDLE → CONNECTING:           client calls connect(), sends CTRL_HELLO
  CONNECTING → KEY_DERIVING:   client receives CTRL_HELLO_ACK; derives session_key
  KEY_DERIVING → ESTABLISHED:  client sends CTRL_READY AND receives a valid CTRL_READY
                               from server (both must occur; either may arrive first)
  ESTABLISHED → CLOSING:       CTRL_CLOSE received or sent
  CLOSING → IDLE:              3-second timeout (send CTRL_CLOSE, wait 1s, retry once,
                               wait 2s, retry once, force-close — 3 frames total, see D-33)
  any → IDLE:                  keepalive budget exhausted, ERR_AUTH_FAIL, CTRL_ERROR received

Server transitions:
  IDLE → KEY_DERIVING:         server receives valid CTRL_HELLO; sends CTRL_HELLO_ACK;
                               derives session_key; sends CTRL_READY immediately
  KEY_DERIVING → ESTABLISHED:  server receives valid CTRL_READY from client
                               (AEAD verified with session_key; server already sent its own
                               CTRL_READY immediately upon entering KEY_DERIVING — see above)
  ESTABLISHED → CLOSING:       CTRL_CLOSE received or sent
  CLOSING → IDLE:              3-second timeout (same as client — see D-33)
  any → IDLE:                  keepalive budget exhausted, ERR_AUTH_FAIL, CTRL_ERROR

Timeouts and retransmission (see D-33):
  HELLO → HELLO_ACK:
    Client sends 5 total CTRL_HELLO frames (1 initial + 4 retries).
    Backoff between attempts: 1s, 2s, 4s, 8s. After 5th attempt, wait 16s then IDLE.
    Total: 31s maximum before giving up. TX counter must equal 5 exactly.
    Same nonce_a used for all retries (see D-33).
  KEY_DERIVING → ESTABLISHED:
    Both sides send CTRL_READY on entering KEY_DERIVING (client:
    immediately; server: immediately on ESP-NOW, after a 250 ms LoRa
    half-duplex stagger on LoRa — see below).
    No CTRL_READY retransmit — if the peer's CTRL_READY is lost, the 10s timeout
    fires and both sides return to IDLE for a fresh handshake. This avoids nonce
    reuse (same SEQ under session_key) and the ERR_SESSION collision (retransmit
    arriving after peer reached ESTABLISHED). Simple: send once, wait, or restart.
    Client waits up to 10s to receive server's CTRL_READY. After 10s: IDLE.
    Server waits up to 10s to receive client's CTRL_READY. After 10s: IDLE.

    CTRL_READY stagger (mandatory on BOTH transports): the server MUST delay
    its CTRL_READY by 250 ms after sending CTRL_HELLO_ACK. On LoRa it prevents
    half-duplex collisions. On ESP-NOW, hardware evidence (commit b33899c
    regression + fix in fix/regression-oled) showed that removing the stagger
    causes both CTRL_READY frames to collide and both sides to time out
    symmetrically in KEY_DERIVING. Do not remove or condition the stagger by
    transport.
  CLOSING → IDLE:
    Send CTRL_CLOSE, retry once after 1s, retry once after 2s, then force-close.
    Total: 3s maximum before unilateral close.

C identifier convention: state names in code use a SESSION_ prefix:
  SESSION_IDLE, SESSION_CONNECTING, SESSION_KEY_DERIVING, SESSION_ESTABLISHED, SESSION_CLOSING.
  Wire/doc names drop the prefix (IDLE, CONNECTING, etc.). Both refer to the same states.

Valid inputs per state (frames that do NOT trigger ERR_SESSION):
  IDLE:              CTRL_HELLO (server only — triggers IDLE → KEY_DERIVING transition);
                     client in IDLE generates no valid input (connect is a local event)
  CONNECTING:        CTRL_HELLO_ACK (from server),
                     CTRL_READY (from server — may arrive before CTRL_HELLO_ACK;
                       buffer it and apply when transitioning to KEY_DERIVING)
  KEY_DERIVING:      CTRL_READY (from peer), CTRL_HELLO (see idempotent rule below),
                     CTRL_HELLO_ACK (silently ignore — may be a retransmit from server
                       that arrived after client already transitioned from CONNECTING),
                     CTRL_KEEPALIVE (silently ignore — peer may have already reached
                       ESTABLISHED and begun sending keepalives)
  ESTABLISHED:       CTRL_KEEPALIVE, CTRL_KEEPALIVE_ACK, CTRL_CLOSE,
                     PTY_OPEN (ch1), PTY_OPEN_ACK (ch1), PTY_OPEN_ERR (ch1),
                     PTY_DATA (ch1), PTY_RESIZE (ch1),
                     PTY_SIGNAL (ch1), PTY_EOF (ch1), PTY_CLOSE (ch1),
                     CTRL_READY (silently ignored — see special cases below)
  CLOSING:           CTRL_CLOSE (see special cases below)

Unexpected input policy:
  Any frame not listed as a valid input for the current state → drop frame,
  send CTRL_ERROR(ERR_SESSION), remain in current state.
  Three CTRL_ERROR(ERR_SESSION) events within 10 seconds → send CTRL_CLOSE, return to IDLE.

  Specific rejections:
    CTRL_HELLO received while CONNECTING or ESTABLISHED → ERR_SESSION
    CTRL_HELLO received while KEY_DERIVING → see special cases below (NOT ERR_SESSION in either case:
      matching nonce_a = idempotent re-emit; non-matching nonce_a = abort KEY_DERIVING, return to IDLE)
    CTRL_HELLO_ACK received by server (listener) in any state → ERR_SESSION
    CTRL_HELLO_ACK received while IDLE or ESTABLISHED → ERR_SESSION
    CTRL_READY received after ESTABLISHED → silently ignore (see special cases above)
    PTY_DATA received before PTY_OPEN_ACK → ERR_SESSION
    PTY_OPEN_ERR received (client): log error, do NOT enter raw terminal mode,
      session remains ESTABLISHED (PTY_OPEN can be retried or user closes manually)
    Any CHAN≥2 frame → CTRL_ERROR(ERR_CAPS), drop

  Special cases (idempotent / graceful):
    CTRL_HELLO received while server is in KEY_DERIVING AND nonce_a matches the
      value stored from the first CTRL_HELLO: re-send the stored CTRL_HELLO_ACK,
      stay in KEY_DERIVING. The client's HELLO_ACK was likely lost; the server
      must not re-derive session_key (same nonce_a → same key is correct).
    CTRL_HELLO received while server is in KEY_DERIVING AND nonce_a differs: the
      client started a fresh handshake. Server aborts KEY_DERIVING, returns to IDLE,
      then re-handles this CTRL_HELLO as a new first contact.
    CTRL_READY received while already ESTABLISHED: silently ignore (may be an
      in-flight retransmit or late delivery). AEAD verifies it is authentic;
      do NOT send ERR_SESSION (would tear down a good session).
    CTRL_CLOSE received while already in CLOSING: send CTRL_CLOSE back, go to IDLE
      immediately. Both sides receiving each other's CTRL_CLOSE simultaneously is
      the normal two-way teardown path — do not generate ERR_SESSION.
    CTRL_CLOSE received while in CONNECTING or KEY_DERIVING: abort handshake,
      go to IDLE. No ERR_SESSION — peer has a legitimate reason to cancel.

---

## 9. Transport abstraction interface (C)

  // Per-transport configuration (transport_ops_t.open receives a pointer to this).
  // Fields used depend on the transport type; unused fields are ignored.
  typedef struct transport_config {
    const char *transport;    // "unix", "heltec", "stdio"
    // unix transport:
    const char *path;         // UNIX domain socket path
    // heltec transport (TTY/serial device):
    const char *tty_device;   // OS-assigned device path, e.g. "/dev/cu.usbserial-0001"
                              // discovered via `pio device list` or `ls /dev/cu.*`
    uint32_t    tty_baud;     // baud rate, default 115200
    // stdio transport:
    const char *exec;         // argv[] for execvp() fork (NULL = use process fd 0/1)
  } transport_config_t;
  // TCP, TLS, and other network transports: use stdio + exec field.
  //   nc host 7700                  → plain TCP
  //   openssl s_client -connect ... → TLS
  //   socat STDIO UDP:host:7700     → UDP (useful with netem for drop simulation)
  // exec uses execvp(argv[0], argv) not sh -c, to avoid shell injection and
  // passphrase/path leakage in ps(1) output. Caller splits on spaces or uses
  // a NULL-terminated argv[] array directly.

  typedef struct transport_stats {
    uint32_t  tx_ok;        // host-side accumulator; wider than USB_STATUS_RSP uint16_t (intentional)
    uint32_t  tx_fail;      // host-side accumulator from rolling USB_STATUS_RSP values
    uint32_t  rx_ok;
    uint32_t  rx_drop;
    int16_t   rssi_last;    // dBm, INT16_MIN if unknown; wider than USB_STATUS_RSP int8_t (intentional)
    int8_t    snr_last;     // tenths of dB, INT8_MIN if unknown
    uint8_t   transport_id; // 0=unix, 1=heltec, 2=stdio
  } transport_stats_t;
  // USB_STATUS_RSP counter reconciliation:
  //   USB counters are uint16_t (rolling). Host accumulates into uint32_t.
  //   On each USB_STATUS_RSP: delta = (int32_t)new_val - (int32_t)prev_val.
  //   If delta < 0, a uint16 wrap occurred: add 0x10000 + delta to accumulator.
  //   If delta >= 0, add delta directly.
  //   RSSI: sign-extend int8_t → int16_t on ingest. Wire sentinel 0x00 → INT16_MIN.
  //   RSSI convention: 0 on the wire means "no data" (not 0 dBm); store as INT16_MIN.

  typedef struct transport transport_t;

  typedef struct transport_ops {
    const char *name;
    int  (*open)  (const transport_config_t *cfg, transport_t **out);
    int  (*send)  (transport_t *t, const uint8_t *data, size_t len);
    int  (*recv)  (transport_t *t, uint8_t *buf, size_t max, int timeout_ms);
    void (*close) (transport_t *t);
    int  (*stats) (transport_t *t, transport_stats_t *out);
  } transport_ops_t;

  // Registration (at startup):
  extern const transport_ops_t transport_unix;    // UNIX domain socket
  extern const transport_ops_t transport_heltec;  // TTY/serial device (Heltec, any CP2102)
  extern const transport_ops_t transport_stdio;   // fd 0/1 or forked subprocess (execvp)

  // Selection by name in config or CLI --transport flag:
  // transport = "unix"    → transport_unix    (cfg.path required)
  // transport = "heltec"  → transport_heltec  (cfg.tty_device required)
  // transport = "stdio"   → transport_stdio   (cfg.exec optional; NULL = use fd 0/1)

  // CLI shortcuts:
  //   --exec "cmd"         equivalent to --transport stdio with cfg.exec = "cmd"
  //   --device /dev/...    sets cfg.tty_device; implies --transport heltec

---

## 10. Channel handler interface (C)

  typedef struct session session_t;

  typedef struct channel_ops {
    uint8_t      id;
    const char  *name;
    int  (*on_open)  (session_t *s);
    int  (*on_data)  (session_t *s, const uint8_t *data, size_t len);
    int  (*on_close) (session_t *s);
  } channel_ops_t;

  extern const channel_ops_t channel_control;  // ch 0
  extern const channel_ops_t channel_pty;      // ch 1
  // ch 2-8: registered but ops = NULL (frames rejected with ERR_CAPS)

---

## 11. Wire constants summary

  USB MAGIC:              0xAB 0xCD
  USB MAX FRAME:          519 bytes
  Radio PAIR_ID:          4 bytes, plaintext
  Radio SEQ:              4 bytes, uint32_t, little-endian
  Radio header total:     12 bytes (CHAN bit 0 = MORE_FRAGMENTS, CHAN bit 1 = FIRST_FRAGMENT; no extra byte)
  AEAD tag:               16 bytes (Poly1305)
  AEAD nonce (data frames): 24 bytes (XChaCha20), direction_byte || SEQ || zeros
  AEAD nonce (CTRL_HELLO/CTRL_HELLO_ACK): 24 bytes random per-send,
                          carried cleartext at the front of the frame body
                          (D-39: prevents Poly1305 one-time-key reuse
                          across sessions under the deterministic hello_key)
  Hello protocol version: 0x02 (was 0x01 before D-39 wire format change)
  Session key:            32 bytes (BLAKE2b keyed-hash output)
  Hello key:              32 bytes (BLAKE2b keyed-hash of PSK + "urtb-hello")
  PSK:                    32 bytes (random, generated by urtb keygen)
  nonce_a, nonce_b:       16 bytes each (random, per-session)
  Max plaintext/frame (ESP-NOW):  222 bytes
  Max plaintext/frame (LoRa SF7): 72 bytes
  Replay window:          256 sequence numbers
  Keepalive period (ESP-NOW):  2s
  Keepalive period (LoRa):     30s
  Failover trigger:       3 consecutive 2s windows with no PAIR_ID frame (firmware)
  Failback trigger:       2 consecutive 2s windows with ESP-NOW PAIR_ID frames
  Session key KDF prefix: "urtb-v1" (7 bytes)
  Hello key KDF input:    "urtb-hello" (10 bytes)
  Max reassembly buffer:  4096 bytes
  Reassembly timeout:     5 seconds (ESP-NOW) / 30 seconds (LoRa)
  SEQ wrap threshold:     0xFFFFFFFF - 1000 (trigger renegotiation before wrap)
  AEAD_FAIL_THRESHOLD:    10 consecutive data-frame AEAD failures (named constant)
  CTRL_HELLO max attempts:        5 total (1 initial + 4 retries; inter-retry backoff: 1s, 2s, 4s, 8s; wait 16s after 5th then IDLE → 31s total)
  CTRL_CLOSE max retries:         2 (3 total frames; backoff: 1s, 2s → force-close)
  Host liveness timeout (ESP-NOW): 8s (4 × 2s windows with no authenticated frame)
  Host liveness timeout (LoRa):   90s (3 × 30s windows with no authenticated frame)
