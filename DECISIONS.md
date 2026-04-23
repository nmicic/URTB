# URTB — Design Decisions
# This document records the design decisions made during URTB development,
# including rationale and rejected alternatives.

---

## D-01  Language: C

Decision: Host app is C (C11, POSIX). Single binary, static-linked, runs on macOS and Linux.
No Python. No Go. No runtime dependencies.

Why: Single binary = zero install friction. Static link = deploy by copying one file.
C is appropriate for the low-level PTY, poll loop, and binary framing work.

How to apply: All host-side code is C11. Build with -static where platform allows.
macOS static link is partial (system libs always dynamic) — acceptable.
Linux fully static (musl or glibc static) is the target for deployment builds.

---

## D-02  Crypto library: Monocypher

Decision: Use Monocypher (single-file header, ~1800 lines, no external dependency).
Do NOT use libsodium for the host app or firmware.

Why: Monocypher is a single .c + .h file — drop into any project, no install.
Works identically on host (macOS/Linux) and firmware (ESP32 via PlatformIO).
Provides XChaCha20-Poly1305 (IETF) and X25519 — everything needed.
libsodium requires install and links dynamically by default.

How to apply: Vendor monocypher.c + monocypher.h into the repo. No package manager.
libsodium is NOT used.

---

## D-03  Encryption split: host encrypts, firmware is a blind modem

Decision: ALL encryption and decryption happens in the host app.
Firmware never sees plaintext payload. Firmware transmits ciphertext opaquely.

Why: Eliminates crypto library from firmware entirely. Firmware complexity drops
significantly. Key material never touches firmware. Simpler security audit surface.
The radio link carries only ciphertext — consistent with "radio always intercepted" threat model.

How to apply:
  SEND: host app → AEAD encrypt payload → USB to Heltec → radio TX (ciphertext)
  RECV: radio RX → Heltec → USB to host → host AEAD decrypt → plaintext

Firmware validates only: PAIR_ID match, hardware CRC (SX1262 built-in).
Firmware has no session key, no PSK, no HMAC — zero crypto.

---

## D-04  Per-packet authentication: AEAD tag carried in payload

Decision: Each encrypted payload includes the Poly1305 auth tag (16 bytes).
Firmware does NOT verify the auth tag — it forwards the full ciphertext+tag to host.
Host verifies the AEAD tag as part of decryption. Failed decryption = drop packet.

Why: Consistent with D-03 (firmware is blind). The tag is inside the encrypted blob,
not a separate MAC the firmware would need a key to verify.

Note: Firmware PAIR_ID check (D-12) prevents processing packets from wrong pairs
without needing cryptographic keys on the firmware.

---

## D-05  PSK storage: password-encrypted capsule (KCAP1-style)

Decision: The pre-shared key (PSK, 32 random bytes) is NEVER stored in plaintext.
At rest: PSK is wrapped in a password-encrypted capsule file (XChaCha20-Poly1305,
KDF from user passphrase). User must type passphrase at startup to unlock.
PSK is held in locked memory (mlock) during session, zeroed on exit.

Why: Protects PSK if the laptop is stolen or disk is imaged.
Minimal binary-header pattern — version, salt, AEAD params, ciphertext.

How to apply:
  urtb keygen              → generates PSK, creates pairing.capsule (prompts passphrase)
  urtb listen              → prompts passphrase, unlocks capsule, derives session key
  urtb connect <host>      → same
  PSK never appears in config file, logs, or env vars in plaintext.

---

## D-06  Pairing procedure: out-of-band capsule transfer

Decision: Pairing is manual and out-of-band. No in-band discovery.
One side runs `urtb keygen`, producing a pairing.capsule file.
That file is transferred to the other machine via gpg+base64, scp, USB stick, etc.
Both sides must have the same capsule file.

Why: In-band pairing (broadcast discovery) leaks PAIR_ID on air.
Manual pairing is simple, explicit, and requires physical access at least once.
This is equivalent to SSH host key acceptance — deliberate, not automatic.

---

## D-07  Session key: derived from PSK + nonces via BLAKE2b keyed-hash

Decision: Session key derivation uses Monocypher's BLAKE2b keyed-hash:

  session_key = crypto_blake2b_keyed(
    out_len = 32,
    key     = PSK (32 bytes),
    message = "urtb-v1" || nonce_a || nonce_b    // 7 + 16 + 16 = 39 bytes
  )

nonce_a and nonce_b are 16-byte random values exchanged in the handshake (CTRL_HELLO / CTRL_HELLO_ACK).
PSK never appears on the wire. Session key is fresh per session.

NOTE: Originally specified as HKDF-SHA512/256, which Monocypher does not provide.
BLAKE2b keyed-hash provides equivalent domain separation and key derivation
properties using the library already decided in D-02. No external dependency added.

Security property: per-session fresh key. This is NOT Perfect Forward Secrecy.
If the PSK is compromised AND the handshake nonces were captured from the wire
(nonces travel in the encrypted payload of CTRL_HELLO / CTRL_HELLO_ACK, protected
by hello_key — an attacker WITH PSK can derive hello_key and decrypt the nonces),
an attacker with PSK can recompute session_key and decrypt any captured session.
PFS is a future goal via X25519 ephemeral exchange (D-30).

Pre-session authentication key (for CTRL_HELLO / CTRL_HELLO_ACK):
  hello_key = crypto_blake2b_keyed(key=PSK, message="urtb-hello", out_len=32)
These handshake frames are encrypted with hello_key so only peers with the PSK
can produce or verify a valid CTRL_HELLO — closes a DoS/amplification vector.

How to apply: Use crypto_blake2b_keyed (Monocypher). Zero PSK from memory
immediately after deriving session_key and hello_key.

---

## D-08  Per-packet nonce: direction byte + sequence number (see D-29)

Decision: XChaCha20 nonce (24 bytes) = direction byte || SEQ || zero-padding.
No separate nonce field in the frame — nonce is implicit from direction + SEQ.

  nonce[0]     = direction byte: 0x00 (client→server) or 0x01 (server→client)
  nonce[1..4]  = SEQ as uint32_t little-endian
  nonce[5..23] = 0x00 (zero-padded)

NOTE: D-29 is the authoritative and superseding decision for nonce construction.
The original D-08 ("SEQ padded to 24 bytes, no direction byte") was found to
cause nonce reuse when both sides reach the same SEQ value simultaneously.
D-29 documents the fix and the reasoning. Read D-29 for full context.

Sequence numbers are 32-bit, per-direction, per-session, monotonically increasing.
Approaching wrap (within 1000 of 0xFFFFFFFF): sender MUST close the session and
re-establish with a new CTRL_HELLO. No separate CTRL_RENEGOTIATE message — use
the normal CTRL_CLOSE → new CTRL_HELLO lifecycle.

---

## D-09  Transport abstraction: generic interface (function pointers)

Decision: All transports implement a common interface:

  typedef struct {
    const char *name;
    int  (*open)(const transport_config_t *cfg, transport_t **out);
    int  (*send)(transport_t *t, const uint8_t *data, size_t len);
    int  (*recv)(transport_t *t, uint8_t *buf, size_t max, int timeout_ms);
    void (*close)(transport_t *t);
    int  (*stats)(transport_t *t, transport_stats_t *out);
  } transport_ops_t;

New transports = new implementation of this interface. No changes to upper layers.

Why: Follows ARCHITECTURAL_PRINCIPLE_GENERIC_PIPELINE pattern from webhook-multi.
Allows testing without hardware. Allows future transports (WiFi direct, TCP, BLE)
without touching channel mux, crypto, or session code.

---

## D-10  Transport implementations

  UNIX socket transport   (same-machine testing, zero hardware)
  stdio/pipe transport    (pipe to fd 0/1, or fork --exec subprocess)
  Heltec transport        (TTY/serial device: /dev/cu.usbserial-*, ttyUSB*)

TCP is NOT implemented as a transport. Any TCP, TLS, or network connectivity is
achieved via stdio + --exec:
  --exec "nc host 7700"                        plain TCP
  --exec "openssl s_client -connect host:443"  TLS
  --exec "socat STDIO UDP:host:7700"           UDP (for netem-based drop simulation)
  --exec "ssh -J jump target urtb listen --transport stdio"   SSH tunnel

Rationale: TCP brings MSS, MTU, congestion control, and OS buffering assumptions
that interfere with our framing. nc/socat/openssl already handle those correctly
at the OS level. The stdio transport gives us all network paths with zero TCP code.
Testing with packet loss: use socat+UDP and Linux netem on the loopback interface
to inject drops/corruption without dealing with TCP retransmit behaviour.

The Heltec transport is simply a TTY fd: open(device_path, O_RDWR) + tcsetattr().
Device path (e.g. /dev/cu.usbserial-0001) is OS-assigned when the USB device connects.
User discovers it with `pio device list` or `ls /dev/cu.*` and sets it in config.
No device enumeration in the host app — just open whatever path the user configured.

---

## D-11  Primary and fallback radio transports

Decision: ESP-NOW is primary. LoRa is fallback.

  Primary:   ESP-NOW (ESP32-S3 WiFi chip, 2.4 GHz, ~100-200m, no duty cycle limit)
  Fallback:  LoRa (SX1262, 869.875 MHz EU, SF7/BW125 default, km range, 1% duty cycle)

These use separate physical hardware on the Heltec V3 (WiFi chip vs SX1262).
They CAN run simultaneously.

---

## D-12  PAIR_ID: routing tag, not a secret

Decision: PAIR_ID is a 4-byte identifier embedded in plaintext in every radio frame header.
It is NOT a secret. It is a routing tag to allow the firmware to discard packets
not addressed to this pair without needing crypto.

PAIR_ID is a random 4-byte value generated by urtb keygen and stored in the capsule.
It is written to both devices via USB_CONFIG during the initial setup sequence.
It is the same on both devices in a pair.
PSK-derived PAIR_ID (e.g., BLAKE2b_keyed(PSK, "urtb-pairid")[:4]) was originally deferred (see FUTURE.md) but is now implemented (see D-38).

Firmware drops any radio packet whose PAIR_ID does not match. No further processing.
Security comes from AEAD encryption (D-04), not PAIR_ID secrecy.

---

## D-13  Transport monitoring: simultaneous, independent hardware

Decision: Both ESP-NOW and LoRa can run simultaneously because they use different
hardware (WiFi chip vs SX1262). Use this:

  ESPNOW_PRIMARY state:
    ESP-NOW: carries all data AND host CTRL_KEEPALIVE frames (every 2s).
    LoRa: listen-only only (no periodic probe — first LoRa frame after failover
          establishes the fallback link without prior warm-up needed).
    Liveness: firmware counts received ESP-NOW frames with matching PAIR_ID.

  LORA_FALLBACK state:
    LoRa: carries all data AND host CTRL_KEEPALIVE frames (every 30s).
    ESP-NOW: firmware sends a raw 4-byte recovery probe (PAIR_ID only) every 2s.
    No user data or encrypted frames on ESP-NOW during fallback.
    Liveness: firmware counts received ESP-NOW recovery probes with matching PAIR_ID.

Data channel: single active transport at a time.
Recovery probes: ESP-NOW only during LORA_FALLBACK, firmware-originated, below the protocol layer (see D-19).
No periodic LoRa probe during ESPNOW_PRIMARY — removes an undefined feature and saves duty-cycle budget.

---

## D-14  Transport failover and failback trigger

Decision: Both sides independently track received frames per transport.

  Failover (ESPNOW_PRIMARY → LORA_FALLBACK):
    3 consecutive 2-second windows with zero received ESP-NOW frames matching PAIR_ID.

  Failback (LORA_FALLBACK → ESPNOW_PRIMARY):
    2 consecutive 2-second windows with ≥1 received ESP-NOW frame matching PAIR_ID.
    These frames may be recovery probes (4 bytes, firmware-to-firmware) or any valid
    data frame if data briefly routes via ESP-NOW.

Both sides run the same state machine. They converge naturally — if ESP-NOW recovers,
both sides receive each other's probes and both independently trigger failback.
Flap avoidance: the 2-consecutive requirement prevents single-probe flapping.

Recovery probe format (firmware-originated, not part of the host protocol):
  4 bytes: PAIR_ID[4] only (no channel, no type, no ciphertext).
  A received frame on ESP-NOW whose first 4 bytes match PAIR_ID AND whose total
  length == 4 bytes exactly is treated as a probe. Length < 12 but ≠ 4 is malformed
  and dropped without counting for failback.
  Firmware counts it for failback, does NOT forward to host (too short to be valid).
  This probe is not a CTRL_KEEPALIVE, not encrypted, not a channel-0 frame.

---

## D-15  Session direction: client initiates only

Decision: Sessions are unidirectional in initiation. Only the client side can start
a session. The server (listener) cannot initiate a connection back.
Once a session is established, data flows in both directions on all channels.

Why: Simpler security model. Server never needs to know the client's address in advance.
Client must actively connect.

---

## D-16  Channel architecture: 4-bit channel ID, 16 channels

Decision: Each frame carries a 4-bit channel ID (16 possible channels).

  Ch  0:  Control          handshake, keepalive, transport status, session lifecycle
  Ch  1:  PTY              terminal I/O, resize signals
  Ch  2:  File push        client → remote file transfer
  Ch  3:  File pull        remote → client file transfer
  Ch  4:  Telemetry-A      app-level stats, client side
  Ch  5:  Telemetry-B      app-level stats, server side
  Ch  6:  Telemetry-Heltec-A  RSSI, SNR, transport, duty cycle
  Ch  7:  Telemetry-Heltec-B  same, other device
  Ch  8:  Debug            raw debug log, either side
  Ch  9-15: Reserved

Channel handler interface:
  typedef struct {
    uint8_t  id;
    const char *name;
    int (*on_data)(session_t *s, const uint8_t *data, size_t len);
    int (*on_open)(session_t *s);
    int (*on_close)(session_t *s);
  } channel_ops_t;

Why: Pluggable channels. Adding file transfer = implementing channel_ops_t for Ch2/Ch3.
No changes to framing, transport, or crypto.

---

## D-17  Current scope: Control + PTY only

Decision: URTB currently implements ONLY channels 0 (Control) and 1 (PTY).
All other channels are reserved in the protocol but not implemented.
File transfer, telemetry, and debug channels are future work.

---

## D-18  QoS: deferred to future work

Decision: URTB currently has no QoS. Control and PTY are the only active channels.
A future version must implement priority scheduling when file channels are added
(to prevent file transfer starving the PTY and Control channels).

Future QoS model (to be specced): strict priority Control > PTY > File,
with rate cap on file channels.

---

## D-19  Firmware role: dumb radio modem

Decision: Heltec V3 firmware is a radio modem only. Responsibilities:

  DOES:     USB framing (frame → radio, radio → frame)
            PAIR_ID check (drop wrong-pair packets)
            ESP-NOW TX/RX (WiFi chip)
            LoRa TX/RX (SX1262 via RadioLib)
            Transport failover state machine (D-14), based on received-frame count
            Hardware CRC (SX1262 built-in, free)
            Notify host of transport changes via USB_STATUS_RSP
            ESP-NOW recovery probe generation while in LORA_FALLBACK state:
              4-byte frame (PAIR_ID only, no channel/type/ciphertext), sent every 2s.
              Purpose: allow peer firmware to detect ESP-NOW link recovery.
              These probes are NOT channel frames; they are NOT forwarded to host.

  DOES NOT: Decrypt or encrypt anything
            Parse channel content (including CHAN byte or TYPE — opaque blobs)
            Generate keepalive, control, or any channel frame (channel data is host-only)
            Verify AEAD tags (no keys — firmware forwards ciphertext blindly)
            Manage PTY or sessions
            Any application logic

Liveness model: firmware detects transport health by counting received radio frames
with matching PAIR_ID. PAIR_ID is in the plaintext radio header (bytes 0-3) — firmware
CAN read it without crypto. Any PAIR_ID-matching received frame (including 4-byte
recovery probes) resets the failover counter for that transport. The host app generates
all authenticated CTRL_KEEPALIVE frames; firmware simply forwards them over radio and
counts their arrival at the peer.

---

## D-20  Firmware crypto: none

Decision: No crypto library on firmware. No monocypher, no libsodium, no mbedTLS.
Firmware has no keys, no session state, no HMAC. Hardware CRC only.
See D-03.

---

## D-21  LoRa frequency: 869.875 MHz, modem settings

Decision: 869.875 MHz (EU g4 sub-band, 869.7-870.0 MHz, 1% duty cycle).
Avoids Meshtastic EU default (869.525 MHz) by 350 kHz.
Modem: SF7, BW125kHz, CR4/5, txpower 7 dBm (configurable).
Both devices must match. Validated in early-stage testing.

---

## D-22  Reticulum: evaluated, not used

Decision: Reticulum (rnsh, rnx, rnsd) is a validated reference implementation
tested during early development. It is NOT used in URTB firmware or host app.
URTB uses a fully custom protocol. No RNode protocol compatibility required.

Why: Reticulum requires Python host. Reticulum's rnsd must exclusively own the USB
serial port — incompatible with our host app owning the port. Clean break.

---

## D-23  Host app binary: single binary, dual mode

Decision: One compiled binary handles both roles:
  urtb listen [options]     → server (listener) mode
  urtb connect <dest>       → client mode
  urtb keygen               → generate pairing capsule

No separate client and server binaries. Mode set by subcommand.

---

## D-24  No VT100 parsing in host app

Decision: Host app does NOT parse or interpret VT100/ANSI escape sequences.
PTY channel is a raw byte pipe: stdin → encrypt → radio → decrypt → remote PTY master.
The user's terminal emulator handles rendering.

Why: Parsing VT100 adds ~2000 lines and is unnecessary. The user's terminal does it.
Status/telemetry information is written to a separate file or stderr, not injected
into the PTY byte stream.

---

## D-25  PTY implementation: fork + openpty pattern

Decision: Use the classic `fork + openpty + poll` pattern, implemented
fresh for URTB. Do not implement VT100 renderer, TUI, or multiplexer screen.
URTB does not replicate tmux/screen functionality. Users run tmux/screen inside the PTY.

---

## D-26  File transfer: channels reserved, predefined folders

Decision: File transfer uses channels 2 (push) and 3 (pull) — reserved but not yet implemented.
Files land in configurable but restricted folders (default: ~/urtb-incoming, ~/urtb-outgoing).
No path traversal. No symlink escape. One file at a time per direction.
No in-band zmodem/uuencode — file transfer is separate channel, not embedded in PTY.

---

## D-27  Status / telemetry output: stderr or status file, not PTY injection

Decision: App-level status (transport switch events, packet loss, connection state)
is written to stderr OR a configurable status file path.
NOT injected as escape sequences into the PTY byte stream.

Future: dedicated telemetry channels (Ch 4-7) carry structured telemetry.
A future companion tool can display live telemetry alongside the terminal session.

---

## D-28  Compression: none currently

Decision: No compression currently. Raw payload bytes only.
A future version may add compression for file transfer channels (not PTY — PTY is mostly
already incompressible VT100 escape sequences and small amounts of text).

---

## D-29  Nonce construction: direction byte required (BUG FIX from NULINK comparison)

Decision: AEAD nonces MUST include a direction byte to prevent nonce reuse.

  nonce[0]    = 0x00 (client→server) or 0x01 (server→client)
  nonce[1..4] = SEQ as uint32_t little-endian
  nonce[5..23] = 0x00 (zero-padded)

Each side maintains its OWN independent SEQ counter. Both start at 0.
The direction byte guarantees nonces are disjoint between the two directions
even when both SEQ counters happen to have the same value.

Why: Without the direction byte, if both sides reach SEQ=N simultaneously,
they use the same nonce with the same session_key — catastrophic AEAD nonce
reuse. Identified during prior NULINK spec comparison.

---

## D-30  X25519 key exchange: future upgrade path

Decision: URTB currently uses PSK (D-07). A future version will add X25519 per-session key exchange
to achieve true forward secrecy even if PSK + captured nonces are later compromised.

Future crypto model (Noise_XX-like):
  - Each device has a long-term X25519 identity keypair (generated at setup)
  - Public keys exchanged during pairing (replaces or augments PSK)
  - Per-session: ephemeral X25519 exchange → shared secret → session key
  - Long-term keys used for mutual authentication only

Why deferred: adds handshake complexity and key management. The current PSK approach
provides per-session fresh keys but NOT Perfect Forward Secrecy (see D-07 note).
X25519 is the right addition once the complexity of ephemeral key exchange is warranted.

---

## D-31  Reliability: application-level only, no frame-level ACK/retry

Decision: The session layer does not implement per-frame ACK or retry.
Firmware does not retry failed radio TX.
Application channels handle their own reliability requirements if needed.

Why: PTY is inherently loss-tolerant (a missed keystroke is just retried by the user).
LoRa is lossy — adding frame-level retry would add latency and complexity.
The AEAD will detect corrupted frames and drop them. The PTY session degrades
gracefully under loss rather than stalling waiting for ACKs.

File transfer (future work) will implement its own ACK/retry at the channel level.

---

## D-32  Wire interoperability with NULINK

Decision: URTB does not currently prioritize wire compatibility with NULINK.
Both specs share the same architecture and XChaCha20-Poly1305 crypto.
Wire compatibility (same MAGIC, same key exchange, same channel mapping)
is a future consideration — worth designing for, not worth constraining the current implementation.

If MAGIC bytes are ever standardized, use: 0x4E 0x55 "NU" (combining both projects).
This is a placeholder — not binding yet.

---

## D-33  Retransmission policy: session establishment only

Decision: Retransmission with exponential backoff is applied ONLY to session
establishment control messages, not to data frames.

Scope:
  CTRL_HELLO (session start):
    Client sends 5 total CTRL_HELLO frames: 1 initial + 4 retries.
    Inter-retry backoff: 1s, 2s, 4s, 8s. After the 5th attempt, wait 16s then IDLE.
    Total wait: 1+2+4+8+16 = 31s. TX counter == 5 (not 6).
    SAME nonce_a used for all retries within one handshake attempt. This allows
    the server to detect a duplicate CTRL_HELLO (nonce_a matches stored value) and
    re-send its stored CTRL_HELLO_ACK without re-deriving session_key.
    New random nonce_a only when starting a completely fresh handshake (after IDLE).

  CTRL_CLOSE (session teardown):
    Send CTRL_CLOSE, retry once after 1s, retry once after 2s, then force-close to IDLE.
    Total: 2 retries, 3 CTRL_CLOSE frames sent, 3s maximum before unilateral close.

  PTY data frames (CHAN=1), CTRL_KEEPALIVE: NO retransmission.
    - PTY is a stream — a retransmitted frame arriving after later frames have been
      processed would corrupt terminal state (VT100 sequences are position-sensitive).
    - Keepalive loss is handled by the liveness model (§6), not retransmission.
    - Application degrades gracefully under loss (user sees garbled chars, retypes).

  File transfer (future work): channel-level ACK/retry at the file channel layer.
    Not specified here — future concern.

Why: D-31 remains correct for data channels. Session establishment is a different
category — a single lost CTRL_HELLO permanently blocks connection without retry.
Exponential backoff follows standard practice; 31s total is long enough to survive
a temporary LoRa channel collision or ESP-NOW congestion burst.

The backoff sequence (powers of 2) is the right shape:
  - 1s handles transient firmware processing delay
  - Up to 16s covers a LoRa duty-cycle back-pressure window
  - Stopping at 16s keeps connection attempt perceptible (user knows within 31s)
  - 128s+ backoff is appropriate for persistent reconnect loops (not implemented
    currently — user sees failure and manually retries)

---

## D-34  Multi-device support: one process per Heltec, TTY device in config

Decision: When multiple Heltec V3 devices are connected to the same laptop, each
is served by a separate urtb process. Each process owns one TTY device path and
one pairing capsule. There is no shared-device multiplexing within a single process.

CLI:
  urtb listen  --device /dev/cu.usbserial-0001 --capsule ~/pair-server-a.capsule
  urtb listen  --device /dev/cu.usbserial-4     --capsule ~/pair-server-b.capsule

The `--device` flag (or config file key `tty_device`) selects which serial port the
heltec transport opens. Default: none (must be specified when transport = "heltec").
The `--capsule` flag selects which PSK/PAIR_ID to use for that instance.

Rationale for one-process-per-device:
  - Clean process isolation: crash in one instance does not affect the other.
  - Each process has its own mlock'd PSK — no sharing of key material between sessions.
  - Simple: no internal dispatch table, no per-device thread coordination.
  - Consistent with the single-session model (each urtb binary is one P2P link).

Future: if managing many devices, a lightweight supervisor process
could launch/monitor urtb instances and route status to a shared dashboard.
Not needed for the two-laptop personal use case.

---

## D-35  Stdio/pipe transport: URTB tunnel over SSH (and similar)

Decision: Add a `stdio` transport implementation that reads/writes on two file
descriptors (default: stdin=0, stdout=1, or pipes to a forked subprocess).

This enables URTB's crypto layer to run over any bidirectional byte stream,
including SSH sessions, netcat pipes, socat relays, etc.

CLI variants:

  # Server side (on remote machine):
  urtb listen --transport stdio

  # Client: connect over plain stdin/stdout (pipe manually):
  urtb connect --transport stdio

  # Client: fork a command and use its stdin/stdout as transport (--exec):
  urtb connect --exec "ssh user@remotehost urtb listen --transport stdio"

The `--exec "cmd"` flag:
  1. Split cmd on spaces into argv[], fork(), execvp(argv[0], argv).
     No shell involved — avoids shell injection and ps(1) passphrase leakage.
  2. Connect child's stdin/stdout to urtb's transport read/write fds via pipes.
  3. urtb treats those pipe fds as the transport channel.
  This is equivalent to ProxyCommand in SSH — a well-established pattern.

Primary use case — untrusted jump host:
  You need to reach a target through a jump host you do not trust.
  You cannot use SSH tunneling or mosh from the jump host.
  The jump host can intercept the SSH session (it terminates TLS/SSH there).

  Solution:
    urtb connect --exec "ssh -J jumphost target urtb listen --transport stdio"

  What the jump host sees: a sequence of URTB ciphertext bytes on the SSH pipe.
  It cannot decrypt them (no PSK). It cannot inject valid frames (no session_key).
  End-to-end encryption is preserved across both SSH hops.

  Alternative for nested SSH (jump host IS the first hop):
    urtb connect --exec "ssh jumphost ssh target urtb listen --transport stdio"
    Note: no shell quoting — execvp splits on spaces; the inner ssh args are positional.

  The `--exec` flag creates a full bidirectional pipe to the child process
  (two unidirectional pipes, one per direction) — not a Unix pipeline, which
  is unidirectional and would not work here.

Security note:
  The stdio transport carries the same URTB frame format as all other transports.
  AEAD encryption and the handshake (CTRL_HELLO with hello_key) apply identically.
  The SSH session provides transport-level confidentiality as an additional layer,
  but URTB's crypto does not depend on or trust SSH — the security model is the same
  as operating over a plaintext pipe with a hostile observer.

Scope:
  Currently: stdio transport + --exec flag implemented.
  The `--pipe` syntax (where a magic START sequence triggers the remote side
  automatically) is NOT implemented. Remote side must explicitly run
  `urtb listen --transport stdio`. This is intentional: requiring an explicit
  command on the remote side is simpler and clearer than an implicit trigger.

  execvp model: argv[] is split on spaces; execvp(argv[0], argv) is called directly.
  No shell. Limitation: no shell metacharacters (no pipes, no quoting, no expansion).
  For complex pipelines, wrap in a script file.

---

## D-36  LoRa duty cycle: degraded fallback, not interactive

Decision: LoRa fallback is a degraded mode. Interactive PTY is not guaranteed.

EU 868 MHz SRD band: 1% duty cycle hard limit (~36s/hour TX budget).
At SF7/BW125, max frame = 72-byte plaintext + 28-byte overhead = 100 bytes → ~70ms TX time.
Budget: 36s/hour ÷ 70ms = ~514 frames/hour = ~8.6 frames/minute.
A human typing at 5 keystrokes/second would exhaust the budget in ~2 minutes.

Current policy:
  Host MUST coalesce PTY writes into ≥7000ms batches when transport == LORA_FALLBACK.
  Coalescing batches multiple keystrokes into single frames, significantly reducing
  LoRa TX count vs. per-keystroke sending. With this window a sustained typer emits
  ~8.6 frames/minute, which is exactly the duty-cycle ceiling — the policy guarantees
  staying within the budget during sustained typing. LoRa fallback is designed for
  low-frequency emergency access only, not continuous interactive sessions.
  No enforcement mechanism beyond coalescing currently. No airtime counter.
  No backpressure frame (USB_TX_BACKPRESSURE) — future work if needed.

This means LoRa fallback supports: slow commands, status checks, emergency fixes.
It does NOT support: vim, top, htop, interactive shell sessions at normal speed.
The session ESTABLISHED state is maintained — the link is alive, just slow.

Future upgrade path: firmware airtime tracking + backpressure notification to host.

---

## D-37  Build-flag-gated RF failure injection (replaces Faraday-cage shielding)

Decision: AC-05-03/04/05, AC-05-08, AC-05-09, AC-09-01 are exercised
via deterministic build-flag-gated RF failure injection rather than
physical RF shielding (cookie-tin / Faraday cage). A separate test
build (`URTB_TEST_INJECT=1`) of both firmware and host adds:

  1. A 1-byte volatile flag word `g_test_inject_flags` in firmware
     accessed with `__atomic_load_n/store_n(..., __ATOMIC_RELAXED)`,
     gating ESP-NOW TX/RX, LoRa TX/RX, and `setOutputPower(2)`.
  2. A new USB frame `0x0B USB_TEST_INJECT` (host → firmware, 1-byte
     body) carrying the wholesale flag set; firmware echoes it back
     as ACK. See PROTOCOL.md §1 "Test-only frames".
  3. A host subcommand `urtb test-inject --pid <pid> <verb>` that
     speaks to the running `urtb-test` process via a 0600 unix
     socket at `/tmp/urtb-inject-<pid>.sock`. Peer-credential check
     (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` + `cr_version` on
     macOS) restricts callers to the same uid. Accepted control
     sockets carry `SO_RCVTIMEO/SO_SNDTIMEO=2s` to defeat same-uid
     blocking-read DoS.
  4. A driver harness `tools/run_inject_acs.sh` running all six ACs
     end-to-end on two real Heltec V3 boards with DTR/RTS hardware
     reset between tests.

Why: A cookie-tin shielding test is non-deterministic, requires a
human present, can't run in CI, and depends on geometry that drifts
between sessions. Build-flag injection is hermetic, repeatable, and
exercises the firmware state machine on real hardware.

Why a separate build (not a runtime flag in prod): zero risk of an
inject path being reached in a shipped binary. The prod env
`heltec_wifi_lora_32_V3` defines `URTB_TEST_INJECT=0`; the test env
`heltec_wifi_lora_32_V3_test` defines `URTB_TEST_INJECT=1`. A
symbol-audit gate in `tools/run_all_tests.sh` requires
`nm urtb | grep -ci inject == 0` in the prod binary and `>0` in the
test binary; CI fails otherwise. Verified: prod 0 syms, test 7 syms.

Why host-IPC (0600 unix socket) rather than a serial-side proxy: the
inject command targets the host process state machine and the
firmware via the same USB transport the session is already using —
multiplexing inject through a side-band proxy would require either
(a) opening the serial device twice (impossible on macOS POSIX) or
(b) inserting a TCP proxy in front of every test, doubling the
attack surface and breaking real-hardware timing. The unix socket
is uid-bounded, deleted on listener exit, and has no network reach.

Real bugs uncovered by this mechanism:

  - **Recovery probe bypass.** `firmware/src/main.cpp:maybe_send_probe()`
    sends the 4-byte PAIR_ID-only recovery heartbeat by calling
    `esp_now_send()` directly, bypassing `radio_tx_active()`. With
    `DROP_ESPNOW_TX` set, the inject correctly stopped data frames
    but the probe leaked through, keeping the peer's
    `g_espnow_rx_in_window` non-zero and preventing failover. Fix:
    add `URTB_TEST_INJECT`-gated check inside `maybe_send_probe()`
    that consults `g_test_inject_flags & TI_DROP_ESPNOW_TX` and
    returns early. Without inject this bug is invisible — the
    drop only matters when the data path is intentionally silenced.
  - **Liveness/failover race.** `src/session.c` initialised the
    mode-1 liveness timeout to 6000 ms (`3 × keepalive`). Firmware
    failover takes `FAILOVER_EMPTY_WINDOWS × WINDOW_MS = 3 × 2000ms
    = 6000 ms` exactly. The two timers raced, and on slow USB IPC
    the host hit liveness before the firmware reported `transport
    mode 2` — connect side closed the session instead of failing
    over. Fix: bump `s->liveness_timeout_ms` to 8000 ms in two
    places (init + `session_set_transport_mode` mode-1 path) so
    window-tick failover always wins. Without inject this race
    only manifests under noisy real-RF conditions and was
    previously masked by the Faraday-cage approach (where the
    operator wraps the board *after* the session is up, giving
    the firmware extra slack).

How to apply: Anyone working on the failover state machine should
re-run `tools/run_inject_acs.sh all` on a two-board bench setup
before touching window_tick, the recovery probe, the host liveness
clocks, or LoRa MTU/coalescing. After tests, reflash both boards
with the prod env (`pio run -e heltec_wifi_lora_32_V3 -t erase &&
pio run -e heltec_wifi_lora_32_V3 -t upload`) to leave the bench in
a clean shippable state. The erase step is required — crossing envs
(`_test` → prod) without erase can leave stale partitions; see
HOWTO.md §Use case 2.

FI-02 (USB cable disconnect) remains needs-user-interactive — there
is no programmatic way to unplug a real USB cable, and the inject
mechanism only models RF failure modes, not host-side I/O failure.

## D-38  PAIR_ID derived from PSK

Decision: PAIR_ID is no longer an independent random 4-byte field
generated by `urtb keygen`. It is derived deterministically from the
PSK at keygen time:

```
pair_id = BLAKE2b_keyed(key=PSK, msg="urtb-pairid")[:4]
```

The capsule wire format is unchanged — `pair_id[4]` still lives at
the same offset inside the encrypted payload, and `capsule_load()`
continues to read whatever PAIR_ID is stored there. Only
`capsule_generate()` changes: it calls the new
`crypto_derive_pair_id(psk, out)` helper in `src/crypto.c` (matching
the house style of `crypto_derive_session_key` and
`crypto_derive_hello_key`).

Reason: the prior random PAIR_ID created an operational footgun
where an operator who retained only the passphrase but lost the
capsule file could not reconstruct a working pairing — regenerating
with the same passphrase produced a fresh random PAIR_ID that
mismatched the firmware. Deriving PAIR_ID from PSK eliminates the
independent-PAIR_ID secret from the recovery story.

Domain separation: BLAKE2b-keyed with disjoint context strings is
already the project's KDF idiom. The three context strings in use —
`"urtb-v1"||nonces` (session key), `"urtb-hello"` (hello key),
`"urtb-pairid"` (this) — are pairwise distinct in both length and
content, so BLAKE2b-keyed PRF independence applies.

Trade-offs accepted:

1. **Two operators picking the same PSK now also collide on
   PAIR_ID.** Previously, identical PSKs would still mismatch on
   PAIR_ID at the firmware pre-AEAD filter
   (`transport_heltec.c` line ~503), surfacing a clear error
   before the session layer. Now they pass the PAIR_ID gate and
   only fail at the AEAD layer. Not a security regression (AEAD
   still catches the mismatch), but one cheap early-reject filter
   is gone. Acceptable because uniformly random 256-bit PSKs
   effectively never collide.

2. **PAIR_ID is broadcast in the clear in every radio frame**
   (`frame.c`: `pair_id[4]` lives in the unencrypted radio
   header). Under the new scheme that 4-byte tag is now
   `BLAKE2b(PSK, "urtb-pairid")[:4]` — PRF output truncated to 32
   bits. Leaks no information about the PSK (PRF, plus an
   Argon2id hop in front of the PSK in the capsule file), but it
   does make PAIR_ID a stable long-term identifier across
   rekeyings that don't change the passphrase. A passive observer
   can use it for traffic correlation. Acceptable for the URTB
   threat model — operators who need traffic-correlation
   resistance should rotate the passphrase, not just the capsule
   file.

3. **Mixed-version deployments fail loudly.** An old (random
   PAIR_ID) capsule paired against firmware flashed via the new
   (derived PAIR_ID) code will mismatch at the USB_HELLO/CONFIG
   handshake. The mismatch surfaces as
   `transport_heltec: PAIR_ID mismatch (fw=…, host=…)` — visible,
   not silent. No migration required: old capsule + old firmware
   still works; regenerating with new code produces a
   self-consistent new pair.

Rejected alternatives:

- *Storing PAIR_ID separately in operator-managed documentation.*
  Fragile, inconsistent with URTB's design principle that the
  passphrase + capsule file are the sole recovery surface.
- *Deriving PAIR_ID from the passphrase directly (skipping the
  PSK).* Would expand the passphrase's blast radius outside
  `derive_capsule_key()` for no real gain — the PSK is already the
  root from which session/hello keys derive, so PAIR_ID joining
  that family is the natural place.

Implementation: `src/crypto.{h,c}` (new `crypto_derive_pair_id`),
`src/capsule.c` (`capsule_generate` calls it instead of
`crypto_random_bytes`), `src/main.c` (keygen prints "PAIR_ID derived
from PSK (no separate backup needed)" annotation).

## D-39  Per-session hello_nonce on CTRL_HELLO/CTRL_HELLO_ACK

Decision: CTRL_HELLO and CTRL_HELLO_ACK no longer derive their
XChaCha20 nonce from `(direction || SEQ)` like data frames. Instead,
the sender samples a fresh 24-byte `hello_nonce` from the CSPRNG on
every send (including retransmits) and ships it in cleartext at the
front of the frame body:

```
BODY = hello_nonce[24] || aead_ciphertext[plaintext_len + 16]
```

The receiver reads `hello_nonce` off the wire and uses it directly as
the XChaCha20 nonce. AD layout is unchanged: `PAIR_ID || SEQ || CHAN
|| TYPE`. The nonce is not in AD because any modification produces a
different keystream + Poly1305 key, which the AEAD tag already
catches. The inner `ctrl_hello.version` / `ctrl_hello_ack.version`
field is bumped from `0x01` to `0x02` to mark the wire change.

Reason — the bug this closes: `hello_key = BLAKE2b_keyed(PSK,
"urtb-hello")` is **deterministic from PSK alone**. With the previous
`(direction || SEQ)` nonce derivation, two sessions established under
the same PSK both produce a CTRL_HELLO with `key=hello_key`,
`nonce=(0x00 || 0 || 0…)` and a CTRL_HELLO_ACK with `key=hello_key`,
`nonce=(0x01 || 0 || 0…)` — i.e. **identical (key, nonce) pairs across
sessions**. XChaCha20-Poly1305 catastrophically fails under
(key, nonce) reuse: an attacker who captures two CTRL_HELLOs from
distinct sessions can recover the Poly1305 one-time key and forge
arbitrary ciphertexts under that one-time key, breaking the integrity
guarantee of the handshake.

This was identified as a hello_key cross-session nonce reuse vulnerability
and resolved here as Option A (per-session 24-byte cleartext nonce).

Why a 24-byte cleartext nonce, not a 32-byte session-keyed scheme:

1. **Cleartext is fine.** XChaCha20 nonces are public inputs; the
   security property is uniqueness, not secrecy. Anyone observing
   the wire already learns the nonce when the receiver decrypts.
2. **24 bytes is the full XChaCha20 nonce width** — no extra
   derivation step, no risk of derivation-function bugs, and the
   collision probability across the lifetime of any plausible
   deployment is `~2^-96` per pair of frames, which is negligible.
3. **Sender-side state requirement is zero.** The sender does not
   need to remember anything between sessions; CSPRNG output is
   independent across calls. Retransmits also resample, so an
   attacker who replays a captured CTRL_HELLO does not get a
   second valid (key, nonce) pair from the legitimate sender.
4. **Receiver-side state requirement is zero.** No per-PSK nonce
   store, no replay window for hello frames (the existing replay
   window only applies to in-session frames anyway).

All other frame types (`CTRL_READY`, `CTRL_KEEPALIVE`, `CTRL_CLOSE`,
`CTRL_ERROR`, PTY data) **keep** the `(direction || SEQ)` nonce path,
because `session_key` is already per-session via `nonce_a` /
`nonce_b` mixing. There is no cross-session (key, nonce) collision
risk for in-session traffic.

Wire-format impact:

- CTRL_HELLO body grows from `48` bytes (`32 pt + 16 tag`) to `72`
  bytes (`24 nonce + 32 pt + 16 tag`). Total radio frame including
  the 12-byte header: `60 → 84` bytes. Well under both the ESP-NOW
  MTU (222) and the LoRa SF7 MTU (72 — note CTRL_HELLO over LoRa is
  exactly at the floor; if a future protocol revision adds bytes
  inside CTRL_HELLO, it will need fragmentation).
- CTRL_HELLO_ACK body grows symmetrically: `48 → 72` bytes,
  total `60 → 84`.
- The `stored_hello_ack[]` buffer in `struct session` (used for
  idempotent re-send of the ACK on duplicate CTRL_HELLO) is
  enlarged accordingly. A `_Static_assert` on its size guards the
  invariant.
- `PROTOCOL.md` §3 (crypto), §4 (control messages), and §11 (wire
  constants summary) updated.

Trade-offs accepted:

1. **24 extra bytes per handshake frame.** Negligible on ESP-NOW.
   On LoRa, CTRL_HELLO+CTRL_HELLO_ACK each go from one ~60-byte
   frame to one ~84-byte frame — still single-fragment at the
   72-byte SF7 MTU after counting the 12-byte radio header
   (84 - 12 = 72 plaintext-ish; the actual AEAD plaintext is 32,
   so we're well within MTU). No fragmentation required.
2. **CSPRNG dependency on every handshake.** `getrandom(2)` (or
   the equivalent Monocypher-side path) is already used per
   session for `nonce_a` / `nonce_b`; one extra 24-byte draw per
   handshake adds nothing meaningful to the entropy budget.
3. **Wire incompatibility with pre-fix firmware.** The version
   bump from `0x01` to `0x02` makes the mismatch surface as
   `ERR_VERSION` rather than a silent AEAD failure. No migration
   path is offered — this is a development-only break, and
   pre-fix binaries should not be run against post-fix binaries.

Rejected alternatives:

- *Mix `nonce_a` into `hello_key` derivation* so `hello_key`
  becomes per-session. Would require the receiver to also know
  `nonce_a` before it can decrypt CTRL_HELLO, which is a
  chicken-and-egg problem (the nonce_a is *inside* the
  CTRL_HELLO plaintext). Solvable by sending `nonce_a` cleartext
  too, at which point the scheme is identical to the chosen
  Option A with extra steps.
- *Use `(PSK_fingerprint || sequence_counter)` as the nonce*
  with the counter persisted on disk. Requires durable per-PSK
  state and recovers gracefully only with great care; a
  filesystem rollback or a fresh keypair-generation tool would
  silently reuse nonces. Rejected as an operational footgun.
- *Switch hello frames to a different AEAD without nonce-misuse
  fragility (e.g. AES-GCM-SIV).* Not in Monocypher; would
  require a second crypto library or hand-rolled code. Rejected
  on minimal-dependency grounds (D-02).

Implementation:

- `src/crypto.{h,c}`: new `crypto_encrypt_with_nonce` /
  `crypto_decrypt_with_nonce` wrappers around
  `crypto_aead_lock` / `crypto_aead_unlock` that take an
  explicit 24-byte nonce instead of deriving from
  `(direction, seq)`. AD layout matches the standard
  `crypto_encrypt` path so other code paths remain untouched.
- `src/session.h`: `stored_hello_ack[]` enlarged to
  `12 + 24 + 32 + 16 = 84` bytes (header + nonce + pt + tag).
- `src/session.c`:
  - `send_hello` (client) bypasses `send_ctrl` /
    `send_frame`, samples a 24-byte `hello_nonce`, builds
    `body = hello_nonce || ciphertext`, calls
    `crypto_encrypt_with_nonce`, and hands the assembled
    frame to the transport. `tx_seq` is incremented exactly
    once per send to keep parity with `send_frame`.
  - `handle_hello` (server) does the same for
    CTRL_HELLO_ACK, using a freshly-sampled nonce. The
    encoded radio frame is also stored in
    `stored_hello_ack[]` for idempotent re-send on a
    duplicate CTRL_HELLO with the same `nonce_a`.
  - `process_frame` peels the 24-byte `hello_nonce` off the
    front of the body for hello frames, then calls
    `crypto_decrypt_with_nonce`. Non-hello frames are
    unchanged. A `ct_len < 24 + 16` guard rejects truncated
    bodies before the AEAD call.
- `src/main.c`: forces `setvbuf(stderr, NULL, _IONBF, 0)` —
  unrelated to the wire change but discovered while debugging
  the AC-03 regression that first masked this fix as "broken". The
  forkpty(3) shell child was inheriting the parent's
  block-buffered stderr buffer and dumping pending bytes onto
  the PTY slave during shell setup, corrupting the first
  frames the server sent back. This fix was committed
  separately so the regression fix is isolated.
- `tools/frame_test.c`: regression sentinels 3-10..3-13, all
  calling `crypto_encrypt_with_nonce` /
  `crypto_decrypt_with_nonce`. These exercise the AEAD wrapper
  contract: 3-10 asserts distinct caller-supplied nonces
  produce distinct ciphertexts; 3-11 asserts a flipped
  cleartext nonce fails the Poly1305 tag on decrypt; 3-12
  asserts cross-session distinctness under the same PSK + SEQ
  + direction + plaintext (catches the wrapper falling back
  to deterministic nonce derivation); 3-13 is a positive
  control asserting that a fixed nonce + fixed inputs produces
  byte-identical output (proves the wrapper actually consumes
  its caller-supplied nonce rather than sampling internally).
  Linked into the build via `Makefile` (frame_test now links
  `src/crypto.c`). **Scope limit:** these sentinels guard the
  `crypto_encrypt_with_nonce` wrapper, NOT `send_hello()`
  itself. A refactor that makes `send_hello` call plain
  `crypto_encrypt` (deterministic nonce) would still pass
  3-10..3-13 — linking session.c into frame_test would pull
  in transport/channel/pty and is out of scope for this
  harness. Audit `send_hello`'s AEAD call site by hand if
  you ever modify it.
- `PROTOCOL.md`: §3 (crypto) gains the "hello_key is
  deterministic" warning and points at this decision; §4
  (control messages) gains the new "Handshake wire format"
  block describing the body layout; §11 (wire constants) lists
  the new hello protocol version and the per-send hello nonce.

Verification:

- `tools/frame_test`: 59 / 59 PASS (no regression; +4 from
  the hello_nonce sentinels 3-10..3-13).
- `tools/ac03_pyte_test.py`: 5 / 5 PASS (top, vim, htop, tab
  completion, arrow history). The post-fix 0/5 regression was
  caused by the unrelated forkpty stdio leak (commit
  the forkpty stdio leak fix), not by the wire format change.
- Manual `urtb listen` + `urtb connect` over Unix-domain
  socket: handshake reaches ESTABLISHED, PTY shell prompt
  renders, interactive use works.

This resolves the hello_key cross-session nonce reuse vulnerability.

## D-40  ESP-NOW channel lives in the capsule, not in CLI flags

**Problem:** Multiple URTB pairs may coexist in the same RF space, so
the channel needs to be configurable per pair. URTB's SPEC is
single-pair (one capsule, two endpoints), so "multiple pairs" means
"multiple capsules" — and each capsule needs to carry its own channel.

**Decision:** The channel is a property of the pair. It is selected
at `urtb keygen` time via `--espnow-channel N` (1..13, default 6) and
sealed inside the capsule's AEAD plaintext at byte offset 68. There is
no runtime flag. Capsule format bumped from v1 to v2 to carry the new
field. The version byte is part of AEAD AD, so it cannot be tampered
with post-creation.

**Rejected:**
- *Runtime `--espnow-channel` flag* (the earlier proposal). Silent-
  mismatch risk: one side on ch 1, the other on
  ch 6 → drops to LoRa, appears "working". A typo (`--espnow-chanel`)
  silently falls back to default 6. Conflicts with single-pair scope
  if used as "one capsule, many channels."
- *Reserved-byte hack at v1* (keep version = 0x01, repurpose
  `reserved[0]` as channel when nonzero). Implicit convention, not
  explicit migration. Version bump is cheap and auditable. "Reserved
  byte N means X when nonzero" is exactly the kind of convention that
  rots across refactors.
- *Separate `urtb configure` subcommand* that mutates an existing
  capsule. Would require either re-entering the passphrase (UX
  friction) or keeping the cleartext around (security loss). Regenerate
  the capsule instead.

**Template for future per-pair RF parameters:** `capsule_load()` now
dispatches on the header version byte. Adding rate, txpower, or other
per-pair RF config means:

1. New `load_v3_plaintext()` with the v3 field list.
2. One case in the post-AEAD dispatch switch in `capsule_load()`.
3. One entry in the pre-AEAD accept-list gate.
4. New keygen flag(s).
5. `capsule_load()`'s signature grows by one out-param per new field —
   that is expected and is the "explicit" part per the generic-pipeline
   principle (`/Users/nenadmicic/webhook-multi/spec/ARCHITECTURAL_PRINCIPLE_GENERIC_PIPELINE.md`).
   The generic part is dispatch; the explicit part is the field list.

**Pre-AEAD version gate — accept-list, not allow-list-of-one.** The
pre-AEAD gate at the top of `capsule_load()` accepts `{0x01, 0x02}`.
A plain `hdr.version != 0x01` check would reject every newly-generated
v2 capsule before AEAD runs, making the post-AEAD dispatch unreachable.

**v1 test fixture — generated at test time, never checked in.** Once
production code stops emitting v1, any committed v1 binary fixture
would be a capsule carrying a fresh PSK that *looks* like a real
credential but is public. Avoided by gating v1 emission behind
`URTB_TEST_V1_EMIT` and building the unit test with that define so the
fixture is regenerated in a temp directory on every run.

**Scope limits (out of phase):**

- Per-pair LoRa frequency / SF / BW / txpower / rate remain
  compile-time constants. Placeholder in FUTURE.md.
- No post-keygen channel change. Regenerate the capsule.
- No automatic channel selection / scanning. A separate scanner tool
  lives at `/Users/nenadmicic/Downloads/heltec_proj1/`.
- No OLED / USB_STATUS_RSP surfacing of the active channel. The
  channel reaches USB_CONFIG byte 18 (tested end-to-end); OLED
  surfacing is a separate feature.

Implementation:

- `src/capsule.{h,c}`: format version constants (v1/v2/current/default),
  per-version plaintext parsers (`load_v1_plaintext` /
  `load_v2_plaintext`, with range check `1..13`), pre-AEAD accept-list,
  post-AEAD dispatch switch. `capsule_generate` emits v2 with
  `reserved[0] = espnow_channel`. `capsule_generate_v1_testonly` behind
  `URTB_TEST_V1_EMIT`. `capsule_load` signature grows an
  `espnow_channel_out` out-parameter.
- `src/main.c`: `cmd_keygen` parses `--espnow-channel N` with
  `strtol` + range validation, default 6. `cmd_session` and
  `cmd_status` read the channel from the capsule and pass it through
  to `transport_config_t.espnow_channel`. Three hardcoded `= 6`
  assignment sites removed (defaults-only path in
  `transport_heltec.c` else-branch annotated and preserved).
- `src/transport_heltec.c`: the `? : 6` fallback at the cfg path is
  removed — the capsule loader is now the single source of truth.
- `tools/capsule_version_test.c`: round-trip tests for v2 channels
  1 / 6 / 13, reject-on-generate for 0 and 14, v1 forward-compat via
  the `URTB_TEST_V1_EMIT` shim, reject forged header version byte.
- `tools/fake_firmware.py`: logs USB_CONFIG byte 18 so integration
  tests can assert the chosen channel reached the wire.
- `tools/heltec_socat_test.sh`: extended to keygen with channel 11
  and assert the fake firmware saw `espnow_channel=11`.

Verification:

- `tools/capsule_version_test`: all cases PASS.
- `tools/heltec_socat_test.sh` with channel 11: fake-firmware log
  shows `espnow_channel=11` for both peers.
- Clean `make clean && make`: zero warnings.
- `make test`: all previous tests continue to PASS.

