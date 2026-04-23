# URTB — Security Specification

---

## Threat model

Assume:
  - All radio traffic is passively captured by a motivated adversary (HackRF/SDR)
  - Adversary stores captured ciphertext indefinitely and attempts offline analysis
  - Adversary can replay captured frames to either device
  - Adversary is in radio range during sessions (esp. for ESP-NOW 2.4 GHz)
  - Laptops may be stolen or disk-imaged (PSK at rest must be protected)
  - Adversary cannot compromise the host app binary itself

Do NOT assume:
  - Radio traffic is private (it is not)
  - Physical proximity is hard (2.4 GHz ESP-NOW has ~200m range)
  - The adversary doesn't know the PAIR_ID (it's in every plaintext radio header)

---

## Security properties provided

  [X] Confidentiality: payload encrypted with XChaCha20-Poly1305
  [X] Integrity:       Poly1305 auth tag on every frame (AEAD)
  [X] Authentication:  session_key derived from PSK + nonces — only peers with PSK
                       can produce or verify valid ciphertext
  [X] Replay resistance: 256-frame sliding window on sequence numbers
  [X] Per-session fresh key: session_key derived fresh from random nonces each session
                       — sessions use different keys; idle PSK theft does not expose
                       previously captured sessions unless nonces were also captured
  [X] Pre-session authentication: CTRL_HELLO encrypted with hello_key = f(PSK, "urtb-hello")
                       — only peers with PSK can produce a valid CTRL_HELLO (DoS-resistant)
  [X] PSK protection at rest: capsule file encrypted with user passphrase (Argon2id)
  [X] Capsule parameter integrity: KDF params (salt, cost) bound into AEAD AD —
                       tampering with Argon2id parameters causes AEAD verification failure
  [X] PAIR_ID isolation: firmware discards frames from other PAIR_IDs

  IMPORTANT — NOT perfect forward secrecy:
  If the PSK is compromised AND the handshake nonces were captured from the wire
  (nonces travel inside CTRL_HELLO ciphertext, decryptable with PSK via hello_key),
  an attacker can recompute session_key = f(PSK, nonce_a, nonce_b) and decrypt any
  captured session. This is NOT PFS. PFS via X25519 is a planned future upgrade (see FUTURE.md).

---

## Security properties NOT provided

  [ ] Perfect forward secrecy (PSK compromise + nonce capture → session decryptable)
  [ ] Post-quantum resistance (ChaCha20 is not PQC; X25519 is also not PQC)
  [ ] Hardware-backed key storage (future: TPM/Secure Enclave integration)
  [ ] Protection against physical access to running laptop (keys in RAM)
  [ ] Anonymity (PAIR_ID is a persistent identifier visible in every frame)
  [ ] Traffic analysis resistance (frame sizes and timing are visible)

---

## Key material lifecycle

  PSK generation:
    `urtb keygen` generates 32 random bytes using the OS CSPRNG (/dev/urandom).
    PSK is immediately encrypted into pairing.capsule using XChaCha20-Poly1305
    with a key derived from user passphrase via Argon2id.
    Raw PSK is zeroed from memory immediately after capsule creation.

  PSK at rest:
    pairing.capsule — encrypted, safe to store or copy.
    File permissions: 0600 (owner read/write only).
    Raw PSK never written to disk.

  PSK in memory (during session):
    Loaded into mlock'd memory on startup after passphrase unlock
    (best-effort — mlock failure is non-fatal; on systems where mlock is
    unavailable, key material may reside in pageable RAM and could be
    written to swap).
    Held under mlock from capsule load through process exit. Two copies
    exist at runtime: main()'s stack copy (the master, persists across
    reconnect iterations in --loop) and s->psk (per-session copy in the
    session struct). The per-session copy is wiped in session_destroy;
    the master copy is wiped in main() after the session loop exits —
    once in both single-session and --loop mode (main.c:540-541).
    This trades the shortest possible PSK RAM-residence for prompt-free
    reconnect. The PSK is never written to disk after capsule load.
    session_key kept in mlock'd memory for session duration.
    PSK pages are also marked MADV_DONTDUMP (Linux 3.4+ only; macOS does not
    provide an equivalent — core dumps are disabled by default on macOS via
    ulimit -c 0, which provides the same practical protection) so they are
    excluded from core dump files — an attacker gaining access to a core dump
    does not obtain key material from these pages.
    Key material is explicitly zeroed on normal exit (session_destroy, then
    crypto_memzero on the mlock'd PSK block in main).
    On SIGTERM/SIGHUP/SIGQUIT:
      - Connect mode: signal handler zeroes PSK + session keys, then _exit().
      - Listen non-loop: same via fatal_signal_handler.
      - Listen loop: handle_loop_exit sets should_exit; main loop exits and the
        normal wipe path at end of cmd_session() zeroes the PSK.
    On SIGSEGV/SIGBUS/SIGFPE, best-effort wipe runs before re-raising for the
    default action (all modes). If the fault occurs inside the wipe path, the
    guarantee does not hold. PSK pages are also excluded from core dumps via
    MADV_DONTDUMP (Linux).
    With --burn, capsule and OTP key files are securely deleted (overwrite +
    fsync + unlink) immediately after loading. Key material exists only in
    mlock'd RAM for the lifetime of the process.

  Session key:
    crypto_blake2b_keyed(key=PSK, msg="urtb-v1"||nonce_a||nonce_b) → 32 bytes.
    Generated fresh for every session. Not stored. Zeroed when session closes.

  nonce_a, nonce_b:
    16 random bytes each, generated per session.
    Exchanged in CTRL_HELLO / CTRL_HELLO_ACK, encrypted under hello_key (not session_key).
    An attacker without PSK cannot decrypt CTRL_HELLO and cannot extract nonces.
    An attacker with PSK can decrypt CTRL_HELLO → can compute session_key (not PFS).

---

## Pairing security

  Pairing requires physical access (or a secure out-of-band channel) to transfer
  the pairing.capsule file. This is intentional.

  Recommended transfer methods:
    scp or rsync over an existing trusted network connection
    gpg --encrypt | base64 → paste via encrypted channel
    USB stick with encrypted filesystem
    Signal / encrypted messaging app

  NOT recommended:
    Email (unencrypted)
    Slack / Teams / similar (stored by vendor)
    AirDrop (convenient but logs metadata)

---

## PAIR_ID considerations

  PAIR_ID is transmitted in every radio frame header in plaintext.
  It is NOT secret — it is a routing tag.

  An observer can:
    Identify that two specific devices are communicating (PAIR_ID fingerprint)
    Count frames (traffic analysis)
    Observe approximate activity periods

  An observer CANNOT:
    Read payload content (encrypted)
    Inject valid frames (no session_key)
    Replay frames usefully (replay window protection)
    Determine what application is running or what data is transferred

  If PAIR_ID anonymity is required (future): derive PAIR_ID from a rotating value
  or use a hash of session material. Not implemented.

---

## Capsule file format (pairing.capsule)

  The wire layout below describes the **v1** format for historical reference. The
  current format is **v2** (adds per-pair ESP-NOW channel at reserved[0], range
  1..13). See `references/capsule_format.md` for the v2 layout and the versioned
  dispatch logic. Trust model (AD binding, AEAD key derivation, PAIR_ID handling)
  is identical between v1 and v2.

  Header (magic + version + KDF parameters — all in plaintext, all in AEAD AD):
    0x55 0x52 0x54 0x42  "URTB" magic (4 bytes)
    0x01                  version = 1 (v1; v2 writes 0x02)
    salt[16]              random Argon2id salt (16 bytes)
    time_cost             uint32_t, iterations (default: 3)
    mem_cost              uint32_t, memory KB (default: 65536 = 64 MB)
    parallelism           uint32_t (default: 1)

  Encrypted payload (nonce + ciphertext):
    nonce[24]             XChaCha20 nonce (random, 24 bytes)
    ciphertext_len        uint32_t, little-endian
    ciphertext            XChaCha20-Poly1305 ciphertext + 16-byte tag

  AEAD construction:
    capsule_key = Argon2id(passphrase, salt, time_cost, mem_cost, parallelism) → 32 bytes
    AD = magic(4) || version(1) || salt(16) || time_cost(4) || mem_cost(4) || parallelism(4)
    ciphertext = XChaCha20-Poly1305(key=capsule_key, nonce=nonce[24], ad=AD, plaintext=psk_data)

  Including KDF params in AD prevents tampering: an attacker who modifies time_cost or
  mem_cost in the header changes the AD, causing AEAD verification failure. This closes
  the attack where an adversary rewrites params to trivialize passphrase brute-force.

  Plaintext payload (inside ciphertext):
    psk[32]               raw PSK bytes
    pair_id[4]            4-byte PAIR_ID
    label[32]             human-readable pair label (null-terminated, optional)
    reserved[28]          set to 0, for future use (v2 carves reserved[0] as
                          espnow_channel; the remaining 27 bytes stay zero)

  Total capsule file size: 4+1+16+4+4+4+24+4+96+16 = 173 bytes (with 16-byte tag)

---

## Firmware security surface

  The Heltec firmware has zero key material. Its security responsibilities:

  PAIR_ID check:
    Drop any radio frame whose PAIR_ID (bytes 0-3) does not match the configured value.
    This is a routing filter, not a security mechanism — but it reduces noise.

  Hardware CRC:
    SX1262 has hardware CRC on LoRa packets (16-bit).
    Enabled by default. Corrupted frames dropped at hardware level.
    ESP-NOW has its own frame integrity at the WiFi layer.

  USB framing integrity:
    CRC-16/CCITT-FALSE on every USB frame.
    Frames with wrong CRC discarded.

  No other security logic in firmware. All authentication is in the host app.

---

## Known risks and mitigations

  Risk: Passphrase brute-force against pairing.capsule
  Mitigation: Argon2id with 64 MB memory, 3 iterations — makes brute-force expensive.
              Use a strong passphrase (≥4 random words or 16+ random characters).

  Risk: Attacker in radio range replays captured frames
  Mitigation: 256-frame sliding window per direction. Replayed SEQ values are rejected
              before AEAD even runs. Three distinct replay scenarios:

              (a) Adversary replays a captured CTRL_HELLO (same SEQ):
              Caught by the replay window. The SEQ was already accepted (HWM set);
              replay attempt is rejected before AEAD runs. No server response.
              No amplification. Cost: one bitmap lookup per attempt.

              (b) Legitimate client RETRANSMITS CTRL_HELLO (new SEQ, same nonce_a):
              The new SEQ passes the replay window. AEAD passes (hello_key unchanged).
              Server is in KEY_DERIVING with matching nonce_a → idempotent re-send
              of stored CTRL_HELLO_ACK (one response per retry). This is the normal
              retry path, not an amplification attack (the client already sent once).

              (c) Wrong-PSK CTRL_HELLO (any SEQ):
              AEAD fails (hello_key mismatch). Server discards silently, no response.

              Accepted: resource-exhaustion via (b) in the same physical radio range
              is not a meaningful threat for this use case.

  Risk: PSK leaked (laptop compromise)
  Mitigation: Past sessions cannot be decrypted IF nonces were not captured — session_key
              is derived from PSK + per-session nonces. However, an attacker who
              captured radio traffic AND obtains the PSK can decrypt past sessions
              (no PFS — see §"Security properties provided"). Future sessions are also
              at risk with a compromised PSK. Rekey by running `urtb keygen` and
              re-distributing pairing.capsule to both devices.

  Risk: PAIR_ID fingerprinting (traffic analysis, device tracking)
  Mitigation: None currently. PAIR_ID is persistent. See FUTURE.md.

  Risk: Forged CTRL_HELLO (connect attempt by wrong device)
  Mitigation: CTRL_HELLO is encrypted with hello_key = BLAKE2b_keyed(key=PSK, msg="urtb-hello").
              An attacker without the PSK cannot produce a CTRL_HELLO that passes
              AEAD verification on the server. The server silently discards any
              CTRL_HELLO that fails AEAD — no response, no amplification.
              Both CTRL_HELLO and the final CTRL_READY (session_key) are authenticated;
              an attacker without PSK cannot establish any session phase.

  Risk: stdio/--exec transport: subprocess execution
  Mitigation: --exec is split on spaces into argv[] and passed to execvp(argv[0], argv).
              No shell involved — eliminates shell injection. The command string never
              passes through sh -c, so shell metacharacters (pipes, expansion, quoting)
              have no effect. Passphrase and capsule path are not in the argv[] string
              (they are read interactively or from a file path argument), so they do
              not appear in ps(1) output from the exec'd subprocess.
              Limitation: no shell metacharacters means no inline pipes; use a wrapper
              script for complex subprocess pipelines. Space-split argv does not handle
              paths containing spaces — document this as a known limitation; use a
              wrapper script if paths with spaces are required.
              Do not accept --exec values from untrusted sources (same as any CLI arg).
              See D-35.

  Risk: Unauthenticated ESP-NOW recovery probes (transport-layer DoS)
  Mitigation: ACCEPTED DESIGN TRADE-OFF.
              The 4-byte recovery probe (PAIR_ID only) is intentionally unauthenticated.
              It operates below the protocol security layer — its sole purpose is to
              detect ESP-NOW link recovery, not to carry any authenticated signal.
              Threat: an attacker within 2.4 GHz range who observes a PAIR_ID (always
              plaintext in every frame) can forge 4-byte probes to trigger spurious
              failback from LoRa to ESP-NOW. If they simultaneously jam ESP-NOW, they
              can cause transport oscillation and duty-cycle starvation on LoRa.
              Practical impact: session degradation (latency, churn), not decryption or
              impersonation. All session content remains fully AEAD-protected regardless
              of transport state. The host liveness watchdog (authenticated frames only)
              provides the actual session health signal — forged probes cannot fake a
              live session.
              Rationale for not authenticating probes: the probe must be recognizable
              by firmware without a session key (no key is available pre-ESTABLISHED).
              Adding a rolling token would require firmware to track session state,
              violating the "firmware is a dumb modem" principle (D-19, D-20).
              Active-RF attackers within range can disrupt radio links by other means
              (jamming, deauth) with or without probe spoofing. This threat is accepted
              for the personal-tool use case.
              See D-13, D-14, D-19.

  Risk: Active RF attacker (transport downgrade, selective frame drop, jamming)
  Mitigation: No session content protection is weakened. An active RF attacker can
              disrupt connectivity but cannot decrypt, inject, or impersonate.
              Unauthenticated probes are one mechanism (see above). Jamming and
              selective frame drop are also possible. The session liveness watchdog
              closes the session if connectivity is lost for 3 × keepalive_period,
              preventing indefinite hanging. Accepted for the threat model.

  Risk: Malicious jump host (--exec "ssh jumphost urtb listen --transport stdio")
  Mitigation: The jump host sees an encrypted byte stream only. All session content
              is end-to-end AEAD-protected between the two urtb endpoints. The jump
              host can drop or corrupt frames (causing AEAD failures / session close)
              but cannot read or modify payload. Traffic timing and volume are visible
              to the jump host. This threat is accepted: the jump-host scenario is
              explicitly motivated by an untrusted relay (D-35).

  Risk: CTRL_HELLO nonce reuse (resolved, D-39)
  Mitigation: `hello_key` is deterministic from PSK, so using the SEQ-based nonce
              (direction=0, SEQ=0) for every session repeated the same (key, nonce) pair.
              An attacker capturing two CTRL_HELLO ciphertexts could recover the Poly1305
              one-time key and forge tags. Fixed in D-39: CTRL_HELLO and CTRL_HELLO_ACK
              now carry a per-send random 24-byte nonce prepended to the ciphertext.
              Non-hello frames continue to use the (direction, SEQ) nonce path, which is
              safe because `session_key` contains per-session random material. See
              PROTOCOL.md §3 for the wire format.

---

## OTP second factor

  HOTP (RFC 4226, HMAC-SHA1) and TOTP (RFC 6238) provide a second factor
  independent of the PSK. The OTP seed is a 20-byte random value generated once
  at key setup (`urtb otp-init`), stored in a mode-0600 file on the listener
  machine, and never transmitted. It is displayed once as an `otpauth://` URI
  for scanning into a mobile authenticator app.

  Key material: HMAC-SHA1 stack buffers (`k`, `ipad`, `opad`, inner hash) are
  zeroed with `crypto_memzero()` after each use. The `otp_key_t` struct
  (containing the seed) is zeroed before `otp_verify()` returns.

  Window sizes: HOTP default window=20 (accepts codes for counter..counter+20),
  suitable for air-gapped machines. TOTP default window=1 (±30 s), suitable for
  NTP-synced machines.

  Timing: the HOTP loop exits on first match; timing variation is not
  exploitable over a radio link and is considered acceptable for this
  deployment. Code comparison uses integer equality after strict 6-digit
  validation.

  Threat model: OTP is defense-in-depth against capsule leakage. It does not
  help if the attacker has physical access to the listener. The 3-attempt limit
  is per-session — under `--loop`, each new connection resets the counter. This
  is intentional: a persistent global lockout would require persistent state and
  is out of scope for v1.

  Interaction with PSK: OTP challenge occurs inside the XChaCha20-Poly1305
  encrypted session. An attacker without the PSK cannot reach the OTP prompt.
  An attacker with the PSK but without the OTP code cannot interact with the
  shell. (The shell process is spawned before OTP completes, but the PTY
  bridge — all input and output — is blocked until the code is accepted.
  The shell is unreachable to the attacker.)
