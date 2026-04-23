# URTB — USB-Radio Terminal Bridge

[![CI](https://github.com/nmicic/URTB/actions/workflows/test.yml/badge.svg)](https://github.com/nmicic/URTB/actions/workflows/test.yml)

Encrypted PTY tunnel over LoRa/ESP-NOW radio links or untrusted jump hosts —
XChaCha20-Poly1305.

Two `urtb` processes paired with the same capsule (a passphrase-encrypted PSK)
establish an authenticated encrypted session and carry an interactive shell
between them. The primary transport is a pair of USB-attached Heltec WiFi
LoRa 32 V3 boards communicating over ESP-NOW with automatic LoRa fallback.
The same host binary also works over a UNIX socket, an SSH jump host, or any
child process's stdio — no radio hardware required to try it.

## Quick start (no hardware)

```
make doctor   # check toolchain
make          # build ./urtb

# one-time: generate a shared capsule (passphrase: test123)
URTB_PASSPHRASE=test123 ./urtb keygen --out /tmp/demo.cap

# terminal A — listener
URTB_PASSPHRASE=test123 ./urtb listen --transport unix \
    --socket /tmp/demo.sock --capsule /tmp/demo.cap

# terminal B — connect
URTB_PASSPHRASE=test123 ./urtb connect --transport unix \
    --socket /tmp/demo.sock --capsule /tmp/demo.cap
```

The connect side enters raw mode and you get a remote shell. Type `exit` to
close. For Heltec V3 hardware and jump-host scenarios see `HOWTO.md`.

## Transports

| Transport | How |
|-----------|-----|
| `--transport unix` | UNIX domain socket — same host or via socat |
| `--transport heltec` | Heltec WiFi LoRa 32 V3 over USB serial |
| `--transport stdio` | urtb is the subprocess (SSH remote command, jump host) |
| `--exec "cmd args"` | urtb spawns a subprocess and uses its stdio |

## Security

- **Key exchange**: capsule carries a 256-bit PSK encrypted with XChaCha20-Poly1305
  under a passphrase-derived key (Argon2id)
- **Session encryption**: XChaCha20-Poly1305 (Monocypher), unique nonce per frame
- **Authentication**: mutual — both sides must hold the same capsule
- **OTP**: optional HOTP/TOTP second factor (`--otp`)
- **Burn mode**: `--burn` securely deletes the capsule and OTP key after loading;
  key material lives only in mlock'd memory for the process lifetime
- **Memory**: PSK and session keys are `mlock`'d and excluded from core dumps
  (`MADV_DONTDUMP` on Linux); wiped on exit, SIGTERM, SIGHUP, SIGQUIT, and best-effort
  on SIGSEGV/SIGBUS/SIGFPE

See `SECURITY.md` for the full threat model and key-handling rules.

## Build

```
make                                   # macOS / Linux default (EU 869.875 MHz)
make REGION=US                         # US 915 MHz, 22 dBm
make CC=gcc CFLAGS="-O2 -std=c11"     # explicit compiler
make urtb-static                       # fully static binary (Linux)
```

The macOS binary links only `libSystem`. See `PORTING.md` for the regional
frequency table and custom frequency options.

## Tests

```
make doctor       # environment readiness
make check        # software tests (~50 s)
make check-hw     # Heltec V3 hardware tests (~3 min, requires 2 boards)
make check-all    # both tiers
make smoke        # frame_test only (~2 s)
```

## Jump host

URTB can run through an untrusted SSH jump host without exposing the PSK
or passphrase to the intermediate machine. See `HOWTO_JUMPHOST.md` for
validated scenarios using `--transport stdio` and `--exec`.

## Hardware

Heltec WiFi LoRa 32 V3. Firmware built with PlatformIO (`make firmware`).
ESP-NOW is the primary radio link; LoRa activates automatically on ESP-NOW
failure. Two boards are required for the hardware transport.

## Documents

| File | Contents |
|------|----------|
| `ACCEPTANCE_CRITERIA.md` | Acceptance criteria and test coverage checklist |
| `DECISIONS.md` | Design decision log — rationale, rejected alternatives, trade-offs |
| `FUTURE.md` | Deferred features and known limitations |
| `HOWTO.md` | Install, four end-to-end use cases, troubleshooting |
| `HOWTO_JUMPHOST.md` | SSH jump-host scenarios (8 validated) |
| `KNOWN_ISSUES.md` | Known limitations and deferred items |
| `PORTING.md` | Regional frequencies, porting to other boards |
| `PRIOR_ART.md` | Prior art survey and design comparisons |
| `PROTOCOL.md` | Wire format, frame types, crypto, state machine |
| `SECURITY.md` | Threat model, key lifecycle, signal handling |
| `SPEC.md` | System scope, components, data flow |
| `TESTING.md` | Test inventory, tiers, failure-injection, CI |
| `compartment/` | Landlock + seccomp sandbox profiles (requires [compartment](https://github.com/nmicic/compartment)) |

## License

Copyright (c) 2026 Nenad Micic. Apache License 2.0 — see `LICENSE`.

Monocypher (`src/vendor/`) is BSD 2-clause (Loup Vaillant). See `src/vendor/README.txt`.
