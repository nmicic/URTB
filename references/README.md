# URTB — Implementation References

Self-contained in-repo copies of the patterns used while implementing
the host binary and firmware. Everything needed to build URTB from the
spec is either in this folder or in the vendored sources under
`src/vendor/`.

---

## Files in this folder

| File | What it is |
|---|---|
| `pty_reference.c` | `forkpty()` server pattern + client raw terminal mode |
| `capsule_format.md` | URTB capsule wire format + monocypher Argon2id API |
| `monocypher_api.md` | Quick reference for all monocypher functions URTB uses |
| `heltec_v3_hardware.md` | Pin definitions, RadioLib init, platformio.ini |

---

## Scope

These references exist so the repo is buildable standalone:

- The capsule format here is the **normative** URTB format. Do not
  copy capsule structures from other encrypt-and-seal implementations
  without checking against `capsule_format.md` and the v2 layout
  described in `DECISIONS.md D-40`. URTB's AEAD associated-data binds
  the KDF parameters into the ciphertext, which is deliberately
  different from simpler "magic + ciphertext" capsule layouts.
- The PTY reference is the classic `forkpty` + `poll` pattern. It's
  included verbatim so the reader does not need to chase external
  sources to understand `src/pty.c`.

For the user-facing crypto and security contract, see `SECURITY.md`
and `PROTOCOL.md` — those are the authoritative documents; the files
here are implementation aids.
