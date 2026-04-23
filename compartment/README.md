# Compartment Profiles for URTB

Kernel-enforced sandboxing profiles for the URTB client using
[compartment](https://github.com/nmicic/compartment) — Landlock
(filesystem) + seccomp (syscalls) + environment sanitization.

## Why sandbox the client?

URTB receives data from untrusted sources — radio peers, jump hosts,
or any remote endpoint. Any of these could be hostile:

- **Radio (ESP-NOW / LoRa):** anyone within radio range can send
  crafted frames. A rogue device could probe for parser bugs in the
  frame decoder, fragmentation engine, or AEAD layer, aiming for code
  execution on your laptop.
- **Jump host / remote server:** a compromised server can send
  malicious terminal escape sequences, malformed URTB frames, or
  payloads designed to pivot from the urtb process to your local system.
- **Man-in-the-middle:** even with AEAD, a bug in the crypto path
  could be exploitable. Defense in depth means not trusting any single
  layer.

The compartment profile restricts what the urtb process can do on YOUR
machine, limiting the blast radius even if the remote side achieves
code execution inside the urtb process.

## What the profiles enforce

| Layer | Restriction |
|-------|-------------|
| **Filesystem** (Landlock) | `$HOME` is read-only. No write access except `/dev` (PTY) and `/tmp` (sockets). Capsule directory read-only. |
| **Syscalls** (seccomp BPF) | 50 dangerous syscalls blocked (ptrace, mount, bpf, kexec, io_uring, etc.). Zero needed by urtb. |
| **Environment** | Strips `LD_PRELOAD`, `SSH_AUTH_SOCK`, cloud credentials, DB passwords before exec. |
| **Privileges** | `no-new-privs` — urtb cannot escalate via setuid/setgid binaries. |

## Profiles

| File | Side | Mode | `$HOME` | Risk |
|------|------|------|---------|------|
| `urtb-connect.conf` | Client | Deny-list (49 blocked) | **Read-only** | Low |
| `urtb-connect-strict.conf` | Client | Allow-list (61 permitted) | **Read-only** | Medium |
| `urtb-listen.conf` | Server | Deny-list (49 blocked) | Read-write + exec | Low |
| `urtb-listen-strict.conf` | Server | Allow-list (61 permitted) | Read-write + exec | Medium |

The connect profiles lock `$HOME` read-only — the client only reads the
capsule. The listen profiles use `rwx $HOME` because the spawned shell
needs to write files and execute tools. Both sides block the same 49
dangerous syscalls (ptrace, mount, bpf, kexec, io_uring, etc.) — urtb
needs zero of them. OTP (TOTP/HOTP) works under all profiles — time
functions use glibc vDSO, no extra syscalls needed.

## Quick start

```bash
# Install compartment-user (single binary, no dependencies)
# See: https://github.com/nmicic/compartment

# ── Client side (your laptop) ──
# Deny-list (recommended — safe, won't break)
compartment-user --profile compartment/urtb-connect.conf -- \
    ./urtb connect --exec "ssh jumphost ssh serverY \
        urtb listen --transport stdio --capsule /path/cap" \
    --capsule cap.cap

# ── Server side (serverY) ──
# Persistent listener with OTP, sandboxed
compartment-user --profile compartment/urtb-listen.conf -- \
    ./urtb listen --transport unix --socket /tmp/urtb.sock \
        --capsule cap.cap --loop --otp otp.key
```

## With audit logging

```bash
compartment-user --profile compartment/urtb-connect.conf --audit -- \
    ./urtb connect --exec "ssh jump ssh server urtb listen ..."
```

Logs to `/var/tmp/compartment-audit-<UID>/YYYY-MM-DD.log`.
Machine-parseable format with PPID chain, profile name, and
enforcement status.

## Combined with `--burn` (when available)

When `--burn` lands (FUTURE.md S-1/S-2), the capsule and OTP key are
shred+unlinked after loading into memory. Combined with compartment:

```bash
compartment-user --profile compartment/urtb-listen.conf -- \
    ./urtb listen --burn --loop --otp otp.key --capsule cap.cap \
        --transport unix --socket /tmp/urtb.sock
```

Defense in depth: even if an attacker exploits urtb, the sandbox
blocks ptrace (can't read key material from memory), blocks
`process_vm_readv` (can't dump another process), and the capsule file
is already gone from disk. Re-profile after `--burn` lands — it may
add `unlink`/`shred` syscalls (likely already in the allow-list).

## Regenerating profiles

If urtb gains new features that need additional syscalls (e.g. file
transfer channels in Phase C), regenerate the profiles:

```bash
# Deny-list
python3 ~/compartment/tools/syscall.py profile \
    -o compartment/urtb-connect.conf -- \
    ./urtb connect --exec "./urtb listen --transport stdio --capsule cap" \
    --capsule cap

# Allow-list
python3 ~/compartment/tools/syscall.py profile --seccomp-mode allow \
    --duration 10 \
    -o compartment/urtb-connect-strict.conf -- \
    ./urtb connect --exec "./urtb listen --transport stdio --capsule cap" \
    --capsule cap
```

Run multiple profiling sessions with different workloads (short session,
long session, window resize, error conditions) and merge results. A
syscall used in ANY run must be in the allow-list.

## Checking before deploying

```bash
# Will the default ai-agent profile work for urtb?
python3 ~/compartment/tools/syscall.py check --profile ai-agent -- \
    ./urtb connect --exec "./urtb listen --transport stdio --capsule cap" \
    --capsule cap
```

## How it works

```
                    compartment sandbox
                    ┌────────────────────────────────┐
[your laptop]       │ urtb connect                   │
                    │   ├─ Landlock: $HOME read-only  │
                    │   ├─ seccomp: 50 syscalls blocked│
                    │   └─ env: credentials stripped   │
                    └──────────┬─────────────────────┘
                               │ byte stream (SSH pipe / serial / radio)
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     (jump host scenario)  (direct radio)  (Heltec USB)
     SSH through serverX   ESP-NOW / LoRa  serial /dev/ttyUSBx
     to serverY            from any peer   to paired device
```

The sandbox protects your laptop regardless of transport. Whether the
hostile input comes from a compromised server through SSH, a rogue
radio device within ESP-NOW/LoRa range, or a tampered Heltec over USB,
the urtb process cannot write to your home directory, read SSH keys,
load kernel modules, or escalate privileges.
