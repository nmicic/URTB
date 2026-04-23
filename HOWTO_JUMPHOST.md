# URTB Jump Host — Validated Examples

Tested on Ubuntu 22.04 (KVM VM at 192.168.1.10).
All examples validated end-to-end with expect-driven automation.

## The idea

URTB gives you a shell on a remote host over an encrypted PTY tunnel
(ESP-NOW/LoRa radio, UNIX socket, or any transport). From that shell
you SSH onward — the "jump" happens inside the tunnel, not at the
transport layer. SSH sees an ordinary terminal; key auth, password
auth, port forwards, and nested hops all work.

```
[your laptop]  ──(urtb tunnel)──  [jump host shell]  ──(SSH)──  [target host]
```

The same pattern works with `socat + openssl` over TCP when you have
an IP path with open non-SSH ports. See the "when to use what" matrix
below for when each approach applies.

---

## What makes URTB different

URTB establishes an encrypted channel inside a **single existing file
descriptor**. No new ports, no new sockets, no new connections. The
AEAD-encrypted tunnel rides on whatever byte stream you already have --
an SSH pipe, a serial port, a radio link, a UNIX socket.

This is what makes it work where everything else fails. VPNs need UDP
ports. `socat + openssl` needs a TCP listener. SSH `-J` needs
`AllowTcpForwarding`. URTB needs **one thing**: a bidirectional byte
stream between two endpoints. If you can `ssh` to a host and run a
command, you have that byte stream, and URTB can build an encrypted
PTY tunnel on top of it.

---

## Quick reference

| Scenario | First hop | Second hop | Status |
|----------|-----------|------------|--------|
| URTB → key auth | URTB tunnel | `ssh -o BatchMode=yes user@target` | **PASS** |
| URTB → password auth | URTB tunnel | `ssh user@target` (type password) | **PASS** |
| URTB → key → password | URTB tunnel | `ssh keyuser@jump` then `ssh passuser@target` | **PASS** |
| URTB → password → key | URTB tunnel | `ssh passuser@jump` then `ssh keyuser@target` | **PASS** |
| `--exec` stdio (no socat!) | `connect --exec "ssh X ssh Y urtb listen --transport stdio"` | **Recommended** — no socat needed | **PASS** |
| `--exec` stdio + ssh -J | `connect --exec "ssh -J X Y urtb listen --transport stdio"` | Cleaner with ProxyJump | **PASS** |
| `--exec` stdio + sshpass | `connect --exec "sshpass ssh X ssh Y urtb listen --transport stdio"` | Password auth jump host | **PASS** |
| `--exec` + socat (fallback) | `connect --exec "ssh X ssh Y socat STDIO UNIX:sock"` | Pre-started listener with --loop | **PASS** |

> **Note:** `socat + openssl` over a TLS port (e.g. 9443) was also validated (key auth, password auth, double hops -- all PASS), but requires an open non-SSH port on the jump host. See Example 5 below. For the restricted jump host scenario (port 22 only), the `--exec` methods above are the relevant approaches.

---

## Setup

### Generate a capsule (URTB, one-time)

```bash
./urtb keygen --out /tmp/jump.cap
# Copy the same capsule to both sides.
```

### Generate TLS certs (socat+openssl, one-time)

```bash
mkdir -p ~/.urtb-tls && cd ~/.urtb-tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout server.key -out server.pem -days 365 -nodes \
    -subj "/CN=$(hostname)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout client.key -out client.pem -days 365 -nodes \
    -subj "/CN=client"
cat server.pem client.pem > ca.pem
# Copy client.{pem,key} + ca.pem to the client side.
```

### Target host SSH access

Set up SSH keys or passwords on the target host as you normally
would. URTB does not interfere with SSH authentication — it is a PTY
tunnel, not a proxy.

---

## Example 1: URTB tunnel → SSH with key auth

**Jump host (listener):**

```bash
URTB_PASSPHRASE=mysecret ./urtb listen \
    --transport unix --socket /tmp/urtb.sock \
    --capsule /tmp/jump.cap --loop
```

For real radio use, replace `--transport unix --socket ...` with
`--transport heltec --device /dev/ttyUSB0`.

**Your laptop (client):**

```bash
URTB_PASSPHRASE=mysecret ./urtb connect \
    --transport unix --socket /tmp/urtb.sock \
    --capsule /tmp/jump.cap
```

**Inside the URTB shell:**

```bash
# Confirm you're inside the tunnel
echo $URTB_SESSION    # prints "1"

# Jump to the target using key auth (no password prompt)
ssh -o BatchMode=yes target-user@internal-host.lan
```

If your key is at a non-default path, use `-i ~/.ssh/my_key` or
add an entry to `~/.ssh/config` on the jump host.

---

## Example 2: URTB tunnel → SSH with password auth

Same listener/connect as Example 1. Inside the URTB shell:

```bash
ssh target-user@internal-host.lan
# SSH shows: target-user@internal-host.lan's password:
# Type the password — URTB's PTY passes it through correctly.
```

Password auth works because URTB allocates a real PTY (`forkpty`).
SSH detects the terminal and shows the password prompt. Keyboard
input is encrypted over the URTB wire (XChaCha20-Poly1305) — the
jump host never sees plaintext keystrokes on the network.

---

## Example 3: Double hop — key then password

```bash
# Inside the URTB shell on the jump host:
ssh -o BatchMode=yes bastion@gateway.lan     # first hop, key auth
# Now on gateway.lan:
ssh operator@db-server.lan                    # second hop, password auth
# Type password at the prompt.
```

---

## Example 4: Double hop — password then key

```bash
# Inside the URTB shell:
ssh operator@gateway.lan                      # first hop, password auth
# Type password.
# Now on gateway.lan:
ssh -o BatchMode=yes deploy@app-server.lan    # second hop, key auth
```

---

## Example 5: socat + openssl (TCP alternative)

When you have an IP path and don't need radio, `socat + openssl`
gives you the same jump-host pattern with zero custom code.

**Jump host (server):**

```bash
socat \
    OPENSSL-LISTEN:9443,reuseaddr,fork,\
cert=$HOME/.urtb-tls/server.pem,\
key=$HOME/.urtb-tls/server.key,\
cafile=$HOME/.urtb-tls/ca.pem,verify=1 \
    EXEC:"/bin/bash -l",pty,stderr,setsid,sigint,sane
```

**Client:**

```bash
socat - \
    OPENSSL:jumphost.example.com:9443,\
cert=$HOME/.urtb-tls/client.pem,\
key=$HOME/.urtb-tls/client.key,\
cafile=$HOME/.urtb-tls/ca.pem,verify=1
```

Then SSH onward exactly as in Examples 1-4. Key auth, password
auth, and double hops all work identically.

---

## Identifying which layer you're in

The URTB-spawned shell sets `URTB_SESSION=1`. Use it in your
prompt to avoid confusion in nested sessions:

```bash
# Add to .bashrc on the jump host:
if [ "$URTB_SESSION" = "1" ]; then
    PS1="[urtb] \u@\h:\w\$ "
fi
```

Or check the TTY — each hop allocates a different PTY:

```bash
tty          # /dev/pts/5  (URTB shell)
ssh user@target
tty          # /dev/pts/7  (SSH session on target)
```

---

## Security comparison: stdio vs. pre-started listener (jump host scenario)

The two URTB methods for untrusted jump hosts have different security
properties. This is the key trade-off:

| Property | Method 1: stdio (`--exec` on demand) | Method 2: pre-started listener (socat bridge) |
|----------|--------------------------------------|-----------------------------------------------|
| Passphrase exposure to jump host | **Yes** -- `URTB_PASSPHRASE=secret` visible in SSH command line / process list | **No** -- passphrase entered locally on serverY, never crosses jump host |
| What jump host sees | SSH command with passphrase + URTB ciphertext | **Only** URTB ciphertext (via socat) |
| Pre-setup needed on serverY | None -- listener starts on demand | Yes -- admin must start listener in advance |
| Requires socat on serverY | No | Yes |
| Supports `--loop` | No (one-shot per `--exec`) | Yes |
| Risk if jump host is compromised | Attacker gets passphrase; still needs capsule file to derive PSK | Attacker sees only opaque ciphertext; cannot derive PSK without both capsule and passphrase |
| Best for | Trusted or semi-trusted jump hosts; convenience | **Untrusted / potentially compromised jump hosts** |

**Bottom line:** If the jump host might be compromised, use Method 2.
The passphrase never leaves the endpoints (your laptop and serverY).
The jump host is reduced to a dumb byte relay seeing only AEAD
ciphertext it cannot decrypt.

> For a comparison of URTB vs. `socat + openssl` (mutual TLS): those
> tools solve a different problem -- encrypted shells over TCP when you
> have open non-SSH ports. See Example 5 and the decision matrix below.
> In the restricted jump host scenario (port 22 only), `socat + openssl`
> listeners are not an option.

---

## The untrusted jump host case (`--exec` through SSH)

### The scenario

You need to reach serverY in a DMZ. The only path is through a
jump host (serverX) you **don't trust**. Constraints:

- Jump host allows SSH (port 22) inbound and outbound **only**
- No other ports open — `socat + openssl` on port 9443 is impossible
- SSH forwarding may be disabled (`AllowTcpForwarding no`)
- `ssh -J` (ProxyJump) may be blocked
- Admin may be logging everything
- The jump host may already be compromised

You want end-to-end encryption between your laptop and serverY that
serverX cannot decrypt — even if serverX has root access to itself.

### Why other approaches fail here

| Approach | Requires | Blocked by this scenario? |
|----------|----------|--------------------------|
| `socat + openssl` | Non-SSH port (e.g. 9443) | **Yes** — only port 22 open |
| `ssh -J` / ProxyJump | `AllowTcpForwarding` on jump host | **Maybe** — often disabled |
| `ssh -W` / `-L` / `-R` | `AllowTcpForwarding` on jump host | **Maybe** — often disabled |
| WireGuard / VPN | Additional UDP/TCP ports | **Yes** — only port 22 open |
| Mosh | UDP ports | **Yes** — only port 22 open |
| Tor hidden service | Tor network access | **Probably** — outbound restricted |

### What URTB `--exec` does differently

`urtb connect --exec "ssh jumphost ssh serverY socat STDIO UNIX:/tmp/urtb.sock"`
does **not** use port forwarding, tunnels, ProxyJump, or any SSH
feature beyond "run a command on the remote host." That's the one
thing a jump host must allow — otherwise it's not a jump host.

```
[laptop]                    [serverX - UNTRUSTED]                 [serverY]
urtb connect --exec "..."        SSH relay only              urtb listen --transport unix
   |                              |                              --socket /tmp/urtb.sock
   +--- URTB AEAD encrypted (end-to-end, XChaCha20-Poly1305) ---+
   |                              |                              |
   ssh → serverX →→→→→→→→→→→ ssh → serverY →→ socat → UNIX socket
         port 22 in                  port 22 out
         (sees URTB ciphertext       (terminates urtb listener,
          only, cannot decrypt)       spawns real PTY shell)
```

ServerX relays bytes but **never sees plaintext** — the URTB AEAD
layer is between your laptop and serverY, independent of SSH.

**What the jump host sees in its logs:** Two SSH sessions (inbound
from laptop, outbound to serverY). The bytes relayed between them
are URTB AEAD ciphertext. Without the PSK capsule, they are opaque.

### What if `ssh -J` IS available?

If ProxyJump works, use it first — it's simpler:

```bash
ssh -J jumpuser@serverX targetuser@serverY
```

SSH's own encryption is end-to-end (laptop ↔ serverY). The jump
host relays TCP but never holds the SSH session keys.

URTB `--exec` is the fallback for when `-J` is blocked.

### Method 1: stdio transport — no socat, no sockets (convenient)

URTB has a `stdio` transport that reads/writes on stdin/stdout
directly. When the remote `urtb listen --transport stdio` is launched
via SSH, it uses the SSH pipe as its transport. **No socat, no UNIX
sockets, no extra tools** — only `urtb` on both endpoints.

> **Security note:** With this method, `URTB_PASSPHRASE=secret` appears
> in the SSH command line that is relayed through the jump host. If the
> jump host is compromised, the attacker can read the passphrase from
> the process list or SSH logs. The capsule file (Argon2id-encrypted)
> remains as protection -- the attacker would need both the capsule
> file *and* the passphrase to derive the PSK. However, if you are
> transferring the capsule through the same jump host (see
> Bootstrapping), an attacker with both pieces can decrypt your tunnel.
> For untrusted jump hosts, prefer **Method 2** (pre-started listener)
> where the passphrase is entered locally on serverY.

```bash
# One command on your laptop — nothing pre-started on serverY:
URTB_PASSPHRASE=secret ./urtb connect \
    --exec "ssh user@serverX ssh user@serverY \
        env URTB_PASSPHRASE=secret urtb listen --transport stdio --capsule /path/cap.cap" \
    --capsule cap.cap
```

What happens:
1. Your laptop forks: `ssh serverX ssh serverY urtb listen --transport stdio`
2. SSH chain delivers the command to serverY (port 22 only)
3. serverY's `urtb listen --transport stdio` reads/writes on its
   stdin/stdout — which is the SSH pipe
4. Your laptop's `urtb connect` reads/writes on the forked process's
   stdin/stdout
5. URTB AEAD handshake completes, PTY spawns on serverY
6. You have a shell on serverY. ServerX saw only ciphertext.

**No persistent listener needed on serverY** — the listener starts
on demand, runs for one session, and exits when you disconnect.
For persistent listening, pre-start with `--loop` or use Method 2.

### Method 2: pre-started listener with UNIX socket + socat (secure for untrusted jump hosts)

If you prefer a persistent listener on serverY (e.g. for `--loop`
or OTP), start the listener in advance and bridge with socat:

> **Security note:** This is the **secure option for untrusted jump
> hosts**. The passphrase is entered locally on serverY (by an admin
> or via out-of-band delivery) and never appears in any SSH command
> that crosses the jump host. The `--exec` command on the laptop side
> only runs `socat STDIO UNIX:/tmp/urtb.sock` -- the jump host sees
> URTB AEAD ciphertext flowing through the socat bridge, nothing else.
> Without the PSK (which never left serverY or your laptop), the jump
> host cannot decrypt any of it.

```bash
# serverY (pre-started, can use --loop):
# Passphrase entered LOCALLY on serverY — never crosses the jump host
URTB_PASSPHRASE=secret ./urtb listen \
    --transport unix --socket /tmp/urtb.sock --capsule cap.cap --loop

# laptop:
# Note: passphrase only needed locally on the laptop — not in the --exec command
URTB_PASSPHRASE=secret ./urtb connect \
    --exec "ssh user@serverX ssh user@serverY socat STDIO UNIX:/tmp/urtb.sock" \
    --capsule cap.cap
```

Requires `socat` on serverY. Method 1 (stdio) is more convenient when
you don't need `--loop`, but exposes the passphrase to the jump host.

### Method 3: `ssh -J` (ProxyJump) in `--exec`

If ProxyJump is available (not blocked on the jump host):

```bash
# stdio transport (no socat):
URTB_PASSPHRASE=secret ./urtb connect \
    --exec "ssh -J user@serverX user@serverY \
        env URTB_PASSPHRASE=secret urtb listen --transport stdio --capsule /path/cap.cap" \
    --capsule cap.cap
```

### Method 4: SSH config (avoids double quoting)

Use `~/.ssh/config` on your laptop:

```
Host urtb-serverY
    ProxyJump user@serverX
    User user-on-serverY
    RemoteCommand env URTB_PASSPHRASE=secret urtb listen --transport stdio --capsule /path/cap.cap
    RequestTTY no
```

Then:

```bash
URTB_PASSPHRASE=secret ./urtb connect --exec "ssh urtb-serverY" --capsule cap.cap
```

Or put a helper on the jump host:

```bash
# serverX: ~/urtb-bridge.sh
#!/bin/sh
exec ssh user@serverY env URTB_PASSPHRASE=secret urtb listen --transport stdio --capsule /path/cap.cap
```

Then: `./urtb connect --exec "ssh user@serverX bash urtb-bridge.sh" --capsule cap.cap`

### Method 5: password auth to the jump host

```bash
URTB_PASSPHRASE=secret ./urtb connect \
    --exec "sshpass -p 'jumppass' ssh user@serverX ssh user@serverY \
        env URTB_PASSPHRASE=secret urtb listen --transport stdio --capsule /path/cap.cap" \
    --capsule cap.cap
```

Or use `SSH_ASKPASS` for interactive password entry without `sshpass`.

### PPP comparison

PPP over SSH uses the same stdin/stdout pipe trick, but requires
**root on both endpoints** for the tun/tap interface. URTB's stdio
transport is entirely userspace — no root, no kernel modules, no
tun/tap.

### Bootstrapping: getting the capsule to serverY

The capsule file (`pairing.capsule`) is already Argon2id-encrypted.
The jump host can see the encrypted file — it cannot extract the PSK
without the passphrase.

**Option A: SCP through the jump host (simplest)**

```bash
# laptop → jump host → serverY (two-step if no -J)
scp cap.cap jumpuser@serverX:/tmp/cap.cap
ssh jumpuser@serverX 'scp /tmp/cap.cap targetuser@serverY:/tmp/cap.cap && rm /tmp/cap.cap'
```

The jump host sees the encrypted capsule file. Harmless — it's
Argon2id-protected. The passphrase must reach serverY through a
different channel (see below).

**Option B: Out-of-band passphrase delivery**

1. SCP the encrypted capsule through the jump host (Option A)
2. Deliver the passphrase via secure messaging, phone call, or
   pre-shared secret with the serverY admin
3. Admin starts the listener: `URTB_PASSPHRASE=secret urtb listen ...`

The passphrase never crosses the jump host.

**Option C: Bootstrap via `ssh -J`, then switch to `--exec`**

If ProxyJump works for the initial setup but you want `--exec` for
ongoing sessions (e.g. because `-J` might be revoked):

```bash
# One-time setup: use -J to reach serverY directly
scp -J jumpuser@serverX cap.cap targetuser@serverY:/tmp/cap.cap
ssh -J jumpuser@serverX targetuser@serverY \
    'URTB_PASSPHRASE=secret urtb listen --transport unix --socket /tmp/urtb.sock --capsule /tmp/cap.cap --loop &'
```

Now switch to `--exec` for all future connections — independent of
whether `-J` stays available.

**Option D: Accept one-time bootstrap risk**

SSH to serverY through the jump host (two-hop), type the passphrase
once to start the listener. The jump host *could* see the passphrase
keystrokes if compromised. But:
- Subsequent sessions are URTB-encrypted end-to-end
- The passphrase never travels through the jump host again
- If the jump host is compromised *after* bootstrap, it's too late
  for the attacker — they'd need the capsule file too

**Option E: `--burn` — delete key files after loading**

Add `--burn` to the listener command to delete the capsule (and OTP key
if `--otp` is used) immediately after loading. Combined with `--loop`,
the process runs indefinitely using in-memory key material only:

```bash
URTB_PASSPHRASE=secret ./urtb listen --burn --loop \
    --transport unix --socket /tmp/urtb.sock --capsule cap.cap
```

After loading, `cap.cap` is overwritten with zeros, fsynced, and
unlinked. An attacker who later gains access to the filesystem finds
no capsule file. Key material exists only in mlock'd, MADV_DONTDUMP
RAM for the lifetime of the process.

With `--otp`: both the capsule and OTP key file are burned. HOTP
counter advances are kept in memory only (not persisted to disk).

> **Warning:** `--burn` cannot be undone. Use it only on single-use
> copies of the capsule provisioned specifically for this invocation.
> Do not use it on the operator's only copy.

### When to use what — decision matrix

| Your situation | Best approach | Why |
|----------------|--------------|-----|
| SSH to both hosts, ProxyJump works | `ssh -J serverX serverY` | Native SSH — end-to-end encrypted, jump host sees ciphertext, zero custom code. **Start here.** |
| ProxyJump blocked, only SSH port 22 | `urtb --exec "ssh X ssh Y socat..."` | Works with zero SSH forwarding features — only needs shell access on jump host |
| ProxyJump blocked + want defense in depth | `urtb --exec "ssh ..."` | Two independent crypto layers (URTB AEAD + SSH) |
| No IP path at all (radio) | `urtb listen/connect` over Heltec | URTB's core use case — ESP-NOW/LoRa radio |
| IP path, non-SSH ports open, no custom code | `socat + openssl` (mutual TLS) | Zero custom code, but needs open TLS port |
| IP path, only SSH, don't want custom code | `ssh -J` or nested `ssh` | If you just need a shell, plain SSH works |

**The restricted jump host scenario** (port 22 only, forwarding
disabled, possibly compromised) has exactly two solutions:

1. **`ssh -J`** if ProxyJump is allowed — simplest, native SSH
   crypto is end-to-end
2. **`urtb --exec`** if ProxyJump is blocked — works because it only
   needs "run a command" on the jump host, not any SSH forwarding
   feature. Adds URTB AEAD as a second crypto layer.

`socat + openssl`, WireGuard, Mosh, VPN — all require non-SSH ports
and are blocked by this scenario.

---

## What doesn't work (by design)

- **`ssh -J urtb-host target`** — URTB is not a SOCKS proxy or TCP
  forwarder. The jump is "shell on the bastion, then SSH from
  there," not a transport-layer proxy. Use `ssh` from inside the
  tunnel instead.

- **`scp local-file urtb-host:remote-path`** — No direct file
  transfer over URTB. Stage files by running `scp` or `rsync`
  *from inside* the URTB shell (the jump host's network).

- **SSH agent forwarding** — Works if the jump host has `ssh-agent`
  running. URTB passes the terminal I/O; the agent socket is on the
  jump host side, independent of URTB.

---

## Troubleshooting

**Password prompt doesn't appear:**
SSH needs a PTY to show the password prompt. If you're using
`socat - OPENSSL:...` (STDIO mode), SSH on the remote side may not
detect a terminal. Make sure the server-side socat uses
`EXEC:...,pty,stderr,setsid,sigint,sane`. URTB always allocates a
PTY via `forkpty`, so this is not an issue with URTB tunnels.

**"Permission denied" on key auth:**
The SSH key must be on the *jump host* (where the URTB listener
runs), not on your laptop. URTB gives you a shell on the jump host;
`ssh` runs there and looks for keys in that user's `~/.ssh/`.

**Slow first connection:**
The URTB handshake (CTRL_HELLO/ACK + key derivation) adds ~1-2
seconds. Subsequent SSH connections from the tunnel shell are
normal speed.

**Double hop hangs:**
If the target host shows a long MOTD (message of the day), the
shell may appear to hang. Create `~/.hushlogin` on the target user
account to suppress it, or just wait for the prompt.
