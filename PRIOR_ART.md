# URTB Prior Art — What Already Exists, What URTB Actually Adds
# Written: 2026-04-15

---

## The question

URTB builds an encrypted, authenticated, PTY-wrapped shell session that runs over a pair of Heltec V3 boards using ESP-NOW as the primary transport and LoRa as a fallback. Anyone familiar with the adjacent tooling will reasonably ask:

> "Reticulum already has `rnsh` — an encrypted remote shell that runs over LoRa via RNodes. Reticulum was tested on the same hardware. Why does URTB exist? Is this just re-implementing rnsh? And for the host-side layer, why not `socat + openssl` or `ssh` over a serial ProxyCommand like every sysadmin would?"

This document answers that question honestly. The short version:

- **On LoRa-only terminal access, Reticulum / `rnsh` is the correct prior art.** It works. It was validated end-to-end on the same hardware. If the requirement were "run a shell over LoRa and nothing else," URTB would not need to exist — the right answer would be `rnsh` plus a well-tuned RNode config.
- **On the host-side crypto + PTY layer, `socat + openssl` and `ssh` are prior art.** A rootless `socat OPENSSL-LISTEN:… EXEC:'/bin/bash',pty` one-liner replicates URTB's non-radio functionality in two shell commands.
- **URTB exists because of a combination that none of the above provide:** dual-radio with **ESP-NOW as primary** (fast, local, unregulated, interactive-usable) and **LoRa as fallback** (slow, ranged, regulated, emergency-only), with seamless mid-session failover between them on the same paired pair of boards. Reticulum does not have a first-class ESP-NOW interface. `rnsh` over LoRa is usable but, as measured on real hardware, **unusable for interactive terminal work** (200–500 ms per keystroke, 10–15 s to redraw `top`). The interactive-terminal experience only becomes viable on ESP-NOW.

This document exists so any future reviewer can see that the prior art was tested, measured, and consciously chosen against only for the dual-radio failover case — not because the building blocks did not exist.

---

## Prior art I: Reticulum / `rnsh` (LoRa-only terminal access)

### What it is

[Reticulum](https://reticulum.network/) is a cryptographic networking stack designed for radio and other constrained links. `rnsh` is its remote-shell utility: an identity-authenticated PTY session over a Reticulum link, with all the crypto, framing, and link management handled by Reticulum's core. It supports the RNodeInterface driver, which turns a Heltec V3 (or RNode, or T-Beam) into a LoRa modem controllable from Python.

### Measurements on real hardware

Summary of the numbers that matter here:

| Metric | Measured on SF7/BW125/CR4/5/869.875 MHz, two Heltec V3 boards |
|---|---|
| `rnsh` link establishment | Works end-to-end with identity-based auth (`-a` flag) |
| Per-keystroke round-trip | 200–500 ms |
| `top` full-screen refresh | 10–15 seconds |
| `htop` / `vim` / `man` | Unusable |
| Short commands (`date`, `id`, `ls` of small dir) | 1–3 seconds (acceptable) |
| Effective terminal throughput | ~200–400 bytes/second |
| Link setup (first connect) | 5–10 seconds |
| Duty-cycle concern | Continuous use will violate EU 868 MHz 1% cap |

These are not URTB's numbers — they are `rnsh`'s, with stock settings, on real hardware, in the same room. **`rnsh` is not broken.** It works exactly as designed. The bottleneck is LoRa itself.

### Why this is not enough for URTB's use case

For the kind of terminal session URTB is built for — typing interactively into a remote shell while doing something else on the same laptop — 200–500 ms keystroke RTT is unusable. `top -s 60` "works" but at 60-second refresh it is not a live monitoring tool. The issue is not `rnsh`'s design; it is LoRa's physical layer at any legal-power configuration in EU868.

The conclusion from hardware testing was explicit: **LoRa is the correct fallback, not the correct primary.** If we want interactive terminal work, we need ESP-NOW as the primary path. And that is where Reticulum does not cover us.

### What Reticulum does not have

Reticulum supports many interface types: RNode (LoRa), TCP, UDP, I²P, Pipe, Serial, AX.25, KISS. It does **not** have a first-class ESP-NOW interface. You could in principle write one (Reticulum interfaces are pluggable Python classes), but:

- ESP-NOW is not an "interface" in Reticulum's model — it is a link-layer broadcast-ish protocol that requires firmware-side support on the ESP32, and some kind of USB-side control channel to shuttle frames in and out of the Python host app. That is exactly what URTB's firmware does, so "writing a Reticulum ESP-NOW interface" would require most of URTB's firmware stack plus a Python shim on top.
- Reticulum's link and transport layers are designed for a mesh/routed model with many identities. URTB's threat model is intentionally simpler: two paired devices, one shared secret, no mesh, no routing, no identity discovery. A Reticulum link can do this but with more machinery than the use case requires.
- Reticulum sessions assume the interface stays put. URTB's failover story — "midway through a session, ESP-NOW degrades, the same session continues on LoRa without renegotiating, and when ESP-NOW returns we fail back" — is not a Reticulum primitive. You would have to tear down and re-establish the link on each transport switch.

**Honest framing:** if someone writes a Reticulum ESP-NOW interface in the future, a lot of URTB becomes redundant on top of Reticulum. That is a legitimate future direction and should be noted in `FUTURE.md`. Today, Reticulum + ESP-NOW does not exist as an off-the-shelf path, so URTB builds it directly.

### What about Meshtastic / Meshcore?

Both were looked at. Both were rejected for this specific use case.

- **Meshtastic** is optimized for short-text messaging over a store-and-forward mesh with optional MQTT gateways. In practice, most Meshtastic deployments rely on internet-bridged MQTT for any message that needs to travel beyond a single hop reliably. That directly defeats URTB's purpose — the whole point is an **out-of-band** path that does not depend on internet routing. An "out-of-band terminal that relies on MQTT over the internet" is not out-of-band. Meshtastic is great for what it is, it just is not trying to be a transparent terminal transport.
- **Meshcore** is closer to the "actual radio-first" design and was tested briefly. It is a promising mesh protocol and could plausibly host a terminal session in the future, but it is not a terminal transport today and does not have a `rnsh` equivalent. ESP-NOW is also not a native Meshcore interface.

So the landscape before URTB started was roughly:

| Tool | LoRa terminal | ESP-NOW terminal | Dual-radio failover | Works on paired Heltec V3 today |
|---|---|---|---|---|
| `rnsh` (Reticulum) | Yes (slow) | No | No | Yes |
| Meshtastic | No (messaging only) | No | No | Yes (as messenger) |
| Meshcore | Possible, not shipped | No | No | Partial |
| Plain `socat + openssl` over serial | Yes (irrelevant — only if you already have a byte pipe) | No native support | No | Only as a host-layer glue |
| `ssh` over serial ProxyCommand | Yes (same caveat) | No | No | Host-layer only |
| **URTB** | Yes (fallback only) | Yes (primary) | Yes | Yes |

The bottom row is the only one that fills the dual-radio interactive-terminal slot. That is the slot URTB is claiming.

---

## Prior art II: `socat + openssl` and `ssh` (host-layer, non-radio)

Everything URTB does on the **host** side — AEAD-encrypted tunnel, mutual auth via a pre-shared secret, PTY wrap, raw-mode client terminal, signal passing — has been a one-liner since roughly 2003. This section documents the off-the-shelf alternatives so that the scaffolding around the radio layer is not mistaken for novelty.

### (a) `socat + openssl` mutual-cert over TCP (closest non-radio analogue)

```bash
# one-time "pairing" (generate a single self-signed cert + key)
openssl req -x509 -newkey ed25519 -nodes -days 3650 \
  -keyout urtb.key -out urtb.pem \
  -subj "/CN=urtb-pair-0001"

# server side
socat OPENSSL-LISTEN:9443,reuseaddr,fork,\
cert=urtb.pem,key=urtb.key,cafile=urtb.pem,verify=1 \
      EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane,ctty

# client side
socat -,raw,echo=0,escape=0x1d \
      OPENSSL:server.example.com:9443,\
cert=urtb.pem,key=urtb.key,cafile=urtb.pem,verify=1
```

What you get: TLS 1.3 encrypted tunnel, mutual authentication via shared cert, a real PTY, raw-mode client terminal, `Ctrl-]` escape. Rootless on both ends. This is ~95% of URTB's host responsibilities in two shell commands.

### (b) `ssh` over a serial ProxyCommand

What a sysadmin would reach for if the physical layer were already in place:

```bash
# far side: bridge /dev/ttyUSB0 to localhost:22
socat /dev/ttyUSB0,b115200,raw,echo=0 TCP:127.0.0.1:22

# near side: connect as if it were a normal ssh target
ssh -o ProxyCommand='socat - /dev/ttyUSB0,raw,echo=0,b115200' \
    urtbuser@localhost
```

What you get: ssh's entire feature set (key auth, `ProxyJump`, port forwarding, `scp`/`sftp`, multiplexing) over a 115200-baud serial wire. This is the "why not ssh?" baseline. It works for any transport that can pretend to be a reliable byte pipe — and that is the catch. See the "Why not ssh?" subsection below for the radio-side reason.

### (c) `ncat --ssl` one-liner

Minimal version:

```bash
# server
ncat --ssl --ssl-cert urtb.pem --ssl-key urtb.key \
     -l 9443 --sh-exec "script -qc '/bin/bash -i' /dev/null"

# client
ncat --ssl --ssl-verify --ssl-trustfile urtb.pem \
     server.example.com 9443
```

### (d) Runnable demo

All of the above are wrapped into one self-contained script at [`tools/prior-art-demo.sh`](tools/prior-art-demo.sh). Modes: `setup`, `server`, `client`, `loopback` (single-machine end-to-end), `cable` (virtual null-modem with linked PTYs for simulating two ends of a serial cable without hardware), `clean`.

### Why not `ssh` over a radio link?

The `ssh` ProxyCommand trick works over any byte-clean bidirectional pipe — which LoRa is not. It needs:

- **Reliable delivery.** LoRa drops frames. SSH over a lossy byte stream breaks unpredictably; you need a link layer between ssh and the radio that retransmits lost frames and reassembles fragments. That link layer is precisely what URTB and Reticulum both implement, differently.
- **Reasonable handshake budget.** SSH's initial key exchange is ~1–2 KB before the first application byte. On LoRa at 8.6 frames/minute with 72-byte MTU, that is ~20 frames = ~2.5 minutes of handshake wall-clock at the sustained duty-cycle cap. Not impossible, but practically horrible.
- **Session-persistent transport.** SSH assumes the byte pipe does not change identity mid-session. ESP-NOW ↔ LoRa failover changes pacing and MTU mid-session, which SSH does not model.

On TCP or over a clean serial cable, `ssh` wins. On LoRa, `ssh` without a link layer underneath does not work in practice.

---

## Why URTB exists anyway: dual-radio with ESP-NOW primary

The slot URTB fills is not "terminal over LoRa" — `rnsh` already owns that, slowly. It is not "terminal over TCP" — `socat + openssl` or `ssh` already owns that, fast. It is the specific combination:

1. **ESP-NOW as the primary interactive path** — because ESP-NOW on the ESP32-S3 gives 1–2 Mbps throughput, <5 ms latency, and no duty-cycle limit, which is fast enough for a real touch-typing terminal experience over ~100–200 m indoors.
2. **LoRa as an emergency fallback** — because when ESP-NOW degrades (range exceeded, interference, the other side's WiFi chip is asleep), a usable-but-slow path still exists via LoRa on the same Heltec board, the same paired session, and the same shared secret.
3. **Seamless mid-session failover** — because tearing down and re-establishing the session each time the path changes is unusable. URTB's session key is transport-independent; failover changes MTU and pacing but does not restart the handshake. Neither `rnsh` nor `ssh` nor `socat + openssl` has this concept natively.
4. **One device model (Heltec V3)** — because both radios are already on the same board, so the whole thing runs on hardware the user already owns in quantity (we had many left over from prior Meshtastic / Meshcore / Reticulum experiments), and there is no second radio to provision.
5. **Paired-device threat model** — because the use case is two specific laptops the user controls, not a mesh with identity discovery. The Argon2id capsule + PSK model fits this directly; TLS PKI or Reticulum's identity model is more machinery than the use case asks for.

Remove any one of these and an off-the-shelf tool becomes the right answer:

- Remove the LoRa fallback → use `socat + openssl` or `ssh` on ESP-NOW alone (but then range collapses to ~100–200 m with no graceful degradation).
- Remove ESP-NOW primary → use `rnsh` on LoRa alone (but then interactive use is unusable, per hardware measurements).
- Remove the failover requirement → use `rnsh` and start a second session manually when the first dies (workable for occasional use, terrible for interactive work).
- Remove the paired-device constraint → use `ssh` with a normal CA-issued cert chain (but then you need PKI you do not want).

URTB exists at the intersection. Delete any axis and the intersection shrinks to a slot some existing tool already fills.

---

## The motivating use case: out-of-band terminal, VPN-independent

This is the scenario that made URTB worth building, and it should be in the documentation because it is not obvious from the protocol spec alone.

### The problem

A common restrictive-network setup:

- **Home server** on Tailscale (or WireGuard, or ZeroTier — any mesh VPN).
- **Client laptop** on a VPN-managed network that blocks additional VPNs or arbitrary outbound destinations.
- **Goal:** get a terminal from the client laptop to the home server without either (a) introducing a split tunnel, (b) routing personal traffic through third-party relay infrastructure, or (c) bridging the two networks at the IP layer.

Important distinction: technical feasibility is **not** policy approval. On an
employer-managed device, attaching an unapproved USB radio or running
unapproved software may violate local policy and can carry real consequences.
URTB is **not recommended** for that use unless it has been explicitly cleared
by the organization's security or IT team. This scenario is included to explain
the network-shape problem, not to suggest bypassing corporate controls.

The usual answers do not work:

- **SSH over the internet** requires the client network to allow outbound SSH to an arbitrary IP or to tolerate a split tunnel carve-out for a specific destination.
- **Tailscale / ZeroTier** requires the client laptop to run a second VPN client, which is often blocked by the primary VPN or by local policy.
- **Bastion host + cloud relay** works but puts the terminal session on somebody else's infrastructure and adds a latency hop.
- **Standalone physical-to-physical cable** works but requires the laptops to be within arm's reach of each other.

### The URTB answer

Two Heltec V3 boards, paired once in person. One plugs into the home server's USB; one plugs into the client laptop's USB. The two boards communicate over ESP-NOW (interactive speed) within ~100–200 m indoor range, with automatic LoRa fallback if the path degrades.

The critical property: **the link is not on the IP network.** It does not traverse either VPN. It does not care what network either laptop is on. It does not introduce a split tunnel, because the "tunnel" is a USB cable + radio + USB cable, not an IP route. From the client machine's network stack's perspective, there is no new routed interface at all — there is a USB serial device, and whatever the user types into `urtb connect` is interpreted as a shell session at the other end of that serial device.

From the garden, from the couch, from the next room: interactive shell on the home server without introducing a new IP path between the two machines. When ESP-NOW goes out of range (say, through three walls), LoRa takes over — you lose interactive speed but you still have a few commands' worth of path to the home box.

### Why this is worth documenting

Because every reviewer reading URTB's spec will ask "why not just SSH?" And "I am deliberately avoiding VPN entanglement, including the entanglement of using SSH over a VPN I cannot control" is not an answer the reader can derive from the protocol spec alone. Putting the use case here makes the design decisions self-justifying: the 72-byte MTU, the ESP-NOW primary path, the failover semantics, the paired-device threat model, the "no internet-facing surface" property — all of these follow directly from "I want an out-of-band terminal between two laptops I own, and I want it to not touch the network layer of either one."

---

## Feature-by-feature comparison

| Capability | URTB | rnsh (Reticulum/LoRa) | socat + openssl over TCP | ssh over serial ProxyCommand |
|---|---|---|---|---|
| **Works over LoRa** | Yes (fallback) | Yes (primary) | No | No |
| **Works over ESP-NOW** | **Yes (primary)** | No | No | No |
| **Works over clean byte pipe (TCP, USB, cable)** | Yes | Yes (via Pipe/TCP interface) | Yes | Yes |
| **Interactive keystroke latency on the designed primary path** | <50 ms (ESP-NOW) | 200–500 ms (LoRa, measured) | <10 ms (TCP) | <10 ms (cable) |
| **`top`/`htop`/`vim` usable on the primary path** | Yes (ESP-NOW) | No (measured) | Yes | Yes |
| **Mid-session transport failover (radio ↔ radio)** | **Yes** | No | No | No |
| **Duty-cycle-aware pacing / coalescing** | Yes | Partial (link-layer only) | N/A | N/A |
| **Encrypted channel** | XChaCha20-Poly1305 (direct over frame) | Reticulum stack (X25519 + AES-GCM) | TLS 1.3 (ChaCha20-Poly1305 / AES-GCM) | SSH (ChaCha20-Poly1305) |
| **Mutual authentication** | PSK in Argon2id capsule | Identity hashes | Mutual TLS with shared cert | SSH keys |
| **Forward secrecy** | No (future) | Yes | Yes (TLS 1.3 ECDHE) | Yes |
| **Offline passphrase hardening of key material** | Yes (Argon2id `t=3/m=64MB/p=1`) | Depends on identity storage | No (key file on disk) | Optional (passphrase on private key) |
| **Handshake size on the wire** | 72 B body (24 nonce + 32 pt + 16 tag) = 84 B radio frame | Several hundred bytes (Reticulum link setup) | ~300–500 B ClientHello, ~1.5 KB full handshake | ~1–2 KB |
| **Works with 72-byte MTU natively** | Yes | Yes (Reticulum handles fragmentation) | Would need ~10 fragments per handshake msg | Would need ~20 fragments |
| **Requires root / CAP_NET_ADMIN** | No | No | No | No |
| **Second VPN stack on client machine** | **No** | No | No | No |
| **Puts session on internet path** | No | No | No (if used over serial) | No (if used over serial) |
| **Single self-contained binary / no external daemon** | Yes (`urtb` CLI) | No (Python + Reticulum daemon) | No (socat + openssl) | No (openssh) |
| **Custom code surface to audit** | ~7100 lines of custom C (src/ ~6000 + firmware/src/main.cpp ~1050; justified by dual-radio + state machine + capsule + PTY) | ~0 (Reticulum is the auditor's burden) | ~0 | ~0 |
| **Mesh / multi-hop routing** | No (intentional) | Yes | No | No |
| **Identity discovery** | No (paired only) | Yes | No | No (known-host model) |
| **Terminal throughput on primary path (measured or estimated)** | >100 KB/s (ESP-NOW) | ~200–400 B/s (LoRa, measured) | Line-rate TCP | Line-rate serial |
| **Usable for out-of-band terminal from a restrictive client network** | **Yes (interactive)** | Marginal (slow commands only) | No (requires IP path) | No (requires byte pipe) |

Reading the table honestly:

- **`rnsh` beats URTB on LoRa terminal work in every dimension *except* latency**, and loses on latency specifically because LoRa's physics cap it there. `rnsh` has forward secrecy, a real identity model, a mature mesh story, and zero custom code to audit. If you have a LoRa-only use case, `rnsh` is the right answer. URTB does not compete with `rnsh` for that slot.
- **`socat + openssl` and `ssh` beat URTB on non-radio terminal work** in almost every dimension. Zero custom code, forward secrecy, enormous audit base. If you already have a clean IP path and do not need the SSH-only stdio relay or the radio failover model, these are the right answer. URTB does not compete with them for that slot either.
- **URTB wins in exactly one row:** "ESP-NOW as primary, with LoRa failover, on paired Heltec V3 hardware." That is the whole product.

---

## Radio math: why the off-the-shelf stacks break on LoRa specifically

Included for completeness. Skip if already convinced.

### MTU math

LoRa SF7/BW125 at EU868 puts the usable plaintext budget at **72 bytes per frame** after subtracting the 12-byte URTB radio header and 16-byte Poly1305 tag from the 100-byte SF7 payload. TLS 1.3's ClientHello is ~300–500 bytes; the full handshake is ~1.5 KB. Running TLS over a 72-byte MTU means fragmenting every handshake message into 5–20 LoRa frames and surviving the packet loss of broadcast LoRa mid-handshake. Technically possible with a link layer underneath; mechanically unpleasant with any stock TLS client.

URTB's CTRL_HELLO is 48 bytes plaintext + 16 byte AEAD tag = **one LoRa frame**.

### Duty-cycle math

EU868 g1 sub-band is capped at 1% duty cycle. A 100-byte frame at SF7/BW125 takes ~70 ms on-air. 1% duty cycle = 36 seconds of airtime per hour = ~514 frames per hour = **~8.6 frames per minute** sustained. That is the entire radio budget for everything: keepalives, PTY bytes, control frames, error frames.

A TLS 1.3 PSK handshake at ~1.5 KB ≈ 21 LoRa frames ≈ **~2.5 minutes of wall-clock** before the first application byte, consuming a quarter of the sustained budget just to say hello. URTB's entire handshake (CTRL_HELLO + CTRL_HELLO_ACK + 2× CTRL_READY) is **4 frames ≈ ~28 seconds at the sustained cap**, or sub-second if the budget is fresh.

`rnsh` over LoRa handles this correctly at the link-layer level — Reticulum does not try to run TLS over LoRa; it has its own framing. URTB's numbers are roughly in line with Reticulum's link setup overhead (5–10 s measured on the same hardware). The difference is that URTB shares the session key across transports, so the ESP-NOW → LoRa failover does not pay the link setup cost a second time.

### Throughput on the two transports

| Transport | Throughput (measured / typical) | Latency | Duty cycle | Practical terminal use |
|---|---|---|---|---|
| LoRa SF7/BW125 (measured) | ~200–400 B/s terminal-effective | 200–500 ms/keystroke | 1% EU868 | Slow commands only |
| ESP-NOW on ESP32-S3 | 1–2 Mbps | <5 ms | None | Full interactive, full-screen tools |
| Serial USB CDC-ACM (URTB ↔ Heltec host link) | 1 Mbit/s class | <1 ms | N/A | Full (not the bottleneck) |

ESP-NOW is ~4 orders of magnitude faster than LoRa for this use case. That gap is what makes interactive terminal work possible on ESP-NOW and not possible on LoRa. URTB's whole design rests on that gap: use the fast radio when it's there, fall back to the slow radio when it isn't, share the session across both so the user does not pay handshake cost on every transition.

---

## Verdict

Three separate verdicts, because the honest answer to "did you reinvent the wheel?" depends on which wheel.

### On the LoRa terminal path: yes, this is prior art.
Reticulum / `rnsh` already does encrypted remote shell over LoRa. It was tested on the same hardware before URTB was designed. It works. URTB's LoRa fallback is not a claim of novelty — it is a minimal implementation of the same idea, specialized to share a session key with the ESP-NOW path. On LoRa alone, `rnsh` is the better tool and this document recommends it for anyone whose use case is LoRa-only.

### On the host-side crypto + PTY layer: yes, this is prior art.
`socat + openssl` or `ssh` over a serial `ProxyCommand` replicates URTB's host layer in two shell commands. The runnable demo at `tools/prior-art-demo.sh` exists so anyone can see this for themselves. URTB's host layer is testing/integration scaffolding for the radio stack, not a novel terminal transport. For non-radio use with a clean IP path, `socat + openssl` is the right answer and this document recommends it.

### On dual-radio ESP-NOW primary + LoRa fallback + seamless failover on paired Heltec V3: no, this is not prior art.
None of the tools surveyed — rnsh, Meshtastic, Meshcore, socat+openssl, ssh, Tailscale, Mosh — implements this combination. The reason is not that the combination is hard to build, but that the use case is narrow enough that no one had built it: you need to want ESP-NOW specifically, and you need to want LoRa as a fallback on the same paired boards, and you need to want a session that survives the transport switch. URTB is built for a specific user (the author) with a specific use case (out-of-band VPN-independent terminal between two laptops he owns). That is the line of novelty. Everything on either side of that line is either prior art or out of scope.

---

## How to use this document

- See `SPEC.md` for URTB's scope and non-goals, and `FUTURE.md` for the
  note that a Reticulum ESP-NOW interface would make much of URTB's host
  layer redundant — a legitimate future direction.
- The comparison table above is structured so the row where URTB wins is
  one specific row, and the rows where URTB loses are labeled. The honest
  accounting is the strongest answer to the "why not rnsh?" question.

---

## Appendix: reference commands for the host-layer alternatives

Paste these after running `tools/prior-art-demo.sh setup` (which generates `urtb.pem` + `urtb.key`):

```bash
# (a) socat + openssl, TCP, mutual-cert PTY shell
#     server:
socat OPENSSL-LISTEN:9443,reuseaddr,fork,cert=urtb.pem,key=urtb.key,cafile=urtb.pem,verify=1 EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane,ctty
#     client:
socat -,raw,echo=0,escape=0x1d OPENSSL:127.0.0.1:9443,cert=urtb.pem,key=urtb.key,cafile=urtb.pem,verify=1

# (b) ncat --ssl one-liner
#     server:
ncat --ssl --ssl-cert urtb.pem --ssl-key urtb.key -l 9443 --sh-exec "script -qc '/bin/bash -i' /dev/null"
#     client:
ncat --ssl --ssl-verify --ssl-trustfile urtb.pem 127.0.0.1 9443

# (c) ssh over a serial cable (assuming far side bridges tty ↔ localhost:22)
ssh -o ProxyCommand='socat - /dev/ttyUSB0,raw,echo=0,b115200' user@localhost

# (d) virtual null-modem for loopback testing
socat -d -d PTY,link=/tmp/tty-a,raw,echo=0 PTY,link=/tmp/tty-b,raw,echo=0

# (e) rnsh over LoRa (stock Reticulum install with RNodeInterface configured)
#     server:
rnsh -l -a ALLOWED_IDENTITY_HASH
#     client:
rnsh TARGET_DESTINATION_HASH
```

None of the first four require root. None require any custom code. All were possible in 2003. `rnsh` is newer but also off-the-shelf, also rootless, and also correctly designed for its use case. URTB does not compete with any of these on their own turf. It competes only in the dual-radio failover slot where none of them reach.
