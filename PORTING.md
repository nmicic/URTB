# Porting URTB to other hardware

URTB has been developed and tested end-to-end on the **Heltec WiFi LoRa
32 V3** (ESP32-S3 + SX1262 + SSD1306). The host side is fully portable.
The firmware is not, but the porting cost is well-bounded and described
in the three layers below. This guide is honest about what works today
and what would have to be edited in place.

## Host side — already portable

The C source tree under `src/` is C11 + POSIX. It builds on any POSIX
system with `make CC=cc CFLAGS="-Wall -Wextra -std=c11 -O2"` and has
been verified clean on macOS (Apple Clang) and Linux (gcc, musl-gcc).
There is no board-specific code on the host. The serial framing
protocol (`USB_*` frame types in `src/transport_heltec.c`) is generic;
any device that speaks that framing protocol over a USB-serial link
will pair against the host without host-side changes.

## Firmware — three layers

The firmware lives under `firmware/src/main.cpp` as a single file. It
is built with PlatformIO, Arduino-ESP32 framework, RadioLib (for the
SX126x/SX127x families), and U8g2 (for the SSD1306 OLED). To port to
other hardware today, **fork `firmware/src/main.cpp` and edit it in
place** — there is no `firmware/boards/<name>.h` abstraction yet, and
this guide does not pretend otherwise. A future refactor could lift
the pin block and the radio constructor into a board header, but no
such file exists in this tree.

The three layers, from cheap to expensive:

### Layer 1 — Pin assignments (5 minutes per board)

The Heltec V3 pin assignments are at the top of `firmware/src/main.cpp`
around lines 45–51 (LoRa SPI) and 208–214 (OLED + Vext). Reproduced
here so you can see what to grep for:

```cpp
// firmware/src/main.cpp ~line 45
#define LORA_NSS   8
#define LORA_IRQ   14
#define LORA_NRST  12
#define LORA_BUSY  13
#define LORA_MOSI  10
#define LORA_MISO  11
#define LORA_SCK   9

// firmware/src/main.cpp ~line 208
#define OLED_SDA      17
#define OLED_SCL      18
#define OLED_RST      21
#define OLED_VEXT     36   // Heltec V3 OLED rail; pull LOW before u8g2.begin()
```

To port to another board, edit these `#define` lines in place to match
the new board's schematic. If the new board has no OLED, leave the
OLED defines alone but expect the `g_oled_present` gate inside `setup()`
to return false on `u8g2.begin()` and skip all draw calls — the OLED
panel is already optional at runtime, no further changes required to
get a headless build working.

`OLED_VEXT` is specific to Heltec V3 (the OLED rail is power-gated by
GPIO36). Boards that wire the OLED to permanent 3V3 should remove the
`pinMode(OLED_VEXT, OUTPUT) / digitalWrite(OLED_VEXT, LOW)` block in
`setup()` (around line 992). Boards that don't have any I2C OLED at
all can leave the block alone — `u8g2.begin()` returning false is
already handled.

### Layer 2 — Radio chip (SX1262 vs SX1276/SX1278)

The Heltec V3 uses an SX1262, constructed at `firmware/src/main.cpp`
line 135–136:

```cpp
static SPIClass loraSPI(FSPI);
static SX1262   radio = new Module(LORA_NSS, LORA_IRQ, LORA_NRST, LORA_BUSY, loraSPI);
```

SX1262 also requires two post-construction initialisations inside
`setup()` (line 1004–1005):

```cpp
radio.setDio2AsRfSwitch(true);   // DIO2 controls the RF switch
radio.setRegulatorDCDC();        // DC-DC regulator (vs LDO) for power
```

For an SX1276/SX1278 board (Heltec V1/V2, TTGO LoRa32 v1, older
T-Beam), replace the type and remove the SX1262-only setup calls:

```cpp
static SX1276 radio = new Module(LORA_NSS, LORA_IRQ, LORA_NRST, LORA_BUSY, loraSPI);
// no setDio2AsRfSwitch
// no setRegulatorDCDC
```

The `radio.begin()` parameter list differs slightly between the SX126x
and SX127x families — check the RadioLib API documentation for the
exact `begin()` signature on your radio chip and update the `begin()`
call inside `setup()` accordingly. SX1276 supports the same SF range
(SF7..SF12) but bandwidth and coding-rate options have minor
differences.

### Layer 3 — ESP-NOW (ESP32 / ESP8266 only)

URTB's failover design uses ESP-NOW as the primary transport and falls
back to LoRa when ESP-NOW becomes unreachable. ESP-NOW is an Espressif
proprietary protocol available **only on ESP32 and ESP8266 families**.
On any other MCU (nRF52, STM32, RP2040, etc.) ESP-NOW is not
available and there is no equivalent.

Boards in that category can still run URTB in **LoRa-only mode** with
no code change to the failover logic: cold-boot starts in
`XSTATE_ESPNOW_PRIMARY`, fails to find any ESP-NOW peer after
`FAILOVER_EMPTY_WINDOWS × WINDOW_MS = 6 s`, and transitions to
`XSTATE_LORA_FALLBACK` permanently. Throughput is bounded by the EU
g4 1 % duty cycle (≈8.6 frames/min at the 72-byte LoRa MTU); see the
`HOWTO.md` "LoRa mode — duty-cycle warning" section.

Stripping the ESP-NOW code path entirely (so a non-ESP32 board doesn't
have to drag in `WiFi.h` and the ESP-NOW callbacks) is more invasive
and would amount to deleting `handle_espnow_slot`, `pump_espnow_rx`,
the `XSTATE_ESPNOW_PRIMARY` branch of `window_tick`, and the failover
state machine. That refactor is not done today. A non-ESP32 port that
wants to be lean would need to do this work.

## Supported and tested boards

| Board | MCU | Radio | ESP-NOW | Display | Status |
|---|---|---|---|---|---|
| Heltec WiFi LoRa 32 V3 | ESP32-S3 | SX1262 | ✓ | SSD1306 | **Tested**, full E2E |
| Heltec WiFi LoRa 32 V2 | ESP32 | SX1276 | ✓ | SSD1306 | Untested, should work after Layer 1 + Layer 2 edit |
| Heltec Wireless Stick V3 | ESP32-S3 | SX1262 | ✓ | SSD1306 (smaller) | Untested, should work after Layer 1 edit |
| Heltec Wireless Stick Lite V3 | ESP32-S3 | SX1262 | ✓ | none | Untested, should work after Layer 1 edit (OLED gate handles missing panel) |
| LilyGO T-Beam (SX1262 variant) | ESP32 | SX1262 | ✓ | optional 0.96" | Untested, Layer 1 edit only |
| LilyGO T-Beam (SX1276 variant) | ESP32 | SX1276 | ✓ | optional 0.96" | Untested, Layer 1 + Layer 2 edit |
| LilyGO TTGO LoRa32 v1 | ESP32 | SX1276 | ✓ | SSD1306 | Untested, Layer 1 + Layer 2 edit |
| T-Echo | nRF52840 | SX1262 | ✗ | epaper | LoRa-only, untested, requires ESP-NOW removal for lean build |
| RAK4631 | nRF52840 | SX1262 | ✗ | none | LoRa-only, untested, requires ESP-NOW removal for lean build |
| Seeed LoRa-E5 | STM32WLE5 | integrated | ✗ | none | LoRa-only, untested, requires non-Arduino RadioLib backend |

"Untested" means nobody has run the firmware on this board. "Should
work after Layer X edit" describes the porting cost based on schematic
review only — no functional verification.

## Worked example: T-Beam SX1262 port

What follows is a **template** for porting to a LilyGO T-Beam with the
SX1262 radio module. The pin numbers below are **not yet verified
against a T-Beam SX1262 schematic** — confirm them against your
specific T-Beam revision before flashing. Treat this section as a
recipe for the porting workflow, not as a production-ready board file.

**Step 1 — edit the LoRa pin block** at `firmware/src/main.cpp` line 45:

```cpp
// T-Beam SX1262 (verify against your revision's schematic before flashing)
#define LORA_NSS   18
#define LORA_IRQ   33
#define LORA_NRST  23
#define LORA_BUSY  32
#define LORA_MOSI  27
#define LORA_MISO  19
#define LORA_SCK   5
```

**Step 2 — radio chip**: the SX1262 constructor is identical to
Heltec V3, so no Layer 2 change is required. Leave the
`radio.setDio2AsRfSwitch(true)` and `radio.setRegulatorDCDC()` calls
in place.

**Step 3 — OLED**: T-Beam variants vary. If your T-Beam has an SSD1306
on I2C 21/22 (the common case), edit lines 208–211 to:

```cpp
#define OLED_SDA      21
#define OLED_SCL      22
#define OLED_RST      U8X8_PIN_NONE   // T-Beam has no OLED reset line
#define OLED_VEXT     U8X8_PIN_NONE   // not power-gated on T-Beam
```

…and remove the Vext write block in `setup()` around line 992 (the
T-Beam OLED is on permanent 3V3, not a power-gated rail).

**Step 4 — `platformio.ini`**: add a new build environment alongside
the existing Heltec V3 entry. The existing `firmware/platformio.ini`
defines `[env:heltec_wifi_lora_32_V3]` — copy that block, rename it to
`[env:tbeam_sx1262]`, and change the `board =` line to the
PlatformIO board ID for your T-Beam variant (e.g. `ttgo-t-beam`).

**Step 5 — build and flash**:

```
pio run -e tbeam_sx1262 -t erase  --upload-port /dev/cu.SLAB_USBtoUART
pio run -e tbeam_sx1262 -t upload --upload-port /dev/cu.SLAB_USBtoUART
```

The erase step is cheap insurance on a first-time flash (cleans any
vendor test firmware or prior NVS state) and is required whenever you
re-flash across build envs or after pulling a new URTB release — see
HOWTO.md §Use case 2 for the full rationale.

Verify by running `urtb status --device /dev/cu.SLAB_USBtoUART` — a
working port returns the parsed status table. If the table comes back
with `transport: LoRa` and `--` for both RSSI fields, you have a
single board responsive over USB but no peer; flash a second board the
same way to validate the full pairing path.

## LoRa-only mode (for non-ESP32 hardware)

For a board that has no ESP-NOW capability (anything outside the ESP32
/ ESP8266 family), the runtime "fall through to LoRa" path already
described in Layer 3 is the easiest option: build with the existing
ESP-NOW code stubbed out at the function level (no calls reach the
hardware) and let the failover state machine settle into
`XSTATE_LORA_FALLBACK` on first boot. Performance will be capped by
the EU 1 % duty cycle.

A leaner port (no `WiFi.h`, no `esp_now.h` includes) requires deleting
the ESP-NOW code paths from `firmware/src/main.cpp`. Sketch:

- Delete `handle_espnow_slot`, `pump_espnow_rx`, the `WiFi.h` /
  `esp_now.h` includes, and the ESP-NOW init in `setup()`.
- In `window_tick`, remove the `XSTATE_ESPNOW_PRIMARY` arm of the
  switch and force the state machine into `XSTATE_LORA_FALLBACK` on
  boot.
- In `oled_redraw`, the "transport mode" line should always render
  `LoRa`.

This refactor is not in the tree today and is left as an exercise for
the porter.

## LoRa regional configuration

Default: EU868 band g4 (869.875 MHz, 7 dBm, 1% duty cycle).

| Region | Frequency | TX power | Duty cycle | Build flag |
|--------|-----------|----------|------------|------------|
| EU (default) | 869.875 MHz | 7 dBm | 1% (EU868 g4) | `make REGION=EU` |
| US | 915.000 MHz | 22 dBm | none | `make REGION=US` |
| Custom | any | any | check local law | `make LORA_FREQ_HZ=... LORA_TXPOWER=...` |

The `REGION` Makefile variable sets compile-time defaults via `-DURTB_LORA_FREQ_HZ`
and `-DURTB_LORA_TXPOWER`. These are carried to the firmware on every connect via
`USB_CONFIG` — no firmware rebuild is needed when changing region, only a host
rebuild. The firmware's own compile-time default (before the first `USB_CONFIG`
arrives) is always EU868; this matters only during the sub-second window between
firmware boot and the first host handshake.

**Legal note**: LoRa frequency allocations are jurisdiction-specific. Verify your
local regulations before transmitting. EU users: stay within EU868 band g4
(869.7-870.0 MHz, 1% duty cycle, ≤25 mW ERP; per ETSI EN 300 220-2). US users:
902-928 MHz ISM band, check FCC Part 15.247.

## Post-publish hardware notes

This section will accumulate confirmed working boards as community
ports come in. Pull requests with verified board pin tables, photos
of a working pairing, and (ideally) `urtb status` output from both
ends are welcome. As boards are confirmed they will be moved from
"Untested" to "Tested" in the table above.
