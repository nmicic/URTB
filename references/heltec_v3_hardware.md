# Heltec WiFi LoRa 32 V3 — Hardware Reference for URTB Firmware
# Source: ~/heltec_v3_scanner_ccomm/  and  heltec_proj1/src/main.cpp
# Date: 2026-04-15

---

## Pin definitions (SX1262 LoRa)

```cpp
#define LORA_NSS   8    /* SPI chip select */
#define LORA_IRQ   14   /* DIO1 interrupt */
#define LORA_NRST  12   /* reset */
#define LORA_BUSY  13   /* busy flag */
#define LORA_MOSI  10
#define LORA_MISO  11
#define LORA_SCK   9
```

## Pin definitions (OLED SSD1306)

```cpp
#define OLED_SDA   17
#define OLED_SCL   18
#define OLED_RST   21
#define VEXT_PIN   36   /* LOW = power ON */
```

OLED/U8g2 is allowed in `setup()` only. Init + one-shot boot draw before
`esp_wifi_init()`. NEVER call display functions from `loop()`, RX/TX callbacks,
or any code path on the hot path of session handshake — SW-I²C bit-bang blocks
for 10–50 ms per full redraw and will break ESP-NOW symmetric RX (ref `e279c05`).

---

## RadioLib initialization (SX1262)

```cpp
#include <RadioLib.h>
#include <SPI.h>

SPIClass loraSPI(FSPI);
SX1262 radio = new Module(LORA_NSS, LORA_IRQ, LORA_NRST, LORA_BUSY, loraSPI);

void setup() {
    Serial.begin(115200);

    loraSPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);

    /* Initialize at 869.875 MHz (EU g4 band, avoids Meshtastic 869.525 MHz) */
    /* SF7, BW125, CR4/5, sync word 0x12 (private network), preamble 8 */
    int state = radio.begin(869.875, 125.0, 7, 5, 0x12, 2, 8);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("Radio init failed: ");
        Serial.println(state);
        while (true) delay(1000);
    }

    /* Required for Heltec V3: DIO2 controls the RF switch */
    radio.setDio2AsRfSwitch(true);

    /* Use DC-DC regulator instead of LDO (more efficient, required for V3) */
    radio.setRegulatorDCDC();

    radio.standby();
}
```

### Key RadioLib parameters for URTB LoRa
```
Frequency:   869.875 MHz   (EU SRD g4, 1% duty cycle)
Bandwidth:   125 kHz       (BW125)
Spreading:   SF7           (shortest airtime, ~70ms for 100-byte frame)
Coding rate: 4/5 (CR5)
Sync word:   0x12          (private — different from LoRaWAN 0x34)
Preamble:    8 symbols
Power:       +2 dBm        (low, indoor range sufficient for primary use case)
```

### ESP-NOW initialization (in addition to LoRa)
```cpp
#include <esp_now.h>
#include <WiFi.h>

void espnow_init(void) {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init failed");
        return;
    }
    /* Register TX and RX callbacks */
    esp_now_register_send_cb(on_data_sent);
    esp_now_register_recv_cb(on_data_recv);
}
```

---

## platformio.ini

```ini
[env:heltec_wifi_lora_32_V3]
platform = espressif32
board = heltec_wifi_lora_32_V3
framework = arduino
monitor_speed = 115200
lib_deps =
    jgromes/RadioLib@^6.6.0
build_flags =
    -DRADIOLIB_DEBUG=0
    -DRADIOLIB_VERBOSE=0
```

Note: U8g2 is used for setup-only boot OLED display (see constraint above).
Note: `board = heltec_wifi_lora_32_V3` (not V2 — different pin layout).

---

## USB serial framing (host ↔ firmware)

USB baud rate: 115200 (host side: tcsetattr with B115200).
The Heltec V3 USB is CDC-ACM (appears as /dev/cu.usbserial-XXXX on macOS,
/dev/ttyUSB0 or /dev/ttyACM0 on Linux).

Frame format (see PROTOCOL.md §1):
```
MAGIC[2]  VER[1]  TYPE[1]  FLAGS[1]  LEN[2]  BODY[N]  CRC16[2]
```
CRC algorithm: CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect).

---

## Transport state machine (firmware side)

```
ESPNOW_PRIMARY:
  - All data TX via ESP-NOW
  - LoRa in receive mode only (no periodic probe)
  - Count 2s windows with no PAIR_ID-matching ESP-NOW RX
  - After 3 consecutive empty windows → switch to LORA_FALLBACK

LORA_FALLBACK:
  - All data TX via LoRa
  - Send ESP-NOW recovery probe every 2s (4-byte PAIR_ID-only frame)
  - Count 2s windows with ≥1 PAIR_ID-matching ESP-NOW frame
  - After 2 consecutive non-empty windows → switch back to ESPNOW_PRIMARY

Emit USB_STATUS_RSP to host on every transport switch (unsolicited).
```

---

## NVS (Non-Volatile Storage) for PAIR_ID

```cpp
#include <Preferences.h>

Preferences prefs;

void nvs_write_pair_id(const uint8_t pair_id[4]) {
    prefs.begin("urtb", false);  /* false = read/write */
    prefs.putBytes("pair_id", pair_id, 4);
    prefs.end();
}

bool nvs_read_pair_id(uint8_t pair_id[4]) {
    prefs.begin("urtb", true);   /* true = read-only */
    size_t n = prefs.getBytes("pair_id", pair_id, 4);
    prefs.end();
    return (n == 4);
}
```

On fresh device (never received USB_CONFIG), `nvs_read_pair_id()` returns false.
Return 0x00000000 in USB_HELLO_ACK.pair_id if not configured.

---

## Serial port open (host side, Linux/macOS)

```c
#include <termios.h>
#include <fcntl.h>

int serial_open(const char *device) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return -1;

    struct termios tty;
    tcgetattr(fd, &tty);
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);
    cfmakeraw(&tty);
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 1;   /* 100ms timeout per read */
    tcsetattr(fd, TCSANOW, &tty);

    /* Remove O_NONBLOCK after configuration */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    return fd;
}
```
