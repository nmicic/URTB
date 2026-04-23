/*
 * URTB Phase B-1 Heltec V3 firmware — dumb radio modem.
 *
 * Responsibilities (per prompts/phase-b1-firmware.md, DECISIONS.md D-03/D-19/D-20):
 *   - Parse / generate URTB USB frames over the USB CDC serial port.
 *   - Bridge USB_DATA_TX (host->fw) onto the active radio (ESP-NOW or LoRa).
 *   - Forward radio frames matching the configured PAIR_ID to the host as USB_DATA_RX.
 *   - Run the failover state machine (ESPNOW_PRIMARY <-> LORA_FALLBACK) based purely
 *     on received-frame counts; emit unsolicited USB_STATUS_RSP on every transition.
 *   - Generate 4-byte ESP-NOW recovery probes every 2 s while in LORA_FALLBACK.
 *
 * The firmware NEVER:
 *   - Decrypts, encrypts, or holds keys.
 *   - Generates application channel frames (CTRL_KEEPALIVE, etc.).
 *   - Inspects ciphertext or AEAD tags.
 *   - Retries failed radio TX.
 *
 * Build: PlatformIO, env heltec_wifi_lora_32_V3, RadioLib >= 6.6.0.
 */

#include <Arduino.h>
#include <Preferences.h>
#include <RadioLib.h>
#include <SPI.h>
#include <WiFi.h>
#include <esp_mac.h>
#include <esp_now.h>
#include <esp_wifi.h>

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define URTB_DISPLAY_SETUP_ONLY  /* main.cpp owns the boot OLED — see display.h */
#include "display.h"

#ifndef URTB_GIT_SHA
#define URTB_GIT_SHA "unknown"
#endif

/* ------------------------------------------------------------------------- */
/* Pin map and radio configuration (references/heltec_v3_hardware.md)        */
/* ------------------------------------------------------------------------- */

#define LORA_NSS   8
#define LORA_IRQ   14
#define LORA_NRST  12
#define LORA_BUSY  13
#define LORA_MOSI  10
#define LORA_MISO  11
#define LORA_SCK   9

#ifndef URTB_FW_VERSION_MAJOR
#define URTB_FW_VERSION_MAJOR 0
#endif
#ifndef URTB_FW_VERSION_MINOR
#define URTB_FW_VERSION_MINOR 1
#endif
#ifndef URTB_FW_VERSION_PATCH
#define URTB_FW_VERSION_PATCH 0
#endif

/* ------------------------------------------------------------------------- */
/* USB frame protocol constants (PROTOCOL.md §1)                              */
/* ------------------------------------------------------------------------- */

#define USB_MAGIC0          0xAB
#define USB_MAGIC1          0xCD
#define USB_VER             0x01

#define USB_DATA_TX         0x01
#define USB_DATA_RX         0x02
#define USB_STATUS_REQ      0x03
#define USB_STATUS_RSP      0x04
#define USB_HELLO           0x05
#define USB_HELLO_ACK       0x06
#define USB_CONFIG          0x07
#define USB_CONFIG_ACK      0x08
#define USB_ERROR           0x09
#define USB_RESET           0x0A
/* Test-only: programmable RF failure injection (PROTOCOL.md §1, "Test-only
 * frames"). Type byte 0x0B is reserved for URTB_TEST_INJECT. In production
 * builds the dispatcher does NOT have a case for this and falls through to
 * the default ERR_SESSION ("unknown type") path. */
#define USB_TEST_INJECT     0x0B

#ifndef URTB_TEST_INJECT
#define URTB_TEST_INJECT 0
#endif

#define USB_HEADER_LEN      7
#define USB_TRAILER_LEN     2
#define USB_OVERHEAD        9
#define USB_MAX_BODY        510
#define USB_MAX_FRAME       519

/* error codes mirror PROTOCOL.md §4 */
#define ERR_VERSION         0x0003
#define ERR_SESSION         0x0005
#define ERR_RESOURCE        0x0006
#define ERR_TIMEOUT         0x0007

/* ------------------------------------------------------------------------- */
/* Radio frame constants (PROTOCOL.md §2)                                     */
/* ------------------------------------------------------------------------- */

#define RADIO_HEADER_LEN    12
#define RADIO_TAG_LEN       16
#define RADIO_MIN_LEN       (RADIO_HEADER_LEN + RADIO_TAG_LEN) /* 28 */
#define RADIO_PROBE_LEN     4    /* PAIR_ID-only recovery probe */
#define RADIO_MAX_LEN       250  /* ESP-NOW MTU */

/* Capability flags returned in USB_HELLO_ACK */
#define CAPS_ESPNOW         0x01
#define CAPS_LORA           0x02

/* ------------------------------------------------------------------------- */
/* Failover state machine (D-13/D-14)                                        */
/* ------------------------------------------------------------------------- */

enum TransportState : uint8_t {
    XSTATE_ESPNOW_PRIMARY = 0,
    XSTATE_LORA_FALLBACK  = 1,
};

#define WINDOW_MS              2000
#define FAILOVER_EMPTY_WINDOWS 3   /* ESP-NOW -> LoRa */
#define FAILBACK_FULL_WINDOWS  2   /* LoRa -> ESP-NOW */
#define PROBE_PERIOD_MS        2000

/* ------------------------------------------------------------------------- */
/* Global state                                                              */
/* ------------------------------------------------------------------------- */

static SPIClass loraSPI(FSPI);
static SX1262   radio = new Module(LORA_NSS, LORA_IRQ, LORA_NRST, LORA_BUSY, loraSPI);

static Preferences prefs;

/* PAIR_ID is the only bit of "configuration" persisted to NVS.
 * g_pair_id_set / g_peer_mac_set are written from the loop task and read
 * from the WiFi task ESP-NOW callback — must be volatile. */
static uint8_t          g_pair_id[4]      = { 0, 0, 0, 0 };
static volatile bool    g_pair_id_set     = false;

static uint8_t          g_peer_mac[6]     = { 0, 0, 0, 0, 0, 0 };
static volatile bool    g_peer_mac_set    = false;
static uint8_t          g_espnow_channel  = 1;

/* LoRa radio params, applied lazily on USB_CONFIG. */
static uint32_t g_lora_freq_hz    = 869875000UL;
static uint8_t  g_lora_sf         = 7;
static uint8_t  g_lora_bw_code    = 7;     /* 125 kHz */
static uint8_t  g_lora_cr         = 5;
static uint8_t  g_lora_txpower    = 7;

/* Stats counters. ESP-NOW counters are written from the WiFi task send
 * callback and read from the loop task — guarded by a portMUX. The LoRa
 * counters and RSSI/SNR are loop-task only. */
static portMUX_TYPE g_stat_mux = portMUX_INITIALIZER_UNLOCKED;
static uint16_t g_espnow_tx_ok   = 0;
static uint16_t g_espnow_tx_fail = 0;
static uint16_t g_lora_tx_ok     = 0;
static uint16_t g_lora_tx_fail   = 0;
static int8_t   g_espnow_rssi    = 0;
static int8_t   g_lora_rssi      = 0;
static int8_t   g_lora_snr       = 0;

/* Failover state. */
static TransportState g_xstate              = XSTATE_ESPNOW_PRIMARY;
static uint32_t       g_window_start_ms     = 0;
static uint16_t       g_espnow_rx_in_window = 0;
static uint8_t        g_empty_espnow_windows = 0;
static uint8_t        g_full_espnow_windows  = 0;
static uint32_t       g_last_probe_ms       = 0;

/* USB RX assembly buffer. */
static uint8_t  g_rx_buf[USB_MAX_FRAME];
static size_t   g_rx_len = 0;

/* ESP-NOW callback ring (single-producer ESP-NOW callback / single-consumer
 * loop task). Drop-newest on full: only the producer writes head, only the
 * consumer writes tail — strict SPSC. */
#define ESPNOW_RING_SLOTS 8
struct EspnowRingSlot {
    uint8_t  data[RADIO_MAX_LEN];
    uint16_t len;
    int8_t   rssi;
};
static EspnowRingSlot   g_espnow_ring[ESPNOW_RING_SLOTS];
static volatile uint8_t g_espnow_ring_head = 0;  /* producer (callback) */
static volatile uint8_t g_espnow_ring_tail = 0;  /* consumer (loop)     */
static volatile uint16_t g_espnow_ring_drop = 0; /* incremented by producer on full */

/* LoRa RX flag set in the IRQ. */
static volatile bool g_lora_rx_flag = false;
static void IRAM_ATTR on_lora_irq() { g_lora_rx_flag = true; }

/* ------------------------------------------------------------------------- */
/* Test-only: programmable RF failure injection flags                        */
/* ------------------------------------------------------------------------- */
#if URTB_TEST_INJECT
/* Bits in g_test_inject_flags (USB_TEST_INJECT body[0]):
 *   bit 0 — DROP_ESPNOW_TX  : esp_now_send wrapper short-circuits, counts fail
 *   bit 1 — DROP_ESPNOW_RX  : on_espnow_recv ignores incoming frame
 *   bit 2 — DROP_LORA_TX    : radio.transmit is skipped, counts fail
 *   bit 3 — DROP_LORA_RX    : pump_lora_rx clears flag without forwarding
 *   bit 4 — LORA_LOW_POWER  : setOutputPower(2) instead of (14)
 *   bit 5..7 reserved (must be 0)
 *
 * Sticky: once set, bits remain in effect until cleared by another
 * USB_TEST_INJECT or until reboot. Written from the loop task and read from
 * the WiFi callback task — use __atomic_{load,store}_n for the race. */
#define TI_DROP_ESPNOW_TX   (1u << 0)
#define TI_DROP_ESPNOW_RX   (1u << 1)
#define TI_DROP_LORA_TX     (1u << 2)
#define TI_DROP_LORA_RX     (1u << 3)
#define TI_LORA_LOW_POWER   (1u << 4)
#define TI_VALID_MASK       0x1Fu

static volatile uint8_t g_test_inject_flags = 0;
#endif

/* ------------------------------------------------------------------------- */
/* CRC-16/CCITT-FALSE                                                        */
/* ------------------------------------------------------------------------- */

static uint16_t crc16_ccitt_false(const uint8_t *buf, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ------------------------------------------------------------------------- */
/* USB framing — encode + send                                                */
/* ------------------------------------------------------------------------- */

static void usb_send_frame(uint8_t type, const uint8_t *body, size_t body_len) {
    if (body_len > USB_MAX_BODY) return;

    uint8_t hdr[USB_HEADER_LEN];
    hdr[0] = USB_MAGIC0;
    hdr[1] = USB_MAGIC1;
    hdr[2] = USB_VER;
    hdr[3] = type;
    hdr[4] = 0; /* flags reserved */
    hdr[5] = (uint8_t)(body_len & 0xFF);
    hdr[6] = (uint8_t)((body_len >> 8) & 0xFF);

    uint16_t crc = crc16_ccitt_false(hdr, USB_HEADER_LEN);
    /* Continue CRC over body without re-initialising — concatenate by feeding
     * body bytes through the same FSM. */
    for (size_t i = 0; i < body_len; i++) {
        crc ^= (uint16_t)body[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }

    uint8_t crc_bytes[2] = { (uint8_t)(crc & 0xFF), (uint8_t)((crc >> 8) & 0xFF) };
    Serial.write(hdr, USB_HEADER_LEN);
    if (body_len) Serial.write(body, body_len);
    Serial.write(crc_bytes, 2);
}

static void usb_send_error(uint16_t code) {
    uint8_t body[4];
    body[0] = (uint8_t)(code & 0xFF);
    body[1] = (uint8_t)((code >> 8) & 0xFF);
    body[2] = 0;
    body[3] = 0;
    usb_send_frame(USB_ERROR, body, sizeof(body));
}

/* ------------------------------------------------------------------------- */
/* USB_HELLO_ACK / USB_STATUS_RSP / USB_CONFIG_ACK responses                 */
/* ------------------------------------------------------------------------- */

static void usb_send_hello_ack() {
    uint8_t body[32] = { 0 };
    body[0] = URTB_FW_VERSION_MAJOR;
    body[1] = URTB_FW_VERSION_MINOR;
    body[2] = URTB_FW_VERSION_PATCH;
    body[3] = CAPS_ESPNOW | CAPS_LORA;
    if (g_pair_id_set) memcpy(body + 4, g_pair_id, 4);
    /* else leave 0x00000000 — fresh device per spec */
    usb_send_frame(USB_HELLO_ACK, body, sizeof(body));
}

static void usb_send_status_rsp() {
    /* Snapshot ESP-NOW counters under the stat mux (written by WiFi task). */
    uint16_t etxok, etxfail, edrop;
    portENTER_CRITICAL(&g_stat_mux);
    etxok   = g_espnow_tx_ok;
    etxfail = g_espnow_tx_fail;
    edrop   = g_espnow_ring_drop;
    portEXIT_CRITICAL(&g_stat_mux);

    /* Packed 16-byte struct (PROTOCOL.md §1). Build bytewise — no struct
     * packing assumptions. */
    uint8_t body[16] = { 0 };
    body[0]  = (uint8_t)g_xstate;
    body[1]  = (uint8_t)g_espnow_rssi;
    body[2]  = (uint8_t)g_lora_rssi;
    body[3]  = (uint8_t)g_lora_snr;
    body[4]  = (uint8_t)(etxok           & 0xFF);
    body[5]  = (uint8_t)((etxok   >> 8)  & 0xFF);
    body[6]  = (uint8_t)(etxfail         & 0xFF);
    body[7]  = (uint8_t)((etxfail >> 8)  & 0xFF);
    body[8]  = (uint8_t)(g_lora_tx_ok         & 0xFF);
    body[9]  = (uint8_t)((g_lora_tx_ok>>8)    & 0xFF);
    body[10] = (uint8_t)(g_lora_tx_fail       & 0xFF);
    body[11] = (uint8_t)((g_lora_tx_fail>>8)  & 0xFF);
    /* bytes 12-13 are espnow_ring_drop (documented in PROTOCOL.md §1
     * USB_STATUS_RSP). Bytes 14-15 are reserved = 0. */
    body[12] = (uint8_t)(edrop        & 0xFF);
    body[13] = (uint8_t)((edrop >> 8) & 0xFF);
    /* body[14..15] reserved = 0 */
    usb_send_frame(USB_STATUS_RSP, body, sizeof(body));
}

static void usb_send_config_ack() {
    usb_send_frame(USB_CONFIG_ACK, NULL, 0);
}

/* ------------------------------------------------------------------------- */
/* NVS PAIR_ID                                                               */
/* ------------------------------------------------------------------------- */

static void nvs_load_pair_id() {
    prefs.begin("urtb", true /* read-only */);
    size_t n = prefs.getBytesLength("pair_id");
    if (n == 4) {
        prefs.getBytes("pair_id", g_pair_id, 4);
        g_pair_id_set = (g_pair_id[0] || g_pair_id[1] || g_pair_id[2] || g_pair_id[3]);
    }
    prefs.end();
}

static void nvs_save_pair_id(const uint8_t pid[4]) {
    /* Idempotent: skip the flash write if the value matches what is already
     * persisted (avoid wear under repeated USB_CONFIG). */
    prefs.begin("urtb", true /* read-only */);
    uint8_t cur[4] = { 0, 0, 0, 0 };
    bool has = prefs.getBytesLength("pair_id") == 4;
    if (has) prefs.getBytes("pair_id", cur, 4);
    prefs.end();
    if (has && memcmp(cur, pid, 4) == 0) return;

    prefs.begin("urtb", false /* read/write */);
    prefs.putBytes("pair_id", pid, 4);
    prefs.end();
}

/* ------------------------------------------------------------------------- */
/* LoRa configuration                                                        */
/* ------------------------------------------------------------------------- */

static float lora_bw_code_to_khz(uint8_t code) {
    switch (code) {
    case 0: return 7.8f;
    case 1: return 10.4f;
    case 2: return 15.6f;
    case 3: return 20.8f;
    case 4: return 31.25f;
    case 5: return 41.7f;
    case 6: return 62.5f;
    case 7: return 125.0f;
    case 8: return 250.0f;
    case 9: return 500.0f;
    default: return 125.0f;
    }
}

static void lora_apply_config() {
    /* Reconfigure must be done from STANDBY — RadioLib does not guarantee
     * setFrequency/etc are safe while SX1262 is in active RX. */
    radio.standby();
    radio.setFrequency((float)g_lora_freq_hz / 1e6f);
    radio.setBandwidth(lora_bw_code_to_khz(g_lora_bw_code));
    radio.setSpreadingFactor(g_lora_sf);
    radio.setCodingRate(g_lora_cr);
    radio.setOutputPower((int8_t)g_lora_txpower);
    radio.startReceive();
}

/* ------------------------------------------------------------------------- */
/* ESP-NOW                                                                   */
/* ------------------------------------------------------------------------- */

/* on_espnow_recv runs in the WiFi task context (NOT a hardware ISR).
 * Constraints: must not block, must not call Serial/Preferences/printf,
 * must not allocate. Strict SPSC: only writes head, never tail. */
static void on_espnow_recv(const uint8_t *mac_addr, const uint8_t *data, int len) {
    (void)mac_addr;
#if URTB_TEST_INJECT
    if (__atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED) & TI_DROP_ESPNOW_RX) {
        return;
    }
#endif
    if (len <= 0 || len > RADIO_MAX_LEN) return;
    /* Drop frames with the wrong PAIR_ID at ingress.
     * Probes (len == 4) MUST have the configured PAIR_ID — they are the
     * first 4 bytes of the radio header in any other valid frame. */
    if (!g_pair_id_set) return;
    if (len < 4) return;
    if (memcmp(data, g_pair_id, 4) != 0) return;

    uint8_t head = g_espnow_ring_head;
    uint8_t next = (uint8_t)((head + 1) % ESPNOW_RING_SLOTS);
    if (next == g_espnow_ring_tail) {
        /* Ring full — drop newest. Producer NEVER writes tail. */
        portENTER_CRITICAL_ISR(&g_stat_mux);
        g_espnow_ring_drop++;
        portEXIT_CRITICAL_ISR(&g_stat_mux);
        return;
    }
    EspnowRingSlot &slot = g_espnow_ring[head];
    memcpy(slot.data, data, (size_t)len);
    slot.len  = (uint16_t)len;
    slot.rssi = 0;  /* RSSI from ESP-NOW callback varies by IDF version; leave 0 */
    /* Release fence: ensure all slot writes are visible before we publish
     * the head update to the consumer running on the other core. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    g_espnow_ring_head = next;
}

static void on_espnow_send(const uint8_t *mac_addr, esp_now_send_status_t status) {
    (void)mac_addr;
    portENTER_CRITICAL_ISR(&g_stat_mux);
    if (status == ESP_NOW_SEND_SUCCESS) g_espnow_tx_ok++;
    else                                g_espnow_tx_fail++;
    portEXIT_CRITICAL_ISR(&g_stat_mux);
}

static bool espnow_register_peer() {
    if (!g_peer_mac_set) return false;
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, g_peer_mac, 6);
    peer.channel = g_espnow_channel;
    peer.encrypt = false;
    if (esp_now_is_peer_exist(g_peer_mac)) {
        esp_now_del_peer(g_peer_mac);
    }
    return esp_now_add_peer(&peer) == ESP_OK;
}

static void espnow_init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    if (esp_now_init() != ESP_OK) return;
    esp_now_register_recv_cb(on_espnow_recv);
    esp_now_register_send_cb(on_espnow_send);
}

/* ------------------------------------------------------------------------- */
/* Radio TX                                                                  */
/* ------------------------------------------------------------------------- */

/* RADIO_LORA_MAX_LEN: defence-in-depth cap on LoRa-mode frame length.
 * The host enforces a 72 B plaintext LoRa MTU + 12 B radio header + 16 B
 * AEAD tag = 100 B on-air. A buggy or misconfigured host could otherwise
 * hand the firmware a 250 B frame (the ESP-NOW MTU) in LoRa mode and burn
 * ~500 ms of airtime per transmission, eating the EU868 g4 1 % duty
 * budget.  (). */
#define RADIO_LORA_MAX_LEN  100

static void radio_tx_active(const uint8_t *frame, size_t len) {
    if (len < RADIO_MIN_LEN || len > RADIO_MAX_LEN) {
        usb_send_error(ERR_RESOURCE);
        return;
    }
    if (g_xstate == XSTATE_LORA_FALLBACK && len > RADIO_LORA_MAX_LEN) {
        usb_send_error(ERR_RESOURCE);
        return;
    }
    if (g_xstate == XSTATE_ESPNOW_PRIMARY) {
        if (!g_peer_mac_set) {
            g_espnow_tx_fail++;
            usb_send_error(ERR_SESSION);
            return;
        }
#if URTB_TEST_INJECT
        if (__atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED) & TI_DROP_ESPNOW_TX) {
            /* Pretend we transmitted, but no bytes hit the air. Bump the fail
             * counter for USB_STATUS_RSP parity; failover itself is driven by
             * the empty-RX-window detector in window_tick(), not by this counter. */
            g_espnow_tx_fail++;
            return;
        }
#endif
        esp_err_t r = esp_now_send(g_peer_mac, frame, len);
        if (r != ESP_OK) g_espnow_tx_fail++;
    } else {
#if URTB_TEST_INJECT
        if (__atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED) & TI_DROP_LORA_TX) {
            g_lora_tx_fail++;
            /* Approximate SF7/125 kHz airtime for a short frame (~50 ms). Not
             * length-scaled — this is loop-pacing, not byte-accurate timing. */
            delay(50);
            return;
        }
#endif
        int s = radio.transmit((uint8_t *)frame, (size_t)len);
        if (s == RADIOLIB_ERR_NONE) g_lora_tx_ok++;
        else                        g_lora_tx_fail++;
        /* SX1262 shares one FIFO for TX and RX. The DIO1 IRQ also fires on
         * TX_DONE (RadioLib's blocking transmit() restores the user IRQ
         * action before returning), so g_lora_rx_flag is left set. If we do
         * not clear it, the next pump_lora_rx() reads getPacketLength() /
         * readData() against the still-populated TX FIFO and forwards our
         * own just-transmitted frame back to the host as USB_DATA_RX, causing
         * the host session to "see" its own CTRL_HELLO. Clear the flag here
         * so only true RX_DONE IRQs after startReceive() trigger ingress. */
        g_lora_rx_flag = false;
        radio.startReceive();
    }
}

/* ------------------------------------------------------------------------- */
/* USB frame dispatch                                                        */
/* ------------------------------------------------------------------------- */

static void handle_usb_data_tx(const uint8_t *body, size_t body_len) {
    if (!g_pair_id_set) {
        /* Per PROTOCOL.md §1: USB_DATA_TX before USB_CONFIG_ACK -> ERR_SESSION. */
        usb_send_error(ERR_SESSION);
        return;
    }
    radio_tx_active(body, body_len);
}

#if URTB_TEST_INJECT
/* USB_TEST_INJECT handler. Body = 1 byte of new flag bits.
 *
 * Reserved bits 5..7 in the request body are masked off so a well-formed test
 * tool can never accidentally enable an undefined bit.
 *
 * The volatile g_test_inject_flags is written here from the loop task and read
 * from the WiFi callback task (on_espnow_recv). Use __atomic_store_n(RELAXED)
 * for a single-byte coherent publish — no acquire/release needed because the
 * flag affects only its own value, not other state.
 *
 * On LORA_LOW_POWER bit transition, call radio.setOutputPower(2 or 14). The
 * SX1262 setOutputPower from the loop task is safe (RadioLib transitions the
 * chip via standby/IRQ); we do not touch the IRQ line. */
static void handle_usb_test_inject(const uint8_t *body, size_t body_len) {
    if (body_len != 1) {
        usb_send_error(ERR_SESSION);
        return;
    }
    uint8_t new_flags = (uint8_t)(body[0] & TI_VALID_MASK);
    uint8_t old_flags = __atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED);
    __atomic_store_n(&g_test_inject_flags, new_flags, __ATOMIC_RELAXED);

    if ((old_flags ^ new_flags) & TI_LORA_LOW_POWER) {
        /* Bracket the reconfigure with standby/startReceive, matching the
         * invariant documented in lora_apply_config(): SX1262 reconfigure
         * paths must not run while the chip is in active RX. */
        radio.standby();
        if (new_flags & TI_LORA_LOW_POWER) {
            radio.setOutputPower(2);
        } else {
            radio.setOutputPower(14);
        }
        radio.startReceive();
    }
    /* Echo the now-active flag byte back to the host as ACK. */
    usb_send_frame(USB_TEST_INJECT, &new_flags, 1);
}
#endif /* URTB_TEST_INJECT */

static void handle_usb_config(const uint8_t *body, size_t body_len) {
    if (body_len != 20) {
        usb_send_error(ERR_SESSION);
        return;
    }
    /* Reject the all-zero PAIR_ID: it would mirror any radio frame whose
     * first 4 bytes are zero and bypass the configured-pair gate. */
    if (body[0] == 0 && body[1] == 0 && body[2] == 0 && body[3] == 0) {
        usb_send_error(ERR_SESSION);
        return;
    }
    /* Range-validate radio params before applying. */
    uint8_t  sf      = body[8];
    uint8_t  bw_code = body[9];
    uint8_t  cr      = body[10];
    uint8_t  txp     = body[11];
    uint8_t  ch      = body[18];
    if (sf < 7 || sf > 12)        { usb_send_error(ERR_RESOURCE); return; }
    if (bw_code > 9)              { usb_send_error(ERR_RESOURCE); return; }
    if (cr < 5 || cr > 8)         { usb_send_error(ERR_RESOURCE); return; }
    if (txp < 2 || txp > 22)      { usb_send_error(ERR_RESOURCE); return; }
    if (ch < 1 || ch > 13)        { usb_send_error(ERR_RESOURCE); return; }

    memcpy(g_pair_id, body + 0, 4);
    g_pair_id_set = true;
    nvs_save_pair_id(g_pair_id);

    g_lora_freq_hz   = (uint32_t)body[4]
                     | ((uint32_t)body[5] << 8)
                     | ((uint32_t)body[6] << 16)
                     | ((uint32_t)body[7] << 24);
    g_lora_sf        = sf;
    g_lora_bw_code   = bw_code;
    g_lora_cr        = cr;
    g_lora_txpower   = txp;
    memcpy(g_peer_mac, body + 12, 6);
    g_peer_mac_set   = true;
    g_espnow_channel = ch;
    /* body[19] reserved */

    /* ESP-NOW only TX/RX on the STA's currently-tuned channel. Tune the
     * STA radio explicitly before peer registration. */
    esp_wifi_set_channel(g_espnow_channel, WIFI_SECOND_CHAN_NONE);
    lora_apply_config();
    espnow_register_peer();

    usb_send_config_ack();
}

static void handle_usb_frame(const uint8_t *frame, size_t total) {
    if (total < USB_OVERHEAD) { usb_send_error(ERR_SESSION); return; }
    if (frame[0] != USB_MAGIC0 || frame[1] != USB_MAGIC1) return;
    if (frame[2] != USB_VER) { usb_send_error(ERR_VERSION); return; }

    uint8_t  type     = frame[3];
    size_t   body_len = (size_t)frame[5] | ((size_t)frame[6] << 8);
    if (body_len > USB_MAX_BODY)      { usb_send_error(ERR_SESSION); return; }
    if (USB_OVERHEAD + body_len != total) { usb_send_error(ERR_SESSION); return; }

    uint16_t want = crc16_ccitt_false(frame, USB_HEADER_LEN + body_len);
    uint16_t got  = (uint16_t)frame[USB_HEADER_LEN + body_len + 0]
                  | ((uint16_t)frame[USB_HEADER_LEN + body_len + 1] << 8);
    if (want != got) {
        /* Layer-1 CRC mismatch: drop silently per spec, no host notification. */
        return;
    }

    const uint8_t *body = frame + USB_HEADER_LEN;
    switch (type) {
    case USB_HELLO:
        usb_send_hello_ack();
        break;
    case USB_CONFIG:
        handle_usb_config(body, body_len);
        break;
    case USB_STATUS_REQ:
        usb_send_status_rsp();
        break;
    case USB_DATA_TX:
        handle_usb_data_tx(body, body_len);
        break;
#if URTB_TEST_INJECT
    case USB_TEST_INJECT:
        handle_usb_test_inject(body, body_len);
        break;
#endif
    case USB_RESET:
        Serial.flush();
        delay(50);
        ESP.restart();
        break;
    default:
        usb_send_error(ERR_SESSION);
        break;
    }
}

/* ------------------------------------------------------------------------- */
/* USB serial assembly state machine                                         */
/* ------------------------------------------------------------------------- */

static void usb_pump() {
    while (Serial.available() > 0) {
        int c = Serial.read();
        if (c < 0) break;
        if (g_rx_len >= sizeof(g_rx_buf)) {
            /* Overflow: full hard resync. Discarding partial state is safe —
             * a corrupted in-flight frame can never be rescued. */
            g_rx_len = 0;
        }
        g_rx_buf[g_rx_len++] = (uint8_t)c;

        /* Resync on magic at byte 0 / byte 1 */
        if (g_rx_len == 1 && g_rx_buf[0] != USB_MAGIC0) { g_rx_len = 0; continue; }
        if (g_rx_len == 2 && g_rx_buf[1] != USB_MAGIC1) {
            /* Slide one byte and re-check. */
            g_rx_buf[0] = g_rx_buf[1];
            g_rx_len = 1;
            if (g_rx_buf[0] != USB_MAGIC0) g_rx_len = 0;
            continue;
        }

        if (g_rx_len < USB_HEADER_LEN) continue;
        size_t body_len = (size_t)g_rx_buf[5] | ((size_t)g_rx_buf[6] << 8);
        if (body_len > USB_MAX_BODY) {
            /* Bogus length — full hard resync (partial buffer is unrecoverable
             * once we've passed the magic-check bytes). */
            g_rx_len = 0;
            continue;
        }
        size_t total = USB_HEADER_LEN + body_len + USB_TRAILER_LEN;
        if (g_rx_len < total) continue;

        handle_usb_frame(g_rx_buf, total);

        /* Consume frame from buffer. */
        size_t leftover = g_rx_len - total;
        if (leftover) memmove(g_rx_buf, g_rx_buf + total, leftover);
        g_rx_len = leftover;
    }
}

/* ------------------------------------------------------------------------- */
/* Failover state machine                                                    */
/* ------------------------------------------------------------------------- */

static void window_tick(uint32_t now) {
    /* Catch up across multiple skipped windows if loop() was delayed. */
    while ((uint32_t)(now - g_window_start_ms) >= WINDOW_MS) {
        g_window_start_ms += WINDOW_MS;

        if (g_espnow_rx_in_window > 0) {
            g_empty_espnow_windows = 0;
            g_full_espnow_windows  = (uint8_t)(g_full_espnow_windows + 1);
            if (g_full_espnow_windows > FAILBACK_FULL_WINDOWS) {
                g_full_espnow_windows = FAILBACK_FULL_WINDOWS;
            }
        } else {
            g_full_espnow_windows = 0;
            g_empty_espnow_windows = (uint8_t)(g_empty_espnow_windows + 1);
            if (g_empty_espnow_windows > FAILOVER_EMPTY_WINDOWS) {
                g_empty_espnow_windows = FAILOVER_EMPTY_WINDOWS;
            }
        }
        g_espnow_rx_in_window = 0;

        if (g_xstate == XSTATE_ESPNOW_PRIMARY
            && g_empty_espnow_windows >= FAILOVER_EMPTY_WINDOWS) {
            g_xstate               = XSTATE_LORA_FALLBACK;
            g_full_espnow_windows  = 0;
            g_empty_espnow_windows = 0;
            usb_send_status_rsp();
        } else if (g_xstate == XSTATE_LORA_FALLBACK
                   && g_full_espnow_windows >= FAILBACK_FULL_WINDOWS) {
            g_xstate               = XSTATE_ESPNOW_PRIMARY;
            g_full_espnow_windows  = 0;
            g_empty_espnow_windows = 0;
            usb_send_status_rsp();
        }
    }
}

/* ------------------------------------------------------------------------- */
/* RX handlers                                                               */
/* ------------------------------------------------------------------------- */

static void handle_espnow_slot(const EspnowRingSlot &slot) {
    if (slot.len == RADIO_PROBE_LEN) {
        /* Recovery probe: count for failback, do NOT forward to host. */
        g_espnow_rx_in_window++;
        return;
    }
    if (slot.len < RADIO_MIN_LEN) {
        /* Length 1..3 or 5..27: malformed — drop without counting. */
        return;
    }
    /* PAIR_ID already verified in the ISR. */
    g_espnow_rssi = slot.rssi;
    g_espnow_rx_in_window++;
    usb_send_frame(USB_DATA_RX, slot.data, slot.len);
}

static void pump_espnow_ring() {
    /* Loop-task only — uses a file-scope buffer to avoid a 256-byte stack
     * snapshot per iteration. */
    static EspnowRingSlot snapshot;
    while (g_espnow_ring_tail != g_espnow_ring_head) {
        /* Acquire fence pairs with the producer's release fence: ensures
         * slot fields are fully visible before we read them. */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        memcpy(&snapshot, &g_espnow_ring[g_espnow_ring_tail], sizeof(snapshot));
        g_espnow_ring_tail = (uint8_t)((g_espnow_ring_tail + 1) % ESPNOW_RING_SLOTS);
        handle_espnow_slot(snapshot);
    }
}

static void pump_lora_rx() {
    if (!g_lora_rx_flag) return;
#if URTB_TEST_INJECT
    if (__atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED) & TI_DROP_LORA_RX) {
        /* Drop the RX without forwarding to the host. Re-arm the radio so the
         * SX1262 keeps listening. */
        g_lora_rx_flag = false;
        radio.startReceive();
        return;
    }
#endif
    g_lora_rx_flag = false;

    uint8_t buf[RADIO_MAX_LEN];
    size_t  len = radio.getPacketLength();
    if (len == 0 || len > sizeof(buf)) {
        radio.startReceive();
        return;
    }
    int s = radio.readData(buf, len);
    if (s != RADIOLIB_ERR_NONE) {
        radio.startReceive();
        return;
    }
    radio.startReceive();

    /* PAIR_ID gate */
    if (!g_pair_id_set || len < RADIO_MIN_LEN) return;
    if (memcmp(buf, g_pair_id, 4) != 0)         return;

    {
        long snr10 = lroundf(radio.getSNR() * 10.0f);
        if (snr10 < -128) snr10 = -128;
        if (snr10 >  127) snr10 =  127;
        g_lora_snr = (int8_t)snr10;
    }
    g_lora_rssi = (int8_t)radio.getRSSI();
    /* LoRa frames count for failover separately is unnecessary — only ESP-NOW
     * frame counts gate the state transition (D-14). */
    usb_send_frame(USB_DATA_RX, buf, len);
}

/* ------------------------------------------------------------------------- */
/* Recovery probe TX                                                         */
/* ------------------------------------------------------------------------- */

static void maybe_send_probe(uint32_t now) {
    if (g_xstate != XSTATE_LORA_FALLBACK) return;
    if (!g_pair_id_set || !g_peer_mac_set) return;
    if (now - g_last_probe_ms < PROBE_PERIOD_MS) return;
#if URTB_TEST_INJECT
    /* Recovery probe bypasses radio_tx_active(), so the DROP_ESPNOW_TX
     * inject must be honored here too — otherwise the peer keeps seeing
     * our PAIR_ID heartbeat and never fails over. */
    if (__atomic_load_n(&g_test_inject_flags, __ATOMIC_RELAXED) & TI_DROP_ESPNOW_TX) {
        g_last_probe_ms = now;
        return;
    }
#endif
    g_last_probe_ms = now;
    /* 4-byte PAIR_ID-only frame, intentionally below the protocol layer. */
    esp_now_send(g_peer_mac, g_pair_id, RADIO_PROBE_LEN);
}

/* ------------------------------------------------------------------------- */
/* Setup + loop                                                              */
/* ------------------------------------------------------------------------- */

void setup() {
    Serial.begin(115200);
    delay(50);

    /* Static-only boot display: runs before WiFi/radio init so I2C activity
     * on GPIO17/18 cannot interfere with the ESP-NOW handshake. */
    {
        uint8_t mac[6] = { 0 };
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        char mac3[9];
        snprintf(mac3, sizeof(mac3), "%02X:%02X:%02X", mac[3], mac[4], mac[5]);
        display_boot_init();
        display_boot_draw(URTB_GIT_SHA, mac3);
    }

    nvs_load_pair_id();

    loraSPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
    int s = radio.begin(869.875f, 125.0f, 7, 5, 0x12, 2, 8);
    if (s == RADIOLIB_ERR_NONE) {
        radio.setDio2AsRfSwitch(true);
        radio.setRegulatorDCDC();
        radio.setDio1Action(on_lora_irq);
        radio.startReceive();
    }

    espnow_init();
    /* Re-assert default channel after OLED Vext/I2C activity in case it
     * perturbed WiFi radio state. USB_CONFIG will override with the real
     * channel when the host connects. */
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

    g_window_start_ms = millis();
    g_last_probe_ms   = millis();
    g_xstate          = XSTATE_ESPNOW_PRIMARY;
}

void loop() {
    usb_pump();
    pump_espnow_ring();
    pump_lora_rx();

    uint32_t now = millis();
    window_tick(now);
    maybe_send_probe(now);

    /* Yield so the FreeRTOS idle/IDLE-WDT task gets time even under sustained
     * USB ingress + blocking LoRa TX. */
    yield();
}
