// SAFETY: NEVER call I2C / display functions from loop() or from any
// RX/TX callback. Software I2C on GPIO17/18 blocks ~10-50ms per full
// redraw and will break ESP-NOW symmetric RX (ref e279c05 regression).
// If you need runtime display updates, put them on core 1 in a
// FreeRTOS task with a >=500ms floor — do NOT mark-dirty from loop().

#define URTB_DISPLAY_SETUP_ONLY  /* implementation TU — see display.h */
#include "display.h"
#include <U8g2lib.h>
#include <Arduino.h>
#include <stdio.h>

// Heltec V3 OLED wiring (references/heltec_v3_hardware.md)
#define OLED_SDA   17
#define OLED_SCL   18
#define OLED_RST   21
#define OLED_VEXT  36  // active-LOW: LOW = VEXT rail on

// Use software I2C to avoid the U8g2 hw-I2C-on-ESP32-S3 quirk where
// u8g2.begin() calls Wire.begin() with no pins, clobbering any prior
// Wire.begin(SDA, SCL) setup. SW I2C drives GPIO directly.
// Constructor: (rotation, clock, data, reset)
static U8G2_SSD1306_128X64_NONAME_F_SW_I2C u8g2(
    U8G2_R0, /*clock=*/OLED_SCL, /*data=*/OLED_SDA, /*reset=*/OLED_RST);

static bool g_oled_present = false;

void display_boot_init(void) {
    pinMode(OLED_VEXT, OUTPUT);
    digitalWrite(OLED_VEXT, LOW);  // enable VEXT rail
    delay(50);
    g_oled_present = u8g2.begin();
    if (g_oled_present) {
        u8g2.clearBuffer();
        u8g2.sendBuffer();
    }
}

void display_boot_draw(const char *sha, const char *mac3) {
    if (!g_oled_present) return;

    char line2[32];
    char line3[32];
    // "<sha>  <build-date>" — __DATE__ is e.g. "Apr 17 2026"
    snprintf(line2, sizeof(line2), "%.7s  %.11s", sha, __DATE__);
    // "MAC ....:XX:YY:ZZ"
    snprintf(line3, sizeof(line3), "MAC ....:%.8s", mac3);

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 12, "URTB");
    u8g2.drawStr(0, 26, line2);
    u8g2.drawStr(0, 40, line3);
    u8g2.drawStr(0, 54, "ready");
    u8g2.sendBuffer();
}
