#pragma once

// SAFETY: NEVER call display functions from loop() or from any RX/TX callback.
// Software I2C on GPIO17/18 blocks ~10-50ms per redraw and will break ESP-NOW
// symmetric RX (ref e279c05 regression). Boot draw is one-shot from setup()
// only. display_mark_dirty is intentionally undefined — any future attempt to
// re-add runtime redraws will be a compile error.
//
// Include-site guard: only translation units that explicitly opt in via
// `#define URTB_DISPLAY_SETUP_ONLY` before this include may use the API.
// This blocks RX/TX-callback files (transport_*.cpp, espnow handlers)
// from accidentally pulling in display calls.
#ifndef URTB_DISPLAY_SETUP_ONLY
#error "display.h is setup-only — define URTB_DISPLAY_SETUP_ONLY before include. NEVER include from loop()/RX-TX callback files (ref e279c05)."
#endif

void display_boot_init(void);
void display_boot_draw(const char *sha, const char *mac3);
