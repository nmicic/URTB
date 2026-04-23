/*
 * channel_pty.h — PTY channel handler (ch 1)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements channel_ops_t for chan 1 using the frame types defined in
 * PROTOCOL.md §5 (PTY_OPEN / PTY_OPEN_ACK / PTY_OPEN_ERR / PTY_DATA /
 * PTY_RESIZE / PTY_SIGNAL / PTY_EOF).
 */
#ifndef URTB_CHANNEL_PTY_H
#define URTB_CHANNEL_PTY_H

#include "channel.h"

/* Registered on both sides. Server spawns on PTY_OPEN; client enters raw
 * mode on PTY_OPEN_ACK. */
extern const channel_ops_t channel_pty;

/* Weak hook: called from channel_pty.c when the client receives
 * PTY_OPEN_ACK. main.c provides the implementation to enter raw mode.
 * If NULL, no raw-mode transition happens. */
typedef void (*channel_pty_on_ack_fn)(session_t *s);
extern channel_pty_on_ack_fn channel_pty_on_client_ack;

/* Called by session_run when PTY master fd is readable (server side).
 * Reads up to s->current_mtu bytes, wraps as PTY_DATA and sends encrypted.
 * On EOF/EIO: sends PTY_EOF + CTRL_CLOSE. */
int channel_pty_pump_master(session_t *s);

/* Called by session_run when stdin is readable (client side). Reads up to
 * s->current_mtu bytes and sends as PTY_DATA. Returns 0 on success, -1
 * on stdin EOF. */
int channel_pty_pump_stdin(session_t *s);

/* Flush the LoRa coalescing buffer as a single PTY_DATA frame (server). */
int channel_pty_flush_lora(session_t *s);

/* flush the server's PTY master write backlog when POLLOUT fires. */
int channel_pty_flush_master_backlog(session_t *s);

/* Helpers used by main.c on the client side. */
int channel_pty_client_send_open(session_t *s, uint16_t rows, uint16_t cols);
int channel_pty_client_send_resize(session_t *s, uint16_t rows, uint16_t cols);
int channel_pty_client_send_signal(session_t *s, uint8_t signum);

#endif /* URTB_CHANNEL_PTY_H */
