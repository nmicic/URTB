/*
 * test_inject.h — programmable RF failure injection control surface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * The header is empty unless URTB_TEST_INJECT is defined and non-zero, so
 * including it from production code is a no-op. The Makefile only links
 * test_inject.c when URTB_TEST_INJECT=1 — the prod binary has no inject
 * symbols at all (nm | grep inject == 0).
 */
#ifndef URTB_TEST_INJECT_H
#define URTB_TEST_INJECT_H

#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT

#include <sys/types.h>

/* Open the control unix socket /tmp/urtb-inject-<getpid()>.sock with mode
 * 0600. Returns 0 on success, -1 on failure. Idempotent. */
int  test_inject_setup(void);

/* Returns the listen fd (or -1 if setup not called). The session loop polls
 * this fd alongside the transport fd. */
int  test_inject_listen_fd(void);

/* Accept one pending connection, validate SO_PEERCRED (peer uid == getuid()),
 * read a 2-byte (set_mask, clear_mask) command, apply sticky semantics to
 * the running flag byte, write a USB_TEST_INJECT frame to serial_fd, send
 * the ack byte back to the peer, and close the accepted fd. */
void test_inject_handle_accept(int serial_fd);

/* Unlink the socket and close the listen fd. */
void test_inject_teardown(void);

/* `urtb test-inject --pid <pid> <verb>` subcommand entry point. */
int  test_inject_subcommand(int argc, char *argv[]);

#endif /* URTB_TEST_INJECT */
#endif /* URTB_TEST_INJECT_H */
