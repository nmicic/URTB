/*
 * test_inject.c — programmable RF failure injection control surface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Build: only linked when `make urtb URTB_TEST_INJECT=1`. The Makefile
 * conditionally appends this source. The production binary never compiles
 * or links this file; `nm urtb | grep -ci inject` returns 0.
 *
 * Wire format on the loopback control socket:
 *   2 bytes: [set_mask][clear_mask]
 *   New flags = (current & ~clear_mask) | set_mask
 * Reply: 1 byte = applied flag value (0xFF/0xFE on encode/write error).
 *
 * Security:
 *   - Unix socket bound under a 0177 umask and chmod'd 0600.
 *   - On accept, SO_PEERCRED (Linux) / LOCAL_PEERCRED (macOS) verifies the
 *     peer uid equals getuid(); cross-uid connect is rejected.
 *   - The control surface only carries flag bytes — no PSK, no payload, no
 *     command shell. There is no way for a peer to read or write keys.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "test_inject.h"

#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/ucred.h>
#ifndef SOL_LOCAL
#define SOL_LOCAL 0
#endif
#endif

#include "frame.h"

/* USB_TEST_INJECT type byte (PROTOCOL.md §1, test-only frames). */
#define USB_TEST_INJECT_TYPE 0x0B
#define TI_VALID_MASK        0x1F

static int      g_listen_fd      = -1;
static char     g_sock_path[128] = { 0 };
static uint8_t  g_current_flags  = 0;

static void make_sock_path(char *out, size_t out_sz, pid_t pid)
{
    snprintf(out, out_sz, "/tmp/urtb-inject-%d.sock", (int)pid);
}

int test_inject_setup(void)
{
    if (g_listen_fd >= 0) return 0;

    make_sock_path(g_sock_path, sizeof(g_sock_path), getpid());
    /* Best-effort cleanup of any stale socket from a prior crashed run. */
    unlink(g_sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("test_inject: socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "test_inject: socket path too long\n");
        close(fd);
        return -1;
    }
    strcpy(addr.sun_path, g_sock_path);

    /* Tighten umask before bind so the inode is created 0600 even on hosts
     * with a permissive default umask. Restore immediately after. */
    mode_t old_umask = umask(0177);
    int br = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved_errno = errno;
    umask(old_umask);
    if (br < 0) {
        errno = saved_errno;
        perror("test_inject: bind");
        close(fd);
        return -1;
    }
    /* Defense in depth: chmod explicitly. */
    if (chmod(g_sock_path, S_IRUSR | S_IWUSR) < 0) {
        perror("test_inject: chmod");
        close(fd);
        unlink(g_sock_path);
        g_sock_path[0] = 0;
        return -1;
    }

    if (listen(fd, 4) < 0) {
        perror("test_inject: listen");
        close(fd);
        unlink(g_sock_path);
        g_sock_path[0] = 0;
        return -1;
    }

    g_listen_fd = fd;
    g_current_flags = 0;
    fprintf(stderr, "test_inject: control socket %s (mode 0600)\n", g_sock_path);
    return 0;
}

int test_inject_listen_fd(void)
{
    return g_listen_fd;
}

void test_inject_teardown(void)
{
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_sock_path[0]) {
        unlink(g_sock_path);
        g_sock_path[0] = 0;
    }
}

/* Verify the connected peer is owned by our uid. Returns 0 on OK. */
static int peer_uid_check(int cfd)
{
#if defined(__linux__)
    struct ucred uc;
    socklen_t len = sizeof(uc);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &uc, &len) < 0) {
        perror("test_inject: SO_PEERCRED");
        return -1;
    }
    if (uc.uid != getuid()) return -1;
    return 0;
#elif defined(__APPLE__)
    struct xucred xuc;
    socklen_t len = sizeof(xuc);
    if (getsockopt(cfd, SOL_LOCAL, LOCAL_PEERCRED, &xuc, &len) < 0) {
        perror("test_inject: LOCAL_PEERCRED");
        return -1;
    }
    /* Reject any future xucred layout we have not been built against. */
    if (xuc.cr_version != XUCRED_VERSION) return -1;
    if (xuc.cr_uid != getuid()) return -1;
    return 0;
#else
    (void)cfd;
    /* Fail closed on unknown platforms. */
    return -1;
#endif
}

static int read_all(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n)
{
    size_t put = 0;
    while (put < n) {
        ssize_t r = write(fd, buf + put, n - put);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        put += (size_t)r;
    }
    return 0;
}

void test_inject_handle_accept(int serial_fd)
{
    if (g_listen_fd < 0) return;
    int cfd = accept(g_listen_fd, NULL, NULL);
    if (cfd < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            perror("test_inject: accept");
        }
        return;
    }

    if (peer_uid_check(cfd) != 0) {
        fprintf(stderr, "test_inject: rejected peer (uid mismatch)\n");
        close(cfd);
        return;
    }

    /* Bound how long a same-uid peer can stall the session loop by sending a
     * partial command. 2 s is well above any legitimate localhost RTT. */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    uint8_t cmd[2];
    if (read_all(cfd, cmd, 2) != 0) {
        fprintf(stderr, "test_inject: short command read\n");
        close(cfd);
        return;
    }
    uint8_t set_mask   = (uint8_t)(cmd[0] & TI_VALID_MASK);
    uint8_t clear_mask = (uint8_t)(cmd[1] & TI_VALID_MASK);
    uint8_t new_flags  = (uint8_t)((g_current_flags & ~clear_mask) | set_mask);

    uint8_t frame[USB_MAX_FRAME];
    int n = urtb_usb_encode(USB_TEST_INJECT_TYPE, 0, &new_flags, 1,
                            frame, sizeof(frame));
    if (n < 0) {
        const uint8_t err = 0xFF;
        write_all(cfd, &err, 1);
        close(cfd);
        return;
    }
    if (serial_fd < 0 || write_all(serial_fd, frame, (size_t)n) != 0) {
        const uint8_t err = 0xFE;
        write_all(cfd, &err, 1);
        close(cfd);
        return;
    }

    g_current_flags = new_flags;
    fprintf(stderr,
            "test_inject: applied flags=0x%02X (set=0x%02X clear=0x%02X)\n",
            new_flags, set_mask, clear_mask);
    write_all(cfd, &new_flags, 1);
    close(cfd);
}

/* -------------------------------------------------------------------------
 * `urtb test-inject --pid <pid> <verb>` subcommand
 * ---------------------------------------------------------------------- */

struct verb_map {
    const char *name;
    uint8_t set;
    uint8_t clear;
};

static const struct verb_map g_verbs[] = {
    { "espnow-down",     0x03, 0x00 },
    { "espnow-up",       0x00, 0x03 },
    { "lora-down",       0x0C, 0x00 },
    { "lora-up",         0x00, 0x0C },
    { "all-down",        0x0F, 0x00 },
    { "reset",           0x00, 0x1F },
    { "lora-low-power",  0x10, 0x00 },
    { "lora-full-power", 0x00, 0x10 },
    { NULL, 0, 0 }
};

static void print_help(void)
{
    fprintf(stderr,
        "Usage: urtb test-inject --pid <pid> <verb> [hex]\n"
        "Verbs:\n"
        "  espnow-down       set bits 0|1 (DROP_ESPNOW_TX|RX)\n"
        "  espnow-up         clear bits 0|1\n"
        "  lora-down         set bits 2|3 (DROP_LORA_TX|RX)\n"
        "  lora-up           clear bits 2|3\n"
        "  all-down          set bits 0..3\n"
        "  reset             clear all bits\n"
        "  lora-low-power    set bit 4\n"
        "  lora-full-power   clear bit 4\n"
        "  raw <hex>         replace flags with <hex> (e.g. raw 0x0F)\n");
}

int test_inject_subcommand(int argc, char *argv[])
{
    pid_t pid = 0;
    const char *verb = NULL;
    const char *raw_hex = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            pid = (pid_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        } else if (verb == NULL) {
            verb = argv[i];
        } else if (raw_hex == NULL) {
            raw_hex = argv[i];
        }
    }
    if (pid <= 0 || verb == NULL) {
        print_help();
        return 2;
    }

    uint8_t set_mask = 0, clear_mask = 0;
    if (strcmp(verb, "raw") == 0) {
        if (!raw_hex) { print_help(); return 2; }
        unsigned v = (unsigned)strtoul(raw_hex, NULL, 0);
        set_mask = (uint8_t)(v & TI_VALID_MASK);
        clear_mask = TI_VALID_MASK; /* replace semantics */
    } else {
        const struct verb_map *vm;
        for (vm = g_verbs; vm->name; vm++) {
            if (strcmp(vm->name, verb) == 0) {
                set_mask = vm->set;
                clear_mask = vm->clear;
                break;
            }
        }
        if (!vm->name) {
            fprintf(stderr, "test-inject: unknown verb '%s'\n", verb);
            print_help();
            return 2;
        }
    }

    char path[128];
    make_sock_path(path, sizeof(path), pid);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("test-inject: socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "test-inject: socket path too long\n");
        close(fd);
        return 1;
    }
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "test-inject: connect %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }
    uint8_t cmd[2] = { set_mask, clear_mask };
    if (write_all(fd, cmd, 2) != 0) {
        perror("test-inject: write");
        close(fd);
        return 1;
    }
    uint8_t reply = 0;
    if (read_all(fd, &reply, 1) != 0) {
        fprintf(stderr, "test-inject: no reply\n");
        close(fd);
        return 1;
    }
    close(fd);
    if (reply == 0xFF || reply == 0xFE) {
        fprintf(stderr, "test-inject: ERR (0x%02X)\n", reply);
        return 1;
    }
    fprintf(stderr, "test-inject: OK (flags=0x%02X)\n", reply);
    return 0;
}

#endif /* URTB_TEST_INJECT */
