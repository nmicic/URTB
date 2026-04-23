/*
 * capsule_version_test.c — unit tests for capsule format versioning.
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers DECISIONS.md D-40. Must be built with -DURTB_TEST_V1_EMIT so
 * the v1 forward-compat case can emit a v1 fixture at test time rather
 * than checking in a binary.
 *
 * Build (see Makefile `tools/capsule_version_test` target):
 *   cc -Wall -Wextra -O2 -std=c11 -DURTB_TEST_V1_EMIT -I src -I src/vendor \
 *      -o tools/capsule_version_test tools/capsule_version_test.c \
 *      src/capsule.c src/crypto.c src/vendor/monocypher.c
 *
 * Run:
 *   tools/capsule_version_test       # prints PASS/FAIL per test, exit 0 = all pass
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "capsule.h"

static int  g_total;
static int  g_failed;

#define CHECK(name, cond) do { \
    g_total++; \
    if (!(cond)) { \
        g_failed++; \
        fprintf(stderr, "FAIL %s   (%s:%d)\n", (name), __FILE__, __LINE__); \
    } else { \
        printf("PASS %s\n", (name)); \
    } \
} while (0)

#define TEST_PASSPHRASE "capsule-version-test"

/* Fresh per-test path under a unique directory to avoid O_EXCL collisions. */
static char  g_tmpdir[256];

static void make_tmpdir(void)
{
    const char *base = getenv("TMPDIR");
    if (!base || !*base) base = "/tmp";
    snprintf(g_tmpdir, sizeof(g_tmpdir),
             "%s/urtb_capsule_version_test.%d", base, (int)getpid());
    /* Best-effort: if directory exists from a prior aborted run, reuse it. */
    if (mkdir(g_tmpdir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s): %s\n", g_tmpdir, strerror(errno));
        exit(2);
    }
}

static void tmp_path(char *out, size_t outlen, const char *name)
{
    snprintf(out, outlen, "%s/%s", g_tmpdir, name);
    (void)unlink(out);  /* ensure O_EXCL generate always sees a clean slot */
}

/* ------------------------------------------------------------------------- */
/* v2 round-trip: generate with channel N, load, assert channel out == N.    */
/* ------------------------------------------------------------------------- */

static void test_v2_roundtrip(uint8_t ch)
{
    char path[300];
    char name[64];
    snprintf(name, sizeof(name), "v2_ch%u.capsule", (unsigned)ch);
    tmp_path(path, sizeof(path), name);

    int rc_gen = capsule_generate(path, TEST_PASSPHRASE, ch);
    char label[128];
    snprintf(label, sizeof(label), "v2 generate ch=%u -> 0", (unsigned)ch);
    CHECK(label, rc_gen == 0);

    /* Verify header byte 4 == 0x02 (v2). */
    uint8_t hdr[5];
    int fd = open(path, O_RDONLY);
    CHECK("v2 open for header read", fd >= 0);
    if (fd >= 0) {
        ssize_t nr = read(fd, hdr, sizeof(hdr));
        CHECK("v2 read header bytes", nr == (ssize_t)sizeof(hdr));
        close(fd);
        snprintf(label, sizeof(label), "v2 header byte 4 == 0x02 (ch=%u)", (unsigned)ch);
        CHECK(label, hdr[4] == 0x02);
    }

    uint8_t psk[32]    = {0};
    uint8_t pair_id[4] = {0};
    uint8_t ch_out     = 0;
    int rc_load = capsule_load(path, TEST_PASSPHRASE, psk, pair_id, &ch_out);
    snprintf(label, sizeof(label), "v2 load ch=%u -> 0", (unsigned)ch);
    CHECK(label, rc_load == 0);

    snprintf(label, sizeof(label), "v2 load returns ch_out=%u", (unsigned)ch);
    CHECK(label, ch_out == ch);

    (void)unlink(path);
}

/* ------------------------------------------------------------------------- */
/* v2 generate rejects 0 and 14 (out of 1..13), writes no file.              */
/* ------------------------------------------------------------------------- */

static void test_v2_generate_rejects(uint8_t bad_ch, const char *label_suffix)
{
    char path[300];
    char name[64];
    snprintf(name, sizeof(name), "v2_bad_%u.capsule", (unsigned)bad_ch);
    tmp_path(path, sizeof(path), name);

    int rc = capsule_generate(path, TEST_PASSPHRASE, bad_ch);
    char label[128];
    snprintf(label, sizeof(label),
             "v2 generate rejects ch=%u (%s) -> -1",
             (unsigned)bad_ch, label_suffix);
    CHECK(label, rc == -1);

    /* No file should have been created. */
    struct stat st;
    int st_rc = stat(path, &st);
    snprintf(label, sizeof(label),
             "v2 generate ch=%u leaves no file on disk",
             (unsigned)bad_ch);
    CHECK(label, st_rc != 0 && errno == ENOENT);
}

/* ------------------------------------------------------------------------- */
/* v1 forward compat: shim-emit v1 capsule, load, assert channel = 6.        */
/* ------------------------------------------------------------------------- */

#ifdef URTB_TEST_V1_EMIT
static void test_v1_forward_compat(void)
{
    char path[300];
    tmp_path(path, sizeof(path), "v1_fixture.capsule");

    int rc_gen = capsule_generate_v1_testonly(path, TEST_PASSPHRASE);
    CHECK("v1 testonly generate -> 0", rc_gen == 0);

    /* Verify header byte 4 == 0x01 (v1). */
    uint8_t hdr[5];
    int fd = open(path, O_RDONLY);
    CHECK("v1 open for header read", fd >= 0);
    if (fd >= 0) {
        ssize_t nr = read(fd, hdr, sizeof(hdr));
        CHECK("v1 read header bytes", nr == (ssize_t)sizeof(hdr));
        close(fd);
        CHECK("v1 header byte 4 == 0x01", hdr[4] == 0x01);
    }

    uint8_t psk[32]    = {0};
    uint8_t pair_id[4] = {0};
    uint8_t ch_out     = 0;
    int rc_load = capsule_load(path, TEST_PASSPHRASE, psk, pair_id, &ch_out);
    CHECK("v1 load -> 0", rc_load == 0);

    /* Runtime assigns default channel = 6 for v1. */
    CHECK("v1 load returns ch_out == 6 (default)", ch_out == 6);

    (void)unlink(path);
}
#endif

/* ------------------------------------------------------------------------- */
/* Corrupted version byte rejected at pre-AEAD accept-list gate.
 *
 * Strategy: produce a valid v2 capsule, then overwrite header byte 4 with
 * 0xFF on disk. capsule_load() must refuse at the accept-list gate. The
 * AEAD would ALSO refuse this (version is in AD), but the accept-list is
 * the cheap early gate and must surface the refusal first.                 */
/* ------------------------------------------------------------------------- */

static void test_corrupted_version_byte(void)
{
    char path[300];
    tmp_path(path, sizeof(path), "v_ff.capsule");

    int rc_gen = capsule_generate(path, TEST_PASSPHRASE, 6);
    CHECK("forged-version fixture: generate v2 -> 0", rc_gen == 0);

    /* Overwrite the version byte (offset 4) with 0xFF. */
    int fd = open(path, O_RDWR);
    CHECK("forged-version fixture: open O_RDWR", fd >= 0);
    if (fd >= 0) {
        uint8_t bad = 0xFF;
        off_t seeked = lseek(fd, 4, SEEK_SET);
        CHECK("forged-version fixture: lseek to byte 4", seeked == 4);
        ssize_t nw = write(fd, &bad, 1);
        CHECK("forged-version fixture: wrote version byte 0xFF", nw == 1);
        close(fd);
    }

    uint8_t psk[32]    = {0};
    uint8_t pair_id[4] = {0};
    uint8_t ch_out     = 0;
    int rc_load = capsule_load(path, TEST_PASSPHRASE, psk, pair_id, &ch_out);
    CHECK("capsule_load rejects version byte 0xFF", rc_load == -1);

    (void)unlink(path);
}

/* ------------------------------------------------------------------------- */

int main(void)
{
    printf("capsule_version_test starting\n");
    make_tmpdir();

    /* Test list (DECISIONS.md D-40):
     *   - v2 round-trip with ch 1, 6 (default), 13
     *   - generate-path rejects ch 0 and ch 14
     *   - v1 forward-compat via URTB_TEST_V1_EMIT shim -> channel = 6
     *   - corrupted version byte 0xFF rejected pre-AEAD
     */
    test_v2_roundtrip(1);
    test_v2_roundtrip(6);
    test_v2_roundtrip(13);

    test_v2_generate_rejects(0,  "below range");
    test_v2_generate_rejects(14, "above range");

#ifdef URTB_TEST_V1_EMIT
    test_v1_forward_compat();
#else
    /* If this binary is ever built without the define, the v1 case is
     * not exercised — that would silently regress AC coverage. Fail loud. */
    fprintf(stderr, "FAIL: capsule_version_test built without "
                    "URTB_TEST_V1_EMIT — v1 forward-compat case is "
                    "unreachable\n");
    g_failed++;
    g_total++;
#endif

    test_corrupted_version_byte();

    (void)rmdir(g_tmpdir);

    printf("\n%d tests, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
