# URTB Phase B Makefile
# Builds:
#   ./urtb              host application binary (Phase B-2+)
#   tools/frame_test    Phase B-0 wire-format & crypto test harness

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -std=c11 -O2
LDFLAGS ?=

#  (): tighten the warning baseline. Appended (not assigned) so
# they survive a `make CFLAGS=...` override on the command line.
#   -Wsign-compare:  catches signed/unsigned comparisons (size_t vs int loops)
#   -Wformat=2:      catches printf format/argument mismatches the default misses
# -Wconversion is gated behind `make WCONV=1` because cleaning the existing
# size_t→int / int→uint8_t sites is a follow-up pass; see DECISIONS.md.
CFLAGS  += -Wsign-compare -Wformat=2
ifdef WCONV
  CFLAGS += -Wconversion
endif

# Sanitizer build: `make test ASAN=1` (or `make urtb ASAN=1`).
# On Linux this enables AddressSanitizer + LeakSanitizer + UBSan; on
# macOS Apple Clang ships ASAN and UBSan but not LeakSanitizer (use
# `make leaks` for the macOS leak-detection equivalent via leaks(1)).
# Coverage scope: `make test` runs tools/frame_test only, which exercises
# wire format, crypto, and reassembler — session/PTY/transport paths
# are not covered by ASAN here. Use the ASAN-built `urtb` binary
# directly for end-to-end ASAN coverage of the runtime paths.
ifdef ASAN
  ifeq ($(shell uname),Darwin)
    CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
    LDFLAGS += -fsanitize=address,undefined
  else
    CFLAGS  += -fsanitize=address,leak,undefined -fno-omit-frame-pointer
    LDFLAGS += -fsanitize=address,leak,undefined
  endif
endif
# macOS ships forkpty in libSystem; no -lutil needed (and -lutil does not exist).
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LDLIBS  ?=
else
LDLIBS  ?= -lutil
endif

VENDOR  := src/vendor
INC     := -I$(VENDOR) -Isrc

# --------------------------------------------------------------------------
# URTB_DEFS — Makefile-owned preprocessor defines.
#
# IMPORTANT: Do NOT use CFLAGS += for project defines. If the user passes
# CFLAGS="..." on the command line, Make treats CFLAGS as an override and
# any in-Makefile CFLAGS += assignments are silently ignored. URTB_DEFS is
# always appended to compile commands regardless of command-line CFLAGS.
# --------------------------------------------------------------------------
URTB_DEFS :=

# LoRa regional defaults — override with: make REGION=US  or  make REGION=EU
# Custom: make LORA_FREQ_HZ=433175000 LORA_TXPOWER=10
REGION ?= EU
ifeq ($(REGION),US)
  LORA_FREQ_HZ  ?= 915000000
  LORA_TXPOWER  ?= 22
else ifeq ($(REGION),EU)
  LORA_FREQ_HZ  ?= 869875000
  LORA_TXPOWER  ?= 7
endif
ifdef LORA_FREQ_HZ
  URTB_DEFS += -DURTB_LORA_FREQ_HZ=$(LORA_FREQ_HZ)U
endif
ifdef LORA_TXPOWER
  URTB_DEFS += -DURTB_LORA_TXPOWER=$(LORA_TXPOWER)
endif

# OTP second-factor support (default: enabled). Disable with: make OTP=0
OTP ?= 1
ifeq ($(OTP),1)
  URTB_DEFS += -DURTB_OTP=1
  OTP_SRCS   = src/otp.c src/vendor/sha1/sha1.c
else
  OTP_SRCS   =
endif

URTB_SRCS := \
    src/main.c \
    src/frame.c \
    src/crypto.c \
    src/capsule.c \
    src/session.c \
    src/channel.c \
    src/channel_control.c \
    src/channel_pty.c \
    src/reasm.c \
    src/pty.c \
    src/transport_unix.c \
    src/transport_heltec.c \
    src/transport_stdio.c \
    $(VENDOR)/monocypher.c \
    $(OTP_SRCS)

# Test-only programmable RF failure injection. Off by default — production
# binaries built via plain `make urtb` have ZERO inject code/symbols. Enable
# with `make urtb URTB_TEST_INJECT=1`; this links src/test_inject.c and
# defines URTB_TEST_INJECT=1 in the preprocessor, which exposes the
# `urtb test-inject --pid <pid> <verb>` subcommand and the per-session
# control socket /tmp/urtb-inject-<pid>.sock used by AC-05-03/04/05/08/09.
URTB_TEST_INJECT ?= 0
ifeq ($(URTB_TEST_INJECT),1)
URTB_DEFS += -DURTB_TEST_INJECT=1
URTB_SRCS += src/test_inject.c
endif

URTB_OBJS := $(URTB_SRCS:.c=.o)

# Default target: host binary if all sources present, otherwise just the test harness.
.PHONY: all
all: tools/frame_test
	@if [ -f src/main.c ]; then $(MAKE) urtb; fi

# Host application binary
urtb: $(URTB_OBJS)
	$(CC) $(CFLAGS) $(URTB_DEFS) $(INC) -o $@ $(URTB_OBJS) $(LDFLAGS) $(LDLIBS)

# Per-source compilation rule (used by urtb)
%.o: %.c
	$(CC) $(CFLAGS) $(URTB_DEFS) $(INC) -c $< -o $@

# Strict static-link build with musl-gcc (Linux only, AC-07-04).
# Requires musl-tools (provides /usr/bin/musl-gcc). Builds a single
# self-contained ELF that ldd reports as "not a dynamic executable".
# musl provides forkpty inside libc — no -lutil needed.
.PHONY: urtb-static
urtb-static: $(URTB_SRCS)
	musl-gcc -Wall -Wextra -std=c11 -O2 -static $(URTB_DEFS) $(INC) -o urtb-static $(URTB_SRCS)

# Phase B-0 test harness — links src/reasm.c (shared §7 state machine)
# and src/crypto.c (so the C-4 hello_nonce regression sentinels exercise
# crypto_encrypt_with_nonce, the actual production path).
tools/frame_test: tools/frame_test.c src/reasm.c src/reasm.h src/crypto.c src/crypto.h $(VENDOR)/monocypher.c $(VENDOR)/monocypher.h
	$(CC) $(CFLAGS) $(URTB_DEFS) $(INC) -o $@ tools/frame_test.c src/reasm.c src/crypto.c $(VENDOR)/monocypher.c

# OTP test harness — RFC 4226 + RFC 6238 test vectors
ifeq ($(OTP),1)
tools/otp_test: tools/otp_test.c src/otp.c src/otp.h src/crypto.c src/crypto.h src/vendor/sha1/sha1.c src/vendor/sha1/sha1.h $(VENDOR)/monocypher.c
	$(CC) $(CFLAGS) $(URTB_DEFS) $(INC) -o $@ tools/otp_test.c src/otp.c src/crypto.c $(VENDOR)/monocypher.c src/vendor/sha1/sha1.c
endif

# Capsule format-version test harness (DECISIONS.md D-40).
# Built with -DURTB_TEST_V1_EMIT so the v1 forward-compat case can emit
# its fixture at test time — NO v1 binary is ever checked in (would be a
# public PSK that looks like a real credential). The production
# `urtb` binary is built without URTB_TEST_V1_EMIT and therefore contains
# no v1 emitter symbol; this build rule is the only place the define
# appears, by design.
tools/capsule_version_test: tools/capsule_version_test.c src/capsule.c src/capsule.h src/crypto.c src/crypto.h $(VENDOR)/monocypher.c $(VENDOR)/monocypher.h
	$(CC) $(CFLAGS) $(URTB_DEFS) -DURTB_TEST_V1_EMIT $(INC) -o $@ \
	    tools/capsule_version_test.c src/capsule.c src/crypto.c $(VENDOR)/monocypher.c

.PHONY: test
ifeq ($(OTP),1)
test: tools/frame_test tools/otp_test tools/capsule_version_test
	./tools/frame_test
	./tools/otp_test
	./tools/capsule_version_test
else
test: tools/frame_test tools/capsule_version_test
	./tools/frame_test
	./tools/capsule_version_test
endif

.PHONY: leaks
# macOS-only: AddressSanitizer doesn't ship a leak sanitizer in Apple
# Clang. Use leaks(1) instead. The --atExit form launches the binary
# itself and reports on exit — necessary because tools/frame_test runs
# in well under a second, so a `leaks $$!` against an already-dead PID
# would race and return "no process". MallocStackLogging gives leaks
# allocation backtraces.
leaks: tools/frame_test
ifeq ($(UNAME_S),Darwin)
	@MallocStackLogging=1 leaks --atExit -- ./tools/frame_test \
	  | tail -n 30
else
	@echo "Use 'make test ASAN=1' on Linux for leak detection"
endif

.PHONY: clean
clean:
	rm -f tools/frame_test tools/otp_test tools/capsule_version_test \
	    $(URTB_OBJS) urtb urtb-static

.PHONY: distclean
distclean: clean
	rm -f *.core core

# --- Phase C: harmonized E2E + environment helpers -----------------------
.PHONY: check check-hw check-all smoke doctor ports clean-all hygiene help

check:
	@bash tools/run_all_tests.sh --tier no-hw

check-hw:
	@bash tools/run_all_tests.sh --tier hw

check-all:
	@bash tools/run_all_tests.sh --tier all

smoke:
	@bash tools/run_all_tests.sh --quick

doctor:
	@bash tools/doctor.sh

ports:
	@bash tools/ports.sh

# Production binary must contain ZERO inject symbols. See DECISIONS.md D-37.
hygiene: urtb
	@count=$$(nm urtb 2>/dev/null | grep -c inject; true); \
	 count=$${count:-0}; \
	 echo "nm urtb | grep -c inject = $$count"; \
	 [ "$$count" -eq 0 ] || { echo "FAIL: prod binary has $$count inject symbols" >&2; exit 1; }

clean-all: clean
	@rm -f urtb urtb-test urtb-static
	@rm -rf /tmp/urtb-* /tmp/fi02-* /tmp/fi03_* /tmp/heltec-* /tmp/ac03_* 2>/dev/null || true

help:
	@echo "URTB Makefile targets:"
	@echo "  make              build host binary (urtb)"
	@echo "  make urtb         build host binary"
	@echo "  make test         frame_test 52/52 (no-hw)"
	@echo "  make check        full no-hw test tier (~40s)"
	@echo "  make check-hw     Heltec V3 hardware tier (~3min, requires 2 boards)"
	@echo "  make check-all    no-hw + hw"
	@echo "  make smoke        frame_test only (~10s)"
	@echo "  make hygiene      symbol audit (prod build must have 0 inject syms)"
	@echo "  make doctor       environment readiness check (compiler, pyte, socat, pio, ports)"
	@echo "  make ports        detect Heltec V3 USB-serial ports"
	@echo "  make urtb-static  Linux musl-static build"
	@echo "  make test ASAN=1  ASAN+LSan+UBSan on Linux, ASAN+UBSan on macOS"
	@echo "  make leaks        macOS leaks(1) over tools/frame_test (--atExit)"
	@echo "  make clean        remove .o files"
	@echo "  make clean-all    remove binaries and /tmp test artifacts"
	@echo
	@echo "Test injection (test-only build, AC-05-03/04/05/08/09 + AC-09-01):"
	@echo "  make urtb URTB_TEST_INJECT=1   build urtb with test-inject subcommand"
