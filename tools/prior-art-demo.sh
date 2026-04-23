#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# prior-art-demo.sh — Reference implementation of URTB's non-radio host layer
# using off-the-shelf tools only. Accompanies ../PRIOR_ART.md.
#
# Demonstrates that an encrypted, mutually-authenticated, PTY-wrapped shell
# session over a bidirectional byte pipe is a ~2-line shell problem when you
# are not constrained by LoRa's 72-byte MTU and 1% duty cycle. URTB's host
# layer reimplements this functionality only because the LoRa constraints
# invalidate off-the-shelf TLS/SSH stacks — not because the building blocks
# did not exist.
#
# Modes:
#   setup     — generate a self-signed ed25519 cert + key (one-time pairing)
#   server    — run socat+openssl server bound to 127.0.0.1:$PORT with PTY bash
#   client    — connect socat+openssl client to $HOST:$PORT
#   loopback  — run server in background, then connect client to it
#   cable     — create a virtual null-modem (two PTYs bridged) for testing
#   clean     — remove generated cert/key + any background server PIDs
#   help      — show this message
#
# Environment:
#   URTB_DEMO_DIR  — where cert/key live (default: ./urtb-demo)
#   URTB_PORT      — TCP port (default: 9443)
#   URTB_HOST      — host for client/loopback (default: 127.0.0.1)
#
# Rootless. Requires: socat, openssl. Optional: ncat (for the --ssl variant).

set -euo pipefail

URTB_DEMO_DIR="${URTB_DEMO_DIR:-./urtb-demo}"
URTB_PORT="${URTB_PORT:-9443}"
URTB_HOST="${URTB_HOST:-127.0.0.1}"
CERT="${URTB_DEMO_DIR}/urtb.pem"
KEY="${URTB_DEMO_DIR}/urtb.key"
PIDFILE="${URTB_DEMO_DIR}/server.pid"

die() { echo "prior-art-demo: $*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

cmd_setup() {
    need openssl
    mkdir -p "$URTB_DEMO_DIR"
    if [[ -f "$CERT" && -f "$KEY" ]]; then
        echo "prior-art-demo: cert+key already exist at $URTB_DEMO_DIR (use 'clean' to reset)"
        return 0
    fi
    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=urtb-prior-art-demo" 2>/dev/null
    chmod 600 "$KEY"
    chmod 644 "$CERT"
    echo "prior-art-demo: wrote $CERT and $KEY"
    echo "prior-art-demo: this cert+key pair is the 'paired device' equivalent — both sides must hold it."
}

ensure_paired() {
    [[ -f "$CERT" && -f "$KEY" ]] || die "no cert/key — run '$0 setup' first"
}

cmd_server() {
    need socat
    ensure_paired
    echo "prior-art-demo: listening on ${URTB_HOST}:${URTB_PORT} (Ctrl-C to stop)"
    echo "prior-art-demo: clients must present a cert signed by $CERT to connect"
    exec socat \
        OPENSSL-LISTEN:${URTB_PORT},bind=${URTB_HOST},reuseaddr,fork,\
cert=${CERT},key=${KEY},cafile=${CERT},verify=1,\
openssl-min-proto-version=TLS1.2 \
        EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane,ctty
}

cmd_client() {
    need socat
    ensure_paired
    local target_host="${1:-$URTB_HOST}"
    echo "prior-art-demo: connecting to ${target_host}:${URTB_PORT}"
    echo "prior-art-demo: escape char is Ctrl-] (0x1d)"
    exec socat \
        -,raw,echo=0,escape=0x1d \
        OPENSSL:${target_host}:${URTB_PORT},\
cert=${CERT},key=${KEY},cafile=${CERT},verify=1,\
openssl-min-proto-version=TLS1.2
}

cmd_loopback() {
    need socat
    ensure_paired

    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "prior-art-demo: server already running (pid $(cat "$PIDFILE"))"
    else
        socat \
            OPENSSL-LISTEN:${URTB_PORT},bind=127.0.0.1,reuseaddr,fork,\
cert=${CERT},key=${KEY},cafile=${CERT},verify=1,\
openssl-min-proto-version=TLS1.2 \
            EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane,ctty \
            >/dev/null 2>&1 &
        echo "$!" > "$PIDFILE"
        echo "prior-art-demo: started server on 127.0.0.1:${URTB_PORT} (pid $!)"
        sleep 0.3
    fi

    echo "prior-art-demo: connecting client — escape char is Ctrl-]"
    echo "prior-art-demo: after disconnect, run '$0 clean' to stop the background server"
    echo "----"
    socat \
        -,raw,echo=0,escape=0x1d \
        OPENSSL:127.0.0.1:${URTB_PORT},\
cert=${CERT},key=${KEY},cafile=${CERT},verify=1,\
openssl-min-proto-version=TLS1.2 \
        || true
    echo "----"
    echo "prior-art-demo: client disconnected. server still running as pid $(cat "$PIDFILE" 2>/dev/null || echo '?')"
}

cmd_cable() {
    need socat
    local a="${1:-/tmp/urtb-tty-a}"
    local b="${2:-/tmp/urtb-tty-b}"
    echo "prior-art-demo: creating virtual null-modem $a <-> $b"
    echo "prior-art-demo: one process reads/writes $a, the other reads/writes $b"
    echo "prior-art-demo: Ctrl-C to tear down"
    exec socat -d -d \
        PTY,link="$a",raw,echo=0,mode=0600 \
        PTY,link="$b",raw,echo=0,mode=0600
}

cmd_clean() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid="$(cat "$PIDFILE")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "prior-art-demo: stopped background server pid $pid"
        fi
        rm -f "$PIDFILE"
    fi
    if [[ -d "$URTB_DEMO_DIR" ]]; then
        rm -f "$CERT" "$KEY"
        rmdir "$URTB_DEMO_DIR" 2>/dev/null || true
        echo "prior-art-demo: removed $URTB_DEMO_DIR"
    fi
}

case "${1:-help}" in
    setup)    shift; cmd_setup "$@" ;;
    server)   shift; cmd_server "$@" ;;
    client)   shift; cmd_client "$@" ;;
    loopback) shift; cmd_loopback "$@" ;;
    cable)    shift; cmd_cable "$@" ;;
    clean)    shift; cmd_clean "$@" ;;
    help|-h|--help) usage ;;
    *)        die "unknown mode: $1 (try: $0 help)" ;;
esac
