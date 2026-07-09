#!/usr/bin/env bash
# run-t1-dev-datapath.sh - orchestrate the standalone two-ended Product A T1
# IpTunnel dev-host datapath run (relay + serving claw + device/guest runner).
#
# This is an ISOLATED experimental (Product A / per-Claw VPN "T1") dev-host
# helper. It NEVER touches production: it is dev-profile only (loopback relay,
# dev feature bins, dev acks). A bare invocation is a SAFE dry-run that prints
# the planned commands and exits 0 without launching or mutating anything.
# Real execution requires the explicit --execute flag PLUS the dev acks/envs,
# and is intended to be run only by an owner/executor under owner-present
# authorization (T1-T4 evidence generation, never a #281 activation).
#
# What it orchestrates (single-sourced rendezvous offer so both ends meet at
# the same relay slot):
#   1. relay_stream_relay_dev        loopback blind splicer (127.0.0.1:49152)
#   2. t1_iptunnel_claw_dev          SELF-MINTS the offer -> OFFER_OUT, serves
#                                    reverse-connect (launched FIRST)
#   3. t1-iptunnel-dev-runner gen-device-config   derive the device session cfg
#   4. t1-iptunnel-dev-runner run-device-datapath opens the real device datapath
#                                    against the SAME offer the claw wrote
#
# Usage:
#   ./scripts/run-t1-dev-datapath.sh [--dry-run]            # default: dry-run
#   ./scripts/run-t1-dev-datapath.sh --execute \
#       --claw-id <id> --guest-device-pub <66-hex> \
#       --device-secret-file <path> [--platform linux|macos] \
#       [--offer-file <path>] [--config-file <path>] \
#       [--pool-network 198.18.0.0/24] [--relay-endpoint 127.0.0.1:49152] \
#       [--bin-dir <dir>]
#
# Real execution additionally requires these to be exported in the environment:
#   THEYOS_T1_DEV_DATAPATH=1  THEYOS_FORCE_SOFTWARE_KEYS=1
#
# Environment:
#   THEYOS_DIR   Repo root (auto-detected from this script's location)
#
set -euo pipefail

# Exact dev-host acknowledgement string required by both dev bins before any
# datapath action. Dev reference (contains no production identifier).
DEV_HOST_ACK="dev-host T1-T4 only; no production activation"

# Bin names orchestrated (dev-feature-gated; built separately by the executor).
RELAY_BIN="relay_stream_relay_dev"
CLAW_BIN="t1_iptunnel_claw_dev"
RUNNER_BIN="t1-iptunnel-dev-runner"

usage() {
    awk '
        NR < 2 { next }
        $0 !~ /^#/ { exit }
        {
            sub(/^# ?/, "")
            print
        }
    ' "$0"
}

die() {
    echo "[error] $1" >&2
    exit "${2:-2}"
}

# Fail-closed production guard. Refuses if ANY production indicator is present
# in the supplied text. The indicator tokens are assembled from fragments so no
# contiguous production identifier appears in this file (mirrors the repo's
# concat!()-split convention): these are strictly what we REFUSE, never what we
# target. Every real target in this script is dev-profile or loopback.
prod_guard() {
    local text="$1"

    # Allowed dev-profile spellings, neutralized first so only prod forms remain.
    local dev_engine="com.soyeht.""engine"".dev"
    local dev_mac="com.soyeht.""mac"".dev"
    local dev_app="Soyeht"" Dev.app"
    # Production forms we reject (and the prod engine port).
    local prod_engine="com.soyeht.""engine"
    local prod_mac="com.soyeht.""mac"
    local prod_app="Soyeht"".app"
    local prod_port="80""91"

    local scrubbed="$text"
    scrubbed="${scrubbed//$dev_engine/__DEV_ENGINE__}"
    scrubbed="${scrubbed//$dev_mac/__DEV_MAC__}"
    scrubbed="${scrubbed//$dev_app/__DEV_APP__}"

    case "$scrubbed" in
        *"$prod_port"*)
            die "production engine port detected in env/args (dev uses 8101, loopback 49152 only)" 3 ;;
        *"$prod_app"*)
            die "production app bundle detected in env/args (dev uses the dev app only)" 3 ;;
        *"$prod_mac"*)
            die "production mac bundle id detected in env/args (dev uses the .dev suffix only)" 3 ;;
        *"$prod_engine"*)
            die "production engine label detected in env/args (dev uses the .dev suffix only)" 3 ;;
    esac
}

# Scan raw args plus a curated set of profile-selecting env vars for any prod
# indicator. Curated (not the whole environ) so the guard is deterministic and
# does not false-positive on unrelated variables.
run_prod_guard() {
    local blob="$*"
    local v
    for v in \
        SOYEHT_ENGINE THEYOS_ENGINE ENGINE_LABEL \
        SOYEHT_APP APP_BUNDLE SOYEHT_BUNDLE_ID \
        RELAY_ENDPOINT THEYOS_RELAY_STREAM_RELAY_ENDPOINT \
        SOYEHT_PROFILE THEYOS_PROFILE; do
        blob+="
${!v-}"
    done
    prod_guard "$blob"
}

MODE="dryrun"
CLAW_ID="claw-dev-alpha"
GUEST_DEVICE_PUB=""
DEVICE_SECRET_FILE=""
PLATFORM=""
OFFER_FILE="t1-iptunnel-offer.cbor"
CONFIG_FILE="t1-device-session-config.json"
POOL_NETWORK="198.18.0.0/24"
RELAY_ENDPOINT="127.0.0.1:49152"
BIN_DIR=""

THEYOS_DIR="${THEYOS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

detect_platform() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux) echo "linux" ;;
        *) echo "linux" ;;
    esac
}

require_value() {
    # $1 = flag name, $2 = count remaining, $3 = value
    if [ "$2" -lt 2 ] || [ -z "$3" ]; then
        die "$1 requires a value"
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run) MODE="dryrun"; shift ;;
            --execute) MODE="execute"; shift ;;
            --claw-id) require_value "$1" "$#" "${2:-}"; CLAW_ID="$2"; shift 2 ;;
            --guest-device-pub) require_value "$1" "$#" "${2:-}"; GUEST_DEVICE_PUB="$2"; shift 2 ;;
            --device-secret-file) require_value "$1" "$#" "${2:-}"; DEVICE_SECRET_FILE="$2"; shift 2 ;;
            --platform) require_value "$1" "$#" "${2:-}"; PLATFORM="$2"; shift 2 ;;
            --offer-file) require_value "$1" "$#" "${2:-}"; OFFER_FILE="$2"; shift 2 ;;
            --config-file) require_value "$1" "$#" "${2:-}"; CONFIG_FILE="$2"; shift 2 ;;
            --pool-network) require_value "$1" "$#" "${2:-}"; POOL_NETWORK="$2"; shift 2 ;;
            --relay-endpoint) require_value "$1" "$#" "${2:-}"; RELAY_ENDPOINT="$2"; shift 2 ;;
            --bin-dir) require_value "$1" "$#" "${2:-}"; BIN_DIR="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    if [ -z "$PLATFORM" ]; then
        PLATFORM="$(detect_platform)"
    fi
    if [ -z "$BIN_DIR" ]; then
        BIN_DIR="$THEYOS_DIR/admin/rust/target/release"
    fi
    case "$PLATFORM" in
        linux|macos) ;;
        *) die "--platform must be linux or macos" ;;
    esac
}

print_plan() {
    cat <<PLAN
T1 dev-host datapath run - PLANNED COMMANDS (dry-run; nothing launched)

  Profile: dev-profile only. Relay is loopback ${RELAY_ENDPOINT}. No production.
  Mode requires --execute + THEYOS_T1_DEV_DATAPATH=1 + THEYOS_FORCE_SOFTWARE_KEYS=1
  to actually launch anything.

  [1] relay (loopback blind splicer, launched first, background):
      THEYOS_RELAY_STREAM_RELAY_ENDPOINT=${RELAY_ENDPOINT} \\
        ${BIN_DIR}/${RELAY_BIN}

  [2] serving claw (SELF-MINTS the offer -> ${OFFER_FILE}, background):
      THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \\
      CLAW_ID=${CLAW_ID} GUEST_DEVICE_PUB=${GUEST_DEVICE_PUB:-<REQUIRED at --execute>} \\
      RELAY_ENDPOINT=${RELAY_ENDPOINT} OFFER_OUT=${OFFER_FILE} \\
        ${BIN_DIR}/${CLAW_BIN} \\
          --dev-host-ack "${DEV_HOST_ACK}"

  [3] device session config (derived by the runner's real allocator):
      ${BIN_DIR}/${RUNNER_BIN} gen-device-config \\
        --platform ${PLATFORM} \\
        --pool-network ${POOL_NETWORK} \\
        --out ${CONFIG_FILE}

  [4] device/guest runner (consumes the SAME ${OFFER_FILE} the claw wrote):
      THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \\
        ${BIN_DIR}/${RUNNER_BIN} run-device-datapath \\
          --offer-file ${OFFER_FILE} \\
          --config-file ${CONFIG_FILE} \\
          --device-secret-file ${DEVICE_SECRET_FILE:-<REQUIRED at --execute>} \\
          --dev-host-ack "${DEV_HOST_ACK}"
PLAN
}

require_execute_gates() {
    # Fail closed: the dev env gates AND the dev-host ack must all be present
    # before any real launch. (The ack is this script's constant, passed to
    # both dev bins; the env gates must be exported by the operator.)
    [ "${THEYOS_T1_DEV_DATAPATH:-}" = "1" ] \
        || die "--execute requires THEYOS_T1_DEV_DATAPATH=1 in the environment" 4
    [ "${THEYOS_FORCE_SOFTWARE_KEYS:-}" = "1" ] \
        || die "--execute requires THEYOS_FORCE_SOFTWARE_KEYS=1 in the environment" 4
    [ -n "$DEV_HOST_ACK" ] \
        || die "--execute requires the dev-host acknowledgement" 4

    [ -n "$GUEST_DEVICE_PUB" ] || die "--execute requires --guest-device-pub <66-hex>" 5
    # A valid guest-device-pub is a 33-byte SEC1-compressed P-256 key: 66 hex
    # chars with an 02/03 tag. Fail fast so a mis-copied value (e.g. the 64-hex
    # device secret) cannot reach the claw as a fatal decode mid-run.
    [ "${#GUEST_DEVICE_PUB}" -eq 66 ] \
        || die "--guest-device-pub must be 66 hex chars (33-byte SEC1 key), got ${#GUEST_DEVICE_PUB}" 5
    case "$GUEST_DEVICE_PUB" in
        02* | 03*) ;;
        *) die "--guest-device-pub must start with the SEC1 compressed tag 02 or 03" 5 ;;
    esac
    case "$GUEST_DEVICE_PUB" in
        *[!0-9a-fA-F]*) die "--guest-device-pub must be hex" 5 ;;
    esac
    [ -n "$DEVICE_SECRET_FILE" ] || die "--execute requires --device-secret-file <path>" 5
    [ -f "$DEVICE_SECRET_FILE" ] || die "device secret file not found: $DEVICE_SECRET_FILE" 5
    [ -x "$BIN_DIR/$RELAY_BIN" ] || die "relay bin not found/executable: $BIN_DIR/$RELAY_BIN" 5
    [ -x "$BIN_DIR/$CLAW_BIN" ] || die "claw bin not found/executable: $BIN_DIR/$CLAW_BIN" 5
    [ -x "$BIN_DIR/$RUNNER_BIN" ] || die "runner bin not found/executable: $BIN_DIR/$RUNNER_BIN" 5
}

RELAY_PID=""
CLAW_PID=""

cleanup() {
    if [ -n "$CLAW_PID" ]; then kill "$CLAW_PID" 2>/dev/null || true; fi
    if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
}

execute_run() {
    require_execute_gates
    trap cleanup EXIT INT TERM

    echo "[t1] starting loopback relay ${RELAY_ENDPOINT}"
    THEYOS_RELAY_STREAM_RELAY_ENDPOINT="$RELAY_ENDPOINT" "$BIN_DIR/$RELAY_BIN" &
    RELAY_PID="$!"

    echo "[t1] starting serving claw (self-mints offer -> ${OFFER_FILE})"
    rm -f "$OFFER_FILE"
    THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        CLAW_ID="$CLAW_ID" GUEST_DEVICE_PUB="$GUEST_DEVICE_PUB" \
        RELAY_ENDPOINT="$RELAY_ENDPOINT" OFFER_OUT="$OFFER_FILE" \
        "$BIN_DIR/$CLAW_BIN" --dev-host-ack "$DEV_HOST_ACK" &
    CLAW_PID="$!"

    echo "[t1] waiting for the claw to write ${OFFER_FILE}"
    local waited=0
    while [ ! -s "$OFFER_FILE" ]; do
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 30 ]; then
            die "timed out waiting for the claw to write $OFFER_FILE" 6
        fi
        if ! kill -0 "$CLAW_PID" 2>/dev/null; then
            die "claw exited before writing $OFFER_FILE" 6
        fi
    done

    echo "[t1] generating device session config -> ${CONFIG_FILE}"
    "$BIN_DIR/$RUNNER_BIN" gen-device-config \
        --platform "$PLATFORM" \
        --pool-network "$POOL_NETWORK" \
        --out "$CONFIG_FILE"

    echo "[t1] opening device datapath against ${OFFER_FILE}"
    THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        "$BIN_DIR/$RUNNER_BIN" run-device-datapath \
            --offer-file "$OFFER_FILE" \
            --config-file "$CONFIG_FILE" \
            --device-secret-file "$DEVICE_SECRET_FILE" \
            --dev-host-ack "$DEV_HOST_ACK"
}

main() {
    # Guard runs BEFORE any mode branch: a prod indicator is refused whether
    # dry-run or execute.
    run_prod_guard "$@"
    parse_args "$@"
    # Re-scan resolved profile-selecting values (endpoint) after parsing.
    prod_guard "$RELAY_ENDPOINT"

    if [ "$MODE" = "dryrun" ]; then
        print_plan
        exit 0
    fi

    execute_run
}

main "$@"
