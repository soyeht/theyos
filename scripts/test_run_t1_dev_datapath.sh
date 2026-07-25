#!/usr/bin/env bash
# test_run_t1_dev_datapath.sh - automated tests for run-t1-dev-datapath.sh.
#
# Proves, without ever launching a real datapath:
#   * bash -n (and shellcheck when available) are clean;
#   * the SAFE dry-run default prints the planned bins/acks/envs and exits 0
#     with no host side effects (no offer/config files written);
#   * the fail-closed production guard refuses prod indicators in env AND args;
#   * dev-profile spellings (.dev suffix) are accepted;
#   * --execute without the dev acks/envs is refused before touching any bin;
#   * --execute refuses a malformed --guest-device-pub (wrong length/tag) before launch;
#   * the script contains no contiguous production identifiers (dev-only source).
#
# Usage:
#   ./scripts/test_run_t1_dev_datapath.sh
#
set -euo pipefail

THEYOS_DIR="${THEYOS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
SCRIPT="$THEYOS_DIR/scripts/run-t1-dev-datapath.sh"

PASS=0
FAIL=0

ok() {
    PASS=$((PASS + 1))
    echo "ok   - $1"
}

bad() {
    FAIL=$((FAIL + 1))
    echo "FAIL - $1" >&2
}

# assert_exit <expected_code> <label> -- runs the remaining args, comparing $?.
# Uses a subshell so `set -e` in this harness does not abort on non-zero.
assert_exit() {
    local expected="$1" label="$2"; shift 2
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?
    if [ "$actual" = "$expected" ]; then
        ok "$label (exit $actual)"
    else
        bad "$label (expected exit $expected, got $actual)"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    case "$haystack" in
        *"$needle"*) ok "$label" ;;
        *) bad "$label (missing: $needle)" ;;
    esac
}

echo "# test_run_t1_dev_datapath.sh"
echo "# SCRIPT=$SCRIPT"

# ---------------------------------------------------------------------------
# 1. static checks
# ---------------------------------------------------------------------------
assert_exit 0 "bash -n is clean" bash -n "$SCRIPT"

if command -v shellcheck >/dev/null 2>&1; then
    assert_exit 0 "shellcheck is clean" shellcheck "$SCRIPT"
else
    echo "ok   - shellcheck not installed; skipped (bash -n covers syntax)"
    PASS=$((PASS + 1))
fi

# ---------------------------------------------------------------------------
# 2. dry-run is the safe default: prints the plan, exits 0, no side effects
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PLAN="$(cd "$WORK" && bash "$SCRIPT")"
DRY_EXIT=0
(cd "$WORK" && bash "$SCRIPT" >/dev/null 2>&1) || DRY_EXIT=$?
if [ "$DRY_EXIT" = "0" ]; then ok "bare dry-run exits 0"; else bad "bare dry-run exits 0 (got $DRY_EXIT)"; fi

# expected bins
assert_contains "$PLAN" "relay_stream_relay_dev" "plan names the relay bin"
assert_contains "$PLAN" "t1_iptunnel_claw_dev" "plan names the claw bin"
assert_contains "$PLAN" "t1-iptunnel-dev-runner gen-device-config" "plan names gen-device-config"
assert_contains "$PLAN" "t1-iptunnel-dev-runner run-device-datapath" "plan names run-device-datapath"

# the two dev-host acks (claw + runner) -- assert both occurrences present
ACK='--dev-host-ack "dev-host T1-T4 only; no production activation"'
ACK_COUNT="$(printf '%s\n' "$PLAN" | grep -c -- "$ACK" || true)"
if [ "$ACK_COUNT" -ge 2 ]; then
    ok "plan carries the dev-host ack on both ends (count=$ACK_COUNT)"
else
    bad "plan should carry the dev-host ack twice (count=$ACK_COUNT)"
fi

# dev envs
assert_contains "$PLAN" "THEYOS_T1_DEV_DATAPATH=1" "plan sets THEYOS_T1_DEV_DATAPATH=1"
assert_contains "$PLAN" "THEYOS_FORCE_SOFTWARE_KEYS=1" "plan sets THEYOS_FORCE_SOFTWARE_KEYS=1"
assert_contains "$PLAN" "THEYOS_RELAY_STREAM_RELAY_ENDPOINT=127.0.0.1:49152" "plan sets loopback relay endpoint"
assert_contains "$PLAN" "OFFER_OUT=t1-iptunnel-offer.cbor" "plan single-sources the offer file"
assert_contains "$PLAN" "--offer-file t1-iptunnel-offer.cbor" "runner consumes the same offer file"

# no side effects from dry-run
if [ -e "$WORK/t1-iptunnel-offer.cbor" ] || [ -e "$WORK/t1-device-session-config.json" ]; then
    bad "dry-run must not write offer/config files"
else
    ok "dry-run wrote no offer/config files"
fi

# ---------------------------------------------------------------------------
# 3. fail-closed production guard (env AND args)
# ---------------------------------------------------------------------------
# Production-indicator fixtures are fragment-assembled so THIS test file, like
# the script under test, carries no contiguous production identifier (the
# section-5 self-check enforces that on both files).
PROD_ENGINE="com.soyeht.""engine"
PROD_MAC="com.soyeht.""mac"
PROD_APP="Soyeht"".app"
PROD_PORT="80""91"

assert_exit 3 "prod guard: prod engine label in env" \
    env "SOYEHT_ENGINE=$PROD_ENGINE" bash "$SCRIPT"
assert_exit 3 "prod guard: prod port in arg" \
    bash "$SCRIPT" --claw-id "host$PROD_PORT"
assert_exit 3 "prod guard: prod app bundle in arg" \
    bash "$SCRIPT" --config-file "/Applications/$PROD_APP/cfg.json"
assert_exit 3 "prod guard: prod mac bundle in env" \
    env "SOYEHT_ENGINE=$PROD_MAC" bash "$SCRIPT"

# dev-profile spellings (.dev) are accepted (guard passes -> dry-run exit 0)
assert_exit 0 "dev profile allowed: engine .dev suffix" \
    env "SOYEHT_ENGINE=$PROD_ENGINE.dev" bash "$SCRIPT"
assert_exit 0 "dev profile allowed: mac .dev suffix" \
    env "SOYEHT_ENGINE=$PROD_MAC.dev" bash "$SCRIPT"

# ---------------------------------------------------------------------------
# 4. --execute fail-closed gates: dev acks/envs, the guest-device-pub format,
#    and missing inputs/bins are all refused before any bin is launched.
#    Point --bin-dir at a nonexistent dir so even a bug cannot launch anything.
# ---------------------------------------------------------------------------
# A format-valid guest-device-pub: 66 hex chars with a SEC1 02/03 tag. (Not a
# real curve point -- the script validates shape only; the bin does the crypto.)
ZEROS64="$(printf '%064d' 0)"
VALID_PUB="03${ZEROS64}"
# The classic mistake the format gate catches: the 64-hex device SECRET scalar
# pasted into --guest-device-pub (a valid pubkey is 66 hex, not 64).
SECRET_LEN_PUB="${ZEROS64}"
# 66 hex chars but not a SEC1 compressed tag (04 is uncompressed/invalid here).
WRONG_TAG_PUB="04${ZEROS64}"

assert_exit 4 "--execute without dev env gates is refused" \
    env -u THEYOS_T1_DEV_DATAPATH -u THEYOS_FORCE_SOFTWARE_KEYS \
        bash "$SCRIPT" --execute \
        --guest-device-pub "$VALID_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# the guest-device-pub format gate (exit 5) fires before any bin is touched
assert_exit 5 "--execute with a 64-hex secret mis-pasted as guest-device-pub is refused" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --guest-device-pub "$SECRET_LEN_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

assert_exit 5 "--execute with a wrong-tag guest-device-pub is refused" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --guest-device-pub "$WRONG_TAG_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# even WITH env gates AND a well-formed pub, missing inputs/bins fail closed
# (exit 5) before launch
assert_exit 5 "--execute with gates but missing inputs fails closed pre-launch" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --guest-device-pub "$VALID_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# ---------------------------------------------------------------------------
# 4b. off-loopback --relay-endpoint: the public-relay ack gate runs before the
#     bin-existence checks above, so --bin-dir stays nonexistent here too --
#     even a bug in check ordering could not launch anything real.
# ---------------------------------------------------------------------------
NON_LOOPBACK_ENDPOINT="203.0.113.5:49152"
PUBLIC_RELAY_ACK="dev-host public relay dial allowed; no production activation"

assert_exit 4 "--execute with a non-loopback relay and no public-relay ack is refused pre-launch" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --relay-endpoint "$NON_LOOPBACK_ENDPOINT" \
        --guest-device-pub "$VALID_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

assert_exit 4 "--execute with a non-loopback relay and a wrong public-relay ack is refused pre-launch" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --relay-endpoint "$NON_LOOPBACK_ENDPOINT" \
        --allow-public-relay-ack "not the ack" \
        --guest-device-pub "$VALID_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# The correct ack clears the new gate (no exit 4) and reaches the next
# fail-closed check in line (exit 5, missing device secret file) -- proving
# the off-loopback path is accepted rather than silently still refused.
assert_exit 5 "--execute with a non-loopback relay and the correct public-relay ack passes the ack gate" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --relay-endpoint "$NON_LOOPBACK_ENDPOINT" \
        --allow-public-relay-ack "$PUBLIC_RELAY_ACK" \
        --guest-device-pub "$VALID_PUB" \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# ---------------------------------------------------------------------------
# 5. dev-only source: no contiguous production identifier in EITHER file,
#    across 4 families (app bundle, engine port, mac bundle id, engine label).
#    Patterns reuse the fragment-assembled $PROD_* strings, so this check embeds
#    no contiguous prod literal either.
# ---------------------------------------------------------------------------
check_no_prod_literal() {
    local target="$1" tname
    tname="$(basename "$target")"
    local entry name literal
    for entry in "app bundle=$PROD_APP" "engine port=$PROD_PORT" \
                 "mac bundle=$PROD_MAC" "engine label=$PROD_ENGINE"; do
        name="${entry%%=*}"
        literal="${entry#*=}"
        if grep -Fq "$literal" "$target"; then
            bad "$tname must not contain the contiguous prod $name literal"
        else
            ok "$tname has no contiguous prod $name literal"
        fi
    done
}
check_no_prod_literal "$SCRIPT"
check_no_prod_literal "${BASH_SOURCE[0]}"

# ---------------------------------------------------------------------------
echo
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "ALL TESTS PASSED"
