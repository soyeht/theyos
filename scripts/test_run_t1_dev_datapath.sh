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
assert_exit 3 "prod guard: SOYEHT_ENGINE=com.soyeht.engine (env)" \
    env SOYEHT_ENGINE=com.soyeht.engine bash "$SCRIPT"
assert_exit 3 "prod guard: arg contains 8091" \
    bash "$SCRIPT" --claw-id host8091
assert_exit 3 "prod guard: arg contains the prod app bundle" \
    bash "$SCRIPT" --config-file /Applications/Soyeht.app/cfg.json
assert_exit 3 "prod guard: SOYEHT_ENGINE=com.soyeht.mac (env)" \
    env SOYEHT_ENGINE=com.soyeht.mac bash "$SCRIPT"

# dev-profile spellings (.dev) are accepted (guard passes -> dry-run exit 0)
assert_exit 0 "dev profile allowed: com.soyeht.engine.dev" \
    env SOYEHT_ENGINE=com.soyeht.engine.dev bash "$SCRIPT"
assert_exit 0 "dev profile allowed: com.soyeht.mac.dev" \
    env SOYEHT_ENGINE=com.soyeht.mac.dev bash "$SCRIPT"

# ---------------------------------------------------------------------------
# 4. --execute is refused without the dev acks/envs, and never launches a bin.
#    Point --bin-dir at a nonexistent dir so even a bug cannot launch anything.
# ---------------------------------------------------------------------------
assert_exit 4 "--execute without dev env gates is refused" \
    env -u THEYOS_T1_DEV_DATAPATH -u THEYOS_FORCE_SOFTWARE_KEYS \
        bash "$SCRIPT" --execute \
        --guest-device-pub deadbeef \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# even WITH env gates, missing inputs/bins fail closed (exit 5) before launch
assert_exit 5 "--execute with gates but missing inputs fails closed pre-launch" \
    env THEYOS_T1_DEV_DATAPATH=1 THEYOS_FORCE_SOFTWARE_KEYS=1 \
        bash "$SCRIPT" --execute \
        --guest-device-pub deadbeef \
        --device-secret-file /nonexistent/secret.hex \
        --bin-dir /nonexistent/bindir

# ---------------------------------------------------------------------------
# 5. dev-only source: no contiguous production identifiers in the script
# ---------------------------------------------------------------------------
if grep -Fq 'Soyeht.app' "$SCRIPT"; then
    bad "script must not contain the contiguous prod app literal"
else
    ok "script contains no contiguous prod app literal"
fi
if grep -Fq '8091' "$SCRIPT"; then
    bad "script must not contain the contiguous prod port literal"
else
    ok "script contains no contiguous prod port literal"
fi

# ---------------------------------------------------------------------------
echo
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "ALL TESTS PASSED"
