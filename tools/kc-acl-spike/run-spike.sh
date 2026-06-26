#!/bin/bash
# THROWAWAY runner for the P0.3-C Tier 2 Keychain ACL/DR durability spike.
#
# Modes:
#   --plan            (default) print the representative plan; execute NOTHING.
#   --self-test       build + run the UNSIGNED helper write/read/delete round-trip
#                     (no Developer ID, no DR test) to prove the tooling works.
#   --run-representative  the full A/B/C Developer ID test. OPERATOR-ONLY: refuses
#                     unless KC_SPIKE_ALLOW_DEVID_SIGN=1 is set, because signing
#                     with the real identity can prompt for signing-key access.
#
# Never stores real key material. Neutral service/account. Cleans up at the end.
# Does NOT touch /Applications/Soyeht.app, the engine, the LaunchAgent, the login
# keychain lock state, or the real household keystore.
set -euo pipefail

MODE="${1:---plan}"
SERVICE="com.soyeht.theyos.acl-spike"
ACCOUNT="probe"
IDENT_AB="com.soyeht.theyos.acl-spike"          # A and B share identifier (re-sign durability)
IDENT_C="com.soyeht.theyos.acl-spike.control"   # C: negative control (different identifier)
TEAM="W7677A5BK2"                               # Developer ID team (documented in CLAUDE.md)
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup_item() {
  # Best-effort removal of the spike keychain item (CLI delete is fine for cleanup;
  # it does not affect the DR test, which is read by the signed binaries).
  security delete-generic-password -s "${SERVICE}" >/dev/null 2>&1 || true
}

print_plan() {
  cat <<PLAN
PLAN (no execution) - representative Developer ID ACL/DR durability spike:
  workdir=\$(mktemp -d)
  cargo build --release --manifest-path ${CRATE_DIR}/Cargo.toml
  cp target/release/kc-acl-spike \$workdir/{A,B,C}
  # Developer ID identity resolved by team ${TEAM} at run time (CN never printed):
  #   HASH=\$(security find-identity -v -p codesigning | awk '/${TEAM}/ && /Developer ID Application/ {print \$2; exit}')
  [operator] codesign --options runtime --identifier ${IDENT_AB} --sign \$HASH \$workdir/A
  [operator] \$workdir/A write          # creates login-keychain item; ACL bound to A's DR
  [operator] codesign --options runtime --identifier ${IDENT_AB} --sign \$HASH \$workdir/B   # same id+team, new cdhash (models a release re-sign)
  [operator] \$workdir/B read           # EXPECT: READ ok matches_probe=true, NO prompt  -> DR durable
  codesign --identifier ${IDENT_C} --sign - \$workdir/C                                     # ad-hoc + different id = negative control
  \$workdir/C read           # EXPECT: READ denied (osstatus -25308/-25244) or prompt -> ACL really gates
  cleanup: security delete-generic-password -s ${SERVICE} ; rm -rf \$workdir

CRITERION (DR-durability evidence): B read OK without prompt + C read denied.
NOT sufficient alone for Stage B: also needs the real engine signing identifier
stable across releases, verify-before-delete migration, and a key-loss recovery
decision. See README.md.
PLAN
}

case "${MODE}" in
  --plan)
    print_plan
    ;;
  --self-test)
    echo "SELF-TEST (no Developer ID): build + unsigned write/read/delete round-trip"
    cargo build --release --manifest-path "${CRATE_DIR}/Cargo.toml"
    BIN="${CRATE_DIR}/target/release/kc-acl-spike"
    trap cleanup_item EXIT
    "${BIN}" write
    "${BIN}" read           # same binary reads its own item -> allowed (no DR test here)
    "${BIN}" delete
    if "${BIN}" read; then
      echo "SELF-TEST FAIL: item still readable after delete"; exit 1
    else
      echo "SELF-TEST ok: write/read matched, delete removed the item"
    fi
    ;;
  --run-representative)
    if [[ "${KC_SPIKE_ALLOW_DEVID_SIGN:-0}" != "1" ]]; then
      echo "REFUSED: representative run needs Developer ID signing (can prompt)." >&2
      echo "Set KC_SPIKE_ALLOW_DEVID_SIGN=1 only as an authorized operator." >&2
      exit 2
    fi
    # Resolve the Developer ID Application identity by team; never print its CN.
    HASH="$(security find-identity -v -p codesigning \
      | awk -v t="${TEAM}" '$0 ~ t && /Developer ID Application/ {print $2; exit}')"
    if [[ -z "${HASH}" ]]; then
      echo "REFUSED: no Developer ID Application identity found for team ${TEAM}." >&2
      exit 4
    fi
    WORK="$(mktemp -d)"
    trap 'cleanup_item; rm -rf "${WORK}"' EXIT
    BIN="${CRATE_DIR}/target/release/kc-acl-spike"
    # Build A/B/C with distinct build tags so each gets a distinct cdhash while
    # A and B keep the SAME identity + identifier (same DR) = models a re-sign.
    for tag in a b c; do
      touch "${CRATE_DIR}/src/main.rs"  # force recompile so option_env! re-bakes the tag
      KC_SPIKE_BUILD_TAG="${tag}" cargo build --release --manifest-path "${CRATE_DIR}/Cargo.toml" >/dev/null
      cp "${BIN}" "${WORK}/$(printf '%s' "${tag}" | tr 'abc' 'ABC')"
    done
    cleanup_item  # ensure no stale item from a prior run
    # A and B: same Developer ID + same identifier (the durability case).
    codesign --force --options runtime --identifier "${IDENT_AB}" --sign "${HASH}" "${WORK}/A"
    codesign --force --options runtime --identifier "${IDENT_AB}" --sign "${HASH}" "${WORK}/B"
    # C: ad-hoc signature + different identifier = negative control (different DR).
    codesign --force --identifier "${IDENT_C}" --sign - "${WORK}/C"

    echo "--- A (Developer ID, id=${IDENT_AB}) write ---"
    "${WORK}/A" write
    echo "--- B (re-signed, same id, distinct cdhash) read  [EXPECT: ok, no prompt] ---"
    if "${WORK}/B" read; then B_OK=1; else B_OK=0; fi
    echo "--- C (ad-hoc, id=${IDENT_C}) read  [EXPECT: denied] ---"
    if "${WORK}/C" read; then C_OK=1; else C_OK=0; fi

    echo "RESULT b_read_ok=${B_OK} c_read_ok=${C_OK}"
    if [[ "${B_OK}" == "1" && "${C_OK}" == "0" ]]; then
      echo "EVIDENCE: DR-durable (re-signed B reads without prompt; ad-hoc C denied)."
    else
      echo "EVIDENCE: NOT durable / inconclusive (b_read_ok=${B_OK} c_read_ok=${C_OK}); inspect osstatus above."
    fi
    ;;
  *)
    echo "usage: run-spike.sh [--plan|--self-test|--run-representative]" >&2
    exit 64
    ;;
esac
