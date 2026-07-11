#!/usr/bin/env bash
# Hermetic mutation tests for the durable owner-present runtime crossing gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER="${ROOT}/.github/scripts/check-mobile-claw-vpn-owner-present-runtime-gate.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

FOUNDATION_REL="admin/rust/server-rs/src/mobile_claw_vpn_owner_present_foundation.rs"
LIB_REL="admin/rust/server-rs/src/lib.rs"
RUNTIME_REL="admin/rust/server-rs/src/mobile_claw_vpn_owner_present_handler.rs"
MARKER_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
ERROR_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_error_wire_v1.json"
ERROR_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_error_wire_v1.json"
PIN_REL="scripts/cross-repo-contract.sha"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

new_repo() {
  local repo="$1"
  git init -q -b main "${repo}"
  git -C "${repo}" config user.name "Runtime Gate Test"
  git -C "${repo}" config user.email "runtime-gate@example.test"
  : > "${repo}/.keep"
  git -C "${repo}" add .keep
  git -C "${repo}" commit -qm "initial"
}

commit_all() {
  local repo="$1" message="$2"
  git -C "${repo}" add -A
  git -C "${repo}" commit -qm "${message}"
  git -C "${repo}" rev-parse HEAD
}

write_inert_foundation() {
  local repo="$1"
  mkdir -p "${repo}/$(dirname "${FOUNDATION_REL}")"
  cp "${ROOT}/${FOUNDATION_REL}" "${repo}/${FOUNDATION_REL}"
  cp "${ROOT}/${LIB_REL}" "${repo}/${LIB_REL}"
}

write_runtime() {
  local repo="$1"
  printf '%s\n' 'struct OwnerPresentRuntimeHandler;' > "${repo}/${RUNTIME_REL}"
}

write_marker() {
  local repo="$1" digest="$2"
  mkdir -p "${repo}/$(dirname "${MARKER_REL}")"
  cat > "${repo}/${MARKER_REL}" <<EOF
{
  "contract": "soyeht-mobile-claw-vpn-owner-present-runtime-activation-v1",
  "version": 1,
  "error_wire": {
    "theyos_path": "${ERROR_REL}",
    "ios_path": "${ERROR_VENDOR_REL}",
    "sha256": "${digest}"
  }
}
EOF
}

write_pin() {
  local ios="$1" pin="$2"
  mkdir -p "${ios}/$(dirname "${PIN_REL}")"
  printf '%s\n' "${pin}" > "${ios}/${PIN_REL}"
}

expect_pass() {
  local label="$1"
  shift
  if ! "$@" > "${TMP_DIR}/${label}.log" 2>&1; then
    cat "${TMP_DIR}/${label}.log"
    echo "expected pass: ${label}" >&2
    exit 1
  fi
}

expect_fail() {
  local label="$1" expected="$2"
  shift 2
  if "$@" > "${TMP_DIR}/${label}.log" 2>&1; then
    cat "${TMP_DIR}/${label}.log"
    echo "expected failure: ${label}" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" "${TMP_DIR}/${label}.log"; then
    cat "${TMP_DIR}/${label}.log"
    echo "missing failure reason for ${label}: ${expected}" >&2
    exit 1
  fi
}

# The current private module is the only allowed PRE-EFFECT state.
INERT_THEYOS="${TMP_DIR}/inert-theyos"
INERT_IOS="${TMP_DIR}/inert-ios"
new_repo "${INERT_THEYOS}"
new_repo "${INERT_IOS}"
write_inert_foundation "${INERT_THEYOS}"
commit_all "${INERT_THEYOS}" "private foundation" >/dev/null
expect_pass inert "${CHECKER}" "${INERT_THEYOS}" "${INERT_IOS}"

for mutation in reexport wrapper route; do
  LIB_THEYOS="${TMP_DIR}/lib-${mutation}-theyos"
  LIB_IOS="${TMP_DIR}/lib-${mutation}-ios"
  git clone -q "${INERT_THEYOS}" "${LIB_THEYOS}"
  git clone -q "${INERT_IOS}" "${LIB_IOS}"
  git -C "${LIB_THEYOS}" config user.name "Runtime Gate Test"
  git -C "${LIB_THEYOS}" config user.email "runtime-gate@example.test"
  case "${mutation}" in
    reexport)
      printf '%s\n' \
        'pub(crate) use mobile_claw_vpn_owner_present_foundation as owner_present_boundary;' \
        >> "${LIB_THEYOS}/${LIB_REL}"
      ;;
    wrapper)
      printf '%s\n' 'fn owner_present_wrapper() {}' >> "${LIB_THEYOS}/${LIB_REL}"
      ;;
    route)
      printf '%s\n' \
        'const OWNER_PRESENT_ROUTE: &str = "/api/v1/mobile/claw-vpn/owner-present/start";' \
        >> "${LIB_THEYOS}/${LIB_REL}"
      ;;
  esac
  commit_all "${LIB_THEYOS}" "lib ${mutation} bypass" >/dev/null
  expect_fail "lib_${mutation}" "requires the ODB-verified activation marker" \
    "${CHECKER}" "${LIB_THEYOS}" "${LIB_IOS}"
done

write_pattern() {
  local output="$1" pattern="$2"
  case "${pattern}" in
    owner_snake) printf '%s\n' 'fn owner_present_probe() {}' >> "${output}" ;;
    owner_hyphen) printf '%s\n' 'const PATH: &str = "owner-present";' >> "${output}" ;;
    owner_camel) printf '%s\n' 'struct OwnerPresentProbe;' >> "${output}" ;;
    owner_upper) printf '%s\n' 'const OWNER_PRESENT: bool = true;' >> "${output}" ;;
    revalidated) printf '%s\n' 'struct RevalidatedCapability;' >> "${output}" ;;
    consumed) printf '%s\n' 'struct ConsumedCapability;' >> "${output}" ;;
    permit) printf '%s\n' 'struct PointOfUsePermit;' >> "${output}" ;;
    consumed_flag) printf '%s\n' 'const owner_approval_consumed: bool = true;' >> "${output}" ;;
  esac
}

# Every alternative in RUNTIME_PATTERN must fail in both the specially handled
# crate root and an ordinary production source file.
for pattern in \
  owner_snake owner_hyphen owner_camel owner_upper \
  revalidated consumed permit consumed_flag; do
  for scope in lib source; do
    PATTERN_THEYOS="${TMP_DIR}/pattern-${pattern}-${scope}-theyos"
    PATTERN_IOS="${TMP_DIR}/pattern-${pattern}-${scope}-ios"
    git clone -q "${INERT_THEYOS}" "${PATTERN_THEYOS}"
    git clone -q "${INERT_IOS}" "${PATTERN_IOS}"
    git -C "${PATTERN_THEYOS}" config user.name "Runtime Gate Test"
    git -C "${PATTERN_THEYOS}" config user.email "runtime-gate@example.test"
    if [[ "${scope}" == "lib" ]]; then
      PATTERN_FILE="${PATTERN_THEYOS}/${LIB_REL}"
    else
      PATTERN_FILE="${PATTERN_THEYOS}/admin/rust/server-rs/src/pattern_probe.rs"
    fi
    write_pattern "${PATTERN_FILE}" "${pattern}"
    commit_all "${PATTERN_THEYOS}" "${pattern} in ${scope}" >/dev/null
    expect_fail "pattern_${pattern}_${scope}" \
      "requires the ODB-verified activation marker" \
      "${CHECKER}" "${PATTERN_THEYOS}" "${PATTERN_IOS}"
  done
done

write_runtime "${INERT_THEYOS}"
commit_all "${INERT_THEYOS}" "runtime without marker" >/dev/null
expect_fail runtime_without_marker "requires the ODB-verified activation marker" \
  "${CHECKER}" "${INERT_THEYOS}" "${INERT_IOS}"

write_marker "${INERT_THEYOS}" \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
commit_all "${INERT_THEYOS}" "marker without error wire" >/dev/null
expect_fail marker_without_error "requires the authoritative error-wire fixture" \
  "${CHECKER}" "${INERT_THEYOS}" "${INERT_IOS}"

# Once runtime exists, source, landed pin, vendor, and marker digest must all
# identify the exact same regular blob.
CLOSED_THEYOS="${TMP_DIR}/closed-theyos"
CLOSED_IOS="${TMP_DIR}/closed-ios"
new_repo "${CLOSED_THEYOS}"
new_repo "${CLOSED_IOS}"
write_inert_foundation "${CLOSED_THEYOS}"
write_runtime "${CLOSED_THEYOS}"
mkdir -p "${CLOSED_THEYOS}/$(dirname "${ERROR_REL}")"
printf '%s\n' '{"contract":"opaque-error-v1"}' > "${CLOSED_THEYOS}/${ERROR_REL}"
ERROR_SHA="$(sha256_file "${CLOSED_THEYOS}/${ERROR_REL}")"
write_marker "${CLOSED_THEYOS}" "${ERROR_SHA}"
CLOSED_HEAD="$(commit_all "${CLOSED_THEYOS}" "closed runtime gate")"
mkdir -p "${CLOSED_IOS}/$(dirname "${ERROR_VENDOR_REL}")"
cp "${CLOSED_THEYOS}/${ERROR_REL}" "${CLOSED_IOS}/${ERROR_VENDOR_REL}"
write_pin "${CLOSED_IOS}" "${CLOSED_HEAD}"
commit_all "${CLOSED_IOS}" "matching error vendor" >/dev/null
git clone -q --bare "${CLOSED_THEYOS}" "${TMP_DIR}/closed-origin.git"
git -C "${CLOSED_THEYOS}" remote add origin "${TMP_DIR}/closed-origin.git"
expect_pass closed "${CHECKER}" "${CLOSED_THEYOS}" "${CLOSED_IOS}"

printf '%s\n' '{"contract":"drift"}' > "${CLOSED_IOS}/${ERROR_VENDOR_REL}"
commit_all "${CLOSED_IOS}" "vendor drift" >/dev/null
expect_fail vendor_drift "must be byte-identical" \
  "${CHECKER}" "${CLOSED_THEYOS}" "${CLOSED_IOS}"

cp "${CLOSED_THEYOS}/${ERROR_REL}" "${CLOSED_IOS}/${ERROR_VENDOR_REL}"
write_pin "${CLOSED_IOS}" "${CLOSED_HEAD}"
commit_all "${CLOSED_IOS}" "restore closure" >/dev/null
PIN_THEYOS="${TMP_DIR}/pin-theyos"
PIN_IOS="${TMP_DIR}/pin-ios"
git clone -q "${TMP_DIR}/closed-origin.git" "${PIN_THEYOS}"
git clone -q "${CLOSED_IOS}" "${PIN_IOS}"
git -C "${PIN_THEYOS}" config user.name "Runtime Gate Test"
git -C "${PIN_THEYOS}" config user.email "runtime-gate@example.test"
git -C "${PIN_IOS}" config user.name "Runtime Gate Test"
git -C "${PIN_IOS}" config user.email "runtime-gate@example.test"
write_marker "${CLOSED_THEYOS}" \
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
commit_all "${CLOSED_THEYOS}" "wrong marker digest" >/dev/null
expect_fail marker_digest "does not match authoritative error-wire bytes" \
  "${CHECKER}" "${CLOSED_THEYOS}" "${CLOSED_IOS}"

SIDE_TREE="$(git -C "${PIN_THEYOS}" rev-parse HEAD^{tree})"
SIDE_PIN="$(printf '%s\n' 'unlanded error pin' | git -C "${PIN_THEYOS}" commit-tree "${SIDE_TREE}")"
write_pin "${PIN_IOS}" "${SIDE_PIN}"
commit_all "${PIN_IOS}" "unlanded error pin" >/dev/null
expect_fail unlanded_pin "is not landed" \
  "${CHECKER}" "${PIN_THEYOS}" "${PIN_IOS}"

echo "Owner-present runtime crossing mutation matrix passed."
