#!/usr/bin/env bash
# Durable crossing guard from the inert owner-present foundation to runtime.
set -euo pipefail

THEYOS_DIR="${1:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR}"
SOYEHT_IOS_DIR="${2:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR}"

FOUNDATION_REL="admin/rust/server-rs/src/mobile_claw_vpn_owner_present_foundation.rs"
SEALED_FOUNDATION_BLOB="172a28670577b6bb37b38f36be48812fba9bbcdc"
LIB_REL="admin/rust/server-rs/src/lib.rs"
MARKER_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
ERROR_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_error_wire_v1.json"
ERROR_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_error_wire_v1.json"
PIN_REL="scripts/cross-repo-contract.sha"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

HEAD_SHA="$(git -C "${THEYOS_DIR}" rev-parse HEAD)"
IOS_HEAD_SHA="$(git -C "${SOYEHT_IOS_DIR}" rev-parse HEAD)"

materialize_regular_blob() {
  local repo="$1" commit="$2" path="$3" destination="$4" label="$5"
  local entry mode type object
  entry="$(git -C "${repo}" ls-tree "${commit}" -- "${path}")"
  if [[ -z "${entry}" ]]; then
    return 1
  fi
  read -r mode type object _ <<< "${entry}"
  if [[ "${mode}" != "100644" || "${type}" != "blob" ]]; then
    echo "::error file=${path}::${label} must be a regular 100644 Git blob"
    exit 1
  fi
  git -C "${repo}" cat-file blob "${object}" > "${destination}"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

FOUNDATION="${TMP_DIR}/foundation"
LIB="${TMP_DIR}/lib"
materialize_regular_blob "${THEYOS_DIR}" "${HEAD_SHA}" "${FOUNDATION_REL}" "${FOUNDATION}" \
  "owner-present foundation"
materialize_regular_blob "${THEYOS_DIR}" "${HEAD_SHA}" "${LIB_REL}" "${LIB}" "server library"

runtime_detected=0
if [[ "$(git hash-object "${FOUNDATION}")" != "${SEALED_FOUNDATION_BLOB}" ]]; then
  echo "Sealed owner-present foundation blob changed: ${FOUNDATION_REL}"
  runtime_detected=1
fi
# The sealed module/lib pair makes use of the reviewed foundation impossible
# without tripping here. The broader terms also catch parallel capability paths.
RUNTIME_PATTERN='owner[-_]present|OwnerPresent|OWNER_PRESENT|RevalidatedCapability|ConsumedCapability|PointOfUsePermit|owner_approval_consumed'
EXPECTED_LIB_OWNER_PRESENT_LINES=$'// the separately reviewed owner-present wiring slice changes its visibility.\nmod mobile_claw_vpn_owner_present_foundation;'
ACTUAL_LIB_OWNER_PRESENT_LINES="$(
  grep -E "${RUNTIME_PATTERN}" "${LIB}" || true
)"
if [[ "${ACTUAL_LIB_OWNER_PRESENT_LINES}" != "${EXPECTED_LIB_OWNER_PRESENT_LINES}" ]]; then
  echo "Owner-present occurrences in lib.rs differ from the sealed PRE-EFFECT set."
  runtime_detected=1
fi

while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  case "${path}" in
    "${FOUNDATION_REL}"|"${LIB_REL}") ;;
    *)
      echo "Runtime owner-present source detected: ${path}"
      runtime_detected=1
      ;;
  esac
done < <(
  git -C "${THEYOS_DIR}" grep -l -E \
    "${RUNTIME_PATTERN}" "${HEAD_SHA}" -- \
    admin/rust/server-rs/src admin/rust/household-rs/src 2>/dev/null \
    | sed 's/^[^:]*://' || true
)

MARKER="${TMP_DIR}/activation-marker"
marker_exists=1
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${MARKER_REL}" "${MARKER}" \
  "owner-present runtime activation marker"; then
  marker_exists=0
fi

if [[ "${runtime_detected}" == "0" && "${marker_exists}" == "0" ]]; then
  echo "Owner-present runtime gate remains PRE-EFFECT and closed."
  exit 0
fi
if [[ "${runtime_detected}" == "1" && "${marker_exists}" == "0" ]]; then
  echo "::error file=${MARKER_REL}::runtime owner-present code requires the ODB-verified activation marker"
  exit 1
fi

if [[ "$(jq -r '.contract' "${MARKER}")" != "soyeht-mobile-claw-vpn-owner-present-runtime-activation-v1" \
  || "$(jq -r '.version' "${MARKER}")" != "1" \
  || "$(jq -r '.error_wire.theyos_path' "${MARKER}")" != "${ERROR_SOURCE_REL}" \
  || "$(jq -r '.error_wire.ios_path' "${MARKER}")" != "${ERROR_VENDOR_REL}" ]]; then
  echo "::error file=${MARKER_REL}::activation marker shape or error-wire ownership paths are invalid"
  exit 1
fi
EXPECTED_SHA256="$(jq -r '.error_wire.sha256' "${MARKER}")"
if [[ ! "${EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::error file=${MARKER_REL}::error-wire SHA-256 must be lowercase 64-hex"
  exit 1
fi

ERROR_SOURCE="${TMP_DIR}/error-source"
ERROR_VENDOR="${TMP_DIR}/error-vendor"
PIN_SOURCE="${TMP_DIR}/pin"
PINNED_ERROR="${TMP_DIR}/pinned-error"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${ERROR_SOURCE_REL}" "${ERROR_SOURCE}" \
  "authoritative owner-present error wire"; then
  echo "::error file=${ERROR_SOURCE_REL}::activation marker requires the authoritative error-wire fixture"
  exit 1
fi
if ! materialize_regular_blob \
  "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${ERROR_VENDOR_REL}" "${ERROR_VENDOR}" \
  "iOS owner-present error-wire vendor"; then
  echo "::error file=${ERROR_VENDOR_REL}::activation marker requires the iOS error-wire vendor"
  exit 1
fi
if ! materialize_regular_blob \
  "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${PIN_REL}" "${PIN_SOURCE}" \
  "iOS cross-repo pin"; then
  echo "::error file=${PIN_REL}::activation marker requires the iOS cross-repo pin"
  exit 1
fi

PIN="$(grep -vE '^[[:space:]]*#' "${PIN_SOURCE}" | tr -d '[:space:]')"
if [[ ! "${PIN}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error file=${PIN_REL}::iOS cross-repo pin must be one lowercase 40-hex commit"
  exit 1
fi
if ! git -C "${THEYOS_DIR}" cat-file -e "${PIN}^{commit}" 2>/dev/null; then
  git -C "${THEYOS_DIR}" fetch --no-tags --depth=1 origin "${PIN}"
fi
if ! git -C "${THEYOS_DIR}" merge-base --is-ancestor "${PIN}" "${HEAD_SHA}" 2>/dev/null; then
  if [[ "$(git -C "${THEYOS_DIR}" rev-parse --is-shallow-repository)" == "true" ]]; then
    git -C "${THEYOS_DIR}" fetch --no-tags --unshallow origin
  else
    git -C "${THEYOS_DIR}" fetch --no-tags origin main
  fi
  if ! git -C "${THEYOS_DIR}" merge-base --is-ancestor "${PIN}" "${HEAD_SHA}"; then
    echo "::error file=${PIN_REL}::error-wire pin ${PIN} is not landed on theyos HEAD ${HEAD_SHA}"
    exit 1
  fi
fi
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${PIN}" "${ERROR_SOURCE_REL}" "${PINNED_ERROR}" \
  "error wire at the iOS pin"; then
  echo "::error file=${PIN_REL}::pin ${PIN} does not contain the owner-present error wire"
  exit 1
fi
if [[ "$(sha256_file "${ERROR_SOURCE}")" != "${EXPECTED_SHA256}" ]]; then
  echo "::error file=${MARKER_REL}::activation marker SHA-256 does not match authoritative error-wire bytes"
  exit 1
fi
if ! cmp -s "${ERROR_SOURCE}" "${PINNED_ERROR}" \
  || ! cmp -s "${ERROR_SOURCE}" "${ERROR_VENDOR}"; then
  echo "::error file=${ERROR_SOURCE_REL}::error-wire source, landed pin, and iOS vendor must be byte-identical"
  exit 1
fi

echo "Owner-present runtime activation marker is backed by a landed, byte-identical error-wire contract."
