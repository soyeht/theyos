#!/usr/bin/env bash
# Phase 0 authority: prove the production theyos-engine build excludes owner-present.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
THEYOS_DIR="${1:-${DEFAULT_ROOT}}"

FOUNDATION_REL="admin/rust/server-rs/src/mobile_claw_vpn_owner_present_foundation.rs"
MANIFEST_REL="admin/rust/Cargo.toml"
MARKER_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
HISTORICAL_WIRE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
AUTHORITY_STATUS_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"

HEAD_SHA="$(git -C "${THEYOS_DIR}" rev-parse HEAD)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT
SNAPSHOT="${TMP_ROOT}/source"
TARGET_DIR="${TMP_ROOT}/target"
mkdir -p "${SNAPSHOT}"

require_regular_blob() {
  local path="$1"
  local entry mode type
  entry="$(git -C "${THEYOS_DIR}" ls-tree "${HEAD_SHA}" -- "${path}")"
  if [[ -z "${entry}" ]]; then
    echo "::error file=${path}::required Phase 0 input is missing"
    exit 1
  fi
  read -r mode type _ <<< "${entry}"
  if [[ "${mode}" != "100644" || "${type}" != "blob" ]]; then
    echo "::error file=${path}::Phase 0 input must be a regular 100644 Git blob"
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for path in \
  "${MANIFEST_REL}" \
  "admin/rust/Cargo.lock" \
  "admin/rust/server-rs/Cargo.toml" \
  "admin/rust/server-rs/src/lib.rs" \
  "admin/rust/server-rs/src/main.rs" \
  "${FOUNDATION_REL}" \
  "${HISTORICAL_WIRE_REL}" \
  "${AUTHORITY_STATUS_REL}"; do
  require_regular_blob "${path}"
done

if git -C "${THEYOS_DIR}" cat-file -e "${HEAD_SHA}:${MARKER_REL}" 2>/dev/null; then
  echo "::error file=${MARKER_REL}::Phase 0 forbids an owner-present activation marker"
  exit 1
fi

git -C "${THEYOS_DIR}" archive --format=tar "${HEAD_SHA}" | tar -xf - -C "${SNAPSHOT}"

HISTORICAL_WIRE="${SNAPSHOT}/${HISTORICAL_WIRE_REL}"
AUTHORITY_STATUS="${SNAPSHOT}/${AUTHORITY_STATUS_REL}"
if [[ "$(jq -r '.contract' "${AUTHORITY_STATUS}")" != \
    "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1" \
  || "$(jq -r '.version' "${AUTHORITY_STATUS}")" != "1" \
  || "$(jq -r '.phase' "${AUTHORITY_STATUS}")" != "phase0-compile-out" \
  || "$(jq -r '.authority' "${AUTHORITY_STATUS}")" != "none" \
  || "$(jq -r '.retired_wire.status' "${AUTHORITY_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_wire.theyos_path' "${AUTHORITY_STATUS}")" != \
    "${HISTORICAL_WIRE_REL}" \
  || "$(jq -r '.phase1_blocker.minimum_wire_version' "${AUTHORITY_STATUS}")" != "2" \
  || "$(jq -r '.phase1_blocker.required_shape' "${AUTHORITY_STATUS}")" != \
    "server-held-finish-consume-mint" ]]; then
  echo "::error file=${AUTHORITY_STATUS_REL}::Phase 0 authority status is invalid"
  exit 1
fi
if [[ "$(jq -r '.retired_wire.historical_sha256' "${AUTHORITY_STATUS}")" != \
  "$(sha256_file "${HISTORICAL_WIRE}")" ]]; then
  echo "::error file=${AUTHORITY_STATUS_REL}::retired V1 wire digest does not match the historical fixture"
  exit 1
fi
if [[ "$(jq -r '.authority_status' "${HISTORICAL_WIRE}")" != \
  "historical-test-only-non-authoritative" ]]; then
  echo "::error file=${HISTORICAL_WIRE_REL}::V1 wire still claims implementation authority"
  exit 1
fi
for forbidden_authority in \
  "proof_token" \
  "proof-bearing mint request" \
  "owner_present_runtime_activation_v1"; do
  if ! jq -e --arg value "${forbidden_authority}" \
    '.retired_wire.prohibited_production_authority | index($value) != null' \
    "${AUTHORITY_STATUS}" >/dev/null; then
    echo "::error file=${AUTHORITY_STATUS_REL}::missing prohibited V1 authority: ${forbidden_authority}"
    exit 1
  fi
done

THEYOS_BUILD_GIT_SHA="${HEAD_SHA}" \
CARGO_TARGET_DIR="${TARGET_DIR}" \
  cargo build \
    --manifest-path "${SNAPSHOT}/${MANIFEST_REL}" \
    --locked \
    --release \
    --package server-rs \
    --bin server

BINARY="${TARGET_DIR}/release/server"
DEPFILE="${TARGET_DIR}/release/server.d"
if [[ ! -x "${BINARY}" ]]; then
  echo "::error::release server binary was not produced"
  exit 1
fi
if [[ ! -f "${DEPFILE}" ]]; then
  echo "::error::release server dependency graph was not produced"
  exit 1
fi

if grep -Fq "mobile_claw_vpn_owner_present_foundation.rs" "${DEPFILE}"; then
  echo "::error file=${FOUNDATION_REL}::owner-present foundation entered the production dependency graph"
  exit 1
fi

STRINGS_OUT="${TMP_ROOT}/server.strings"
LC_ALL=C strings "${BINARY}" > "${STRINGS_OUT}"
while IFS= read -r forbidden; do
  [[ -z "${forbidden}" ]] && continue
  if grep -Fqi -- "${forbidden}" "${STRINGS_OUT}"; then
    echo "::error::production theyos-engine contains forbidden Phase 0 marker: ${forbidden}"
    exit 1
  fi
done <<'FORBIDDEN'
/api/v1/mobile/claw-vpn/owner-present/
owner_present
owner-present
OwnerPresent
OWNER_PRESENT
mesh_c_owner_present_offer_control
RevalidatedCapability
ConsumedCapability
PointOfUsePermit
owner_approval_consumed
FORBIDDEN

echo "Owner-present Phase 0 compile-out is closed in the production theyos-engine artifact."
