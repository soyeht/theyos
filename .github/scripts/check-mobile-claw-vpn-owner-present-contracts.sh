#!/usr/bin/env bash
# ODB-backed ownership guard for historical owner-present wire evidence.
# The V1 golden declares every nested cross-repo dependency; this guard verifies
# those pairs plus the authoritative retirement status without trusting either
# checkout.
set -euo pipefail

THEYOS_DIR="${1:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
SOYEHT_IOS_DIR="${2:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
BASE_SHA="${3:-}"

CONTRACT_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
CONTRACT_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
STATUS_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
STATUS_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
RETIREMENT_PRIOR_SHA256="ff9ad533567e29261ecbd8e11e84e9490f1829bd4d2e5b50fe8783dc82b000d1"
RETIREMENT_HISTORICAL_SHA256="55fe55c6f1985103f21e679c5e6227646035e4d03da3e75193cfc9d1eeb45f8f"
API_SHAPES_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/api_shapes.json"
API_SHAPES_PRIOR_SHA256="7d31e66fd6172c9e7340455e73d0c2b06629b491442428a14c53edd45f49b7a6"
API_SHAPES_HISTORICAL_SHA256="6482badfe02f220e5954ddf0f73385a622d317ba7b9b9d1063562724574f33b4"
if [[ "${OWNER_PRESENT_CONTRACT_GUARD_LOCAL_TEST:-0}" == "1" ]]; then
  RETIREMENT_PRIOR_SHA256="${OWNER_PRESENT_RETIREMENT_PRIOR_SHA256:?local prior digest is required}"
  RETIREMENT_HISTORICAL_SHA256="${OWNER_PRESENT_RETIREMENT_HISTORICAL_SHA256:?local historical digest is required}"
fi
PIN_REL="scripts/cross-repo-contract.sha"
WORKFLOW_REL=".github/workflows/contracts-cross-repo-sync.yml"

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

HEAD_CONTRACT="${TMP_DIR}/head-contract"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${CONTRACT_SOURCE_REL}" "${HEAD_CONTRACT}" \
  "historical success fixture"; then
  echo "::error file=${CONTRACT_SOURCE_REL}::historical success fixture is missing"
  exit 1
fi

HEAD_STATUS="${TMP_DIR}/head-status"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${STATUS_SOURCE_REL}" "${HEAD_STATUS}" \
  "authoritative wire status"; then
  echo "::error file=${STATUS_SOURCE_REL}::authoritative wire status is missing"
  exit 1
fi
HEAD_BOUNDARY="${TMP_DIR}/head-boundary"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${BOUNDARY_REL}" "${HEAD_BOUNDARY}" \
  "signed Phase 0 artifact boundary"; then
  echo "::error file=${BOUNDARY_REL}::signed Phase 0 artifact boundary is missing"
  exit 1
fi
if [[ "$(jq -r '.contract' "${HEAD_STATUS}")" != \
    "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1" \
  || "$(jq -r '.phase' "${HEAD_STATUS}")" != "phase0-compile-out" \
  || "$(jq -r '.authority' "${HEAD_STATUS}")" != "none" \
  || "$(jq -r '.retired_wire.status' "${HEAD_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_api_shapes.status' "${HEAD_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_api_shapes.theyos_path' "${HEAD_STATUS}")" != \
    "admin/contracts/mobile-claw-vpn/v1/api_shapes.json" \
  || "$(jq -r '.retired_api_shapes.prior_authoritative_sha256' "${HEAD_STATUS}")" != \
    "${API_SHAPES_PRIOR_SHA256}" \
  || "$(jq -r '.retired_api_shapes.historical_sha256' "${HEAD_STATUS}")" != \
    "${API_SHAPES_HISTORICAL_SHA256}" \
  || "$(jq -r '.retired_wire.prior_authoritative_sha256' "${HEAD_STATUS}")" != \
    "${RETIREMENT_PRIOR_SHA256}" \
  || "$(jq -r '.retired_wire.historical_sha256' "${HEAD_STATUS}")" != \
    "${RETIREMENT_HISTORICAL_SHA256}" \
  || "$(jq -r '.phase0_artifact_boundary.theyos_path' "${HEAD_STATUS}")" != \
    "${BOUNDARY_REL}" \
  || "$(jq -r '.phase0_artifact_boundary.sha256' "${HEAD_STATUS}")" != \
    "$(sha256_file "${HEAD_BOUNDARY}")" \
  || "$(jq -r '.phase0_artifact_boundary.staged_product' "${HEAD_STATUS}")" != \
    "theyos-engine" \
  || "$(jq -r '.phase0_artifact_boundary.required_published_targets | sort | join(",")' "${HEAD_STATUS}")" != \
    "aarch64-apple-darwin,aarch64-unknown-linux-musl,x86_64-unknown-linux-musl" \
  || "$(jq -r '.phase1_blocker.minimum_wire_version' "${HEAD_STATUS}")" != "2" \
  || "$(jq -r '.phase1_blocker.required_shape' "${HEAD_STATUS}")" != \
    "server-held-finish-consume-mint" \
  || "$(sha256_file "${HEAD_CONTRACT}")" != "${RETIREMENT_HISTORICAL_SHA256}" \
  || "$(jq -r '.authority_status' "${HEAD_CONTRACT}")" != \
    "historical-test-only-non-authoritative" ]]; then
  echo "::error file=${STATUS_SOURCE_REL}::wire authority status does not close the exact V1 retirement"
  exit 1
fi

PAIRS=()
while IFS= read -r pair; do
  PAIRS+=("${pair}")
done < <(jq -r '.dependencies[] | [.theyos_path, .ios_path] | @tsv' "${HEAD_CONTRACT}")
PAIRS+=("${CONTRACT_SOURCE_REL}"$'\t'"${CONTRACT_VENDOR_REL}")
PAIRS+=("${STATUS_SOURCE_REL}"$'\t'"${STATUS_VENDOR_REL}")
if [[ "${#PAIRS[@]}" -ne 5 ]]; then
  echo "::error file=${CONTRACT_SOURCE_REL}::expected three dependencies, the historical wire, and its authority status"
  exit 1
fi
if [[ "$(printf '%s\n' "${PAIRS[@]}" | sort -u | wc -l | tr -d ' ')" -ne "${#PAIRS[@]}" ]]; then
  echo "::error file=${CONTRACT_SOURCE_REL}::duplicate cross-repo fixture pair"
  exit 1
fi

PIN_SOURCE="${TMP_DIR}/pin"
if ! materialize_regular_blob \
  "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${PIN_REL}" "${PIN_SOURCE}" \
  "iOS cross-repo pin"; then
  echo "::error file=${PIN_REL}::iOS cross-repo pin is missing"
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
    echo "::error file=${PIN_REL}::iOS pin ${PIN} is not an ancestor of theyos HEAD ${HEAD_SHA}"
    exit 1
  fi
fi

BASE_CONTEXT=0
RETIREMENT_BOOTSTRAP=0
BASE_WORKFLOW="${TMP_DIR}/base-workflow"
if [[ "${BASE_SHA}" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "${BASE_SHA}" != "0000000000000000000000000000000000000000" ]]; then
  BASE_CONTEXT=1
  if ! git -C "${THEYOS_DIR}" cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
    git -C "${THEYOS_DIR}" fetch --no-tags --depth=1 origin "${BASE_SHA}"
  fi
  if ! git -C "${THEYOS_DIR}" show "${BASE_SHA}:${WORKFLOW_REL}" > "${BASE_WORKFLOW}" 2>/dev/null; then
    : > "${BASE_WORKFLOW}"
  fi
  BASE_CONTRACT="${TMP_DIR}/base-contract"
  if materialize_regular_blob \
    "${THEYOS_DIR}" "${BASE_SHA}" "${CONTRACT_SOURCE_REL}" "${BASE_CONTRACT}" \
    "base historical fixture" \
    && [[ "$(sha256_file "${BASE_CONTRACT}")" == "${RETIREMENT_PRIOR_SHA256}" ]] \
    && [[ "$(sha256_file "${HEAD_CONTRACT}")" == "${RETIREMENT_HISTORICAL_SHA256}" ]] \
    && ! git -C "${THEYOS_DIR}" cat-file -e "${BASE_SHA}:${STATUS_SOURCE_REL}" 2>/dev/null; then
    RETIREMENT_BOOTSTRAP=1
  fi
fi

INDEX=0
for pair in "${PAIRS[@]}"; do
  INDEX=$((INDEX + 1))
  IFS=$'\t' read -r source_rel vendor_rel <<< "${pair}"
  if [[ -z "${source_rel}" || -z "${vendor_rel}" \
    || "${source_rel}" == /* || "${vendor_rel}" == /* \
    || "${source_rel}" == *".."* || "${vendor_rel}" == *".."* ]]; then
    echo "::error file=${CONTRACT_SOURCE_REL}::unsafe cross-repo dependency path"
    exit 1
  fi

  head_source="${TMP_DIR}/head-${INDEX}"
  if ! materialize_regular_blob \
    "${THEYOS_DIR}" "${HEAD_SHA}" "${source_rel}" "${head_source}" \
    "authoritative dependency"; then
    echo "::error file=${source_rel}::authoritative dependency is missing"
    exit 1
  fi

  source_new=0
  source_retirement=0
  registration_new=0
  if [[ "${BASE_CONTEXT}" == "1" ]]; then
    base_source="${TMP_DIR}/base-${INDEX}"
    if materialize_regular_blob \
      "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${base_source}" \
      "base dependency"; then
      if ! cmp -s "${base_source}" "${head_source}"; then
        if [[ "${source_rel}" == "${CONTRACT_SOURCE_REL}" \
          && "$(sha256_file "${base_source}")" == "${RETIREMENT_PRIOR_SHA256}" \
          && "$(sha256_file "${head_source}")" == "${RETIREMENT_HISTORICAL_SHA256}" ]]; then
          source_retirement=1
        elif [[ "${source_rel}" == "${API_SHAPES_SOURCE_REL}" \
          && "$(sha256_file "${base_source}")" == "${API_SHAPES_PRIOR_SHA256}" \
          && "$(sha256_file "${head_source}")" == "${API_SHAPES_HISTORICAL_SHA256}" ]]; then
          source_retirement=1
        else
          echo "::error file=${source_rel}::pinned V1 dependency is immutable; add a new version"
          diff -u "${base_source}" "${head_source}" || true
          exit 1
        fi
      fi
    else
      source_new=1
    fi
    if ! grep -Fq "${source_rel}" "${BASE_WORKFLOW}"; then
      registration_new=1
    fi
  fi

  declared_sha="$(jq -r --arg source "${source_rel}" \
    '.dependencies[]? | select(.theyos_path == $source) | (.sha256 // empty)' \
    "${HEAD_CONTRACT}")"
  if [[ -n "${declared_sha}" && "${declared_sha}" != "$(sha256_file "${head_source}")" ]]; then
    echo "::error file=${CONTRACT_SOURCE_REL}::declared dependency digest differs from ${source_rel}"
    exit 1
  fi

  vendor_source="${TMP_DIR}/vendor-${INDEX}"
  vendor_exists=1
  if ! materialize_regular_blob \
    "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${vendor_rel}" "${vendor_source}" \
    "iOS vendor"; then
    vendor_exists=0
  fi

  if [[ "${source_new}" == "1" ]]; then
    if [[ "${vendor_exists}" == "1" ]]; then
      echo "::error file=${vendor_rel}::vendor exists before its new authoritative source lands"
      exit 1
    fi
    if [[ "${registration_new}" != "1" ]]; then
      echo "::error file=${WORKFLOW_REL}::new source is unexpectedly registered in the base workflow"
      exit 1
    fi
    echo "Bootstrap: ${source_rel} must land in theyos before iOS vendors ${vendor_rel}."
    continue
  fi

  if [[ "${source_retirement}" == "1" ]]; then
    if [[ "${RETIREMENT_BOOTSTRAP}" != "1" ]]; then
      echo "::error file=${source_rel}::V1 retirement is not the exact ordered bootstrap"
      exit 1
    fi
    if [[ "${vendor_exists}" == "1" ]] && ! cmp -s "${base_source}" "${vendor_source}"; then
      echo "::error file=${vendor_rel}::V1 retirement requires the prior iOS vendor until the theyos authority lands"
      exit 1
    fi
    retirement_pinned="${TMP_DIR}/retirement-pinned-${INDEX}"
    if ! materialize_regular_blob \
      "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${retirement_pinned}" \
      "fixture at the trusted PR base" \
      || ! cmp -s "${base_source}" "${retirement_pinned}"; then
      echo "::error file=${source_rel}::V1 retirement requires the exact prior source at the trusted PR base"
      exit 1
    fi
    echo "Retirement bootstrap: historical V1 authority must land in theyos before the iOS repin."
    continue
  fi

  if [[ "${vendor_exists}" != "1" ]]; then
    if [[ "${RETIREMENT_BOOTSTRAP}" == "1" ]]; then
      retirement_dependency="${TMP_DIR}/retirement-dependency-${INDEX}"
      if ! materialize_regular_blob \
        "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${retirement_dependency}" \
        "historical dependency at the trusted PR base" \
        || ! cmp -s "${head_source}" "${retirement_dependency}"; then
        echo "::error file=${source_rel}::missing historical vendor requires a byte-identical source at the trusted PR base"
        exit 1
      fi
      echo "Retirement bootstrap: ${source_rel} may be vendored only after the Phase 0 authority lands."
      continue
    fi
    if [[ "${registration_new}" == "1" ]]; then
      echo "::error file=${vendor_rel}::existing authoritative source must already have a matching vendor before registration"
    else
      echo "::error file=${vendor_rel}::iOS vendor is missing for ${source_rel}"
    fi
    exit 1
  fi

  if [[ "${registration_new}" == "1" ]]; then
    echo "Registration bootstrap will be verified strictly: ${source_rel}"
  fi

  pinned_source="${TMP_DIR}/pinned-${INDEX}"
  if ! materialize_regular_blob \
    "${THEYOS_DIR}" "${PIN}" "${source_rel}" "${pinned_source}" \
    "fixture at the iOS pin"; then
    if [[ "${registration_new}" == "1" ]]; then
      echo "::error file=${PIN_REL}::registration bootstrap pin ${PIN} does not contain ${source_rel}"
    else
      echo "::error file=${PIN_REL}::iOS pin ${PIN} does not contain ${source_rel}"
    fi
    exit 1
  fi
  if ! cmp -s "${pinned_source}" "${vendor_source}"; then
    echo "::error file=${vendor_rel}::vendor differs from its pinned theyos source ${PIN}"
    diff -u "${pinned_source}" "${vendor_source}" || true
    exit 1
  fi
  if ! cmp -s "${head_source}" "${vendor_source}"; then
    echo "::error file=${source_rel}::theyos HEAD differs from the landed iOS vendor"
    diff -u "${head_source}" "${vendor_source}" || true
    exit 1
  fi
  if [[ "${registration_new}" == "1" ]]; then
    echo "Verified strict registration bootstrap: ${source_rel} <-> ${vendor_rel}"
  else
    echo "Verified ODB pair: ${source_rel} <-> ${vendor_rel}"
  fi
done

echo "Mobile owner-present cross-repo contract ownership is closed."
