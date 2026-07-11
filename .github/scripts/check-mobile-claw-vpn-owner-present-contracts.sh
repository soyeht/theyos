#!/usr/bin/env bash
# ODB-backed ownership guard for the mobile Claw VPN owner-present contract.
# The success fixture declares every nested cross-repo dependency; this guard
# verifies those pairs plus the fixture itself without trusting either checkout.
set -euo pipefail

THEYOS_DIR="${1:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
SOYEHT_IOS_DIR="${2:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
BASE_SHA="${3:-}"

CONTRACT_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
CONTRACT_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
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

HEAD_CONTRACT="${TMP_DIR}/head-contract"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${CONTRACT_SOURCE_REL}" "${HEAD_CONTRACT}" \
  "authoritative success fixture"; then
  echo "::error file=${CONTRACT_SOURCE_REL}::authoritative success fixture is missing"
  exit 1
fi

PAIRS=()
while IFS= read -r pair; do
  PAIRS+=("${pair}")
done < <(jq -r '.dependencies[] | [.theyos_path, .ios_path] | @tsv' "${HEAD_CONTRACT}")
PAIRS+=("${CONTRACT_SOURCE_REL}"$'\t'"${CONTRACT_VENDOR_REL}")
if [[ "${#PAIRS[@]}" -ne 4 ]]; then
  echo "::error file=${CONTRACT_SOURCE_REL}::expected three dependencies plus the success fixture"
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
  registration_new=0
  if [[ "${BASE_CONTEXT}" == "1" ]]; then
    base_source="${TMP_DIR}/base-${INDEX}"
    if materialize_regular_blob \
      "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${base_source}" \
      "base dependency"; then
      if ! cmp -s "${base_source}" "${head_source}"; then
        echo "::error file=${source_rel}::pinned V1 dependency is immutable; add a new version"
        diff -u "${base_source}" "${head_source}" || true
        exit 1
      fi
    else
      source_new=1
    fi
    if ! grep -Fq "${source_rel}" "${BASE_WORKFLOW}"; then
      registration_new=1
    fi
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

  if [[ "${vendor_exists}" != "1" ]]; then
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
