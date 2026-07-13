#!/usr/bin/env bash
# Hermetic mutation tests for the owner-present cross-repo ODB guard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER="${ROOT}/.github/scripts/check-mobile-claw-vpn-owner-present-contracts.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

SOURCE_ROOT="admin/contracts/mobile-claw-vpn/v1"
CONTRACT_REL="${SOURCE_ROOT}/owner_present_success_wire_v1.json"
STATUS_REL="${SOURCE_ROOT}/owner_present_wire_authority_status_v1.json"
BOUNDARY_REL="${SOURCE_ROOT}/owner_present_phase0_artifact_boundary_v1.tsv"
WORKFLOW_REL=".github/workflows/contracts-cross-repo-sync.yml"
PIN_REL="scripts/cross-repo-contract.sha"
VENDOR_ROOT="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/guard-test"
CONTRACT_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
STATUS_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"

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
  git -C "${repo}" config user.name "Contract Guard Test"
  git -C "${repo}" config user.email "guard@example.test"
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

write_sources() {
  local repo="$1"
  mkdir -p "${repo}/${SOURCE_ROOT}"
  printf '%s\n' '{"fixture":"one"}' > "${repo}/${SOURCE_ROOT}/guard_dep_one.json"
  printf '%s\n' '{"fixture":"two"}' > "${repo}/${SOURCE_ROOT}/guard_dep_two.json"
  printf '%s\n' '{"fixture":"three"}' > "${repo}/${SOURCE_ROOT}/guard_dep_three.json"
  cat > "${repo}/${CONTRACT_REL}" <<'JSON'
{
  "authority_status": "historical-test-only-non-authoritative",
  "dependencies": [
    {
      "theyos_path": "admin/contracts/mobile-claw-vpn/v1/guard_dep_one.json",
      "ios_path": "Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/guard-test/guard_dep_one.json"
    },
    {
      "theyos_path": "admin/contracts/mobile-claw-vpn/v1/guard_dep_two.json",
      "ios_path": "Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/guard-test/guard_dep_two.json"
    },
    {
      "theyos_path": "admin/contracts/mobile-claw-vpn/v1/guard_dep_three.json",
      "ios_path": "Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/guard-test/guard_dep_three.json"
    }
  ]
}
JSON
  local contract_sha
  contract_sha="$(sha256_file "${repo}/${CONTRACT_REL}")"
  cat > "${repo}/${BOUNDARY_REL}" <<'TSV'
# synthetic-phase0-boundary
100644	blob	1111111111111111111111111111111111111111	admin/contracts/claw-store/v1/contract.json
100644	blob	8888888888888888888888888888888888888888	admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json
040000	tree	2222222222222222222222222222222222222222	admin/rust
040000	tree	3333333333333333333333333333333333333333	claws
100644	blob	5555555555555555555555555555555555555555	flake.lock
100644	blob	6666666666666666666666666666666666666666	flake.nix
040000	tree	7777777777777777777777777777777777777777	nix
040000	tree	4444444444444444444444444444444444444444	scripts
TSV
  cat > "${repo}/${STATUS_REL}" <<JSON
{
  "contract": "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1",
  "phase": "phase0-compile-out",
  "authority": "none",
  "retired_wire": {
    "prior_authoritative_sha256": "${contract_sha}",
    "historical_sha256": "${contract_sha}",
    "status": "historical-test-only-non-authoritative"
  },
  "retired_api_shapes": {
    "theyos_path": "admin/contracts/mobile-claw-vpn/v1/api_shapes.json",
    "status": "historical-test-only-non-authoritative",
    "prior_authoritative_sha256": "7d31e66fd6172c9e7340455e73d0c2b06629b491442428a14c53edd45f49b7a6",
    "historical_sha256": "6482badfe02f220e5954ddf0f73385a622d317ba7b9b9d1063562724574f33b4"
  },
  "phase0_artifact_boundary": {
    "theyos_path": "${BOUNDARY_REL}",
    "format": "closed-git-inputs-v2",
    "policy_change_control": "base-owned-proof-machinery-commit-bound-inputs",
    "object_identity_update": "per-reviewed-commit-revalidation",
    "object_identity_authority": "commit-bound-evidence-not-independent-approval",
    "release_provenance": "checker-on-release-subject-and-final-package-attestation",
    "staged_products": [
      "nix-theyos-runtime",
      "theyos-engine",
      "theyos-llm-proxy"
    ],
    "required_published_targets": [
      "x86_64-unknown-linux-musl",
      "aarch64-unknown-linux-musl",
      "aarch64-apple-darwin",
      "nix-theyos-runtime-x86_64-linux"
    ]
  },
  "proof_machinery_transition": {
    "protocol": "soyeht-owner-present-proof-machinery-transition-v1",
    "authority": "base-owned-integrity-checker",
    "state": "unarmed",
    "arming": "owner-reviewed-commit-changes-only-transition-auth-and-policy",
    "consumption": "one-shot-exact-tree-and-policy-oid-removes-transition-auth",
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  },
  "phase1_blocker": {
    "minimum_wire_version": 2,
    "required_shape": "server-held-finish-consume-mint"
  }
}
JSON
}

write_workflow() {
  local repo="$1"
  mkdir -p "${repo}/$(dirname "${WORKFLOW_REL}")"
  cat > "${repo}/${WORKFLOW_REL}" <<EOF
paths:
  - "${SOURCE_ROOT}/guard_dep_one.json"
  - "${SOURCE_ROOT}/guard_dep_two.json"
  - "${SOURCE_ROOT}/guard_dep_three.json"
  - "${CONTRACT_REL}"
  - "${STATUS_REL}"
  - "${BOUNDARY_REL}"
EOF
}

write_empty_workflow() {
  local repo="$1"
  mkdir -p "${repo}/$(dirname "${WORKFLOW_REL}")"
  printf '%s\n' 'paths: []' > "${repo}/${WORKFLOW_REL}"
}

write_vendors() {
  local theyos="$1" ios="$2" include_contract="${3:-1}"
  mkdir -p "${ios}/${VENDOR_ROOT}"
  cp "${theyos}/${SOURCE_ROOT}/guard_dep_one.json" "${ios}/${VENDOR_ROOT}/guard_dep_one.json"
  cp "${theyos}/${SOURCE_ROOT}/guard_dep_two.json" "${ios}/${VENDOR_ROOT}/guard_dep_two.json"
  cp "${theyos}/${SOURCE_ROOT}/guard_dep_three.json" "${ios}/${VENDOR_ROOT}/guard_dep_three.json"
  if [[ "${include_contract}" == "1" ]]; then
    mkdir -p "${ios}/$(dirname "${CONTRACT_VENDOR_REL}")"
    cp "${theyos}/${CONTRACT_REL}" "${ios}/${CONTRACT_VENDOR_REL}"
    cp "${theyos}/${STATUS_REL}" "${ios}/${STATUS_VENDOR_REL}"
  fi
}

write_pin() {
  local ios="$1" pin="$2"
  mkdir -p "${ios}/$(dirname "${PIN_REL}")"
  printf '%s\n' "${pin}" > "${ios}/${PIN_REL}"
}

add_local_origin() {
  local repo="$1" origin="$2"
  git clone -q --bare "${repo}" "${origin}"
  git -C "${repo}" remote add origin "${origin}"
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

# Fully registered graph: every source, pin, and vendor is byte-identical.
EXACT_THEYOS="${TMP_DIR}/exact-theyos"
EXACT_IOS="${TMP_DIR}/exact-ios"
new_repo "${EXACT_THEYOS}"
new_repo "${EXACT_IOS}"
write_sources "${EXACT_THEYOS}"
TEST_CONTRACT_SHA="$(sha256_file "${EXACT_THEYOS}/${CONTRACT_REL}")"
export OWNER_PRESENT_CONTRACT_GUARD_LOCAL_TEST=1
export OWNER_PRESENT_RETIREMENT_PRIOR_SHA256="${TEST_CONTRACT_SHA}"
export OWNER_PRESENT_RETIREMENT_HISTORICAL_SHA256="${TEST_CONTRACT_SHA}"
write_workflow "${EXACT_THEYOS}"
EXACT_BASE="$(commit_all "${EXACT_THEYOS}" "registered sources")"
write_vendors "${EXACT_THEYOS}" "${EXACT_IOS}"
write_pin "${EXACT_IOS}" "${EXACT_BASE}"
commit_all "${EXACT_IOS}" "matching vendors" >/dev/null
add_local_origin "${EXACT_THEYOS}" "${TMP_DIR}/exact-origin.git"
expect_pass exact "${CHECKER}" "${EXACT_THEYOS}" "${EXACT_IOS}" "${EXACT_BASE}"

# Ordered bootstrap is valid only when the authoritative sources are new and
# every corresponding vendor is absent.
NEW_THEYOS="${TMP_DIR}/new-theyos"
NEW_IOS="${TMP_DIR}/new-ios"
new_repo "${NEW_THEYOS}"
new_repo "${NEW_IOS}"
write_empty_workflow "${NEW_THEYOS}"
NEW_BASE="$(commit_all "${NEW_THEYOS}" "base without authority")"
write_sources "${NEW_THEYOS}"
write_workflow "${NEW_THEYOS}"
commit_all "${NEW_THEYOS}" "new authority" >/dev/null
write_pin "${NEW_IOS}" "${NEW_BASE}"
commit_all "${NEW_IOS}" "pin before bootstrap" >/dev/null
expect_pass new_source_vendor_absent \
  "${CHECKER}" "${NEW_THEYOS}" "${NEW_IOS}" "${NEW_BASE}"

mkdir -p "${NEW_IOS}/${VENDOR_ROOT}"
cp "${NEW_THEYOS}/${SOURCE_ROOT}/guard_dep_one.json" \
  "${NEW_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
commit_all "${NEW_IOS}" "vendor before authority" >/dev/null
expect_fail vendor_before_source "vendor exists before its new authoritative source lands" \
  "${CHECKER}" "${NEW_THEYOS}" "${NEW_IOS}" "${NEW_BASE}"

# The one-time V1 retirement may change only the exact historical contract
# metadata while the prior byte-identical iOS vendor remains pinned. The new
# authority-status source must land before its vendor.
RETIRE_THEYOS="${TMP_DIR}/retire-theyos"
RETIRE_IOS="${TMP_DIR}/retire-ios"
new_repo "${RETIRE_THEYOS}"
new_repo "${RETIRE_IOS}"
write_sources "${RETIRE_THEYOS}"
perl -0pi -e \
  's/historical-test-only-non-authoritative/legacy-authoritative/' \
  "${RETIRE_THEYOS}/${CONTRACT_REL}"
write_vendors "${RETIRE_THEYOS}" "${RETIRE_IOS}"
rm "${RETIRE_IOS}/${STATUS_VENDOR_REL}"
rm "${RETIRE_IOS}/${CONTRACT_VENDOR_REL}"
rm "${RETIRE_IOS}/${VENDOR_ROOT}/guard_dep_two.json"
rm "${RETIRE_THEYOS}/${STATUS_REL}"
write_workflow "${RETIRE_THEYOS}"
grep -v "${STATUS_REL}" "${RETIRE_THEYOS}/${WORKFLOW_REL}" > \
  "${RETIRE_THEYOS}/${WORKFLOW_REL}.tmp"
mv "${RETIRE_THEYOS}/${WORKFLOW_REL}.tmp" "${RETIRE_THEYOS}/${WORKFLOW_REL}"
RETIRE_BASE="$(commit_all "${RETIRE_THEYOS}" "authoritative V1 base")"
write_pin "${RETIRE_IOS}" "${RETIRE_BASE}"
commit_all "${RETIRE_IOS}" "prior V1 vendor" >/dev/null
RETIRE_PRIOR_SHA="$(sha256_file "${RETIRE_THEYOS}/${CONTRACT_REL}")"

write_sources "${RETIRE_THEYOS}"
write_workflow "${RETIRE_THEYOS}"
RETIRE_HISTORICAL_SHA="$(sha256_file "${RETIRE_THEYOS}/${CONTRACT_REL}")"
jq --arg prior "${RETIRE_PRIOR_SHA}" \
  '.retired_wire.prior_authoritative_sha256 = $prior' \
  "${RETIRE_THEYOS}/${STATUS_REL}" > "${RETIRE_THEYOS}/${STATUS_REL}.tmp"
mv "${RETIRE_THEYOS}/${STATUS_REL}.tmp" "${RETIRE_THEYOS}/${STATUS_REL}"
commit_all "${RETIRE_THEYOS}" "retire V1 authority" >/dev/null
expect_pass retirement_bootstrap \
  env OWNER_PRESENT_RETIREMENT_PRIOR_SHA256="${RETIRE_PRIOR_SHA}" \
    OWNER_PRESENT_RETIREMENT_HISTORICAL_SHA256="${RETIRE_HISTORICAL_SHA}" \
  "${CHECKER}" "${RETIRE_THEYOS}" "${RETIRE_IOS}" "${RETIRE_BASE}"

# Existing sources first registered by this change require already-landed,
# pin-equal vendors. Logging drift is never a successful bootstrap state.
REG_THEYOS="${TMP_DIR}/registration-theyos"
REG_IOS="${TMP_DIR}/registration-ios"
new_repo "${REG_THEYOS}"
new_repo "${REG_IOS}"
mkdir -p "${REG_THEYOS}/${SOURCE_ROOT}"
printf '%s\n' '{"fixture":"one"}' > "${REG_THEYOS}/${SOURCE_ROOT}/guard_dep_one.json"
printf '%s\n' '{"fixture":"two"}' > "${REG_THEYOS}/${SOURCE_ROOT}/guard_dep_two.json"
printf '%s\n' '{"fixture":"three"}' > "${REG_THEYOS}/${SOURCE_ROOT}/guard_dep_three.json"
write_empty_workflow "${REG_THEYOS}"
REG_BASE="$(commit_all "${REG_THEYOS}" "existing unregistered sources")"
write_sources "${REG_THEYOS}"
write_workflow "${REG_THEYOS}"
commit_all "${REG_THEYOS}" "register existing sources" >/dev/null
write_vendors "${REG_THEYOS}" "${REG_IOS}" 0
write_pin "${REG_IOS}" "${REG_BASE}"
commit_all "${REG_IOS}" "matching existing vendors" >/dev/null
add_local_origin "${REG_THEYOS}" "${TMP_DIR}/registration-origin.git"
expect_pass registration_exact \
  "${CHECKER}" "${REG_THEYOS}" "${REG_IOS}" "${REG_BASE}"

MISSING_REG_IOS="${TMP_DIR}/registration-missing-ios"
git clone -q "${REG_IOS}" "${MISSING_REG_IOS}"
git -C "${MISSING_REG_IOS}" config user.name "Contract Guard Test"
git -C "${MISSING_REG_IOS}" config user.email "guard@example.test"
rm "${MISSING_REG_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
commit_all "${MISSING_REG_IOS}" "registration missing vendor" >/dev/null
expect_fail registration_missing_vendor \
  "existing authoritative source must already have a matching vendor before registration" \
  "${CHECKER}" "${REG_THEYOS}" "${MISSING_REG_IOS}" "${REG_BASE}"

printf '%s\n' '{"fixture":"drift"}' > "${REG_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
commit_all "${REG_IOS}" "registration drift" >/dev/null
expect_fail registration_drift "vendor differs from its pinned theyos source" \
  "${CHECKER}" "${REG_THEYOS}" "${REG_IOS}" "${REG_BASE}"

rm "${REG_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
ln -s guard_dep_two.json "${REG_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
commit_all "${REG_IOS}" "symlink vendor" >/dev/null
expect_fail vendor_mode "must be a regular 100644 Git blob" \
  "${CHECKER}" "${REG_THEYOS}" "${REG_IOS}" "${REG_BASE}"

# A pin whose commit exists but is not landed on authoritative HEAD must fail.
EXACT_TREE="$(git -C "${EXACT_THEYOS}" rev-parse HEAD^{tree})"
SIDE_PIN="$(printf '%s\n' 'unlanded pin' | git -C "${EXACT_THEYOS}" commit-tree "${EXACT_TREE}")"
write_pin "${EXACT_IOS}" "${SIDE_PIN}"
commit_all "${EXACT_IOS}" "unlanded pin" >/dev/null
expect_fail pin_not_landed "is not an ancestor" \
  "${CHECKER}" "${EXACT_THEYOS}" "${EXACT_IOS}" "${EXACT_BASE}"

# Coordinated source/vendor/pin drift still violates immutable V1 ownership.
DRIFT_THEYOS="${TMP_DIR}/coordinated-theyos"
DRIFT_IOS="${TMP_DIR}/coordinated-ios"
git clone -q "${TMP_DIR}/exact-origin.git" "${DRIFT_THEYOS}"
git clone -q "${EXACT_IOS}" "${DRIFT_IOS}"
git -C "${DRIFT_THEYOS}" config user.name "Contract Guard Test"
git -C "${DRIFT_THEYOS}" config user.email "guard@example.test"
git -C "${DRIFT_IOS}" config user.name "Contract Guard Test"
git -C "${DRIFT_IOS}" config user.email "guard@example.test"
printf '%s\n' '{"fixture":"coordinated"}' > \
  "${DRIFT_THEYOS}/${SOURCE_ROOT}/guard_dep_one.json"
DRIFT_HEAD="$(commit_all "${DRIFT_THEYOS}" "coordinated source drift")"
cp "${DRIFT_THEYOS}/${SOURCE_ROOT}/guard_dep_one.json" \
  "${DRIFT_IOS}/${VENDOR_ROOT}/guard_dep_one.json"
write_pin "${DRIFT_IOS}" "${DRIFT_HEAD}"
commit_all "${DRIFT_IOS}" "coordinated vendor drift" >/dev/null
expect_fail coordinated_drift "pinned V1 dependency is immutable" \
  "${CHECKER}" "${DRIFT_THEYOS}" "${DRIFT_IOS}" "${EXACT_BASE}"

# Unsafe fixture paths are rejected before any materialization can escape.
PATH_THEYOS="${TMP_DIR}/path-theyos"
PATH_IOS="${TMP_DIR}/path-ios"
git clone -q "${TMP_DIR}/exact-origin.git" "${PATH_THEYOS}"
git clone -q "${EXACT_IOS}" "${PATH_IOS}"
git -C "${PATH_THEYOS}" config user.name "Contract Guard Test"
git -C "${PATH_THEYOS}" config user.email "guard@example.test"
git -C "${PATH_IOS}" config user.name "Contract Guard Test"
git -C "${PATH_IOS}" config user.email "guard@example.test"
write_pin "${PATH_IOS}" "${EXACT_BASE}"
commit_all "${PATH_IOS}" "restore landed pin" >/dev/null
perl -0pi -e 's#admin/contracts/mobile-claw-vpn/v1/guard_dep_one\.json#../escape.json#' \
  "${PATH_THEYOS}/${CONTRACT_REL}"
PATH_CONTRACT_SHA="$(sha256_file "${PATH_THEYOS}/${CONTRACT_REL}")"
jq --arg sha "${PATH_CONTRACT_SHA}" \
  '.retired_wire.historical_sha256 = $sha' \
  "${PATH_THEYOS}/${STATUS_REL}" > "${PATH_THEYOS}/${STATUS_REL}.tmp"
mv "${PATH_THEYOS}/${STATUS_REL}.tmp" "${PATH_THEYOS}/${STATUS_REL}"
commit_all "${PATH_THEYOS}" "unsafe dependency path" >/dev/null
expect_fail unsafe_path "unsafe cross-repo dependency path" \
  env OWNER_PRESENT_RETIREMENT_HISTORICAL_SHA256="${PATH_CONTRACT_SHA}" \
  "${CHECKER}" "${PATH_THEYOS}" "${PATH_IOS}" "${EXACT_BASE}"

echo "Owner-present ODB guard mutation matrix passed."
