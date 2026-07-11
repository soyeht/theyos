#!/usr/bin/env bash
# Hermetic mutation tests for the base-owned Phase 0 authority integrity check.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="${SCRIPT_DIR}/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-phase0-integrity-test.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT
REPO="${TMP_ROOT}/repo"

PROTECTED_PATHS=(
  ".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
  ".github/scripts/test-mobile-claw-vpn-owner-present-phase0-compileout.sh"
  ".github/workflows/owner-present-phase0-compileout.yml"
  ".github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/workflows/owner-present-phase0-integrity.yml"
  ".github/scripts/check-mobile-claw-vpn-owner-present-contracts.sh"
  ".github/scripts/test-mobile-claw-vpn-owner-present-contracts.sh"
  ".github/workflows/contracts-cross-repo-sync.yml"
  "admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
  "admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
)

mkdir -p "${REPO}"
git -C "${REPO}" init --quiet
git -C "${REPO}" config user.name "phase0-integrity-test"
git -C "${REPO}" config user.email "phase0-integrity@example.invalid"
for path in "${PROTECTED_PATHS[@]}"; do
  mkdir -p "${REPO}/$(dirname "${path}")"
  printf 'protected:%s\n' "${path}" > "${REPO}/${path}"
done
git -C "${REPO}" add .
git -C "${REPO}" commit --quiet -m base
BASE="$(git -C "${REPO}" rev-parse HEAD)"
BRANCH="$(git -C "${REPO}" branch --show-current)"

printf '%s\n' "unrelated" > "${REPO}/unrelated.txt"
git -C "${REPO}" add .
git -C "${REPO}" commit --quiet -m unrelated
HEAD_OK="$(git -C "${REPO}" rev-parse HEAD)"
git -C "${REPO}" switch --quiet --detach "${BASE}"
PHASE0_INTEGRITY_LOCAL_TEST=1 \
  "${CHECKER}" "${REPO}" "${BASE}" "${HEAD_OK}" 0 >/dev/null
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS unrelated_change"

expect_failure() {
  local label="$1" expected="$2"
  local head
  git -C "${REPO}" add -A
  git -C "${REPO}" commit --quiet -m "${label}"
  head="$(git -C "${REPO}" rev-parse HEAD)"
  git -C "${REPO}" switch --quiet --detach "${BASE}"
  if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    "${CHECKER}" "${REPO}" "${BASE}" "${head}" 0 \
    >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: integrity checker accepted ${label}" >&2
    exit 1
  fi
  grep -Fq "${expected}" "${TMP_ROOT}/${label}.log"
  git -C "${REPO}" switch --quiet "${BRANCH}"
  echo "PASS ${label}_refused"
}

printf '%s\n' 'exit 0' > \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
expect_failure checker_noop "protected Phase 0 authority differs from trusted base"

git -C "${REPO}" restore --source="${HEAD_OK}" -- \
  ".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
rm "${REPO}/.github/workflows/owner-present-phase0-compileout.yml"
expect_failure workflow_deleted "protected Phase 0 authority object is missing"

git -C "${REPO}" restore --source="${HEAD_OK}" -- \
  ".github/workflows/owner-present-phase0-compileout.yml"
printf '%s\n' '{"authority":"v1"}' > \
  "${REPO}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
expect_failure authority_status_changed \
  "protected Phase 0 authority differs from trusted base"

git -C "${REPO}" restore --source="${HEAD_OK}" -- \
  "admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
printf '%s\n' '100644 deadbeef invalid' > \
  "${REPO}/admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
expect_failure boundary_manifest_changed \
  "protected Phase 0 authority differs from trusted base"

echo "Phase 0 authority integrity mutation matrix passed."
