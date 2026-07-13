#!/usr/bin/env bash
# Hermetic mutation tests for the base-owned Phase 0 authority integrity check.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER_SOURCE="${SCRIPT_DIR}/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
WORKFLOW_SOURCE="${SCRIPT_DIR}/../workflows/owner-present-phase0-integrity.yml"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-phase0-integrity-test.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT
REPO="${TMP_ROOT}/repo"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"

mkdir -p \
  "${REPO}/.github/scripts" \
  "${REPO}/.github/workflows" \
  "${REPO}/protected"
git -C "${REPO}" init --quiet
git -C "${REPO}" config user.name "phase0-integrity-test"
git -C "${REPO}" config user.email "phase0-integrity@example.invalid"
cp "${CHECKER_SOURCE}" \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
cp "${BASH_SOURCE[0]}" \
  "${REPO}/.github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
cp "${WORKFLOW_SOURCE}" \
  "${REPO}/.github/workflows/owner-present-phase0-integrity.yml"
printf '%s\n' 'frozen-v1' > "${REPO}/protected/frozen.txt"
FROZEN_OID="$(git -C "${REPO}" hash-object -w "${REPO}/protected/frozen.txt")"
printf '%s\n' 'future-v1' > "${TMP_ROOT}/future.txt"
FUTURE_OID="$(git -C "${REPO}" hash-object -w "${TMP_ROOT}/future.txt")"
{
  printf '# mode\ttype\toid\ttransition\tpath\n'
  printf '100644\tblob\t%s\tfrozen\tprotected/frozen.txt\n' "${FROZEN_OID}"
  for index in $(seq 1 9); do
    printf '100644\tblob\t%s\tland-exact\tprotected/future-%s.txt\n' \
      "${FUTURE_OID}" "${index}"
  done
} > "${REPO}/${POLICY_REL}"
git -C "${REPO}" add .
git -C "${REPO}" commit --quiet -m base
BASE="$(git -C "${REPO}" rev-parse HEAD)"
BRANCH="$(git -C "${REPO}" branch --show-current)"

for index in $(seq 1 9); do
  cp "${TMP_ROOT}/future.txt" "${REPO}/protected/future-${index}.txt"
done
printf '%s\n' unrelated > "${REPO}/unrelated.txt"
git -C "${REPO}" add .
git -C "${REPO}" commit --quiet -m exact-landing
HEAD_OK="$(git -C "${REPO}" rev-parse HEAD)"
git -C "${REPO}" switch --quiet --detach "${BASE}"
PHASE0_INTEGRITY_LOCAL_TEST=1 \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
  "${REPO}" "${BASE}" "${HEAD_OK}" 0 >/dev/null
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS exact_policy_landing"

expect_failure() {
  local label="$1" expected="$2"
  git -C "${REPO}" add -A
  git -C "${REPO}" commit --quiet -m "${label}"
  local head="$(git -C "${REPO}" rev-parse HEAD)"
  git -C "${REPO}" switch --quiet --detach "${BASE}"
  if PHASE0_INTEGRITY_LOCAL_TEST=1 \
      "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
      "${REPO}" "${BASE}" "${head}" 0 >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: integrity checker accepted ${label}" >&2
    exit 1
  fi
  grep -Fq "${expected}" "${TMP_ROOT}/${label}.log"
  git -C "${REPO}" switch --quiet "${BRANCH}"
  echo "PASS ${label}_refused"
}

printf '%s\n' tampered > "${REPO}/protected/future-1.txt"
expect_failure payload_tamper "protected Phase 0 object differs from base-owned policy"
git -C "${REPO}" restore --source="${HEAD_OK}" -- "protected/future-1.txt"

rm "${REPO}/protected/future-2.txt"
expect_failure missing_land_exact "protected Phase 0 object differs from base-owned policy"
git -C "${REPO}" restore --source="${HEAD_OK}" -- "protected/future-2.txt"

printf '%s\n' tampered > "${REPO}/protected/frozen.txt"
expect_failure frozen_tamper "protected Phase 0 object differs from base-owned policy"
git -C "${REPO}" restore --source="${HEAD_OK}" -- "protected/frozen.txt"

printf '%s\n' '# changed' >> "${REPO}/${POLICY_REL}"
expect_failure policy_tamper "base-owned integrity root differs from trusted base"
git -C "${REPO}" restore --source="${HEAD_OK}" -- "${POLICY_REL}"

printf '%s\n' 'exit 0' > \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
expect_failure checker_tamper "base-owned integrity root differs from trusted base"

echo "Phase 0 base-owned policy mutation matrix passed."
