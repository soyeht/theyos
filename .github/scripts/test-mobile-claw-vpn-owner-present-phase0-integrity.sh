#!/usr/bin/env bash
# Hermetic mutation tests for the trusted-base land-exact integrity checker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
TEST_REL=".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
WORKFLOW_REL=".github/workflows/owner-present-phase0-integrity.yml"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"
TRANSITION_REL=".github/owner-present-phase0-transition-v1.json"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/phase0-land-exact-test.XXXXXX")"
trap 'chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true; rm -rf "${TMP_ROOT}"' EXIT
BASE_REPO="${TMP_ROOT}/base"

mkdir -p \
  "${BASE_REPO}/.github/scripts" \
  "${BASE_REPO}/.github/workflows" \
  "${BASE_REPO}/protected"
git -C "${BASE_REPO}" init --quiet
git -C "${BASE_REPO}" config user.name phase0-land-exact-test
git -C "${BASE_REPO}" config user.email phase0-land-exact@example.invalid
cp "${ROOT}/${CHECKER_REL}" "${BASE_REPO}/${CHECKER_REL}"
cp "${ROOT}/${TEST_REL}" "${BASE_REPO}/${TEST_REL}"
cp "${ROOT}/${WORKFLOW_REL}" "${BASE_REPO}/${WORKFLOW_REL}"
printf '%s\n' frozen-v1 >"${BASE_REPO}/protected/frozen.txt"
for index in 1 2 3 4 5 6 7; do
  printf 'land-%s-v1\n' "${index}" >"${BASE_REPO}/protected/land-${index}.txt"
done

blob_oid() {
  git -C "$1" hash-object --no-filters "$1/$2"
}

{
  printf '# mode\ttype\toid\ttransition\tpath\n'
  printf '100755\tblob\t%s\tland-exact\t%s\n' \
    "$(blob_oid "${BASE_REPO}" "${CHECKER_REL}")" "${CHECKER_REL}"
  printf '100755\tblob\t%s\tland-exact\t%s\n' \
    "$(blob_oid "${BASE_REPO}" "${TEST_REL}")" "${TEST_REL}"
  printf '100644\tblob\t%s\tland-exact\t%s\n' \
    "$(blob_oid "${BASE_REPO}" "${WORKFLOW_REL}")" "${WORKFLOW_REL}"
  printf '100644\tblob\t%s\tfrozen\tprotected/frozen.txt\n' \
    "$(blob_oid "${BASE_REPO}" protected/frozen.txt)"
  for index in 1 2 3 4 5 6 7; do
    protected_path="protected/land-${index}.txt"
    printf '100644\tblob\t%s\tland-exact\t%s\n' \
      "$(blob_oid "${BASE_REPO}" "${protected_path}")" "${protected_path}"
  done
} >"${BASE_REPO}/${POLICY_REL}"
git -C "${BASE_REPO}" add .
git -C "${BASE_REPO}" commit --quiet -m base
BASE_SHA="$(git -C "${BASE_REPO}" rev-parse HEAD)"

clone_case() {
  local label="$1" destination
  destination="${TMP_ROOT}/${label}"
  git clone --quiet --shared "${BASE_REPO}" "${destination}"
  git -C "${destination}" config user.name phase0-land-exact-test
  git -C "${destination}" config user.email phase0-land-exact@example.invalid
  git -C "${destination}" switch --quiet --detach "${BASE_SHA}"
  printf '%s\n' "${destination}"
}

reseal() {
  local repo="$1" protected_path="$2" oid tmp
  oid="$(blob_oid "${repo}" "${protected_path}")"
  tmp="${repo}/${POLICY_REL}.tmp"
  awk -F '\t' -v OFS='\t' -v candidate="${protected_path}" -v value="${oid}" '
    $5 == candidate { $3 = value; found = 1 }
    { print }
    END { if (!found) exit 2 }
  ' "${repo}/${POLICY_REL}" >"${tmp}"
  mv "${tmp}" "${repo}/${POLICY_REL}"
}

commit_case() {
  local repo="$1" label="$2"
  git -C "${repo}" add -A
  git -C "${repo}" commit --quiet -m "${label}"
  git -C "${repo}" rev-parse HEAD
}

expect_success() {
  local label="$1" repo="$2" head_sha="$3"
  git -C "${repo}" switch --quiet --detach "${BASE_SHA}"
  PHASE0_INTEGRITY_LOCAL_TEST=1 \
    bash "${repo}/${CHECKER_REL}" "${repo}" "${BASE_SHA}" "${head_sha}" 0 \
    >"${TMP_ROOT}/${label}.log" 2>&1 \
    || { cat "${TMP_ROOT}/${label}.log" >&2; exit 1; }
  echo "PASS ${label}"
}

expect_failure() {
  local label="$1" expected="$2" repo="$3" head_sha="$4"
  git -C "${repo}" switch --quiet --detach "${BASE_SHA}"
  if PHASE0_INTEGRITY_LOCAL_TEST=1 \
      bash "${repo}/${CHECKER_REL}" "${repo}" "${BASE_SHA}" "${head_sha}" 0 \
      >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: integrity checker accepted ${label}" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${TMP_ROOT}/${label}.log" \
    || { cat "${TMP_ROOT}/${label}.log" >&2; exit 1; }
  echo "PASS ${label}_refused"
}

PHASE0_INTEGRITY_LOCAL_TEST=1 \
  bash "${BASE_REPO}/${CHECKER_REL}" \
    "${BASE_REPO}" "${BASE_SHA}" "${BASE_SHA}" 0 >/dev/null
echo "PASS unchanged_policy"

repo="$(clone_case unrelated-change)"
printf '%s\n' unrelated >"${repo}/unrelated.txt"
head_sha="$(commit_case "${repo}" unrelated-change)"
expect_success unrelated_change "${repo}" "${head_sha}"

repo="$(clone_case exact-policy-landing)"
printf '%s\n' land-1-v2 >"${repo}/protected/land-1.txt"
reseal "${repo}" protected/land-1.txt
head_sha="$(commit_case "${repo}" exact-policy-landing)"
expect_success exact_policy_landing "${repo}" "${head_sha}"

repo="$(clone_case payload-tamper)"
printf '%s\n' tampered >"${repo}/protected/land-1.txt"
head_sha="$(commit_case "${repo}" payload-tamper)"
expect_failure payload_tamper "head policy may only reseal exact land-exact objects" \
  "${repo}" "${head_sha}"

repo="$(clone_case missing-land-exact)"
git -C "${repo}" rm --quiet protected/land-2.txt
head_sha="$(commit_case "${repo}" missing-land-exact)"
expect_failure missing_land_exact "head removed protected object" "${repo}" "${head_sha}"

repo="$(clone_case frozen-tamper)"
printf '%s\n' frozen-v2 >"${repo}/protected/frozen.txt"
reseal "${repo}" protected/frozen.txt
head_sha="$(commit_case "${repo}" frozen-tamper)"
expect_failure frozen_tamper "frozen Phase 0 object differs from trusted base" \
  "${repo}" "${head_sha}"

repo="$(clone_case policy-tamper)"
perl -0pi -e 's/land-exact\tprotected\/land-3\.txt/frozen\tprotected\/land-3.txt/' \
  "${repo}/${POLICY_REL}"
head_sha="$(commit_case "${repo}" policy-tamper)"
expect_failure policy_tamper "head policy may only reseal exact land-exact objects" \
  "${repo}" "${head_sha}"

repo="$(clone_case checker-tamper)"
printf '%s\n' '# unsealed checker mutation' >>"${repo}/${CHECKER_REL}"
head_sha="$(commit_case "${repo}" checker-tamper)"
expect_failure checker_tamper "head policy may only reseal exact land-exact objects" \
  "${repo}" "${head_sha}"

repo="$(clone_case checker-reseal)"
printf '%s\n' '# exact checker evolution' >>"${repo}/${CHECKER_REL}"
reseal "${repo}" "${CHECKER_REL}"
head_sha="$(commit_case "${repo}" checker-reseal)"
expect_success checker_exact_reseal "${repo}" "${head_sha}"

repo="$(clone_case append-root)"
printf '%s\n' new-root >"${repo}/protected/appended.txt"
printf '100644\tblob\t%s\tland-exact\tprotected/appended.txt\n' \
  "$(blob_oid "${repo}" protected/appended.txt)" >>"${repo}/${POLICY_REL}"
head_sha="$(commit_case "${repo}" append-root)"
expect_success append_only_root "${repo}" "${head_sha}"

repo="$(clone_case transition-replay)"
printf '%s\n' '{}' >"${repo}/${TRANSITION_REL}"
head_sha="$(commit_case "${repo}" transition-replay)"
expect_failure transition_replay "retired arm/consume authorization object must be absent" \
  "${repo}" "${head_sha}"

repo="$(clone_case policy-removal)"
sed -i.bak '/protected\/land-7.txt/d' "${repo}/${POLICY_REL}"
git -C "${repo}" restore --staged . 2>/dev/null || true
head_sha="$(commit_case "${repo}" policy-removal)"
expect_failure policy_removal "head policy may only reseal exact land-exact objects" \
  "${repo}" "${head_sha}"

echo "Phase 0 base-owned land-exact mutation matrix passed."
