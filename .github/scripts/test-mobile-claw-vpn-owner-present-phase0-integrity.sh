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
TRANSITION_AUTH_REL=".github/owner-present-phase0-transition-v1.json"

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
cat > "${REPO}/${TRANSITION_AUTH_REL}" <<'JSON'
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "unarmed",
  "generation": 0,
  "owner_authorization": {
    "mode": "github-owner-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_author_association": "OWNER",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
TRANSITION_AUTH_OID="$(git -C "${REPO}" hash-object -w "${REPO}/${TRANSITION_AUTH_REL}")"
printf '%s\n' 'frozen-v1' > "${REPO}/protected/frozen.txt"
FROZEN_OID="$(git -C "${REPO}" hash-object -w "${REPO}/protected/frozen.txt")"
printf '%s\n' 'future-v1' > "${TMP_ROOT}/future.txt"
FUTURE_OID="$(git -C "${REPO}" hash-object -w "${TMP_ROOT}/future.txt")"
{
  printf '# mode\ttype\toid\ttransition\tpath\n'
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "${TRANSITION_AUTH_OID}" "${TRANSITION_AUTH_REL}"
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

# The transition protocol is two-phase: an owner-reviewed arm commit changes
# only the authorization object, then a later commit consumes it by matching
# the exact authorized tree/policy and removing the one-shot object.
TRANSITION_PLAN="${TMP_ROOT}/transition-plan"
git clone --quiet --shared "${REPO}" "${TRANSITION_PLAN}"
git -C "${TRANSITION_PLAN}" switch --quiet --detach "${HEAD_OK}"
awk -F '\t' -v OFS='\t' -v auth="${TRANSITION_AUTH_REL}" \
  '$5 != auth { print }' \
  "${TRANSITION_PLAN}/${POLICY_REL}" > "${TRANSITION_PLAN}/${POLICY_REL}.tmp"
mv "${TRANSITION_PLAN}/${POLICY_REL}.tmp" "${TRANSITION_PLAN}/${POLICY_REL}"
rm "${TRANSITION_PLAN}/${TRANSITION_AUTH_REL}"
printf '%s\n' transition-v1 > "${TRANSITION_PLAN}/protected/future-1.txt"
TRANSITION_FUTURE_OID="$(git -C "${TRANSITION_PLAN}" hash-object -w "${TRANSITION_PLAN}/protected/future-1.txt")"
awk -F '\t' -v OFS='\t' -v path="protected/future-1.txt" -v oid="${TRANSITION_FUTURE_OID}" \
  '$5 == path { $3 = oid } { print }' \
  "${TRANSITION_PLAN}/${POLICY_REL}" > "${TRANSITION_PLAN}/${POLICY_REL}.tmp"
mv "${TRANSITION_PLAN}/${POLICY_REL}.tmp" "${TRANSITION_PLAN}/${POLICY_REL}"
git -C "${TRANSITION_PLAN}" add -A
TRANSITION_TREE_OID="$(git -C "${TRANSITION_PLAN}" write-tree)"
TRANSITION_POLICY_OID="$(git -C "${TRANSITION_PLAN}" rev-parse "${TRANSITION_TREE_OID}:${POLICY_REL}")"
git -C "${REPO}" switch --quiet "${BRANCH}"
cat > "${REPO}/${TRANSITION_AUTH_REL}" <<JSON
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "armed",
  "generation": 1,
  "armed_from_base_sha": "${HEAD_OK}",
  "expected_head_tree_oid": "${TRANSITION_TREE_OID}",
  "expected_policy_blob_oid": "${TRANSITION_POLICY_OID}",
  "allowed_paths": [
    "${POLICY_REL}",
    "protected/future-1.txt"
  ],
  "owner_authorization": {
    "mode": "github-owner-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_author_association": "OWNER",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
ARM_AUTH_OID="$(git -C "${REPO}" hash-object -w "${REPO}/${TRANSITION_AUTH_REL}")"
awk -F '\t' -v OFS='\t' -v auth="${TRANSITION_AUTH_REL}" -v oid="${ARM_AUTH_OID}" \
  '$5 == auth { $3 = oid } { print }' \
  "${REPO}/${POLICY_REL}" > "${REPO}/${POLICY_REL}.tmp"
mv "${REPO}/${POLICY_REL}.tmp" "${REPO}/${POLICY_REL}"
git -C "${REPO}" add "${TRANSITION_AUTH_REL}"
git -C "${REPO}" add "${POLICY_REL}"
git -C "${REPO}" commit --quiet -m transition-arm
ARM_HEAD="$(git -C "${REPO}" rev-parse HEAD)"
OWNER_REVIEW_JSON="${TMP_ROOT}/owner-review.json"
cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1},
    "author_association": "OWNER",
    "state": "APPROVED",
    "commit_id": "${ARM_HEAD}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON
git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
PHASE0_INTEGRITY_LOCAL_TEST=1 \
PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
  "${REPO}" "${HEAD_OK}" "${ARM_HEAD}" 0 >/dev/null
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS transition_arm"

cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1},
    "author_association": "MEMBER",
    "state": "APPROVED",
    "commit_id": "${ARM_HEAD}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON
git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${REPO}" "${HEAD_OK}" "${ARM_HEAD}" 0 \
    >"${TMP_ROOT}/owner-review-non-owner.log" 2>&1; then
  echo "error: integrity checker accepted a non-owner transition review" >&2
  exit 1
fi
grep -Fq "exact arm commit lacks a current approved GitHub owner review" \
  "${TMP_ROOT}/owner-review-non-owner.log" \
  || { cat "${TMP_ROOT}/owner-review-non-owner.log" >&2; exit 1; }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS owner_review_non_owner_refused"

jq -n --arg head "${ARM_HEAD}" '[range(0; 101) | {
  user: {id: 1},
  author_association: "OWNER",
  state: (if . == 100 then "CHANGES_REQUESTED" else "APPROVED" end),
  commit_id: $head,
  submitted_at: (("000" + (.|tostring))[-3:])
}]' >"${OWNER_REVIEW_JSON}"
git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${REPO}" "${HEAD_OK}" "${ARM_HEAD}" 0 \
    >"${TMP_ROOT}/owner-review-pagination.log" 2>&1; then
  echo "error: integrity checker accepted a stale owner approval after a later rejection" >&2
  exit 1
fi
grep -Fq "exact arm commit lacks a current approved GitHub owner review" \
  "${TMP_ROOT}/owner-review-pagination.log" \
  || { cat "${TMP_ROOT}/owner-review-pagination.log" >&2; exit 1; }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS owner_review_pagination_refused"

ARM_WEAKEN_PLAN="${TMP_ROOT}/transition-arm-weakening"
git clone --quiet --shared "${REPO}" "${ARM_WEAKEN_PLAN}"
git -C "${ARM_WEAKEN_PLAN}" switch --quiet --detach "${ARM_HEAD}"
printf '100644\tblob\t0000000000000000000000000000000000000000\tland-exact\tprotected/unscoped.txt\n' \
  >>"${ARM_WEAKEN_PLAN}/${POLICY_REL}"
git -C "${ARM_WEAKEN_PLAN}" add "${POLICY_REL}"
git -C "${ARM_WEAKEN_PLAN}" commit --quiet -m transition-arm-policy-weakening
ARM_WEAKEN_HEAD="$(git -C "${ARM_WEAKEN_PLAN}" rev-parse HEAD)"
cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1},
    "author_association": "OWNER",
    "state": "APPROVED",
    "commit_id": "${ARM_WEAKEN_HEAD}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON
git -C "${ARM_WEAKEN_PLAN}" switch --quiet --detach "${HEAD_OK}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${ARM_WEAKEN_PLAN}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${ARM_WEAKEN_PLAN}" "${HEAD_OK}" "${ARM_WEAKEN_HEAD}" 0 \
    >"${TMP_ROOT}/arm-policy-weakening.log" 2>&1; then
  echo "error: integrity checker accepted an arm policy weakening" >&2
  exit 1
fi
grep -Fq "arming transition may only update the authorization OID in the base policy" \
  "${TMP_ROOT}/arm-policy-weakening.log" \
  || { cat "${TMP_ROOT}/arm-policy-weakening.log" >&2; exit 1; }
echo "PASS arm_policy_weakening_refused"

awk -F '\t' -v OFS='\t' -v auth="${TRANSITION_AUTH_REL}" \
  '$5 != auth { print }' \
  "${REPO}/${POLICY_REL}" > "${REPO}/${POLICY_REL}.tmp"
mv "${REPO}/${POLICY_REL}.tmp" "${REPO}/${POLICY_REL}"
rm "${REPO}/${TRANSITION_AUTH_REL}"
printf '%s\n' transition-v1 > "${REPO}/protected/future-1.txt"
awk -F '\t' -v OFS='\t' -v path="protected/future-1.txt" -v oid="${TRANSITION_FUTURE_OID}" \
  '$5 == path { $3 = oid } { print }' \
  "${REPO}/${POLICY_REL}" > "${REPO}/${POLICY_REL}.tmp"
mv "${REPO}/${POLICY_REL}.tmp" "${REPO}/${POLICY_REL}"
git -C "${REPO}" add -A
git -C "${REPO}" commit --quiet -m transition-consume
TRANSITION_HEAD="$(git -C "${REPO}" rev-parse HEAD)"
[[ "$(git -C "${REPO}" rev-parse "${TRANSITION_HEAD}^{tree}")" == "${TRANSITION_TREE_OID}" ]] \
  || { echo "error: transition test tree changed unexpectedly" >&2; exit 1; }
git -C "${REPO}" switch --quiet --detach "${ARM_HEAD}"
PHASE0_INTEGRITY_LOCAL_TEST=1 \
  "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
  "${REPO}" "${ARM_HEAD}" "${TRANSITION_HEAD}" 0 \
  >"${TMP_ROOT}/transition-consume.log" 2>&1 || {
    cat "${TMP_ROOT}/transition-consume.log" >&2
    exit 1
  }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS transition_consume"

printf '%s\n' replayed > "${REPO}/protected/future-2.txt"
git -C "${REPO}" add -A
git -C "${REPO}" commit --quiet -m transition-replay
REPLAY_HEAD="$(git -C "${REPO}" rev-parse HEAD)"
git -C "${REPO}" switch --quiet --detach "${TRANSITION_HEAD}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${REPO}" "${TRANSITION_HEAD}" "${REPLAY_HEAD}" 0 \
    >"${TMP_ROOT}/transition-replay.log" 2>&1; then
  echo "error: integrity checker accepted a replay after transition consumption" >&2
  exit 1
fi
if ! grep -Fq "protected Phase 0 object differs from base-owned policy" \
  "${TMP_ROOT}/transition-replay.log"; then
  cat "${TMP_ROOT}/transition-replay.log" >&2
  exit 1
fi
git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
git -C "${REPO}" branch --force --quiet "${BRANCH}" "${HEAD_OK}"
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS transition_replay_refused"

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
  if ! grep -Fq "${expected}" "${TMP_ROOT}/${label}.log"; then
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
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
