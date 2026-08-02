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
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
    "direct_merge": "rejected-by-required-merge-queue-ruleset"
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
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
      "direct_merge": "rejected-by-required-merge-queue-ruleset"
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
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "admin",
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

# ─── ARM from the steady state (insertion path) ─────────────────────────────
# The steady state of the arm/consume cycle carries NO versioned-transition
# line and NO transition JSON: that is what the consume leaves behind, and it
# is what every arm starts from after the first cycle. These cases pin the
# insertion path (the normal case) and its seal: the expected policy is a pure
# function of (base bytes, head authorization blob OID, fixed literals) — the
# inserted line's mode, type, transition kind, path, and position are fixed
# literals, only its OID field crosses from the head.

STEADY_PLAN="${TMP_ROOT}/steady-plan"
git clone --quiet --shared "${REPO}" "${STEADY_PLAN}"
git -C "${STEADY_PLAN}" switch --quiet --detach "${HEAD_OK}"
# A consume-shaped base: no transition line, no transition JSON.
awk -F '\t' -v OFS='\t' -v auth="${TRANSITION_AUTH_REL}" \
  '$5 != auth { print }' \
  "${STEADY_PLAN}/${POLICY_REL}" > "${STEADY_PLAN}/${POLICY_REL}.tmp"
mv "${STEADY_PLAN}/${POLICY_REL}.tmp" "${STEADY_PLAN}/${POLICY_REL}"
rm "${STEADY_PLAN}/${TRANSITION_AUTH_REL}"
git -C "${STEADY_PLAN}" add -A
git -C "${STEADY_PLAN}" commit --quiet -m steady-state
STEADY_BASE="$(git -C "${STEADY_PLAN}" rev-parse HEAD)"

# Build one armed head on top of STEADY_BASE with a caller-supplied head
# policy file. $1 = path of the fully-formed head policy TSV. Prints the arm
# head SHA on stdout. The post-consume world equals the steady base exactly,
# so the JSON's expected tree/policy OIDs come straight from STEADY_BASE.
build_arm_head_from_steady() {
  local head_policy_file="$1"
  git -C "${STEADY_PLAN}" switch --quiet --detach "${STEADY_BASE}"
  cp "${head_policy_file}" "${STEADY_PLAN}/${POLICY_REL}"
  cat > "${STEADY_PLAN}/${TRANSITION_AUTH_REL}" <<JSON
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "armed",
  "generation": 1,
  "armed_from_base_sha": "${STEADY_BASE}",
  "expected_head_tree_oid": "$(git -C "${STEADY_PLAN}" rev-parse "${STEADY_BASE}^{tree}")",
  "expected_policy_blob_oid": "$(git -C "${STEADY_PLAN}" rev-parse "${STEADY_BASE}:${POLICY_REL}")",
  "allowed_paths": [
    "${POLICY_REL}"
  ],
  "owner_authorization": {
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
      "direct_merge": "rejected-by-required-merge-queue-ruleset"
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
  git -C "${STEADY_PLAN}" add -A
  git -C "${STEADY_PLAN}" commit --quiet -m steady-arm
  git -C "${STEADY_PLAN}" rev-parse HEAD
}

# The head policy for a CORRECT insertion: steady base plus the transition
# line as the first data line, carrying the arm authorization blob OID.
STEADY_ARM_AUTH_JSON="${TMP_ROOT}/steady-arm-auth.json"
# (1) Build the armed JSON first to learn its blob OID: the OID feeds the
# inserted line, and the line feeds nothing else.
git -C "${STEADY_PLAN}" switch --quiet --detach "${STEADY_BASE}"
cat > "${STEADY_ARM_AUTH_JSON}" <<JSON
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "armed",
  "generation": 1,
  "armed_from_base_sha": "${STEADY_BASE}",
  "expected_head_tree_oid": "$(git -C "${STEADY_PLAN}" rev-parse "${STEADY_BASE}^{tree}")",
  "expected_policy_blob_oid": "$(git -C "${STEADY_PLAN}" rev-parse "${STEADY_BASE}:${POLICY_REL}")",
  "allowed_paths": [
    "${POLICY_REL}"
  ],
  "owner_authorization": {
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
      "direct_merge": "rejected-by-required-merge-queue-ruleset"
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
STEADY_ARM_AUTH_OID="$(git -C "${STEADY_PLAN}" hash-object -w "${STEADY_ARM_AUTH_JSON}")"

CORRECT_INSERT_POLICY="${TMP_ROOT}/correct-insert-policy.tsv"
{
  head -n 1 "${STEADY_PLAN}/${POLICY_REL}"
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "${STEADY_ARM_AUTH_OID}" "${TRANSITION_AUTH_REL}"
  tail -n +2 "${STEADY_PLAN}/${POLICY_REL}"
} > "${CORRECT_INSERT_POLICY}"

run_arm_case() {
  # $1 = label, $2 = head policy file, $3 = "accept" or "refuse"
  local label="$1" head_policy_file="$2" expectation="$3" arm_head
  arm_head="$(build_arm_head_from_steady "${head_policy_file}")"
  cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "admin",
    "state": "APPROVED",
    "commit_id": "${arm_head}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON
  git -C "${STEADY_PLAN}" switch --quiet --detach "${STEADY_BASE}"
  if PHASE0_INTEGRITY_LOCAL_TEST=1 \
      PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
      "${STEADY_PLAN}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
      "${STEADY_PLAN}" "${STEADY_BASE}" "${arm_head}" 0 \
      >"${TMP_ROOT}/${label}.log" 2>&1; then
    [[ "${expectation}" == "accept" ]] || {
      echo "error: integrity checker accepted ${label}" >&2
      exit 1
    }
    echo "PASS ${label}"
  else
    [[ "${expectation}" == "refuse" ]] || {
      cat "${TMP_ROOT}/${label}.log" >&2
      exit 1
    }
    grep -Fq "arming transition may only update the authorization OID in the base policy" \
      "${TMP_ROOT}/${label}.log" \
      || { cat "${TMP_ROOT}/${label}.log" >&2; exit 1; }
    echo "PASS ${label}_refused"
  fi
}

# (1) base without the line + head inserting the CORRECT line: the case that
# was impossible before the fix — the normal arm from the steady state.
run_arm_case steady_arm_insert "${CORRECT_INSERT_POLICY}" accept

# (2) base without the line + insertion carrying the WRONG OID: refused.
WRONG_OID_POLICY="${TMP_ROOT}/wrong-oid-policy.tsv"
{
  head -n 1 "${STEADY_PLAN}/${POLICY_REL}"
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "${STEADY_ARM_AUTH_OID//a/b}" "${TRANSITION_AUTH_REL}"
  tail -n +2 "${STEADY_PLAN}/${POLICY_REL}"
} > "${WRONG_OID_POLICY}"
run_arm_case steady_arm_wrong_oid "${WRONG_OID_POLICY}" refuse

# (3) base without the line + insertion in a DIFFERENT position (last line):
# the position is a defended literal, not an ordering consequence.
WRONG_POSITION_POLICY="${TMP_ROOT}/wrong-position-policy.tsv"
{
  cat "${STEADY_PLAN}/${POLICY_REL}"
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "${STEADY_ARM_AUTH_OID}" "${TRANSITION_AUTH_REL}"
} > "${WRONG_POSITION_POLICY}"
run_arm_case steady_arm_wrong_position "${WRONG_POSITION_POLICY}" refuse

# (4) base without the line + correct insertion AND another line altered: the
# rest of the policy stays sealed.
INSERT_PLUS_TAMPER_POLICY="${TMP_ROOT}/insert-plus-tamper-policy.tsv"
awk -F '\t' -v OFS='\t' \
  'NR == 3 { $3 = "0000000000000000000000000000000000000000" } { print }' \
  "${CORRECT_INSERT_POLICY}" > "${INSERT_PLUS_TAMPER_POLICY}"
run_arm_case steady_arm_insert_plus_tamper "${INSERT_PLUS_TAMPER_POLICY}" refuse

# (5) base without the line + insertion with mode/type != 100644/blob: proves
# the literals are not read from the head.
WRONG_MODE_POLICY="${TMP_ROOT}/wrong-mode-policy.tsv"
{
  head -n 1 "${STEADY_PLAN}/${POLICY_REL}"
  printf '100755\tblob\t%s\tversioned-transition\t%s\n' \
    "${STEADY_ARM_AUTH_OID}" "${TRANSITION_AUTH_REL}"
  tail -n +2 "${STEADY_PLAN}/${POLICY_REL}"
} > "${WRONG_MODE_POLICY}"
run_arm_case steady_arm_wrong_mode "${WRONG_MODE_POLICY}" refuse

# (7) base WITH the line + head with the line DUPLICATED (a second
# versioned-transition entry): duplication is an insertion in disguise, not a
# substitution, and must be refused even on the legacy path.
DUPLICATE_PLAN="${TMP_ROOT}/duplicate-plan"
git clone --quiet --shared "${REPO}" "${DUPLICATE_PLAN}"
git -C "${DUPLICATE_PLAN}" switch --quiet --detach "${HEAD_OK}"
DUPLICATE_POLICY="${TMP_ROOT}/duplicate-policy.tsv"
{
  head -n 2 "${DUPLICATE_PLAN}/${POLICY_REL}"
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "$(git -C "${DUPLICATE_PLAN}" hash-object -w "${TMP_ROOT}/future.txt")" \
    "${TRANSITION_AUTH_REL}"
  tail -n +3 "${DUPLICATE_PLAN}/${POLICY_REL}"
} > "${DUPLICATE_POLICY}"
cat > "${DUPLICATE_PLAN}/${TRANSITION_AUTH_REL}" <<JSON
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "armed",
  "generation": 1,
  "armed_from_base_sha": "${HEAD_OK}",
  "expected_head_tree_oid": "$(git -C "${DUPLICATE_PLAN}" rev-parse "${HEAD_OK}^{tree}")",
  "expected_policy_blob_oid": "$(git -C "${DUPLICATE_PLAN}" rev-parse "${HEAD_OK}:${POLICY_REL}")",
  "allowed_paths": [
    "${POLICY_REL}"
  ],
  "owner_authorization": {
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
      "direct_merge": "rejected-by-required-merge-queue-ruleset"
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
cp "${DUPLICATE_POLICY}" "${DUPLICATE_PLAN}/${POLICY_REL}"
git -C "${DUPLICATE_PLAN}" add -A
git -C "${DUPLICATE_PLAN}" commit --quiet -m duplicate-arm
DUPLICATE_HEAD="$(git -C "${DUPLICATE_PLAN}" rev-parse HEAD)"
cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "admin",
    "state": "APPROVED",
    "commit_id": "${DUPLICATE_HEAD}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON
git -C "${DUPLICATE_PLAN}" switch --quiet --detach "${HEAD_OK}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${DUPLICATE_PLAN}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${DUPLICATE_PLAN}" "${HEAD_OK}" "${DUPLICATE_HEAD}" 0 \
    >"${TMP_ROOT}/duplicate-arm.log" 2>&1; then
  echo "error: integrity checker accepted a duplicated transition line" >&2
  exit 1
fi
grep -Fq "arming transition may only update the authorization OID in the base policy" \
  "${TMP_ROOT}/duplicate-arm.log" \
  || { cat "${TMP_ROOT}/duplicate-arm.log" >&2; exit 1; }
echo "PASS steady_arm_duplicate_line_refused"

# Restore the review fixture the following cases expect (transition_arm's).
cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "admin",
    "state": "APPROVED",
    "commit_id": "${ARM_HEAD}",
    "submitted_at": "2026-01-01T00:00:00Z"
  }
]
JSON

MERGE_GROUP_JSON="${TMP_ROOT}/merge-group.json"
cat > "${MERGE_GROUP_JSON}" <<JSON
{
  "merge_group": {
    "base_sha": "${HEAD_OK}",
    "head_sha": "${ARM_HEAD}",
    "head_commit": {"tree_id": "${TRANSITION_TREE_OID}"}
  },
  "pull_requests": [
    {
      "number": 1,
      "head": {"sha": "${ARM_HEAD}"},
      "base": {"sha": "${HEAD_OK}"}
    }
  ]
}
JSON
git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_REQUIRE_MERGE_GROUP=1 \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${REPO}" "${HEAD_OK}" "${ARM_HEAD}" 1 \
    >"${TMP_ROOT}/direct-arm-without-merge-group.log" 2>&1; then
  echo "error: integrity checker accepted an arm outside a merge-group revalidation" >&2
  exit 1
fi
grep -Fq "owner authorization is valid only during a merge-group revalidation" \
  "${TMP_ROOT}/direct-arm-without-merge-group.log" \
  || { cat "${TMP_ROOT}/direct-arm-without-merge-group.log" >&2; exit 1; }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS direct_arm_without_merge_group_refused"

git -C "${REPO}" switch --quiet --detach "${HEAD_OK}"
if ! PHASE0_INTEGRITY_LOCAL_TEST=1 \
    PHASE0_INTEGRITY_REQUIRE_MERGE_GROUP=1 \
    PHASE0_INTEGRITY_MERGE_GROUP=1 \
    PHASE0_INTEGRITY_MERGE_GROUP_JSON="${MERGE_GROUP_JSON}" \
    PHASE0_INTEGRITY_OWNER_REVIEW_JSON="${OWNER_REVIEW_JSON}" \
    "${REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${REPO}" "${HEAD_OK}" "${ARM_HEAD}" 1 \
    >"${TMP_ROOT}/merge-group-arm.log" 2>&1; then
  cat "${TMP_ROOT}/merge-group-arm.log" >&2
  exit 1
fi
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS merge_group_arm_revalidation"

cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "write",
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
grep -Fq "exact arm commit lacks a current approved GitHub repository-admin review" \
  "${TMP_ROOT}/owner-review-non-owner.log" \
  || { cat "${TMP_ROOT}/owner-review-non-owner.log" >&2; exit 1; }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS owner_review_non_owner_refused"

jq -n --arg head "${ARM_HEAD}" '[range(0; 101) | {
  user: {id: 1, login: "reviewer"},
  author_association: "MEMBER",
  repository_permission: "admin",
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
grep -Fq "exact arm commit lacks a current approved GitHub repository-admin review" \
  "${TMP_ROOT}/owner-review-pagination.log" \
  || { cat "${TMP_ROOT}/owner-review-pagination.log" >&2; exit 1; }
git -C "${REPO}" switch --quiet "${BRANCH}"
echo "PASS owner_review_pagination_refused"

ARM_WEAKEN_PLAN="${TMP_ROOT}/transition-arm-weakening"
git clone --quiet --shared "${REPO}" "${ARM_WEAKEN_PLAN}"
git -C "${ARM_WEAKEN_PLAN}" config user.name "phase0-integrity-test"
git -C "${ARM_WEAKEN_PLAN}" config user.email "phase0-integrity@example.invalid"
git -C "${ARM_WEAKEN_PLAN}" switch --quiet --detach "${ARM_HEAD}"
printf '100644\tblob\t0000000000000000000000000000000000000000\tland-exact\tprotected/unscoped.txt\n' \
  >>"${ARM_WEAKEN_PLAN}/${POLICY_REL}"
git -C "${ARM_WEAKEN_PLAN}" add "${POLICY_REL}"
git -C "${ARM_WEAKEN_PLAN}" commit --quiet -m transition-arm-policy-weakening
ARM_WEAKEN_HEAD="$(git -C "${ARM_WEAKEN_PLAN}" rev-parse HEAD)"
cat > "${OWNER_REVIEW_JSON}" <<JSON
[
  {
    "user": {"id": 1, "login": "reviewer"},
    "author_association": "MEMBER",
    "repository_permission": "admin",
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

# Exercise the real bootstrap-to-payload handoff failure mode: a bootstrap
# policy must not pin a future frozen blob while the bootstrap tree still
# contains an older blob. The payload may repair the tree, but the handoff
# checker must reject the pair until the bootstrap carries the pinned blob.
HANDOFF_REPO="${TMP_ROOT}/bootstrap-payload-handoff"
mkdir -p "${HANDOFF_REPO}/.github/scripts" \
  "${HANDOFF_REPO}/.github/workflows" "${HANDOFF_REPO}/protected"
git -C "${HANDOFF_REPO}" init --quiet
git -C "${HANDOFF_REPO}" config user.name "phase0-integrity-handoff-test"
git -C "${HANDOFF_REPO}" config user.email "phase0-integrity-handoff@example.invalid"
cp "${CHECKER_SOURCE}" \
  "${HANDOFF_REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
cp "${BASH_SOURCE[0]}" \
  "${HANDOFF_REPO}/.github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
cp "${WORKFLOW_SOURCE}" \
  "${HANDOFF_REPO}/.github/workflows/owner-present-phase0-integrity.yml"
cat > "${HANDOFF_REPO}/${TRANSITION_AUTH_REL}" <<'JSON'
{
  "contract": "soyeht-owner-present-proof-machinery-transition-v1",
  "version": 1,
  "state": "unarmed",
  "generation": 0,
  "owner_authorization": {
    "mode": "github-repository-admin-review-exact-arm-commit",
    "requires_owner_review": true,
    "requires_required_integrity_check": true,
    "owner_review": {
      "provider": "github",
      "required_repository_permission": "admin",
      "binds_to": "exact-arm-head-sha",
      "latest_review_only": true
    },
    "merge_point": {
      "provider": "github",
      "mode": "required-merge-group-revalidation",
      "requires_current_permission": true,
      "direct_merge": "rejected-by-required-merge-queue-ruleset"
    },
    "canary": "arm-then-consume-merge-blocked-and-allowed",
    "anti_replay": "base-sha-expected-head-tree-generation-one-shot-consumption"
  }
}
JSON
HANDOFF_AUTH_OID="$(git -C "${HANDOFF_REPO}" hash-object -w \
  "${HANDOFF_REPO}/${TRANSITION_AUTH_REL}")"
printf '%s\n' 'bootstrap-frozen-v1' > "${HANDOFF_REPO}/protected/frozen.txt"
printf '%s\n' 'payload-frozen-v2' > "${TMP_ROOT}/handoff-future-frozen.txt"
HANDOFF_FUTURE_FROZEN_OID="$(git -C "${HANDOFF_REPO}" hash-object -w \
  "${TMP_ROOT}/handoff-future-frozen.txt")"
printf '%s\n' 'land-exact-v1' > "${TMP_ROOT}/handoff-land.txt"
HANDOFF_LAND_OID="$(git -C "${HANDOFF_REPO}" hash-object -w \
  "${TMP_ROOT}/handoff-land.txt")"
for index in $(seq 1 9); do
  cp "${TMP_ROOT}/handoff-land.txt" \
    "${HANDOFF_REPO}/protected/future-${index}.txt"
done
{
  printf '# mode\ttype\toid\ttransition\tpath\n'
  printf '100644\tblob\t%s\tversioned-transition\t%s\n' \
    "${HANDOFF_AUTH_OID}" "${TRANSITION_AUTH_REL}"
  printf '100644\tblob\t%s\tfrozen\tprotected/frozen.txt\n' \
    "${HANDOFF_FUTURE_FROZEN_OID}"
  for index in $(seq 1 9); do
    printf '100644\tblob\t%s\tland-exact\tprotected/future-%s.txt\n' \
      "${HANDOFF_LAND_OID}" "${index}"
  done
} > "${HANDOFF_REPO}/${POLICY_REL}"
git -C "${HANDOFF_REPO}" add .
git -C "${HANDOFF_REPO}" commit --quiet -m bootstrap
HANDOFF_BASE="$(git -C "${HANDOFF_REPO}" rev-parse HEAD)"
cp "${TMP_ROOT}/handoff-future-frozen.txt" \
  "${HANDOFF_REPO}/protected/frozen.txt"
git -C "${HANDOFF_REPO}" add protected/frozen.txt
git -C "${HANDOFF_REPO}" commit --quiet -m payload
HANDOFF_HEAD="$(git -C "${HANDOFF_REPO}" rev-parse HEAD)"
git -C "${HANDOFF_REPO}" switch --quiet --detach "${HANDOFF_BASE}"
if PHASE0_INTEGRITY_LOCAL_TEST=1 \
    "${HANDOFF_REPO}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh" \
    "${HANDOFF_REPO}" "${HANDOFF_BASE}" "${HANDOFF_HEAD}" 0 \
    >"${TMP_ROOT}/bootstrap-payload-handoff.log" 2>&1; then
  echo "error: bootstrap-to-payload handoff accepted a stale frozen object" >&2
  exit 1
fi
grep -Fq "frozen Phase 0 object differs from trusted base policy" \
  "${TMP_ROOT}/bootstrap-payload-handoff.log" \
  || { cat "${TMP_ROOT}/bootstrap-payload-handoff.log" >&2; exit 1; }
echo "PASS bootstrap_payload_handoff_refused"

echo "Phase 0 base-owned policy mutation matrix passed."
