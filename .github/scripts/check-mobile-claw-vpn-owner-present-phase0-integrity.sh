#!/usr/bin/env bash
# Base-owned integrity check for the Phase 0 compile-out authority.
set -euo pipefail

REPO="${1:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
BASE_SHA="${2:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
HEAD_SHA="${3:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
PR_NUMBER="${4:-0}"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"
TRANSITION_AUTH_REL=".github/owner-present-phase0-transition-v1.json"
SELF_PATHS=(
  ".github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/workflows/owner-present-phase0-integrity.yml"
  "${POLICY_REL}"
  "${TRANSITION_AUTH_REL}"
)

TRANSITION_CONTRACT="soyeht-owner-present-proof-machinery-transition-v1"
OWNER_REVIEW_ASSOCIATION="OWNER"

die_transition() {
  echo "::error file=${TRANSITION_AUTH_REL}::$1"
  exit 1
}

valid_sha() {
  [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]
}

path_is_safe() {
  local path="${1:-}"
  [[ -n "${path}" && "${path}" != /* && "${path}" != *"../"* \
    && "${path}" != *$'\n'* && "${path}" != *$'\r'* ]]
}

validate_transition_common() {
  local file="$1"
  jq -e \
    --arg contract "${TRANSITION_CONTRACT}" \
    '.contract == $contract
      and .version == 1
      and (.owner_authorization | type == "object")
      and .owner_authorization.mode == "github-owner-review-exact-arm-commit"
      and .owner_authorization.requires_owner_review == true
      and .owner_authorization.requires_required_integrity_check == true
      and (.owner_authorization.owner_review | type == "object")
      and .owner_authorization.owner_review.provider == "github"
      and .owner_authorization.owner_review.required_author_association == "OWNER"
      and .owner_authorization.owner_review.binds_to == "exact-arm-head-sha"
      and .owner_authorization.owner_review.latest_review_only == true
      and .owner_authorization.canary == "arm-then-consume-merge-blocked-and-allowed"
      and .owner_authorization.anti_replay == "base-sha-expected-head-tree-generation-one-shot-consumption"' \
    "${file}" >/dev/null || die_transition "transition authorization metadata is invalid"
  jq -e '.state as $state
    | (($state == "unarmed" and .generation == 0)
      or ($state == "armed"
        and (.generation | type == "number" and floor == . and . >= 1)
        and (.armed_from_base_sha | type == "string")
        and (.expected_head_tree_oid | type == "string")
        and (.expected_policy_blob_oid | type == "string")
        and (.allowed_paths | type == "array")))' \
    "${file}" >/dev/null || die_transition "transition authorization state is invalid"
}

load_allowed_paths() {
  local file="$1"
  ALLOWED_PATHS=()
  while IFS= read -r path; do
    path_is_safe "${path}" || die_transition "transition allowed path is unsafe"
    [[ "${path}" != "${TRANSITION_AUTH_REL}" ]] \
      || die_transition "transition authorization cannot authorize itself"
    ALLOWED_PATHS+=("${path}")
  done < <(jq -r '.allowed_paths[]' "${file}")
  [[ "$(jq -r '.allowed_paths | length' "${file}")" -gt 0 ]] \
    || die_transition "transition allowed path set is empty"
  local sorted actual
  sorted="$(printf '%s\n' "${ALLOWED_PATHS[@]}" | sort -u)"
  actual="$(printf '%s\n' "${ALLOWED_PATHS[@]}")"
  [[ "${sorted}" == "${actual}" && "$(printf '%s\n' "${ALLOWED_PATHS[@]}" | sort -u | wc -l | tr -d ' ')" == "${#ALLOWED_PATHS[@]}" ]] \
    || die_transition "transition allowed path set must be sorted and unique"
}

verify_owner_approval() {
  local reviews_file="" reviews_dir page page_file page_count
  if [[ "${PHASE0_INTEGRITY_LOCAL_TEST:-0}" == "1" ]]; then
    reviews_file="${PHASE0_INTEGRITY_OWNER_REVIEW_JSON:-}"
    [[ -n "${reviews_file}" && -f "${reviews_file}" ]] \
      || die_transition "local transition test must provide an owner review fixture"
  else
    : "${GITHUB_TOKEN:?GITHUB_TOKEN is required for owner review verification}"
    [[ "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]] \
      || die_transition "pull request number is invalid for owner review verification"
    [[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
      || die_transition "repository identity is invalid for owner review verification"
    reviews_dir="${TRANSITION_DIR}/review-pages"
    mkdir -p "${reviews_dir}"
    page=1
    while :; do
      page_file="${reviews_dir}/page-${page}.json"
      /usr/bin/curl --fail --silent --show-error --location --max-time 20 \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100&page=${page}" \
        >"${page_file}" \
        || die_transition "could not fetch the trusted GitHub review page"
      jq -e 'type == "array"' "${page_file}" >/dev/null \
        || die_transition "GitHub owner review page is not a JSON array"
      page_count="$(jq -er 'length' "${page_file}")" \
        || die_transition "GitHub owner review page length is invalid"
      (( page_count <= 100 )) \
        || die_transition "GitHub returned more than the documented review page size"
      (( page_count < 100 )) && break
      (( page >= 1000 )) \
        && die_transition "GitHub owner review pagination exceeded the fail-closed limit"
      page=$((page + 1))
    done
    reviews_file="$(mktemp "${TRANSITION_DIR}/reviews.XXXXXX")"
    jq -s 'add' "${reviews_dir}"/page-*.json >"${reviews_file}" \
      || die_transition "could not combine the complete GitHub review history"
  fi

  jq -e \
    --arg head "${HEAD_SHA}" \
    --arg association "${OWNER_REVIEW_ASSOCIATION}" \
    'type == "array"
      and ([ .[]
        | select((.user | type) == "object")
        | select((.user.id | type) == "number")
        | select(.author_association == $association)
        | select(.state == "APPROVED" or .state == "DISMISSED" or .state == "CHANGES_REQUESTED")
      ]
      | group_by(.user.id)
      | map(max_by(.submitted_at // ""))
      | any(.[]; .state == "APPROVED"
        and .commit_id == $head
        and .author_association == $association))' \
    "${reviews_file}" >/dev/null \
    || die_transition "exact arm commit lacks a current approved GitHub owner review"
}

path_is_allowed() {
  local candidate="$1"
  local allowed
  for allowed in "${ALLOWED_PATHS[@]}"; do
    [[ "${candidate}" == "${allowed}" ]] && return 0
  done
  return 1
}

changed_paths_match() {
  local actual expected
  actual="$(git -C "${REPO}" diff --name-only "${BASE_SHA}" "${HEAD_SHA}" | sort -u)"
  expected="$(printf '%s\n' "${TRANSITION_AUTH_REL}" "${ALLOWED_PATHS[@]}" | sort -u)"
  [[ "${actual}" == "${expected}" ]] \
    || die_transition "transition changed-path set does not match its exact authorization scope"
}

arm_policy_matches_base() {
  local base_policy head_policy expected_policy head_auth_oid
  base_policy="$(mktemp "${TRANSITION_DIR}/base-policy.XXXXXX")"
  head_policy="$(mktemp "${TRANSITION_DIR}/head-policy.XXXXXX")"
  expected_policy="$(mktemp "${TRANSITION_DIR}/expected-arm-policy.XXXXXX")"
  git -C "${REPO}" cat-file blob "${BASE_SHA}:${POLICY_REL}" >"${base_policy}"
  git -C "${REPO}" cat-file blob "${HEAD_SHA}:${POLICY_REL}" >"${head_policy}" \
    || die_transition "arming transition policy is missing"
  head_auth_oid="$(git -C "${REPO}" rev-parse "${HEAD_SHA}:${TRANSITION_AUTH_REL}" 2>/dev/null || true)"
  [[ "${head_auth_oid}" =~ ^[0-9a-f]{40}$ ]] \
    || die_transition "arming transition authorization blob is invalid"
  awk -F '\t' -v OFS='\t' \
    -v auth="${TRANSITION_AUTH_REL}" -v oid="${head_auth_oid}" \
    '$5 == auth { $3 = oid } { print }' \
    "${base_policy}" >"${expected_policy}"
  cmp -s "${expected_policy}" "${head_policy}" \
    || die_transition "arming transition may only update the authorization OID in the base policy"
}

if [[ ! "${BASE_SHA}" =~ ^[0-9a-f]{40}$ || ! "${HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::base and head must be full lowercase Git SHAs"
  exit 1
fi
if [[ "$(git -C "${REPO}" rev-parse HEAD)" != "${BASE_SHA}" ]]; then
  echo "::error::integrity checker must execute from the trusted base SHA"
  exit 1
fi

if [[ "${PHASE0_INTEGRITY_LOCAL_TEST:-0}" != "1" ]]; then
  if [[ ! "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::pull request number is invalid"
    exit 1
  fi
  : "${GITHUB_TOKEN:?GITHUB_TOKEN is required for the base-owned PR object fetch}"
  AUTH_HEADER="$(printf 'x-access-token:%s' "${GITHUB_TOKEN}" | base64 | tr -d '\n')"
  git -C "${REPO}" \
    -c "http.extraheader=AUTHORIZATION: basic ${AUTH_HEADER}" \
    fetch --no-tags origin \
    "refs/pull/${PR_NUMBER}/head:refs/remotes/phase0-integrity/head"
  unset AUTH_HEADER
  FETCHED="$(git -C "${REPO}" rev-parse refs/remotes/phase0-integrity/head)"
  if [[ "${FETCHED}" != "${HEAD_SHA}" ]]; then
    echo "::error::fetched PR head does not match the event head SHA"
    exit 1
  fi
else
  git -C "${REPO}" cat-file -e "${HEAD_SHA}^{commit}"
fi

TRANSITION_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phase0-transition.XXXXXX")"
trap 'rm -rf "${TRANSITION_DIR}"' EXIT
BASE_AUTH="${TRANSITION_DIR}/base.json"
HEAD_AUTH="${TRANSITION_DIR}/head.json"
BASE_AUTH_PRESENT=1
HEAD_AUTH_PRESENT=1
if git -C "${REPO}" cat-file -e "${BASE_SHA}:${TRANSITION_AUTH_REL}" 2>/dev/null; then
  git -C "${REPO}" cat-file blob "${BASE_SHA}:${TRANSITION_AUTH_REL}" > "${BASE_AUTH}"
else
  BASE_AUTH_PRESENT=0
fi
if git -C "${REPO}" cat-file -e "${HEAD_SHA}:${TRANSITION_AUTH_REL}" 2>/dev/null; then
  git -C "${REPO}" cat-file blob "${HEAD_SHA}:${TRANSITION_AUTH_REL}" > "${HEAD_AUTH}"
else
  HEAD_AUTH_PRESENT=0
fi
if [[ "${BASE_AUTH_PRESENT}" == "1" ]]; then
  validate_transition_common "${BASE_AUTH}"
  BASE_STATE="$(jq -r '.state' "${BASE_AUTH}")"
  BASE_GENERATION="$(jq -r '.generation' "${BASE_AUTH}")"
else
  BASE_STATE="absent"
  BASE_GENERATION=0
fi
if [[ "${HEAD_AUTH_PRESENT}" == "1" ]]; then
  validate_transition_common "${HEAD_AUTH}"
  HEAD_STATE="$(jq -r '.state' "${HEAD_AUTH}")"
else
  HEAD_STATE="absent"
fi
TRANSITION_MODE="none"
ALLOWED_PATHS=()

if [[ "${HEAD_STATE}" == "armed" && ( "${BASE_STATE}" == "absent" || "${BASE_STATE}" == "unarmed" || "${BASE_STATE}" == "consumed" ) ]]; then
  load_allowed_paths "${HEAD_AUTH}"
  [[ "$(jq -r '.armed_from_base_sha' "${HEAD_AUTH}")" == "${BASE_SHA}" ]] \
    || die_transition "arming record is not bound to the trusted base SHA"
  [[ "$(jq -r '.generation' "${HEAD_AUTH}")" == "$((BASE_GENERATION + 1))" ]] \
    || die_transition "arming record generation is not monotonic"
  EXPECTED_HEAD_TREE_OID="$(jq -r '.expected_head_tree_oid' "${HEAD_AUTH}")"
  EXPECTED_POLICY_OID="$(jq -r '.expected_policy_blob_oid' "${HEAD_AUTH}")"
  [[ "${EXPECTED_HEAD_TREE_OID}" =~ ^[0-9a-f]{40}$ ]] \
    || die_transition "arming record expected head tree OID is invalid"
  [[ "${EXPECTED_POLICY_OID}" =~ ^[0-9a-f]{40}$ ]] \
    || die_transition "arming record expected policy blob OID is invalid"
  actual="$(git -C "${REPO}" diff --name-only "${BASE_SHA}" "${HEAD_SHA}" | sort -u)"
  expected="$(printf '%s\n' "${TRANSITION_AUTH_REL}" "${POLICY_REL}" | sort -u)"
  [[ "${actual}" == "${expected}" ]] \
    || die_transition "arming commit may change only the transition authorization and policy objects"
  arm_policy_matches_base
  verify_owner_approval
  TRANSITION_MODE="arm"
elif [[ "${BASE_STATE}" == "armed" && "${HEAD_STATE}" == "absent" ]]; then
  load_allowed_paths "${BASE_AUTH}"
  EXPECTED_HEAD_TREE_OID="$(jq -r '.expected_head_tree_oid' "${BASE_AUTH}")"
  EXPECTED_POLICY_OID="$(jq -r '.expected_policy_blob_oid' "${BASE_AUTH}")"
  [[ "$(git -C "${REPO}" rev-parse "${HEAD_SHA}^{tree}")" == "${EXPECTED_HEAD_TREE_OID}" ]] \
    || die_transition "transition head tree does not match the owner-armed tree OID"
  HEAD_POLICY_OID="$(git -C "${REPO}" rev-parse "${HEAD_SHA}:${POLICY_REL}" 2>/dev/null || true)"
  [[ "${HEAD_POLICY_OID}" == "${EXPECTED_POLICY_OID}" ]] \
    || die_transition "transition head policy does not match the owner-armed policy OID"
  changed_paths_match "consume"
  TRANSITION_MODE="consume"
else
  if [[ "${BASE_AUTH_PRESENT}" != "${HEAD_AUTH_PRESENT}" ]] \
    || { [[ "${BASE_AUTH_PRESENT}" == "1" ]] && ! cmp -s "${BASE_AUTH}" "${HEAD_AUTH}"; }; then
    die_transition "transition authorization changed outside its arm/consume protocol"
  fi
fi

for path in "${SELF_PATHS[@]}"; do
  base_entry="$(git -C "${REPO}" ls-tree "${BASE_SHA}" -- "${path}")"
  head_entry="$(git -C "${REPO}" ls-tree "${HEAD_SHA}" -- "${path}")"
  if [[ "${path}" == "${TRANSITION_AUTH_REL}" && "${TRANSITION_MODE}" == "arm" ]]; then
    [[ -n "${head_entry}" ]] || die_transition "arming transition authorization object is missing"
    continue
  fi
  if [[ "${path}" == "${TRANSITION_AUTH_REL}" && "${TRANSITION_MODE}" == "consume" ]]; then
    [[ -z "${head_entry}" ]] || die_transition "consuming transition must remove its one-shot authorization object"
    continue
  fi
  if [[ "${path}" == "${POLICY_REL}" && "${TRANSITION_MODE}" == "arm" ]]; then
    [[ -n "${head_entry}" ]] || die_transition "arming transition must retain its policy object"
    base_shape="$(printf '%s\n' "${base_entry}" | awk '{print $1 "\t" $2}')"
    head_shape="$(printf '%s\n' "${head_entry}" | awk '{print $1 "\t" $2}')"
    [[ "${head_shape}" == "${base_shape}" ]] \
      || die_transition "arming transition changed the policy object type or mode"
    continue
  fi
  if [[ "${path}" == "${TRANSITION_AUTH_REL}" && "${TRANSITION_MODE}" == "none" \
    && -z "${base_entry}" && -z "${head_entry}" ]]; then
    continue
  fi
  if [[ "${TRANSITION_MODE}" == "consume" ]] && path_is_allowed "${path}"; then
    [[ -n "${head_entry}" ]] || die_transition "transition scope cannot delete a proof-machinery root"
    base_shape="$(printf '%s\n' "${base_entry}" | awk '{print $1 "\t" $2}')"
    head_shape="$(printf '%s\n' "${head_entry}" | awk '{print $1 "\t" $2}')"
    [[ "${head_shape}" == "${base_shape}" ]] \
      || die_transition "transition scope changed a proof-machinery object type or mode"
    continue
  fi
  if [[ -z "${base_entry}" || "${head_entry}" != "${base_entry}" ]]; then
    echo "::error file=${path}::base-owned integrity root differs from trusted base"
    exit 1
  fi
done

POLICY="$(mktemp "${TMPDIR:-/tmp}/phase0-protected-objects.XXXXXX")"
trap 'rm -f "${POLICY}"' EXIT
git -C "${REPO}" cat-file blob "${BASE_SHA}:${POLICY_REL}" > "${POLICY}"
count=0
while IFS=$'\t' read -r mode type oid transition path extra; do
  [[ -z "${mode}" || "${mode}" == \#* ]] && continue
  if [[ -n "${extra:-}" \
    || ! "${mode}" =~ ^(100644|100755)$ \
    || "${type}" != "blob" \
    || ! "${oid}" =~ ^[0-9a-f]{40}$ \
    || ! "${transition}" =~ ^(frozen|land-exact|versioned-transition)$ \
    || -z "${path}" \
    || "${path}" == /* \
    || "${path}" == *"../"* ]]; then
    echo "::error file=${POLICY_REL}::invalid protected-object policy entry"
    exit 1
  fi
  if [[ "${transition}" == "versioned-transition" ]]; then
    [[ "${path}" == "${TRANSITION_AUTH_REL}" ]] \
      || die_transition "versioned-transition is reserved for the transition authorization object"
    base_entry="$(git -C "${REPO}" ls-tree \
      --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
      "${BASE_SHA}" -- "${path}")"
    expected="${mode}"$'\t'"${type}"$'\t'"${oid}"
    [[ "${base_entry}" == "${expected}" ]] \
      || die_transition "base transition authorization does not match its policy OID"
    base_auth_oid="$(git -C "${REPO}" rev-parse "${BASE_SHA}:${TRANSITION_AUTH_REL}")"
    [[ "${oid}" == "${base_auth_oid}" ]] \
      || die_transition "base transition authorization policy entry is not bound to its blob"
    if [[ "${TRANSITION_MODE}" == "arm" ]]; then
      head_auth_oid="$(git -C "${REPO}" rev-parse "${HEAD_SHA}:${TRANSITION_AUTH_REL}" 2>/dev/null || true)"
      head_entry="$(git -C "${REPO}" ls-tree \
        --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
        "${HEAD_SHA}" -- "${path}")"
      [[ -n "${head_auth_oid}" && "${head_entry}" == "${mode}"$'\t'"${type}"$'\t'"${head_auth_oid}" ]] \
        || die_transition "armed transition policy entry is not bound to the armed authorization blob"
    fi
    continue
  fi
  expected="${mode}"$'\t'"${type}"$'\t'"${oid}"
  head_entry="$(git -C "${REPO}" ls-tree \
    --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
    "${HEAD_SHA}" -- "${path}")"
  if [[ "${TRANSITION_MODE}" == "consume" ]] && path_is_allowed "${path}"; then
    [[ -n "${head_entry}" ]] || die_transition "transition scope removed a protected policy object"
    head_shape="$(printf '%s\n' "${head_entry}" | awk '{print $1 "\t" $2}')"
    [[ "${head_shape}" == "${mode}"$'\t'"${type}" ]] \
      || die_transition "transition scope changed a protected policy object type or mode"
    count=$((count + 1))
    continue
  fi
  if [[ "${TRANSITION_MODE}" == "arm" && "${path}" == "${POLICY_REL}" ]]; then
    [[ -n "${head_entry}" ]] || die_transition "arming transition removed its policy object"
    head_shape="$(printf '%s\n' "${head_entry}" | awk '{print $1 "\t" $2}')"
    [[ "${head_shape}" == "${mode}"$'\t'"${type}" ]] \
      || die_transition "arming transition changed the policy object type or mode"
    continue
  fi
  if [[ "${head_entry}" != "${expected}" ]]; then
    echo "::error file=${path}::protected Phase 0 object differs from base-owned policy"
    exit 1
  fi
  if [[ "${transition}" == "frozen" ]]; then
    base_entry="$(git -C "${REPO}" ls-tree \
      --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
      "${BASE_SHA}" -- "${path}")"
    if [[ "${base_entry}" != "${expected}" ]]; then
      echo "::error file=${path}::frozen Phase 0 object differs from trusted base policy"
      exit 1
    fi
  fi
  count=$((count + 1))
done < "${POLICY}"

if [[ "${TRANSITION_MODE}" == "consume" ]]; then
  HEAD_POLICY="${TRANSITION_DIR}/head-policy.tsv"
  git -C "${REPO}" cat-file blob "${HEAD_SHA}:${POLICY_REL}" > "${HEAD_POLICY}"
  declare -a HEAD_POLICY_PATHS=()
  while IFS=$'\t' read -r mode type oid transition path extra; do
    [[ -z "${mode}" || "${mode}" == \#* ]] && continue
    if [[ -n "${extra:-}" \
      || ! "${mode}" =~ ^(100644|100755)$ \
      || "${type}" != "blob" \
      || ! "${oid}" =~ ^[0-9a-f]{40}$ \
      || ! "${transition}" =~ ^(frozen|land-exact|versioned-transition)$ ]]; then
      die_transition "transition head policy entry is invalid"
    fi
    path_is_safe "${path}" \
      || die_transition "transition head policy entry path is unsafe"
    if [[ "${transition}" == "versioned-transition" && "${path}" != "${TRANSITION_AUTH_REL}" ]]; then
      die_transition "transition head policy contains an unauthorized versioned entry"
    fi
    duplicate="$(printf '%s\n' "${HEAD_POLICY_PATHS[@]-}" | grep -Fx -- "${path}" || true)"
    [[ -z "${duplicate}" ]] || die_transition "transition head policy contains a duplicate path"
    HEAD_POLICY_PATHS+=("${path}")
    head_entry="$(git -C "${REPO}" ls-tree \
      --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
      "${HEAD_SHA}" -- "${path}")"
    expected="${mode}"$'\t'"${type}"$'\t'"${oid}"
    [[ "${head_entry}" == "${expected}" ]] \
      || die_transition "transition head policy entry does not match the head tree: ${path}"
    if ! printf '%s\n' "${ALLOWED_PATHS[@]-}" "${TRANSITION_AUTH_REL}" | grep -Fqx -- "${path}" \
      && ! awk -F '\t' -v candidate="${path}" '$5 == candidate { found = 1 } END { exit !found }' "${POLICY}"; then
      die_transition "transition head policy added an unscoped protected path"
    fi
  done < "${HEAD_POLICY}"
fi

if [[ "${count}" -lt 10 ]]; then
  echo "::error file=${POLICY_REL}::protected-object policy is unexpectedly small"
  exit 1
fi

echo "Phase 0 authority matches the trusted base-owned object policy."
