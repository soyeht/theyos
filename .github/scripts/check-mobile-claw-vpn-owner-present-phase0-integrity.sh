#!/usr/bin/env bash
# Trusted-base integrity check for the Phase 0 proof machinery.
#
# There is deliberately no person/identity ceremony here. A pull request may
# evolve a land-exact object only by updating the base-owned policy to the
# exact object that is present at the PR head. This checker always executes
# from the trusted base, derives the only acceptable head policy from that
# base, and never executes code from the PR head.
set -euo pipefail

REPO="${1:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
BASE_SHA="${2:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
HEAD_SHA="${3:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
PR_NUMBER="${4:-0}"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"
CLOSED_INPUT_ROOTS_REL=".github/owner-present-phase0-closed-input-roots-v1.txt"
RETIRED_TRANSITION_REL=".github/owner-present-phase0-transition-v1.json"
REQUIRED_SELF_PATHS=(
  "${CLOSED_INPUT_ROOTS_REL}"
  ".github/scripts/check-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
  ".github/workflows/owner-present-phase0-integrity.yml"
)

die() {
  echo "::error file=${POLICY_REL}::$1"
  exit 1
}

valid_sha() {
  [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]
}

path_is_safe() {
  local candidate="${1:-}"
  [[ -n "${candidate}" && "${candidate}" != /* && "${candidate}" != *"../"* \
    && "${candidate}" != *$'\n'* && "${candidate}" != *$'\r'* ]]
}

tree_entry() {
  local commit="$1" candidate="$2"
  git -C "${REPO}" ls-tree \
    --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
    "${commit}" -- "${candidate}"
}

if ! valid_sha "${BASE_SHA}" || ! valid_sha "${HEAD_SHA}"; then
  echo "::error::base and head must be full lowercase Git SHAs"
  exit 1
fi
if [[ "$(git -C "${REPO}" rev-parse HEAD)" != "${BASE_SHA}" ]]; then
  echo "::error::integrity checker must execute from the trusted base SHA"
  exit 1
fi

if [[ "${PHASE0_INTEGRITY_LOCAL_TEST:-0}" == "1" ]]; then
  git -C "${REPO}" cat-file -e "${HEAD_SHA}^{commit}"
else
  [[ "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]] \
    || { echo "::error::pull request number is invalid"; exit 1; }
  : "${GITHUB_TOKEN:?GITHUB_TOKEN is required for the base-owned PR fetch}"
  auth_header="$(printf 'x-access-token:%s' "${GITHUB_TOKEN}" | base64 | tr -d '\n')"
  git -C "${REPO}" \
    -c "http.extraheader=AUTHORIZATION: basic ${auth_header}" \
    fetch --no-tags origin \
    "refs/pull/${PR_NUMBER}/head:refs/remotes/phase0-integrity/head"
  fetched="$(git -C "${REPO}" rev-parse refs/remotes/phase0-integrity/head)"
  [[ "${fetched}" == "${HEAD_SHA}" ]] \
    || { echo "::error::fetched PR head does not match the event head SHA"; exit 1; }
fi

for commit in "${BASE_SHA}" "${HEAD_SHA}"; do
  if git -C "${REPO}" cat-file -e "${commit}:${RETIRED_TRANSITION_REL}" 2>/dev/null; then
    die "retired arm/consume authorization object must be absent"
  fi
done

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/phase0-land-exact.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT
base_policy="${tmp_root}/base.tsv"
head_policy="${tmp_root}/head.tsv"
expected_prefix="${tmp_root}/expected-prefix.tsv"
seen_paths="${tmp_root}/seen-paths.txt"
git -C "${REPO}" cat-file blob "${BASE_SHA}:${POLICY_REL}" >"${base_policy}" \
  || die "trusted base policy is missing"
git -C "${REPO}" cat-file blob "${HEAD_SHA}:${POLICY_REL}" >"${head_policy}" \
  || die "head policy is missing"

header='# mode	type	oid	transition	path'
[[ "$(head -n 1 "${base_policy}")" == "${header}" \
  && "$(head -n 1 "${head_policy}")" == "${header}" ]] \
  || die "protected-object policy header is invalid"
printf '%s\n' "${header}" >"${expected_prefix}"
: >"${seen_paths}"

base_count=0
while IFS=$'\t' read -r mode type oid transition protected_path extra; do
  [[ -n "${mode}" ]] || die "blank policy entries are forbidden"
  if [[ -n "${extra:-}" \
    || ! "${mode}" =~ ^(100644|100755)$ \
    || "${type}" != "blob" \
    || ! "${oid}" =~ ^[0-9a-f]{40}$ \
    || ! "${transition}" =~ ^(frozen|land-exact)$ ]]; then
    die "trusted base policy entry is invalid"
  fi
  path_is_safe "${protected_path}" || die "trusted base policy path is unsafe"
  ! grep -Fqx -- "${protected_path}" "${seen_paths}" \
    || die "trusted base policy contains a duplicate path"
  printf '%s\n' "${protected_path}" >>"${seen_paths}"

  base_entry="$(tree_entry "${BASE_SHA}" "${protected_path}")"
  expected_base="$(printf '%s\t%s\t%s' "${mode}" "${type}" "${oid}")"
  [[ "${base_entry}" == "${expected_base}" ]] \
    || die "trusted base object does not match policy: ${protected_path}"

  head_entry="$(tree_entry "${HEAD_SHA}" "${protected_path}")"
  [[ -n "${head_entry}" ]] || die "head removed protected object: ${protected_path}"
  head_mode="$(cut -f1 <<<"${head_entry}")"
  head_type="$(cut -f2 <<<"${head_entry}")"
  head_oid="$(cut -f3 <<<"${head_entry}")"
  [[ "${head_mode}" == "${mode}" && "${head_type}" == "${type}" ]] \
    || die "head changed protected object mode/type: ${protected_path}"

  if [[ "${transition}" == "frozen" ]]; then
    [[ "${head_oid}" == "${oid}" ]] \
      || die "frozen Phase 0 object differs from trusted base: ${protected_path}"
    expected_oid="${oid}"
  else
    expected_oid="${head_oid}"
    if [[ "${head_oid}" != "${oid}" ]]; then
      echo "::warning file=${protected_path}::land-exact object resealed from ${oid} to ${head_oid}"
    fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "${mode}" "${type}" "${expected_oid}" "${transition}" "${protected_path}" \
    >>"${expected_prefix}"
  base_count=$((base_count + 1))
done < <(tail -n +2 "${base_policy}")
(( base_count >= 10 )) || die "protected-object policy is unexpectedly small"

head_prefix="${tmp_root}/head-prefix.tsv"
head -n "$((base_count + 1))" "${head_policy}" >"${head_prefix}"
cmp -s "${expected_prefix}" "${head_prefix}" \
  || die "head policy may only reseal exact land-exact objects from the trusted base"

# New roots may only strengthen the policy: append-only, land-exact, and bound
# to an object that already exists at the head. Existing roots cannot be
# removed, reordered, weakened, or have their mode/type/transition changed.
head_count="${base_count}"
while IFS=$'\t' read -r mode type oid transition protected_path extra; do
  [[ -n "${mode}" ]] || die "blank appended policy entries are forbidden"
  if [[ -n "${extra:-}" \
    || ! "${mode}" =~ ^(100644|100755)$ \
    || "${type}" != "blob" \
    || ! "${oid}" =~ ^[0-9a-f]{40}$ \
    || "${transition}" != "land-exact" ]]; then
    die "appended policy entry must be an exact land-exact blob"
  fi
  path_is_safe "${protected_path}" || die "appended policy path is unsafe"
  ! grep -Fqx -- "${protected_path}" "${seen_paths}" \
    || die "head policy contains a duplicate path"
  printf '%s\n' "${protected_path}" >>"${seen_paths}"
  expected="$(printf '%s\t%s\t%s' "${mode}" "${type}" "${oid}")"
  [[ "$(tree_entry "${HEAD_SHA}" "${protected_path}")" == "${expected}" ]] \
    || die "appended policy entry does not match the head object: ${protected_path}"
  echo "::warning file=${protected_path}::new land-exact integrity root appended"
  head_count=$((head_count + 1))
done < <(tail -n +$((base_count + 2)) "${head_policy}")

for required_path in "${REQUIRED_SELF_PATHS[@]}"; do
  grep -Fqx -- "${required_path}" "${seen_paths}" \
    || die "base-owned integrity root is absent from the head policy: ${required_path}"
done

# The build/depfile closure has one base-owned source of truth. Existing roots
# are immutable in position and spelling; a PR may only append a valid Git
# tree/blob path. The exact object identities remain runtime evidence and are
# deliberately not committed to this policy.
base_roots="${tmp_root}/base-roots.txt"
head_roots="${tmp_root}/head-roots.txt"
git -C "${REPO}" cat-file blob "${BASE_SHA}:${CLOSED_INPUT_ROOTS_REL}" >"${base_roots}" \
  || die "trusted base closed-input roots policy is missing"
git -C "${REPO}" cat-file blob "${HEAD_SHA}:${CLOSED_INPUT_ROOTS_REL}" >"${head_roots}" \
  || die "head closed-input roots policy is missing"

validate_closed_roots() {
  local commit="$1" roots_file="$2" label="$3"
  local root entry mode type count=0 roots_seen="${tmp_root}/${label}-roots-seen.txt"
  : >"${roots_seen}"
  while IFS= read -r root || [[ -n "${root}" ]]; do
    [[ -n "${root}" && "${root}" != \#* && "${root}" != *$'\r'* ]] \
      || die "${label} closed-input root is invalid"
    path_is_safe "${root}" || die "${label} closed-input root is unsafe"
    ! grep -Fqx -- "${root}" "${roots_seen}" \
      || die "${label} closed-input roots contain a duplicate path"
    printf '%s\n' "${root}" >>"${roots_seen}"
    entry="$(tree_entry "${commit}" "${root}")"
    mode="$(cut -f1 <<<"${entry}")"
    type="$(cut -f2 <<<"${entry}")"
    [[ ( "${mode}" == "040000" && "${type}" == "tree" ) \
      || ( "${mode}" =~ ^100(644|755)$ && "${type}" == "blob" ) ]] \
      || die "${label} closed-input root is not a Git tree or regular blob: ${root}"
    count=$((count + 1))
  done <"${roots_file}"
  (( count >= 8 )) || die "${label} closed-input roots policy is unexpectedly small"
}

validate_closed_roots "${BASE_SHA}" "${base_roots}" "trusted-base"
base_root_count="$(wc -l <"${base_roots}" | tr -d ' ')"
head_root_prefix="${tmp_root}/head-roots-prefix.txt"
head -n "${base_root_count}" "${head_roots}" >"${head_root_prefix}"
cmp -s "${base_roots}" "${head_root_prefix}" \
  || die "closed-input roots may only be appended relative to the trusted base"
validate_closed_roots "${HEAD_SHA}" "${head_roots}" "head"

echo "Phase 0 authority matches the trusted base-owned land-exact policy (${head_count} roots)."
