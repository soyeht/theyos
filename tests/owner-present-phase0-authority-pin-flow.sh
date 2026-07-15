#!/usr/bin/env bash
# Regression coverage for ordinary Phase 0 boundary updates.
#
# This script is deliberately outside the base-owned authority root. It calls
# the protected checkers as a consumer and must never become their authority.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTEGRITY_MATRIX_REL=".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
STRUCTURAL_CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
THIS_TEST_REL="tests/owner-present-phase0-authority-pin-flow.sh"
THIS_WORKFLOW_REL=".github/workflows/claw-store-contract-ci.yml"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-phase0-authority-pin-flow.XXXXXX")"
trap 'chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true; rm -rf "${TMP_ROOT}"' EXIT

for path in "${THIS_TEST_REL}" "${THIS_WORKFLOW_REL}"; do
  if awk -F '\t' -v path="${path}" '$5 == path { found = 1 } END { exit !found }' \
      "${ROOT}/${POLICY_REL}"; then
    echo "error: external regression surface unexpectedly entered the protected policy: ${path}" >&2
    exit 1
  fi
done

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "${HOST_TARGET}" ]] || { echo "error: could not determine Rust host target" >&2; exit 1; }
MUTATION_TARGET="${HOST_TARGET}"
MUTATION_BUILD_TOOL="cargo"
if [[ "${HOST_TARGET}" != *-apple-darwin ]]; then
  MUTATION_TARGET="x86_64-unknown-linux-musl"
  MUTATION_BUILD_TOOL="cross"
fi
SHARED_TARGET="${TMP_ROOT}/target"
REQUIRE_STRUCTURAL="${PHASE0_AUTHORITY_PIN_REQUIRE_STRUCTURAL:-0}"
if [[ "${CI:-}" == "true" ]]; then
  REQUIRE_STRUCTURAL=1
fi

if [[ "${HOST_TARGET}" == *-apple-darwin ]]; then
  PHASE0_EXPECTED_XCODE_VERSION="${PHASE0_EXPECTED_XCODE_VERSION:-$(xcodebuild -version | sed -n 's/^Xcode //p')}"
  PHASE0_EXPECTED_XCODE_BUILD="${PHASE0_EXPECTED_XCODE_BUILD:-$(xcodebuild -version | sed -n 's/^Build version //p')}"
  PHASE0_EXPECTED_MACOS_SDK_VERSION="${PHASE0_EXPECTED_MACOS_SDK_VERSION:-$(xcrun --sdk macosx --show-sdk-version)}"
  PHASE0_EXPECTED_DEVELOPER_DIR="${PHASE0_EXPECTED_DEVELOPER_DIR:-$(xcode-select -p)}"
  export PHASE0_EXPECTED_XCODE_VERSION PHASE0_EXPECTED_XCODE_BUILD \
    PHASE0_EXPECTED_MACOS_SDK_VERSION PHASE0_EXPECTED_DEVELOPER_DIR
fi

clone_head() {
  local destination="$1"
  git clone --quiet --shared --no-checkout "${ROOT}" "${destination}"
  git -C "${destination}" checkout --quiet "$(git -C "${ROOT}" rev-parse HEAD)"
  git -C "${destination}" config user.name "phase0-authority-pin-flow"
  git -C "${destination}" config user.email "phase0-authority-pin-flow@example.invalid"
}

prepare_empty_authority_inputs() {
  chmod -R u+w "${SHARED_TARGET}" 2>/dev/null || true
  rm -rf "${SHARED_TARGET}"
  mkdir -p "${SHARED_TARGET}"
}

refresh_boundary_tree_entry() {
  local root="$1" path="$2"
  local manifest="${root}/${BOUNDARY_REL}" root_tree oid tmp="${root}/${BOUNDARY_REL}.tmp"

  git -C "${root}" add -A
  root_tree="$(git -C "${root}" write-tree)"
  oid="$(git -C "${root}" rev-parse "${root_tree}:${path}")"
  awk -F '\t' -v OFS='\t' -v path="${path}" -v oid="${oid}" '
    $4 == path { $3 = oid; found = 1 }
    { print }
    END { if (!found) exit 2 }
  ' "${manifest}" > "${tmp}"
  mv "${tmp}" "${manifest}"
}

run_structural_checker() {
  local root="$1"
  env -u CARGO_HOME -u RUSTUP_HOME -u PHASE0_RUSTUP_HOME \
    PHASE0_TARGET="${MUTATION_TARGET}" \
    PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
    PHASE0_CARGO_TARGET_DIR="${SHARED_TARGET}" \
    "${root}/${STRUCTURAL_CHECKER_REL}" "${root}"
}

structural_available=1

expect_structural_success() {
  local label="$1" root="$2"
  prepare_empty_authority_inputs
  if ! run_structural_checker "${root}" > "${TMP_ROOT}/${label}.log" 2>&1; then
    if [[ "${REQUIRE_STRUCTURAL}" != "1" \
      && "$(grep -Fc "selected Phase 0 toolchain policy mismatch" "${TMP_ROOT}/${label}.log")" == "1" ]]; then
      echo "SKIP ${label}_closed_toolchain_unavailable_locally"
      structural_available=0
      return 0
    fi
    echo "error: structural checker rejected ${label}" >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  echo "PASS ${label}_accepted"
}

expect_structural_failure() {
  local label="$1" expected="$2" root="$3"
  prepare_empty_authority_inputs
  if run_structural_checker "${root}" > "${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: structural checker accepted ${label}" >&2
    exit 1
  fi
  if ! grep -Fq -- "${expected}" "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} missed expected refusal: ${expected}" >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  echo "PASS ${label}_refused"
}

# The protected integrity matrix owns the fixture for policy and checker
# tampering. Running it here ensures this external CI job consumes the same
# trusted checker behavior without adding a second authority implementation.
integrity_log="${TMP_ROOT}/integrity-matrix.log"
if ! bash "${ROOT}/${INTEGRITY_MATRIX_REL}" > "${integrity_log}" 2>&1; then
  cat "${integrity_log}" >&2
  exit 1
fi
for expected in "PASS payload_tamper_refused" "PASS checker_tamper_refused"; do
  if ! grep -Fq -- "${expected}" "${integrity_log}"; then
    echo "error: protected integrity matrix omitted ${expected}" >&2
    cat "${integrity_log}" >&2
    exit 1
  fi
done
echo "PASS stale_policy_pin_refused"
echo "PASS checker_tamper_refused"

# A normal admin/rust change with a fresh tree OID must pass the actual
# structural checker. This is the legitimate PR path that #348 lacked.
normal_reseal="${TMP_ROOT}/normal-reseal"
clone_head "${normal_reseal}"
printf '\n// external authority-pin regression mutation\n' >> \
  "${normal_reseal}/admin/rust/server-rs/src/handlers_misc.rs"
refresh_boundary_tree_entry "${normal_reseal}" "admin/rust"
git -C "${normal_reseal}" add -A
git -C "${normal_reseal}" commit --quiet -m normal-admin-rust-reseal
expect_structural_success normal_admin_rust_reseal "${normal_reseal}"

# The same change without re-sealing must fail before it can become a release
# input. The expected error binds the rejection to the stale boundary root.
stale_boundary="${TMP_ROOT}/stale-boundary"
clone_head "${stale_boundary}"
printf '\n// external stale boundary regression mutation\n' >> \
  "${stale_boundary}/admin/rust/server-rs/src/handlers_misc.rs"
git -C "${stale_boundary}" add -A
git -C "${stale_boundary}" commit --quiet -m stale-boundary-tsv
if [[ "${structural_available}" == "1" ]]; then
  expect_structural_failure stale_boundary_tsv_requires_reseal \
    "file=admin/rust::signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
    "${stale_boundary}"
else
  stale_boundary_oid="$(awk -F '\t' '$4 == "admin/rust" { print $3 }' \
    "${stale_boundary}/${BOUNDARY_REL}")"
  stale_tree_oid="$(git -C "${stale_boundary}" rev-parse "HEAD:admin/rust")"
  [[ "${stale_boundary_oid}" =~ ^[0-9a-f]{40}$ \
    && "${stale_boundary_oid}" != "${stale_tree_oid}" ]] \
    || { echo "error: stale boundary mutation was not material" >&2; exit 1; }
  echo "SKIP stale_boundary_tsv_requires_reseal_closed_toolchain_unavailable_locally"
fi

echo "Phase 0 external authority-pin regression passed."
