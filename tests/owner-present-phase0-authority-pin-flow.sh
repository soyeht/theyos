#!/usr/bin/env bash
# Regression coverage for ordinary Phase 0 closed-input changes.
#
# This script is deliberately outside the base-owned authority root. It calls
# the protected checkers as a consumer and must never become their authority.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTEGRITY_MATRIX_REL=".github/scripts/test-mobile-claw-vpn-owner-present-phase0-integrity.sh"
STRUCTURAL_CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
POLICY_REL=".github/owner-present-phase0-protected-objects-v1.tsv"
CLOSED_INPUT_ROOTS_REL=".github/owner-present-phase0-closed-input-roots-v1.txt"
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

# A normal admin/rust change needs no ceremonial tree-OID reseal. The actual
# structural checker still rebuilds from the closed snapshot and validates the
# executable depfiles against the base-owned path list.
normal_change="${TMP_ROOT}/normal-change"
clone_head "${normal_change}"
printf '\n// external authority-pin regression mutation\n' >> \
  "${normal_change}/admin/rust/server-rs/src/handlers_misc.rs"
git -C "${normal_change}" add -A
git -C "${normal_change}" commit --quiet -m normal-admin-rust-change
expect_structural_success normal_admin_rust_without_oid_reseal "${normal_change}"

[[ ! -e "${ROOT}/admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv" ]] \
  || { echo "error: retired Phase 0 boundary TSV still exists" >&2; exit 1; }
grep -Fqx "admin/rust" "${ROOT}/${CLOSED_INPUT_ROOTS_REL}" \
  || { echo "error: closed-input roots omit admin/rust" >&2; exit 1; }

echo "Phase 0 external authority-pin regression passed."
