#!/usr/bin/env bash
# Base-owned integrity check for the Phase 0 compile-out authority.
set -euo pipefail

REPO="${1:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
BASE_SHA="${2:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
HEAD_SHA="${3:?usage: $0 REPO BASE_SHA HEAD_SHA PR_NUMBER}"
PR_NUMBER="${4:-0}"

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
  ".github/workflows/release-linux.yml"
  ".github/workflows/release-macos.yml"
  "admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
  "admin/rust/.cargo/config.toml"
  "admin/rust/Cross.toml"
  "admin/rust/rust-toolchain.toml"
  "admin/rust/core-rs/build.rs"
  "admin/rust/household-rs/build.rs"
  "admin/rust/server-rs/build.rs"
  "admin/rust/theyos-engine-build-rs/Cargo.toml"
  "admin/rust/theyos-engine-build-rs/src/main.rs"
  "scripts/make.sh"
)

for path in "${PROTECTED_PATHS[@]}"; do
  base_entry="$(git -C "${REPO}" ls-tree "${BASE_SHA}" -- "${path}")"
  head_entry="$(git -C "${REPO}" ls-tree "${HEAD_SHA}" -- "${path}")"
  if [[ -z "${base_entry}" || -z "${head_entry}" ]]; then
    echo "::error file=${path}::protected Phase 0 authority object is missing"
    exit 1
  fi
  if [[ "${base_entry}" != "${head_entry}" ]]; then
    echo "::error file=${path}::protected Phase 0 authority differs from trusted base"
    exit 1
  fi
done

echo "Phase 0 compile-out authority matches the trusted base objects."
