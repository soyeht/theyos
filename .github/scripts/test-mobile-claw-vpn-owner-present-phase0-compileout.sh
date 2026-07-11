#!/usr/bin/env bash
# Mutations for the structural Phase 0 build boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0-test.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
SHARED_TARGET="${TMP_ROOT}/target"

clone_head() {
  local destination="$1"
  git clone --quiet --shared --no-checkout "${REPO_ROOT}" "${destination}"
  git -C "${destination}" checkout --quiet "$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  git -C "${destination}" config user.name "phase0-compileout-test"
  git -C "${destination}" config user.email "phase0-compileout@example.invalid"
}

commit_mutation() {
  local root="$1" label="$2"
  git -C "${root}" add -A
  git -C "${root}" commit --quiet -m "${label}"
}

refresh_boundary_entry() {
  local root="$1" path="$2"
  local manifest="${root}/${BOUNDARY_REL}"
  local oid tmp="${manifest}.tmp"
  oid="$(git -C "${root}" hash-object "${path}")"
  awk -F '\t' -v OFS='\t' -v path="${path}" -v oid="${oid}" '
    $3 == path { $2 = oid; found = 1 }
    { print }
    END { if (!found) exit 2 }
  ' "${manifest}" > "${tmp}"
  mv "${tmp}" "${manifest}"

  local digest status status_tmp
  digest="$(
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${manifest}" | awk '{print $1}'
    else
      shasum -a 256 "${manifest}" | awk '{print $1}'
    fi
  )"
  status="${root}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
  status_tmp="${status}.tmp"
  jq --arg digest "${digest}" \
    '.phase0_artifact_boundary.sha256 = $digest' \
    "${status}" > "${status_tmp}"
  mv "${status_tmp}" "${status}"
}

expect_checker_failure() {
  local label="$1" expected="$2" root="$3"
  if PHASE0_TARGET="${HOST_TARGET}" \
      PHASE0_BUILD_TOOL=cargo \
      PHASE0_CARGO_TARGET_DIR="${SHARED_TARGET}" \
      "${root}/${CHECKER_REL}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: checker accepted ${label}" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} missed expected reason: ${expected}" >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  echo "PASS ${label}_refused"
}

if CARGO_TARGET_DIR="${SHARED_TARGET}" \
    cargo check \
      --manifest-path "${REPO_ROOT}/admin/rust/Cargo.toml" \
      --locked \
      --release \
      --package server-rs \
      --bin server \
      --features dev_t1_datapath \
      >"${TMP_ROOT}/dev-feature.log" 2>&1; then
  echo "error: release server accepted dev_t1_datapath" >&2
  exit 1
fi
grep -Fq "production server binary cannot be built with DEV/test features" \
  "${TMP_ROOT}/dev-feature.log"
echo "PASS release_dev_feature_refused"

module_crossing="${TMP_ROOT}/module-crossing"
clone_head "${module_crossing}"
perl -0pi -e \
  's/#\[cfg\(any\(test, feature = "dev_t1_datapath"\)\)\]\npub mod claw_vpn_packet_pump;/pub mod claw_vpn_packet_pump;/' \
  "${module_crossing}/admin/rust/server-rs/src/lib.rs"
refresh_boundary_entry "${module_crossing}" "admin/rust/server-rs/src/lib.rs"
commit_mutation "${module_crossing}" module-crossing
expect_checker_failure module_crossing \
  "retired owner-present effect source entered the ${HOST_TARGET} production graph: claw_vpn_packet_pump.rs" \
  "${module_crossing}"

composer_crossing="${TMP_ROOT}/composer-crossing"
clone_head "${composer_crossing}"
perl -0pi -e \
  's/\.merge\(mobile_claw_vpn_phase0::routes\(\)\)/.route("\/claw-vpn\/hidden", get(mobile_claw_vpn_phase0::handle_status))\n        .merge(mobile_claw_vpn_phase0::routes())/' \
  "${composer_crossing}/admin/rust/server-rs/src/mobile_api_routes.rs"
commit_mutation "${composer_crossing}" composer-crossing
expect_checker_failure composer_crossing \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${composer_crossing}"

store_open="${TMP_ROOT}/store-open"
clone_head "${store_open}"
perl -0pi -e \
  's/pub const IP_TUNNEL_RESOURCE_COMPILED: bool = cfg!\(any\(test, feature = "dev_t1_datapath"\)\);/pub const IP_TUNNEL_RESOURCE_COMPILED: bool = true;/' \
  "${store_open}/admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs"
commit_mutation "${store_open}" store-open
expect_checker_failure generic_ip_tunnel_store \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${store_open}"

build_cfg="${TMP_ROOT}/build-cfg"
clone_head "${build_cfg}"
perl -0pi -e \
  's/emit_build_git_sha\(\);/emit_build_git_sha();\n    println!("cargo:rustc-cfg=owner_present_hidden");/' \
  "${build_cfg}/admin/rust/server-rs/build.rs"
commit_mutation "${build_cfg}" build-cfg
expect_checker_failure build_cfg_crossing \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${build_cfg}"

recipe_drift="${TMP_ROOT}/recipe-drift"
clone_head "${recipe_drift}"
perl -0pi -e \
  's/--no-default-features/--features dev_t1_datapath/' \
  "${recipe_drift}/scripts/build-theyos-engine.sh"
commit_mutation "${recipe_drift}" recipe-drift
expect_checker_failure release_recipe_drift \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${recipe_drift}"

marker="${TMP_ROOT}/marker"
clone_head "${marker}"
printf '%s\n' '{"contract":"activation"}' > \
  "${marker}/admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
commit_mutation "${marker}" marker
expect_checker_failure activation_marker \
  "Phase 0 forbids an owner-present activation marker" \
  "${marker}"

status_open="${TMP_ROOT}/status-open"
clone_head "${status_open}"
perl -0pi -e 's/"authority": "none"/"authority": "v1"/' \
  "${status_open}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
commit_mutation "${status_open}" status-open
expect_checker_failure v1_authority \
  "Phase 0 authority status is invalid" \
  "${status_open}"

echo "Owner-present Phase 0 structural mutation matrix passed."
