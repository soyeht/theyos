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

refresh_boundary_tree_entry() {
  local root="$1" path="$2"
  local manifest="${root}/${BOUNDARY_REL}"
  local oid root_tree tmp="${manifest}.tmp"
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

expect_route_test_failure() {
  local label="$1" root="$2"
  if CARGO_TARGET_DIR="${SHARED_TARGET}" \
      cargo test \
        --manifest-path "${root}/admin/rust/Cargo.toml" \
        --locked \
        --package server-rs \
        --test claw_store_wire_contract \
        mobile_claw_vpn_phase0_mutation_routes_are_absent \
        -- --test-threads=1 \
        >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: real Phase 0 route composer accepted ${label}" >&2
    exit 1
  fi
  if ! grep -Fq "mobile_claw_vpn_phase0_mutation_routes_are_absent" \
      "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} did not fail in the real Phase 0 route composer test" >&2
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
refresh_boundary_tree_entry "${module_crossing}" "admin/rust"
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

composer_route_crossing="${TMP_ROOT}/composer-route-crossing"
clone_head "${composer_route_crossing}"
perl -0pi -e \
  's/\.merge\(mobile_claw_vpn_phase0::routes\(\)\)/.route("\/claw-vpn\/owner\/grant", post(mobile_claw_vpn_phase0::handle_status))\n        .merge(mobile_claw_vpn_phase0::routes())/' \
  "${composer_route_crossing}/admin/rust/server-rs/src/mobile_api_routes.rs"
refresh_boundary_tree_entry "${composer_route_crossing}" "admin/rust"
commit_mutation "${composer_route_crossing}" composer-route-crossing
expect_route_test_failure composer_route_crossing "${composer_route_crossing}"

linked_module_crossing="${TMP_ROOT}/linked-module-crossing"
clone_head "${linked_module_crossing}"
printf '%s\n' \
  'pub const PHASE0_LINKED_MODULE_CROSSING: &str = "/api/v1/mobile/claw-vpn/owner/grant";' \
  >> "${linked_module_crossing}/admin/rust/server-rs/src/handlers_misc.rs"
commit_mutation "${linked_module_crossing}" linked-module-crossing
expect_checker_failure linked_module_crossing \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${linked_module_crossing}"

linked_ip_tunnel_seam="${TMP_ROOT}/linked-ip-tunnel-seam"
clone_head "${linked_ip_tunnel_seam}"
printf '%s\n' \
  'use crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter;' \
  >> "${linked_ip_tunnel_seam}/admin/rust/server-rs/src/handlers_misc.rs"
refresh_boundary_tree_entry "${linked_ip_tunnel_seam}" "admin/rust"
commit_mutation "${linked_ip_tunnel_seam}" linked-ip-tunnel-seam
expect_checker_failure linked_ip_tunnel_seam \
  "canonical theyos-engine build failed" \
  "${linked_ip_tunnel_seam}"

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

build_tool_codegen="${TMP_ROOT}/build-tool-codegen"
clone_head "${build_tool_codegen}"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${build_tool_codegen}/admin/rust/theyos-engine-build-rs/build.rs"
refresh_boundary_tree_entry "${build_tool_codegen}" "admin/rust"
commit_mutation "${build_tool_codegen}" build-tool-codegen
expect_checker_failure build_tool_codegen \
  "canonical engine build tool must not have a build.rs codegen seam" \
  "${build_tool_codegen}"

ancestor_cargo_config="${TMP_ROOT}/ancestor-cargo-config"
clone_head "${ancestor_cargo_config}"
mkdir -p "${ancestor_cargo_config}/.cargo"
printf '%s\n' '[net]' 'retry = 2' > "${ancestor_cargo_config}/.cargo/config.toml"
commit_mutation "${ancestor_cargo_config}" ancestor-cargo-config
expect_checker_failure ancestor_cargo_config \
  "canonical theyos-engine build forbids ancestor Cargo config" \
  "${ancestor_cargo_config}"

recipe_drift="${TMP_ROOT}/recipe-drift"
clone_head "${recipe_drift}"
perl -0pi -e \
  's/--no-default-features/--features dev_t1_datapath/' \
  "${recipe_drift}/admin/rust/theyos-engine-build-rs/src/main.rs"
commit_mutation "${recipe_drift}" recipe-drift
expect_checker_failure release_recipe_drift \
  "signed Phase 0 boundary object differs from ${BOUNDARY_REL}" \
  "${recipe_drift}"

release_subject_bypass="${TMP_ROOT}/release-subject-bypass"
clone_head "${release_subject_bypass}"
perl -0pi -e \
  's#bash \.github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout\.sh#true#g' \
  "${release_subject_bypass}/.github/workflows/release-linux.yml"
refresh_boundary_tree_entry "${release_subject_bypass}" ".github"
commit_mutation "${release_subject_bypass}" release-subject-bypass
expect_checker_failure release_subject_bypass \
  "every theyos-engine release target must run the Phase 0 checker on its own subject" \
  "${release_subject_bypass}"

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
