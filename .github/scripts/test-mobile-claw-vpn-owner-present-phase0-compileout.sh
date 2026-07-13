#!/usr/bin/env bash
# Mutations for the structural Phase 0 build boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0-test.XXXXXX")"
trap 'chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true; rm -rf "${TMP_ROOT}"' EXIT

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
MUTATION_TARGET="${HOST_TARGET}"
MUTATION_BUILD_TOOL=cargo
if [[ "${HOST_TARGET}" != *-apple-darwin ]]; then
  MUTATION_TARGET=x86_64-unknown-linux-musl
  MUTATION_BUILD_TOOL=cross
fi
SHARED_TARGET="${TMP_ROOT}/target"
CHECKER_CARGO_HOME="${TMP_ROOT}/cargo-home/home"
mkdir -p "${CHECKER_CARGO_HOME}"
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
  git clone --quiet --shared --no-checkout "${REPO_ROOT}" "${destination}"
  git -C "${destination}" checkout --quiet "$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  git -C "${destination}" config user.name "phase0-compileout-test"
  git -C "${destination}" config user.email "phase0-compileout@example.invalid"
}

prepare_empty_authority_inputs() {
  chmod -R u+w "${SHARED_TARGET}" "${CHECKER_CARGO_HOME}" 2>/dev/null || true
  rm -rf "${SHARED_TARGET}" "${CHECKER_CARGO_HOME}"
  mkdir -p "${SHARED_TARGET}" "${CHECKER_CARGO_HOME}"
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
  prepare_empty_authority_inputs
  if PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_HOME="${CHECKER_CARGO_HOME}" \
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

run_complete_route_test() {
  local root="$1" log="$2"
  CARGO_TARGET_DIR="${SHARED_TARGET}" \
    cargo test \
      --manifest-path "${root}/admin/rust/Cargo.toml" \
      --locked \
      --package server-rs \
      --test claw_store_wire_contract \
      mobile_claw_vpn_phase0_complete_production_app_rejects_mutation_routes \
      -- --test-threads=1 \
      >"${log}" 2>&1
}

expect_complete_route_test_failure() {
  local label="$1" root="$2"
  if run_complete_route_test "${root}" "${TMP_ROOT}/${label}.log"; then
    echo "error: complete production app accepted ${label}" >&2
    exit 1
  fi
  if ! grep -Fq \
      "mobile_claw_vpn_phase0_complete_production_app_rejects_mutation_routes" \
      "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} did not fail in the complete production app test" >&2
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

BUILD_TOOL_TARGET="${TMP_ROOT}/build-tool-target"
CARGO_TARGET_DIR="${BUILD_TOOL_TARGET}" \
  cargo build \
    --manifest-path "${REPO_ROOT}/admin/rust/Cargo.toml" \
    --locked \
    --release \
    --package theyos-engine-build-rs \
    >/dev/null
BUILD_TOOL_BIN="${BUILD_TOOL_TARGET}/release/theyos-engine-build"
if [ ! -x "${BUILD_TOOL_BIN}" ]; then
  echo "error: canonical build helper was not produced" >&2
  exit 1
fi

prepare_empty_authority_inputs
if CROSS_CONTAINER_OPTS='--volume=/tmp/untrusted:/claws:ro' \
    PHASE0_TARGET="${MUTATION_TARGET}" \
    PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
    PHASE0_CARGO_HOME="${CHECKER_CARGO_HOME}" \
    PHASE0_CARGO_TARGET_DIR="${SHARED_TARGET}" \
    "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/cross-env.log" 2>&1; then
  echo "error: canonical build accepted external CROSS_CONTAINER_OPTS" >&2
  exit 1
fi
grep -Fq "CROSS_CONTAINER_OPTS must be unset" "${TMP_ROOT}/cross-env.log"
echo "PASS external_cross_container_opts_refused"

if CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS='--cfg feature="dev_t1_datapath" --cfg feature="dev_claw_share_mint" -C debug-assertions=yes' \
    CARGO_TARGET_DIR="${SHARED_TARGET}" \
    "${BUILD_TOOL_BIN}" build "${HOST_TARGET}" cargo \
    >"${TMP_ROOT}/target-rustflags.log" 2>&1; then
  echo "error: canonical build accepted target-specific Rust flags" >&2
  exit 1
fi
grep -Fq \
  "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS must be unset" \
  "${TMP_ROOT}/target-rustflags.log"
echo "PASS target_specific_rustflags_refused"

UNTRUSTED_CARGO_HOME="${TMP_ROOT}/untrusted-cargo-home"
mkdir -p "${UNTRUSTED_CARGO_HOME}"
printf '%s\n' '[build]' 'rustflags = ["--cfg", "owner_present_hidden"]' > \
  "${UNTRUSTED_CARGO_HOME}/config.toml"
if CARGO_HOME="${UNTRUSTED_CARGO_HOME}" \
    CARGO_TARGET_DIR="${SHARED_TARGET}" \
    "${BUILD_TOOL_BIN}" build "${HOST_TARGET}" cargo \
    >"${TMP_ROOT}/cargo-home-config.log" 2>&1; then
  echo "error: canonical build accepted a Cargo home config" >&2
  exit 1
fi
grep -Fq "canonical theyos-engine build forbids Cargo home config" \
  "${TMP_ROOT}/cargo-home-config.log"
echo "PASS cargo_home_config_refused"

module_crossing="${TMP_ROOT}/module-crossing"
clone_head "${module_crossing}"
perl -0pi -e \
  's/#\[cfg\(any\(test, feature = "dev_t1_datapath"\)\)\]\npub mod claw_vpn_packet_pump;/pub mod claw_vpn_packet_pump;/' \
  "${module_crossing}/admin/rust/server-rs/src/lib.rs"
refresh_boundary_tree_entry "${module_crossing}" "admin/rust"
commit_mutation "${module_crossing}" module-crossing
expect_checker_failure module_crossing \
  "retired owner-present effect source entered the ${MUTATION_TARGET} production graph: claw_vpn_packet_pump.rs" \
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

middleware_interception="${TMP_ROOT}/middleware-interception"
clone_head "${middleware_interception}"
perl -0pi -e \
  's/(pub async fn public_site_gateway\(\n    State\(state\): State<SharedState>,\n    req: Request<Body>,\n    next: Next,\n\) -> Response \{)/$1\n    if req.uri().path().starts_with("\/api\/v1\/mobile\/claw-vpn\/")\n        \&\& req.uri().path() != "\/api\/v1\/mobile\/claw-vpn\/status"\n    {\n        return StatusCode::OK.into_response();\n    }/' \
  "${middleware_interception}/admin/rust/server-rs/src/public_sites.rs"
if ! run_complete_route_test \
    "${middleware_interception}" \
    "${TMP_ROOT}/middleware-interception-closed.log"; then
  echo "error: outer Phase 0 guard did not precede middleware interception" >&2
  cat "${TMP_ROOT}/middleware-interception-closed.log" >&2
  exit 1
fi
echo "PASS middleware_interception_blocked_before_effect"
perl -0pi -e \
  's/mobile_claw_vpn_phase0::close_production_app\(app\)/app/' \
  "${middleware_interception}/admin/rust/server-rs/src/production_app.rs"
expect_complete_route_test_failure middleware_without_outer_guard "${middleware_interception}"

while IFS='|' read -r listener_label listener_source; do
  listener_bypass="${TMP_ROOT}/${listener_label}"
  clone_head "${listener_bypass}"
  perl -0pi -e \
    's/core_rs::phase0_axum_serve!/axum::serve/' \
    "${listener_bypass}/${listener_source}"
  refresh_boundary_tree_entry "${listener_bypass}" "admin/rust"
  commit_mutation "${listener_bypass}" "${listener_label}"
  expect_checker_failure "${listener_label}" \
    "published HTTP listener must use the Phase 0 serve choke-point" \
    "${listener_bypass}"
done <<'LISTENERS'
main_listener_bypass|admin/rust/server-rs/src/main.rs
household_listener_bypass|admin/rust/server-rs/src/household_listener.rs
macos_local_listener_bypass|admin/rust/server-rs/src/macos_local_registration_listener.rs
install_listener_bypass|admin/rust/server-rs/src/install_cli.rs
llm_proxy_listener_bypass|admin/rust/llm-proxy-rs/src/bin/theyos-llm-proxy.rs
relay_public_listener_bypass|admin/rust/server-rs/src/bin/relay_stream_public_relay.rs
LISTENERS

new_unclosed_listener="${TMP_ROOT}/new-unclosed-listener"
clone_head "${new_unclosed_listener}"
cat >> "${new_unclosed_listener}/admin/rust/server-rs/src/handlers_misc.rs" <<'RUST'

pub async fn phase0_unclosed_http_listener(
    listener: tokio::net::TcpListener,
    router: axum::Router,
) {
    let _ = axum::serve(listener, router).await;
}
RUST
refresh_boundary_tree_entry "${new_unclosed_listener}" "admin/rust"
commit_mutation "${new_unclosed_listener}" new-unclosed-listener
expect_checker_failure new_unclosed_listener \
  'use of a disallowed method `axum::serve`' \
  "${new_unclosed_listener}"

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
  'unresolved import `crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter`' \
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
  's#emit_build_git_sha\(\);#emit_build_git_sha();\n    println!("cargo:rustc-cfg=owner_present_hidden");\n    let source = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/handlers_misc.rs");\n    let bytes = std::fs::read(&source).unwrap();\n    match std::fs::write(&source, &bytes) {\n        Ok(()) => panic!("Phase 0 source snapshot was writable"),\n        Err(error) => panic!("Phase 0 source mutation was blocked: {error}"),\n    }#' \
  "${build_cfg}/admin/rust/server-rs/build.rs"
refresh_boundary_tree_entry "${build_cfg}" "admin/rust"
commit_mutation "${build_cfg}" build-cfg
expect_checker_failure build_cfg_crossing \
  "Phase 0 source mutation was blocked" \
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

new_build_script="${TMP_ROOT}/new-build-script"
clone_head "${new_build_script}"
mkdir -p "${new_build_script}/admin/rust/server-rs/generated"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${new_build_script}/admin/rust/server-rs/generated/build.rs"
refresh_boundary_tree_entry "${new_build_script}" "admin/rust"
commit_mutation "${new_build_script}" new-build-script
expect_checker_failure new_build_script \
  "Phase 0 permits exactly the three reviewed in-repo Rust build scripts" \
  "${new_build_script}"

custom_named_build_script="${TMP_ROOT}/custom-named-build-script"
clone_head "${custom_named_build_script}"
perl -0pi -e 's/(publish = false\n)/$1build = "phase0_codegen.rs"\n/' \
  "${custom_named_build_script}/admin/rust/theyos-engine-build-rs/Cargo.toml"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${custom_named_build_script}/admin/rust/theyos-engine-build-rs/phase0_codegen.rs"
refresh_boundary_tree_entry "${custom_named_build_script}" "admin/rust"
commit_mutation "${custom_named_build_script}" custom-named-build-script
expect_checker_failure custom_named_build_script \
  "Cargo metadata custom-build targets differ from the three reviewed build scripts" \
  "${custom_named_build_script}"

local_proc_macro="${TMP_ROOT}/local-proc-macro"
clone_head "${local_proc_macro}"
mkdir -p "${local_proc_macro}/admin/rust/phase0-proc-macro/src"
cat > "${local_proc_macro}/admin/rust/phase0-proc-macro/Cargo.toml" <<'TOML'
[package]
name = "phase0-proc-macro"
version = "0.1.0"
edition = "2024"

[lib]
proc-macro = true
TOML
cat > "${local_proc_macro}/admin/rust/phase0-proc-macro/src/lib.rs" <<'RUST'
extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn phase0_hidden(input: TokenStream) -> TokenStream {
    input
}
RUST
perl -0pi -e \
  's/(    "theyos-engine-build-rs",\n)/$1    "phase0-proc-macro",\n/' \
  "${local_proc_macro}/admin/rust/Cargo.toml"
cat >> "${local_proc_macro}/admin/rust/server-rs/Cargo.toml" <<'TOML'

[dependencies.phase0-proc-macro]
path = "../phase0-proc-macro"
TOML
(
  cd "${local_proc_macro}/admin/rust"
  cargo generate-lockfile --quiet
)
refresh_boundary_tree_entry "${local_proc_macro}" "admin/rust"
commit_mutation "${local_proc_macro}" local-proc-macro
expect_checker_failure local_proc_macro \
  "Phase 0 forbids local proc-macro codegen targets" \
  "${local_proc_macro}"

external_include="${TMP_ROOT}/external-include"
clone_head "${external_include}"
printf '%s\n' 'external compile input' > \
  "${external_include}/docs/phase0 external input.txt"
cat >> "${external_include}/admin/rust/server-rs/src/handlers_misc.rs" <<'RUST'

pub const PHASE0_EXTERNAL_INCLUDE: &str =
    include_str!("../../../../docs/phase0 external input.txt");
RUST
refresh_boundary_tree_entry "${external_include}" "admin/rust"
commit_mutation "${external_include}" external-include
expect_checker_failure external_include \
  "canonical theyos-engine build failed for ${HOST_TARGET} with cargo" \
  "${external_include}"

allow_alias_escape="${TMP_ROOT}/allow-alias-escape"
clone_head "${allow_alias_escape}"
cat >> "${allow_alias_escape}/admin/rust/server-rs/src/handlers_misc.rs" <<'RUST'

#[allow(clippy::disallowed_methods)]
fn phase0_unreviewed_allow_alias() {
    let _ = axum::serve;
}
RUST
refresh_boundary_tree_entry "${allow_alias_escape}" "admin/rust"
commit_mutation "${allow_alias_escape}" allow-alias-escape
expect_checker_failure allow_alias_escape \
  "only the two reviewed Phase 0 wrapper sites may allow disallowed HTTP methods" \
  "${allow_alias_escape}"

absolute_external_include="${TMP_ROOT}/absolute-external-include"
clone_head "${absolute_external_include}"
ambient_input="${TMP_ROOT}/ambient-compile-input.txt"
printf '%s\n' 'ambient input must never be an authority' > "${ambient_input}"
cat >> "${absolute_external_include}/admin/rust/server-rs/src/handlers_misc.rs" <<RUST

pub const PHASE0_ABSOLUTE_EXTERNAL_INCLUDE: &[u8] =
    include_bytes!("${ambient_input}");
RUST
refresh_boundary_tree_entry "${absolute_external_include}" "admin/rust"
commit_mutation "${absolute_external_include}" absolute-external-include
expect_checker_failure absolute_external_include \
  "Rust depfile input is outside the modeled immutable roots" \
  "${absolute_external_include}"

manifest_override="${TMP_ROOT}/manifest-override"
clone_head "${manifest_override}"
cat >> "${manifest_override}/admin/rust/Cargo.toml" <<'TOML'

[patch.crates-io]
serde = { version = "=1.0.228" }
TOML
refresh_boundary_tree_entry "${manifest_override}" "admin/rust"
commit_mutation "${manifest_override}" manifest-override
expect_checker_failure manifest_override \
  "Phase 0 forbids Cargo override table(s): patch" \
  "${manifest_override}"

cargo_config_override="${TMP_ROOT}/cargo-config-override"
clone_head "${cargo_config_override}"
cat >> "${cargo_config_override}/admin/rust/.cargo/config.toml" <<'TOML'

[build]
rustflags = ["--cfg", "owner_present_hidden"]
TOML
refresh_boundary_tree_entry "${cargo_config_override}" "admin/rust"
commit_mutation "${cargo_config_override}" cargo-config-override
expect_checker_failure cargo_config_override \
  "Phase 0 permits only the frozen PKG_CONFIG_PATH Cargo environment entry" \
  "${cargo_config_override}"

cross_pre_build="${TMP_ROOT}/cross-pre-build"
clone_head "${cross_pre_build}"
perl -0pi -e \
  's/pre-build = \[\]/pre-build = ["printf owner-present-hidden"]/' \
  "${cross_pre_build}/admin/rust/Cross.toml"
refresh_boundary_tree_entry "${cross_pre_build}" "admin/rust"
commit_mutation "${cross_pre_build}" cross-pre-build
expect_checker_failure cross_pre_build \
  "Phase 0 forbids Cross pre-build commands" \
  "${cross_pre_build}"

git_source_dependency="${TMP_ROOT}/git-source-dependency"
clone_head "${git_source_dependency}"
perl -0pi -e \
  's~source = "registry\+https://github.com/rust-lang/crates.io-index"~source = "git+file:///tmp/phase0-source#0000000000000000000000000000000000000000"~' \
  "${git_source_dependency}/admin/rust/Cargo.lock"
refresh_boundary_tree_entry "${git_source_dependency}" "admin/rust"
commit_mutation "${git_source_dependency}" git-source-dependency
expect_checker_failure git_source_dependency \
  "Phase 0 forbids non-canonical Cargo source" \
  "${git_source_dependency}"

environment_clear_removed="${TMP_ROOT}/environment-clear-removed"
clone_head "${environment_clear_removed}"
perl -0pi -e 's/    command\.env_clear\(\);/    \/\/ mutation removed env_clear/' \
  "${environment_clear_removed}/admin/rust/theyos-engine-build-rs/src/main.rs"
if CARGO_TARGET_DIR="${SHARED_TARGET}" \
    cargo test \
      --manifest-path "${environment_clear_removed}/admin/rust/Cargo.toml" \
      --locked \
      --package theyos-engine-build-rs \
      child_process_environment_is_positive_allowlist \
      >"${TMP_ROOT}/environment-clear-removed.log" 2>&1; then
  echo "error: helper tests accepted removal of env_clear" >&2
  exit 1
fi
grep -Fq "child_process_environment_is_positive_allowlist" \
  "${TMP_ROOT}/environment-clear-removed.log"
echo "PASS environment_clear_removal_refused"

external_path_dependency="${TMP_ROOT}/external-path-dependency"
clone_head "${external_path_dependency}"
mkdir -p "${external_path_dependency}/outside-phase0/src"
printf '%s\n' \
  '[package]' \
  'name = "outside-phase0"' \
  'version = "0.1.0"' \
  'edition = "2024"' \
  > "${external_path_dependency}/outside-phase0/Cargo.toml"
printf '%s\n' 'pub const OWNER_PRESENT_HIDDEN: bool = true;' > \
  "${external_path_dependency}/outside-phase0/src/lib.rs"
cat >> "${external_path_dependency}/admin/rust/server-rs/Cargo.toml" <<'TOML'

[dependencies.outside-phase0]
path = "../../../outside-phase0"
TOML
(
  cd "${external_path_dependency}/admin/rust"
  cargo generate-lockfile --quiet
)
refresh_boundary_tree_entry "${external_path_dependency}" "admin/rust"
commit_mutation "${external_path_dependency}" external-path-dependency
expect_checker_failure external_path_dependency \
  "local Cargo dependency escapes the closed admin/rust tree" \
  "${external_path_dependency}"

ancestor_cargo_config="${TMP_ROOT}/ancestor-cargo-config"
clone_head "${ancestor_cargo_config}"
mkdir -p "${ancestor_cargo_config}/.cargo"
printf '%s\n' '[net]' 'retry = 2' > "${ancestor_cargo_config}/.cargo/config.toml"
commit_mutation "${ancestor_cargo_config}" ancestor-cargo-config
expect_checker_failure ancestor_cargo_config \
  "canonical theyos-engine build forbids ancestor Cargo config" \
  "${ancestor_cargo_config}"

above_repo_cargo_config_root="${TMP_ROOT}/above-repo-cargo-config"
mkdir -p \
  "${above_repo_cargo_config_root}/checkout" \
  "${above_repo_cargo_config_root}/.cargo"
above_repo_cargo_config="${above_repo_cargo_config_root}/checkout/repo"
clone_head "${above_repo_cargo_config}"
printf '%s\n' '[build]' 'rustflags = ["--cfg", "owner_present_hidden"]' > \
  "${above_repo_cargo_config_root}/.cargo/config.toml"
expect_checker_failure above_repo_cargo_config \
  "canonical theyos-engine build forbids Cargo config above the repository" \
  "${above_repo_cargo_config}"

workspace_cargo_alias="${TMP_ROOT}/workspace-cargo-alias"
clone_head "${workspace_cargo_alias}"
printf '%s\n' '[net]' 'retry = 2' > \
  "${workspace_cargo_alias}/admin/rust/.cargo/config"
refresh_boundary_tree_entry "${workspace_cargo_alias}" "admin/rust"
commit_mutation "${workspace_cargo_alias}" workspace-cargo-alias
expect_checker_failure workspace_cargo_alias \
  "canonical theyos-engine build forbids ancestor Cargo config: admin/rust/.cargo/config" \
  "${workspace_cargo_alias}"

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
commit_mutation "${release_subject_bypass}" release-subject-bypass
expect_checker_failure release_subject_bypass \
  "every theyos-engine release target must run the Phase 0 checker on its own subject" \
  "${release_subject_bypass}"

alternate_publisher="${TMP_ROOT}/alternate-publisher"
clone_head "${alternate_publisher}"
cat > "${alternate_publisher}/.github/workflows/release-alt.yml" <<'YAML'
name: Unclassified publisher
on:
  workflow_dispatch:
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: echo forbidden
YAML
commit_mutation "${alternate_publisher}" alternate-publisher
expect_checker_failure alternate_publisher \
  ".github/workflows contains an unclassified publisher or attestation workflow" \
  "${alternate_publisher}"

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
