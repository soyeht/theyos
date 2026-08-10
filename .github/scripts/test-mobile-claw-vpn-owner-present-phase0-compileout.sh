#!/usr/bin/env bash
# Mutations for the structural Phase 0 build boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
WORKFLOW_REL=".github/workflows/owner-present-phase0-compileout.yml"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0-test.XXXXXX")"
trap 'chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true; rm -rf "${TMP_ROOT}"' EXIT

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
MUTATION_TARGET="${HOST_TARGET}"
MUTATION_BUILD_TOOL=cargo
if [[ "${HOST_TARGET}" != *-apple-darwin ]]; then
  MUTATION_TARGET=x86_64-unknown-linux-musl
  MUTATION_BUILD_TOOL=cross
fi
# Separate cargo target dirs. The authority build writes 0444 (read-only)
# source copies inside its target; a route test (or a later mutation build)
# that writes into the SAME dir hits PermissionDenied (errno 13) on the second
# overwrite — a harness artefact, not a boundary verdict. Splitting the two
# removes the contention without relaxing any boundary constraint.
AUTHORITY_TARGET="${TMP_ROOT}/authority-target"
ROUTE_TEST_TARGET="${TMP_ROOT}/route-test-target"
if ! grep -Fq \
    'build_tool_version "$(run_clean "${BUILD_TOOL_BIN}" --version)"' \
    "${REPO_ROOT}/${CHECKER_REL}"; then
  echo "error: cross attestation must query the Docker CLI with --version" >&2
  exit 1
fi
if ! grep -Fq \
    'test("^1\\.92\\.0-[0-9a-z_-]+$")' \
    "${REPO_ROOT}/${WORKFLOW_REL}"; then
  echo "error: published-target workflow must accept pinned Rust triples with underscores" >&2
  exit 1
fi
workflow_job_runner_temp_refs() {
  awk '
    /^  [A-Za-z0-9_-]+:$/ { in_job = 1; job = $0; next }
    in_job && /^    steps:$/ { in_job = 0; next }
    in_job && /\$\{\{[[:space:]]*runner\.temp[[:space:]]*\}\}/ {
      print job ":" NR ":" $0
    }
  ' "$1"
}
release_macos_workflow="${REPO_ROOT}/.github/workflows/release-macos.yml"
if [[ -n "$(workflow_job_runner_temp_refs "${release_macos_workflow}")" ]]; then
  echo "error: release-macos uses runner.temp in job-level env" >&2
  exit 1
fi
release_macos_context_mutation="${TMP_ROOT}/release-macos-runner-context.yml"
cp "${release_macos_workflow}" "${release_macos_context_mutation}"
perl -0pi -e \
  's/(    env:\n)/$1      TEST_RUNNER_TEMP: "\$\{\{ runner.temp \}\}"\n/' \
  "${release_macos_context_mutation}"
if [[ -z "$(workflow_job_runner_temp_refs "${release_macos_context_mutation}")" ]]; then
  echo "error: release workflow runner context canary did not detect job-level runner.temp" >&2
  exit 1
fi
if ! grep -Fq 'runner.temp is unavailable in job-level env' \
    "${REPO_ROOT}/${CHECKER_REL}"; then
  echo "error: compileout checker lacks the release workflow context validator" >&2
  exit 1
fi
release_macos_formula_job="$(sed -n '/^  update-homebrew-formula:/,$p' "${release_macos_workflow}")"
formula_auth_setup_line="$(grep -nF 'gh auth setup-git' <<<"${release_macos_formula_job}" \
  | head -1 | cut -d: -f1 || true)"
formula_push_line="$(grep -nF 'git push origin' <<<"${release_macos_formula_job}" \
  | head -1 | cut -d: -f1 || true)"
if [[ -z "${formula_auth_setup_line}" || -z "${formula_push_line}" \
  || "${formula_auth_setup_line}" -ge "${formula_push_line}" ]]; then
  echo "error: formula push lacks GitHub CLI credential setup" >&2
  exit 1
fi
formula_auth_home="${TMP_ROOT}/formula-auth-home"
mkdir -p "${formula_auth_home}/gh"
if ! env -u GH_TOKEN \
    HOME="${formula_auth_home}" \
    GH_CONFIG_DIR="${formula_auth_home}/gh" \
    GH_TOKEN=phase0-dry-run-token \
    gh auth setup-git >/dev/null 2>&1; then
  echo "error: gh auth setup-git dry-run failed" >&2
  exit 1
fi
if ! env HOME="${formula_auth_home}" \
    git config --global --get-all 'credential.https://github.com.helper' \
    | grep -Fq 'gh auth git-credential'; then
  echo "error: gh auth setup-git did not install the GitHub credential helper" >&2
  exit 1
fi
echo "PASS release_workflow_context_and_push_auth_contract"
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

run_checker() {
  env -u CARGO_HOME -u RUSTUP_HOME -u PHASE0_RUSTUP_HOME "$@"
}

prepare_empty_authority_inputs() {
  # The authority build populates its target with 0444 (read-only) source
  # copies; clearing it for the next mutation needs u+w first. This is a
  # transient cleanup step — the build itself never receives write permission,
  # so the read-only posture the boundary enforces is unchanged.
  chmod -R u+w "${AUTHORITY_TARGET}" 2>/dev/null || true
  rm -rf "${AUTHORITY_TARGET}"
  mkdir -p "${AUTHORITY_TARGET}"
}

commit_mutation() {
  local root="$1" label="$2"
  git -C "${root}" add -A
  git -C "${root}" commit --quiet -m "${label}"
}

expect_checker_failure() {
  local label="$1" expected="$2" root="$3"
  prepare_empty_authority_inputs
  if PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      run_checker "${root}/${CHECKER_REL}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: checker accepted ${label}" >&2
    exit 1
  fi
  if grep -Fq "failed to run custom build command" "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} HARNESS FAILURE — the build died before the semantic check (failed to run custom build command); the negative control is INCONCLUSIVE, not satisfied. Fix the harness, not the expectation." >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} missed expected reason: ${expected}" >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  echo "PASS ${label}_refused"
}

expect_checker_failure_any() {
  local label="$1" root="$2"
  shift 2
  prepare_empty_authority_inputs
  if PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      run_checker "${root}/${CHECKER_REL}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: checker accepted ${label}" >&2
    exit 1
  fi
  if grep -Fq "failed to run custom build command" "${TMP_ROOT}/${label}.log"; then
    echo "error: ${label} HARNESS FAILURE — the build died before the semantic check (failed to run custom build command); the negative control is INCONCLUSIVE, not satisfied. Fix the harness, not the expectation." >&2
    cat "${TMP_ROOT}/${label}.log" >&2
    exit 1
  fi
  local expected
  for expected in "$@"; do
    if grep -Fq -- "${expected}" "${TMP_ROOT}/${label}.log"; then
      echo "PASS ${label}_refused"
      return
    fi
  done
  echo "error: ${label} missed all expected reasons: $*" >&2
  cat "${TMP_ROOT}/${label}.log" >&2
  exit 1
}

expect_route_test_failure() {
  local label="$1" root="$2"
  if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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
  CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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

if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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
    PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
    run_checker "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/cross-env.log" 2>&1; then
  echo "error: canonical build accepted external CROSS_CONTAINER_OPTS" >&2
  exit 1
fi
grep -Fq "CROSS_CONTAINER_OPTS must be unset" "${TMP_ROOT}/cross-env.log"
echo "PASS external_cross_container_opts_refused"

for docker_override in \
  "DOCKER_HOST=tcp://127.0.0.1:1" \
  "DOCKER_CONTEXT=untrusted-context" \
  "DOCKER_CONFIG=${TMP_ROOT}/untrusted-docker-config"; do
  docker_name="${docker_override%%=*}"
  if env -u CARGO_HOME -u RUSTUP_HOME -u PHASE0_RUSTUP_HOME \
      "${docker_override}" \
      PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/${docker_name}.log" 2>&1; then
    echo "error: canonical build accepted external ${docker_name}" >&2
    exit 1
  fi
  if ! grep -Fq "${docker_name} must be unset" "${TMP_ROOT}/${docker_name}.log"; then
    echo "error: ${docker_name} refusal reported an unexpected reason" >&2
    cat "${TMP_ROOT}/${docker_name}.log" >&2
    exit 1
  fi
  echo "PASS ${docker_name}_refused"
done

UNTRUSTED_RUSTUP_HOME="${TMP_ROOT}/untrusted-rustup-home"
if env -u CARGO_HOME -u RUSTUP_HOME \
    PHASE0_RUSTUP_HOME="${UNTRUSTED_RUSTUP_HOME}" \
    PHASE0_TARGET=unsupported-phase0-target \
    PHASE0_BUILD_TOOL=cross \
    PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
    "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/rustup-home.log" 2>&1; then
  echo "error: canonical build accepted caller-selected PHASE0_RUSTUP_HOME" >&2
  exit 1
fi
if ! grep -Fq "PHASE0_RUSTUP_HOME must be unset" "${TMP_ROOT}/rustup-home.log"; then
  echo "error: PHASE0_RUSTUP_HOME refusal reported an unexpected reason" >&2
  cat "${TMP_ROOT}/rustup-home.log" >&2
  exit 1
fi
echo "PASS phase0_rustup_home_refused"

FAKE_TOOL_BIN="${TMP_ROOT}/fake-tool-bin"
mkdir -p "${FAKE_TOOL_BIN}"
for fake_tool in rustc rustup docker; do
  printf '%s\n' '#!/bin/sh' "echo fake-${fake_tool} >&2" 'exit 99' \
    > "${FAKE_TOOL_BIN}/${fake_tool}"
  chmod 755 "${FAKE_TOOL_BIN}/${fake_tool}"
done
GIT_WRAPPER_LOG="${TMP_ROOT}/ambient-git-invoked.log"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\\n" ambient-git-invoked >> "${GIT_WRAPPER_LOG}"' \
  'exec /usr/bin/git "$@"' > "${FAKE_TOOL_BIN}/git"
chmod 755 "${FAKE_TOOL_BIN}/git"
if PATH="${FAKE_TOOL_BIN}:${PATH}" \
    PHASE0_TARGET="${MUTATION_TARGET}" \
    PHASE0_BUILD_TOOL=unsupported \
    PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
    run_checker "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/path-tools.log" 2>&1; then
  echo "error: canonical build accepted an unsupported build tool" >&2
  exit 1
fi
if grep -Eq 'fake-(rustc|rustup|docker)' "${TMP_ROOT}/path-tools.log"; then
  echo "error: canonical tool selection executed a PATH-provided stub" >&2
  cat "${TMP_ROOT}/path-tools.log" >&2
  exit 1
fi
if ! grep -Fq "unsupported Phase 0 build tool: unsupported" "${TMP_ROOT}/path-tools.log"; then
  echo "error: PATH tool injection test reported an unexpected reason" >&2
  cat "${TMP_ROOT}/path-tools.log" >&2
  exit 1
fi
echo "PASS path_tool_injection_ignored"

prepare_empty_authority_inputs
if PATH="${FAKE_TOOL_BIN}:${PATH}" \
    PHASE0_TARGET="${MUTATION_TARGET}" \
    PHASE0_BUILD_TOOL=unsupported \
    PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
    GIT_WRAPPER_LOG="${GIT_WRAPPER_LOG}" \
    run_checker "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/path-git.log" 2>&1; then
  echo "error: canonical build accepted an unsupported build tool with a PATH Git wrapper" >&2
  exit 1
fi
if [[ -s "${GIT_WRAPPER_LOG}" ]]; then
  echo "error: canonical source selection executed a PATH-provided Git wrapper" >&2
  cat "${GIT_WRAPPER_LOG}" >&2
  exit 1
fi
if ! grep -Fq "unsupported Phase 0 build tool: unsupported" "${TMP_ROOT}/path-git.log"; then
  echo "error: PATH Git injection test reported an unexpected reason" >&2
  cat "${TMP_ROOT}/path-git.log" >&2
  exit 1
fi
echo "PASS path_git_injection_ignored"

if [[ -x /usr/bin/docker && "${HOST_TARGET}" != *-apple-darwin ]]; then
  prepare_empty_authority_inputs
  if PATH="${FAKE_TOOL_BIN}:${PATH}" \
      PHASE0_TARGET=x86_64-unknown-linux-musl \
      PHASE0_BUILD_TOOL=cross \
      PHASE0_DOCKER_HOST=tcp://127.0.0.1:1 \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      run_checker "${REPO_ROOT}/${CHECKER_REL}" >"${TMP_ROOT}/path-docker.log" 2>&1; then
    echo "error: canonical build accepted an external Docker authority" >&2
    exit 1
  fi
  if grep -Eq 'fake-(rustc|rustup|docker)' "${TMP_ROOT}/path-docker.log"; then
    echo "error: canonical Docker/toolchain selection executed a PATH-provided stub" >&2
    cat "${TMP_ROOT}/path-docker.log" >&2
    exit 1
  fi
  grep -Fq "DOCKER_HOST is forbidden" "${TMP_ROOT}/path-docker.log"
  echo "PASS path_docker_injection_ignored"
else
  echo "PASS path_docker_injection_ignored (fixed Docker path unavailable on this host)"
fi

if CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS='--cfg feature="dev_t1_datapath" --cfg feature="dev_claw_share_mint" -C debug-assertions=yes' \
    CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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
    CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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
commit_mutation "${module_crossing}" module-crossing
expect_checker_failure module_crossing \
  "retired owner-present effect source entered the ${MUTATION_TARGET} production graph: claw_vpn_packet_pump.rs" \
  "${module_crossing}"

composer_route_crossing="${TMP_ROOT}/composer-route-crossing"
clone_head "${composer_route_crossing}"
perl -0pi -e \
  's/\.merge\(mobile_claw_vpn_phase0::routes\(\)\)/.route("\/claw-vpn\/owner\/grant", post(mobile_claw_vpn_phase0::handle_status))\n        .merge(mobile_claw_vpn_phase0::routes())/' \
  "${composer_route_crossing}/admin/rust/server-rs/src/mobile_api_routes.rs"
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
commit_mutation "${new_unclosed_listener}" new-unclosed-listener
expect_checker_failure new_unclosed_listener \
  'use of a disallowed method `axum::serve`' \
  "${new_unclosed_listener}"

linked_ip_tunnel_seam="${TMP_ROOT}/linked-ip-tunnel-seam"
clone_head "${linked_ip_tunnel_seam}"
printf '%s\n' \
  'use crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter;' \
  >> "${linked_ip_tunnel_seam}/admin/rust/server-rs/src/handlers_misc.rs"
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
  "published theyos-engine Phase 0 artifact contract is not status-only" \
  "${store_open}"

build_cfg="${TMP_ROOT}/build-cfg"
clone_head "${build_cfg}"
perl -0pi -e \
  's#emit_build_git_sha\(\);#emit_build_git_sha();\n    println!("cargo:rustc-cfg=owner_present_hidden");\n    let source = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/handlers_misc.rs");\n    let bytes = std::fs::read(&source).unwrap();\n    match std::fs::write(&source, &bytes) {\n        Ok(()) => panic!("Phase 0 source snapshot was writable"),\n        Err(error) => panic!("Phase 0 source mutation was blocked: {error}"),\n    }#' \
  "${build_cfg}/admin/rust/server-rs/build.rs"
commit_mutation "${build_cfg}" build-cfg
expect_checker_failure build_cfg_crossing \
  "Phase 0 source mutation was blocked" \
  "${build_cfg}"

build_tool_codegen="${TMP_ROOT}/build-tool-codegen"
clone_head "${build_tool_codegen}"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${build_tool_codegen}/admin/rust/theyos-engine-build-rs/build.rs"
commit_mutation "${build_tool_codegen}" build-tool-codegen
expect_checker_failure build_tool_codegen \
  "canonical engine build tool must not have a build.rs codegen seam" \
  "${build_tool_codegen}"

new_build_script="${TMP_ROOT}/new-build-script"
clone_head "${new_build_script}"
mkdir -p "${new_build_script}/admin/rust/server-rs/generated"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${new_build_script}/admin/rust/server-rs/generated/build.rs"
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
commit_mutation "${local_proc_macro}" local-proc-macro
expect_checker_failure local_proc_macro \
  "Phase 0 forbids local proc-macro codegen targets" \
  "${local_proc_macro}"

external_include="${TMP_ROOT}/external-include"
clone_head "${external_include}"
# The repository intentionally has no tracked docs/ tree. Recreate the
# out-of-boundary directory inside the mutation clone so this negative tests
# the checker rather than failing while arranging its fixture.
mkdir -p "${external_include}/docs"
printf '%s\n' 'external compile input' > \
  "${external_include}/docs/phase0 external input.txt"
cat >> "${external_include}/admin/rust/server-rs/src/handlers_misc.rs" <<'RUST'

pub const PHASE0_EXTERNAL_INCLUDE: &str =
    include_str!("../../../../docs/phase0 external input.txt");
RUST
commit_mutation "${external_include}" external-include
expect_checker_failure external_include \
  "couldn't read \`server-rs/src/../../../../docs/phase0 external input.txt\`" \
  "${external_include}"

allow_alias_escape="${TMP_ROOT}/allow-alias-escape"
clone_head "${allow_alias_escape}"
cat >> "${allow_alias_escape}/admin/rust/server-rs/src/handlers_misc.rs" <<'RUST'

#[allow(clippy::disallowed_methods)]
fn phase0_unreviewed_allow_alias() {
    let _ = axum::serve;
}
RUST
commit_mutation "${allow_alias_escape}" allow-alias-escape
expect_checker_failure allow_alias_escape \
  "only the two reviewed Phase 0 wrapper sites may allow disallowed HTTP methods" \
  "${allow_alias_escape}"

absolute_external_include="${TMP_ROOT}/absolute-external-include"
clone_head "${absolute_external_include}"
ambient_input="/etc/hosts"
cat >> "${absolute_external_include}/admin/rust/server-rs/src/handlers_misc.rs" <<RUST

pub const PHASE0_ABSOLUTE_EXTERNAL_INCLUDE: &[u8] =
    include_bytes!("${ambient_input}");
RUST
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
commit_mutation "${cargo_config_override}" cargo-config-override
expect_checker_failure cargo_config_override \
  "Phase 0 permits only the frozen PKG_CONFIG_PATH Cargo environment entry" \
  "${cargo_config_override}"

cross_pre_build="${TMP_ROOT}/cross-pre-build"
clone_head "${cross_pre_build}"
perl -0pi -e \
  's/pre-build = \[\]/pre-build = ["printf owner-present-hidden"]/' \
  "${cross_pre_build}/admin/rust/Cross.toml"
commit_mutation "${cross_pre_build}" cross-pre-build
expect_checker_failure cross_pre_build \
  "Phase 0 forbids Cross pre-build commands" \
  "${cross_pre_build}"

git_source_dependency="${TMP_ROOT}/git-source-dependency"
clone_head "${git_source_dependency}"
perl -0pi -e \
  's~source = "registry\+https://github.com/rust-lang/crates.io-index"~source = "git+file:///tmp/phase0-source#0000000000000000000000000000000000000000"~' \
  "${git_source_dependency}/admin/rust/Cargo.lock"
commit_mutation "${git_source_dependency}" git-source-dependency
expect_checker_failure git_source_dependency \
  "Phase 0 forbids non-canonical Cargo source" \
  "${git_source_dependency}"

environment_clear_removed="${TMP_ROOT}/environment-clear-removed"
clone_head "${environment_clear_removed}"
perl -0pi -e 's/    command\.env_clear\(\);/    \/\/ mutation removed env_clear/' \
  "${environment_clear_removed}/admin/rust/theyos-engine-build-rs/src/main.rs"
if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
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
commit_mutation "${external_path_dependency}" external-path-dependency
expect_checker_failure_any external_path_dependency \
  "${external_path_dependency}" \
  "local Cargo dependency escapes the closed admin/rust tree" \
  "local Cargo dependency path escapes the closed admin/rust tree" \
  'failed to read `/project/outside-phase0/Cargo.toml`'

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
  "production server binary cannot be built with DEV/test features" \
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
