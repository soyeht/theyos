#!/usr/bin/env bash
# Phase 0 authority: prove the published theyos-engine target excludes the
# owner-present issuer, mutable Mesh-C store, and relay authority.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
THEYOS_DIR_INPUT="${1:-${DEFAULT_ROOT}}"
THEYOS_DIR="$(cd "${THEYOS_DIR_INPUT}" && pwd -P)"
TARGET="${PHASE0_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
BUILD_TOOL="${PHASE0_BUILD_TOOL:-cargo}"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
PUBLISHED_TARGET=true

case "${TARGET}:${BUILD_TOOL}" in
  x86_64-unknown-linux-musl:cross | \
  aarch64-unknown-linux-musl:cross | \
  aarch64-apple-darwin:cargo) ;;
  "${HOST_TARGET}:cargo") PUBLISHED_TARGET=false ;;
  *)
    echo "::error::unsupported Phase 0 target/build-tool pair: ${TARGET}:${BUILD_TOOL}"
    exit 1
    ;;
esac

FOUNDATION_REL="admin/rust/server-rs/src/mobile_claw_vpn_owner_present_foundation.rs"
PHASE0_REL="admin/rust/server-rs/src/mobile_claw_vpn_phase0.rs"
MANIFEST_REL="admin/rust/Cargo.toml"
MARKER_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
HISTORICAL_WIRE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
AUTHORITY_STATUS_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
BUILD_TOOL_MANIFEST_REL="admin/rust/theyos-engine-build-rs/Cargo.toml"
BUILD_TOOL_SOURCE_REL="admin/rust/theyos-engine-build-rs/src/main.rs"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"

HEAD_SHA="$(git -C "${THEYOS_DIR}" rev-parse HEAD)"
HEAD_TREE="$(git -C "${THEYOS_DIR}" rev-parse "${HEAD_SHA}^{tree}")"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT
SNAPSHOT="${THEYOS_DIR}"
TARGET_DIR="${PHASE0_CARGO_TARGET_DIR:-${SNAPSHOT}/admin/rust/target}"

if [[ -n "$(git -C "${THEYOS_DIR}" status --porcelain --untracked-files=all)" ]]; then
  echo "::error::Phase 0 checker requires a clean checkout of the exact head object"
  exit 1
fi

require_blob() {
  local path="$1" expected_mode="${2:-100644}"
  local entry mode type
  entry="$(git -C "${THEYOS_DIR}" ls-tree "${HEAD_SHA}" -- "${path}")"
  if [[ -z "${entry}" ]]; then
    echo "::error file=${path}::required Phase 0 input is missing"
    exit 1
  fi
  read -r mode type _ <<< "${entry}"
  if [[ "${mode}" != "${expected_mode}" || "${type}" != "blob" ]]; then
    echo "::error file=${path}::Phase 0 input must be a regular ${expected_mode} Git blob"
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

validate_boundary_manifest() {
  local manifest="${1}" seen_paths="${TMP_ROOT}/boundary-paths.txt"
  local mode type oid path entry expected count=0
  : > "${seen_paths}"

  while IFS=$'\t' read -r mode type oid path; do
    [[ -z "${mode}" || "${mode}" == \#* ]] && continue
    if [[ ! "${mode}" =~ ^(040000|100644|100755)$ \
      || ! "${type}" =~ ^(blob|tree)$ \
      || ! "${oid}" =~ ^[0-9a-f]{40}$ \
      || -z "${path}" \
      || "${path}" == /* \
      || "${path}" == *"../"* \
      || "${path}" == *$'\n'* ]]; then
      echo "::error file=${BOUNDARY_REL}::invalid signed Phase 0 boundary entry"
      exit 1
    fi
    if [[ ( "${mode}" == "040000" && "${type}" != "tree" ) \
      || ( "${mode}" != "040000" && "${type}" != "blob" ) ]]; then
      echo "::error file=${BOUNDARY_REL}::signed Phase 0 boundary mode/type mismatch"
      exit 1
    fi
    if grep -Fqx -- "${path}" "${seen_paths}"; then
      echo "::error file=${BOUNDARY_REL}::duplicate signed Phase 0 boundary path: ${path}"
      exit 1
    fi
    printf '%s\n' "${path}" >> "${seen_paths}"

    entry="$(git -C "${THEYOS_DIR}" ls-tree \
      --format='%(objectmode)%x09%(objecttype)%x09%(objectname)' \
      "${HEAD_SHA}" -- "${path}")"
    expected="${mode}"$'\t'"${type}"$'\t'"${oid}"
    if [[ "${entry}" != "${expected}" ]]; then
      echo "::error file=${path}::signed Phase 0 boundary object differs from ${BOUNDARY_REL}"
      exit 1
    fi
    count=$((count + 1))
  done < "${manifest}"

  if [[ "${count}" -ne 4 ]]; then
    echo "::error file=${BOUNDARY_REL}::signed Phase 0 boundary must contain exactly four closed subtrees"
    exit 1
  fi

  for path in \
    ".github" \
    "admin/rust" \
    "claws" \
    "scripts"; do
    if ! grep -Fqx -- "${path}" "${seen_paths}"; then
      echo "::error file=${BOUNDARY_REL}::required Phase 0 boundary path is absent: ${path}"
      exit 1
    fi
  done
}

for path in \
  "admin/rust/.cargo/config.toml" \
  "admin/rust/Cross.toml" \
  "${MANIFEST_REL}" \
  "admin/rust/Cargo.lock" \
  "admin/rust/rust-toolchain.toml" \
  "admin/rust/household-rs/Cargo.toml" \
  "admin/rust/household-rs/build.rs" \
  "admin/rust/household-rs/data/emoji-security-code-wordlist.csv" \
  "admin/rust/household-rs/src/lib.rs" \
  "admin/rust/core-rs/build.rs" \
  "admin/rust/server-rs/Cargo.toml" \
  "admin/rust/server-rs/build.rs" \
  "admin/rust/server-rs/src/lib.rs" \
  "admin/rust/server-rs/src/main.rs" \
  "admin/rust/server-rs/src/mobile_api_routes.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_mount.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_runtime.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_target_router.rs" \
  "admin/rust/server-rs/src/claw_store_routes.rs" \
  "admin/rust/server-rs/src/state.rs" \
  "admin/rust/server-rs/src/handlers_mobile.rs" \
  "${BUILD_TOOL_MANIFEST_REL}" \
  "${BUILD_TOOL_SOURCE_REL}" \
  "${FOUNDATION_REL}" \
  "${PHASE0_REL}" \
  "admin/contracts/mobile-claw-vpn/v1/api_shapes.json" \
  "claws/manifest.yml" \
  "${HISTORICAL_WIRE_REL}" \
  "${AUTHORITY_STATUS_REL}" \
  "${BOUNDARY_REL}"; do
  require_blob "${path}"
done

EXPECTED_BUILD_SCRIPTS="${TMP_ROOT}/expected-build-scripts.txt"
ACTUAL_BUILD_SCRIPTS="${TMP_ROOT}/actual-build-scripts.txt"
printf '%s\n' \
  "admin/rust/core-rs/build.rs" \
  "admin/rust/household-rs/build.rs" \
  "admin/rust/server-rs/build.rs" \
  | LC_ALL=C sort > "${EXPECTED_BUILD_SCRIPTS}"
: > "${ACTUAL_BUILD_SCRIPTS}"
while IFS= read -r -d '' path; do
  case "${path}" in
    */build.rs) printf '%s\n' "${path}" >> "${ACTUAL_BUILD_SCRIPTS}" ;;
  esac
done < <(git -C "${THEYOS_DIR}" ls-tree -r -z --name-only "${HEAD_SHA}" -- admin/rust)
LC_ALL=C sort -o "${ACTUAL_BUILD_SCRIPTS}" "${ACTUAL_BUILD_SCRIPTS}"
if ! cmp -s "${EXPECTED_BUILD_SCRIPTS}" "${ACTUAL_BUILD_SCRIPTS}"; then
  echo "::error::Phase 0 permits exactly the three reviewed in-repo Rust build scripts"
  exit 1
fi

METADATA_JSON="${TMP_ROOT}/cargo-metadata.json"
cargo metadata \
  --manifest-path "${SNAPSHOT}/admin/rust/Cargo.toml" \
  --locked \
  --format-version 1 \
  > "${METADATA_JSON}"
if ! jq -e '
    all(.packages[] | select(.source == null); .manifest_path | contains("\n") | not)
  ' "${METADATA_JSON}" >/dev/null; then
  echo "::error::local Cargo manifest paths must be single-line UTF-8 paths"
  exit 1
fi
while IFS= read -r manifest_path; do
  manifest_dir="$(cd "$(dirname "${manifest_path}")" && pwd -P)"
  case "${manifest_dir}/" in
    "${SNAPSHOT}/admin/rust/"*) ;;
    *)
      echo "::error file=${manifest_path}::local Cargo dependency escapes the closed admin/rust tree"
      exit 1
      ;;
  esac
done < <(jq -r '.packages[] | select(.source == null) | .manifest_path' "${METADATA_JSON}")

BOUNDARY_MANIFEST="${TMP_ROOT}/phase0-boundary.tsv"
git -C "${THEYOS_DIR}" cat-file blob "${HEAD_SHA}:${BOUNDARY_REL}" > "${BOUNDARY_MANIFEST}"
validate_boundary_manifest "${BOUNDARY_MANIFEST}"

RELEASE_CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
if [[ "$(grep -Fc "${RELEASE_CHECKER_REL}" "${SNAPSHOT}/.github/workflows/release-linux.yml")" -ne 2 \
  || "$(grep -Fc "${RELEASE_CHECKER_REL}" "${SNAPSHOT}/.github/workflows/release-macos.yml")" -ne 1 ]]; then
  echo "::error::every theyos-engine release target must run the Phase 0 checker on its own subject"
  exit 1
fi
if [[ "$(grep -Fc "mobile_claw_vpn_phase0_" "${SNAPSHOT}/.github/workflows/release-linux.yml")" -ne 2 \
  || "$(grep -Fc "mobile_claw_vpn_phase0_" "${SNAPSHOT}/.github/workflows/release-macos.yml")" -ne 1 ]]; then
  echo "::error::every release target must exercise the exact Phase 0 route composer"
  exit 1
fi
for release_path in \
  ".github/workflows/release-linux.yml" \
  ".github/workflows/release-macos.yml"; do
  if ! grep -Fq \
      "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a" \
      "${SNAPSHOT}/${release_path}"; then
    echo "::error file=${release_path}::published package provenance attestation is missing"
    exit 1
  fi
done
if ! grep -Fq "phase0_engine_sha256" "${SNAPSHOT}/.github/workflows/release-linux.yml" \
  || ! grep -Fq "published_signed_engine_sha256" \
    "${SNAPSHOT}/.github/workflows/release-macos.yml" \
  || ! grep -Fq "PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256" \
    "${SNAPSHOT}/scripts/make.sh"; then
  echo "::error::release provenance does not bind the verified engine to the published package"
  exit 1
fi
if git -C "${THEYOS_DIR}" cat-file -e \
    "${HEAD_SHA}:admin/rust/theyos-engine-build-rs/build.rs" 2>/dev/null; then
  echo "::error::the canonical engine build tool must not have a build.rs codegen seam"
  exit 1
fi

for retired_path in \
  "admin/rust/server-rs/src/mobile_claw_vpn_relay_auth.rs" \
  "admin/rust/server-rs/src/mobile_claw_vpn_relay_dial_config.rs" \
  "admin/rust/server-rs/src/mobile_claw_vpn_relay_responder.rs" \
  "admin/rust/server-rs/src/mobile_claw_vpn_relay_responder_config.rs"; do
  if git -C "${THEYOS_DIR}" cat-file -e "${HEAD_SHA}:${retired_path}" 2>/dev/null; then
    echo "::error file=${retired_path}::retired Phase 0 effect source must not be present"
    exit 1
  fi
done

if git -C "${THEYOS_DIR}" cat-file -e "${HEAD_SHA}:${MARKER_REL}" 2>/dev/null; then
  echo "::error file=${MARKER_REL}::Phase 0 forbids an owner-present activation marker"
  exit 1
fi

HISTORICAL_WIRE="${SNAPSHOT}/${HISTORICAL_WIRE_REL}"
AUTHORITY_STATUS="${SNAPSHOT}/${AUTHORITY_STATUS_REL}"
if [[ "$(jq -r '.contract' "${AUTHORITY_STATUS}")" != \
    "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1" \
  || "$(jq -r '.version' "${AUTHORITY_STATUS}")" != "1" \
  || "$(jq -r '.phase' "${AUTHORITY_STATUS}")" != "phase0-compile-out" \
  || "$(jq -r '.authority' "${AUTHORITY_STATUS}")" != "none" \
  || "$(jq -r '.retired_wire.status' "${AUTHORITY_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_wire.theyos_path' "${AUTHORITY_STATUS}")" != \
    "${HISTORICAL_WIRE_REL}" \
  || "$(jq -r '.retired_api_shapes.status' "${AUTHORITY_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_api_shapes.theyos_path' "${AUTHORITY_STATUS}")" != \
    "admin/contracts/mobile-claw-vpn/v1/api_shapes.json" \
  || "$(jq -r '.retired_api_shapes.historical_sha256' "${AUTHORITY_STATUS}")" != \
    "$(sha256_file "${SNAPSHOT}/admin/contracts/mobile-claw-vpn/v1/api_shapes.json")" \
  || "$(jq -r '.phase0_artifact_boundary.theyos_path' "${AUTHORITY_STATUS}")" != \
    "${BOUNDARY_REL}" \
  || "$(jq -r '.phase0_artifact_boundary.format' "${AUTHORITY_STATUS}")" != \
    "closed-git-subtrees-v1" \
  || "$(jq -r '.phase0_artifact_boundary.policy_change_control' "${AUTHORITY_STATUS}")" != \
    "explicit-owner-approved-versioned-transition" \
  || "$(jq -r '.phase0_artifact_boundary.object_identity_update' "${AUTHORITY_STATUS}")" != \
    "per-reviewed-commit-revalidation" \
  || "$(jq -r '.phase0_artifact_boundary.object_identity_authority' "${AUTHORITY_STATUS}")" != \
    "commit-bound-evidence-not-independent-approval" \
  || "$(jq -r '.phase0_artifact_boundary.release_provenance' "${AUTHORITY_STATUS}")" != \
    "checker-on-release-subject-and-final-package-attestation" \
  || "$(jq -r '.phase0_artifact_boundary.staged_product' "${AUTHORITY_STATUS}")" != \
    "theyos-engine" \
  || "$(jq -r '.phase0_artifact_boundary.required_published_targets | sort | join(",")' "${AUTHORITY_STATUS}")" != \
    "aarch64-apple-darwin,aarch64-unknown-linux-musl,x86_64-unknown-linux-musl" \
  || "$(jq -r '.phase1_blocker.minimum_wire_version' "${AUTHORITY_STATUS}")" != "2" \
  || "$(jq -r '.phase1_blocker.required_shape' "${AUTHORITY_STATUS}")" != \
    "server-held-finish-consume-mint" ]]; then
  echo "::error file=${AUTHORITY_STATUS_REL}::Phase 0 authority status is invalid"
  exit 1
fi
if [[ "$(jq -r '.retired_wire.historical_sha256' "${AUTHORITY_STATUS}")" != \
  "$(sha256_file "${HISTORICAL_WIRE}")" ]]; then
  echo "::error file=${AUTHORITY_STATUS_REL}::retired V1 wire digest does not match the historical fixture"
  exit 1
fi
if [[ "$(jq -r '.authority_status' "${HISTORICAL_WIRE}")" != \
  "historical-test-only-non-authoritative" ]]; then
  echo "::error file=${HISTORICAL_WIRE_REL}::V1 wire still claims implementation authority"
  exit 1
fi
for forbidden_authority in \
  "proof_token" \
  "proof-bearing mint request" \
  "owner_present_runtime_activation_v1"; do
  if ! jq -e --arg value "${forbidden_authority}" \
    '.retired_wire.prohibited_production_authority | index($value) != null' \
    "${AUTHORITY_STATUS}" >/dev/null; then
    echo "::error file=${AUTHORITY_STATUS_REL}::missing prohibited V1 authority: ${forbidden_authority}"
    exit 1
  fi
done

if grep -ERn \
  --include='*.rs' \
  'pub (async )?fn handle_(admin_)?mobile_claw_vpn_(mint|consume|authorize|enroll|set|grant|revoke)' \
  "${SNAPSHOT}/admin/rust/server-rs/src" >/dev/null; then
  echo "::error::Phase 0 production source exports a retired Mobile Claw VPN effect handler"
  exit 1
fi

(
  cd "${SNAPSHOT}/admin/rust"
  THEYOS_BUILD_GIT_SHA="${HEAD_SHA}" \
  CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo run \
      --manifest-path Cargo.toml \
      --locked \
      --release \
      --package theyos-engine-build-rs \
      -- build "${TARGET}" "${BUILD_TOOL}" >/dev/null
)

BINARY_DIR="${TARGET_DIR}/${TARGET}/release"
BINARY="${BINARY_DIR}/server"
DEPFILE="${BINARY_DIR}/server.d"
STAGED_ENGINE="${PHASE0_STAGED_ENGINE_OUT:-${TMP_ROOT}/theyos-engine}"
if [[ ! -x "${BINARY}" ]]; then
  echo "::error::release server binary was not produced for ${TARGET}"
  exit 1
fi
if [[ ! -f "${DEPFILE}" ]]; then
  echo "::error::release server dependency graph was not produced for ${TARGET}"
  exit 1
fi

(
  cd "${SNAPSHOT}/admin/rust"
  cargo run \
    --manifest-path Cargo.toml \
    --locked \
    --release \
    --package theyos-engine-build-rs \
    -- stage "${BINARY_DIR}" "${STAGED_ENGINE}"
)
if ! cmp -s "${BINARY}" "${STAGED_ENGINE}"; then
  echo "::error::staged theyos-engine is not byte-identical to server-rs/server"
  exit 1
fi

for required_source in \
  "mobile_claw_vpn_phase0.rs" \
  "mobile_api_routes.rs" \
  "claw_share_relay_stream_mount.rs" \
  "claw_share_relay_stream_offer_store.rs" \
  "claw_share_relay_stream_runtime.rs" \
  "claw_share_relay_stream_target_router.rs" \
  "claw_store_routes.rs" \
  "handlers_mobile.rs"; do
  if ! grep -Fq "${required_source}" "${DEPFILE}"; then
    echo "::error::Phase 0 boundary source is missing from the ${TARGET} production graph: ${required_source}"
    exit 1
  fi
done
for forbidden_source in \
  "mobile_claw_vpn_owner_present_foundation.rs" \
  "claw_vpn_mobile_mesh_store.rs" \
  "claw_vpn_mobile_state.rs" \
  "claw_vpn_interface_route_plan.rs" \
  "claw_vpn_linux_tun.rs" \
  "claw_vpn_macos_utun.rs" \
  "claw_vpn_nonblocking_frame.rs" \
  "claw_vpn_packet_pump.rs" \
  "claw_vpn_pollable_pump.rs" \
  "claw_vpn_relay_stream.rs" \
  "claw_vpn_runtime.rs" \
  "claw_vpn_t1_caller.rs" \
  "claw_vpn_t1_relay_stream_router.rs" \
  "claw_vpn_target_session_relay.rs" \
  "claw_vpn_target_session_router.rs" \
  "claw_vpn_target_session_runtime.rs" \
  "claw_vpn_wiring.rs" \
  "mobile_claw_vpn_relay_auth.rs" \
  "mobile_claw_vpn_relay_dial_config.rs" \
  "mobile_claw_vpn_relay_responder.rs" \
  "mobile_claw_vpn_relay_responder_config.rs"; do
  if grep -Fq "${forbidden_source}" "${DEPFILE}"; then
    echo "::error::retired owner-present effect source entered the ${TARGET} production graph: ${forbidden_source}"
    exit 1
  fi
done

if [[ "${TARGET}" == "${HOST_TARGET}" || "${PHASE0_RUN_ARTIFACT_DIRECT:-0}" == "1" ]]; then
  CONTRACT_JSON="${TMP_ROOT}/artifact-contract.json"
  "${STAGED_ENGINE}" --owner-present-phase0-contract > "${CONTRACT_JSON}"
  if [[ "$(jq -r '.schema' "${CONTRACT_JSON}")" != \
      "theyos-owner-present-phase0-artifact-contract-v1" \
    || "$(jq -r '.authority' "${CONTRACT_JSON}")" != "none" \
    || "$(jq -r '.production_activation' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.third_target_injection_seam_compiled' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.generic_ip_tunnel_backend_compiled' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.generic_ip_tunnel_store_accepts_resource' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.generic_ip_tunnel_env_accepts_resource' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.declared_product_a_routes | length' "${CONTRACT_JSON}")" != "1" \
    || "$(jq -r '.declared_product_a_routes[0]' "${CONTRACT_JSON}")" != \
      "/claw-vpn/status" ]]; then
    echo "::error::published theyos-engine Phase 0 artifact contract is not status-only"
    exit 1
  fi
fi

# Auxiliary tripwire only. Structural absence above is the authority.
STRINGS_OUT="${TMP_ROOT}/server.strings"
LC_ALL=C strings "${BINARY}" > "${STRINGS_OUT}"
while IFS= read -r forbidden; do
  [[ -z "${forbidden}" ]] && continue
  if grep -Fqi -- "${forbidden}" "${STRINGS_OUT}"; then
    echo "::error::production theyos-engine contains auxiliary Phase 0 tripwire: ${forbidden}"
    exit 1
  fi
done <<'FORBIDDEN'
/api/v1/mobile/claw-vpn/owner-present/
/api/v1/mobile/claw-vpn/offers
/api/v1/mobile/claw-vpn/sessions
/api/v1/mobile/claw-vpn/rendezvous/authorize
/api/v1/mobile/claw-vpn/owner/enroll-device
/api/v1/mobile/claw-vpn/owner/claw-availability
/api/v1/mobile/claw-vpn/owner/grant
/api/v1/mobile/claw-vpn/owner/revoke-grant
mesh_c_owner_present_offer_control
RevalidatedCapability
ConsumedCapability
PointOfUsePermit
owner_approval_consumed
RelayStreamIpTunnelRouter
RelayStreamIpTunnelTarget
new_with_ip_tunnel_router
bind_relay_stream_reverse_connect_with_ip_tunnel_router
assemble_relay_stream_live_with_ip_tunnel_router
FORBIDDEN

NORMALIZED_DEPFILE="${TMP_ROOT}/server.normalized.d"
sed \
  -e "s#${SNAPSHOT}#\$SOURCE#g" \
  -e "s#${TARGET_DIR}#\$TARGET#g" \
  "${DEPFILE}" > "${NORMALIZED_DEPFILE}"

ATTESTATION_OUT="${PHASE0_ATTESTATION_OUT:-${TMP_ROOT}/phase0-attestation-${TARGET}.json}"
mkdir -p "$(dirname "${ATTESTATION_OUT}")"
XCODE_VERSION=""
MACOS_SDK_VERSION=""
if [[ "${TARGET}" == *-apple-darwin ]]; then
  XCODE_VERSION="$(xcodebuild -version)"
  MACOS_SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
fi
jq -n -S \
  --arg schema "theyos-owner-present-phase0-artifact-attestation-v1" \
  --arg source_sha "${HEAD_SHA}" \
  --arg source_tree "${HEAD_TREE}" \
  --arg target "${TARGET}" \
  --arg build_tool "${BUILD_TOOL}" \
  --arg build_tool_version "$("${BUILD_TOOL}" -V)" \
  --arg rustc "$(rustc -Vv)" \
  --arg cargo "$(cargo -V)" \
  --arg cargo_config_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/.cargo/config.toml")" \
  --arg cross_config_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/Cross.toml")" \
  --arg cargo_lock_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/Cargo.lock")" \
  --arg cargo_workspace_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/Cargo.toml")" \
  --arg claws_manifest_sha256 "$(sha256_file "${SNAPSHOT}/claws/manifest.yml")" \
  --arg core_build_rs_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/core-rs/build.rs")" \
  --arg household_build_rs_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/household-rs/build.rs")" \
  --arg emoji_wordlist_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/household-rs/data/emoji-security-code-wordlist.csv")" \
  --arg rust_toolchain_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/rust-toolchain.toml")" \
  --arg server_manifest_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/server-rs/Cargo.toml")" \
  --arg server_build_rs_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/server-rs/build.rs")" \
  --arg boundary_manifest_sha256 "$(sha256_file "${SNAPSHOT}/${BOUNDARY_REL}")" \
  --arg engine_build_tool_manifest_sha256 "$(sha256_file "${SNAPSHOT}/${BUILD_TOOL_MANIFEST_REL}")" \
  --arg engine_build_tool_source_sha256 "$(sha256_file "${SNAPSHOT}/${BUILD_TOOL_SOURCE_REL}")" \
  --arg depfile_sha256 "$(sha256_file "${NORMALIZED_DEPFILE}")" \
  --arg server_sha256 "$(sha256_file "${BINARY}")" \
  --arg theyos_engine_sha256 "$(sha256_file "${STAGED_ENGINE}")" \
  --arg xcode_version "${XCODE_VERSION}" \
  --arg macos_sdk_version "${MACOS_SDK_VERSION}" \
  --argjson published_target "${PUBLISHED_TARGET}" \
  '{
    schema: $schema,
    source_sha: $source_sha,
    source_tree: $source_tree,
    target: $target,
    build_tool: $build_tool,
    build_tool_version: $build_tool_version,
    rustc: $rustc,
    cargo: $cargo,
    cargo_config_sha256: $cargo_config_sha256,
    cross_config_sha256: $cross_config_sha256,
    cargo_lock_sha256: $cargo_lock_sha256,
    cargo_workspace_sha256: $cargo_workspace_sha256,
    claws_manifest_sha256: $claws_manifest_sha256,
    core_build_rs_sha256: $core_build_rs_sha256,
    household_build_rs_sha256: $household_build_rs_sha256,
    emoji_wordlist_sha256: $emoji_wordlist_sha256,
    rust_toolchain_sha256: $rust_toolchain_sha256,
    server_manifest_sha256: $server_manifest_sha256,
    server_build_rs_sha256: $server_build_rs_sha256,
    boundary_manifest_sha256: $boundary_manifest_sha256,
    engine_build_tool_manifest_sha256: $engine_build_tool_manifest_sha256,
    engine_build_tool_source_sha256: $engine_build_tool_source_sha256,
    depfile_sha256: $depfile_sha256,
    server_sha256: $server_sha256,
    theyos_engine_sha256: $theyos_engine_sha256,
    xcode_version: $xcode_version,
    macos_sdk_version: $macos_sdk_version,
    published_target: $published_target,
    server_equals_theyos_engine: true,
    owner_present_authority: "none",
    phase: "phase0-compile-out",
    cargo_features: []
  }' > "${ATTESTATION_OUT}"

echo "Owner-present Phase 0 structural compile-out is closed for ${TARGET}."
echo "Phase 0 attestation: ${ATTESTATION_OUT}"
