#!/usr/bin/env bash
# Phase 0 authority: prove the published theyos-engine target excludes the
# owner-present issuer, mutable Mesh-C store, and relay authority.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
THEYOS_DIR="${1:-${DEFAULT_ROOT}}"
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
STAGE_REL="scripts/stage-theyos-engine.sh"
BUILD_REL="scripts/build-theyos-engine.sh"
BOUNDARY_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"

HEAD_SHA="$(git -C "${THEYOS_DIR}" rev-parse HEAD)"
HEAD_TREE="$(git -C "${THEYOS_DIR}" rev-parse "${HEAD_SHA}^{tree}")"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT
SNAPSHOT="${TMP_ROOT}/source"
TARGET_DIR="${PHASE0_CARGO_TARGET_DIR:-${SNAPSHOT}/admin/rust/target-phase0}"
mkdir -p "${SNAPSHOT}"

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
  local mode oid path entry expected count=0
  : > "${seen_paths}"

  while IFS=$'\t' read -r mode oid path; do
    [[ -z "${mode}" || "${mode}" == \#* ]] && continue
    if [[ ! "${mode}" =~ ^100(644|755)$ \
      || ! "${oid}" =~ ^[0-9a-f]{40}$ \
      || -z "${path}" \
      || "${path}" == /* \
      || "${path}" == *"../"* \
      || "${path}" == *$'\n'* ]]; then
      echo "::error file=${BOUNDARY_REL}::invalid signed Phase 0 boundary entry"
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
    expected="${mode}"$'\t'"blob"$'\t'"${oid}"
    if [[ "${entry}" != "${expected}" ]]; then
      echo "::error file=${path}::signed Phase 0 boundary object differs from ${BOUNDARY_REL}"
      exit 1
    fi
    count=$((count + 1))
  done < "${manifest}"

  if [[ "${count}" -ne 56 ]]; then
    echo "::error file=${BOUNDARY_REL}::signed Phase 0 boundary must contain exactly 56 objects"
    exit 1
  fi

  for path in \
    "admin/rust/server-rs/src/main.rs" \
    "admin/rust/server-rs/src/mobile_api_routes.rs" \
    "admin/rust/server-rs/src/mobile_claw_vpn_phase0.rs" \
    "admin/rust/server-rs/src/claw_share_relay_stream_mount.rs" \
    "admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs" \
    "admin/rust/server-rs/src/claw_share_relay_stream_runtime.rs" \
    "admin/rust/server-rs/src/claw_share_relay_stream_target_router.rs" \
    "admin/rust/server-rs/tests/claw_store_route_contract.rs" \
    "admin/rust/server-rs/tests/claw_store_wire_contract.rs" \
    "scripts/build-theyos-engine.sh" \
    "scripts/stage-theyos-engine.sh" \
    ".github/workflows/release-linux.yml" \
    ".github/workflows/release-macos.yml"; do
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
  "${FOUNDATION_REL}" \
  "${PHASE0_REL}" \
  "admin/contracts/mobile-claw-vpn/v1/api_shapes.json" \
  "claws/manifest.yml" \
  "${HISTORICAL_WIRE_REL}" \
  "${AUTHORITY_STATUS_REL}" \
  "${BOUNDARY_REL}"; do
  require_blob "${path}"
done
require_blob "${STAGE_REL}" 100755
require_blob "${BUILD_REL}" 100755

BOUNDARY_MANIFEST="${TMP_ROOT}/phase0-boundary.tsv"
git -C "${THEYOS_DIR}" cat-file blob "${HEAD_SHA}:${BOUNDARY_REL}" > "${BOUNDARY_MANIFEST}"
validate_boundary_manifest "${BOUNDARY_MANIFEST}"

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

git -C "${THEYOS_DIR}" archive --format=tar "${HEAD_SHA}" | tar -xf - -C "${SNAPSHOT}"

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
  || "$(jq -r '.phase0_artifact_boundary.sha256' "${AUTHORITY_STATUS}")" != \
    "$(sha256_file "${SNAPSHOT}/${BOUNDARY_REL}")" \
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

if rg -n \
  'pub (async )?fn handle_(admin_)?mobile_claw_vpn_(mint|consume|authorize|enroll|set|grant|revoke)' \
  "${SNAPSHOT}/admin/rust/server-rs/src" >/dev/null; then
  echo "::error::Phase 0 production source exports a retired Mobile Claw VPN effect handler"
  exit 1
fi

THEYOS_BUILD_GIT_SHA="${HEAD_SHA}" \
CARGO_TARGET_DIR="${TARGET_DIR}" \
  "${SNAPSHOT}/${BUILD_REL}" "${TARGET}" "${BUILD_TOOL}" >/dev/null

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

"${SNAPSHOT}/${STAGE_REL}" "${BINARY_DIR}" "${STAGED_ENGINE}"
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
    || "$(jq -r '.generic_ip_tunnel_backend_compiled' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.generic_ip_tunnel_store_accepts_resource' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.generic_ip_tunnel_env_accepts_resource' "${CONTRACT_JSON}")" != "false" \
    || "$(jq -r '.product_a_routes | length' "${CONTRACT_JSON}")" != "1" \
    || "$(jq -r '.product_a_routes[0]' "${CONTRACT_JSON}")" != \
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
mesh_c_owner_present_offer_control
RevalidatedCapability
ConsumedCapability
PointOfUsePermit
owner_approval_consumed
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
  --arg build_recipe_sha256 "$(sha256_file "${SNAPSHOT}/${BUILD_REL}")" \
  --arg stage_recipe_sha256 "$(sha256_file "${SNAPSHOT}/${STAGE_REL}")" \
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
    build_recipe_sha256: $build_recipe_sha256,
    stage_recipe_sha256: $stage_recipe_sha256,
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
