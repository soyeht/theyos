#!/usr/bin/env bash
# Phase 0 authority: prove the published theyos-engine target excludes the
# owner-present issuer, mutable Mesh-C store, and relay authority.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
THEYOS_DIR_INPUT="${1:-${DEFAULT_ROOT}}"
THEYOS_DIR="$(cd "${THEYOS_DIR_INPUT}" && pwd -P)"
BUILD_TOOL="${PHASE0_BUILD_TOOL:-cargo}"

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
cleanup() {
  if [[ -n "${CARGO_HOME_DIR:-}" && -e "${CARGO_HOME_DIR}" ]]; then
    chmod -R u+w "${CARGO_HOME_DIR}" 2>/dev/null || true
  fi
  chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

if [[ -n "$(git -C "${THEYOS_DIR}" status --porcelain --untracked-files=all)" ]]; then
  echo "::error::Phase 0 checker requires a clean checkout of the exact head object"
  exit 1
fi

SNAPSHOT_PARENT="${TMP_ROOT}/snapshot-parent"
SNAPSHOT="${SNAPSHOT_PARENT}/source"
mkdir -p "${SNAPSHOT}"
git -C "${THEYOS_DIR}" archive --format=tar "${HEAD_SHA}" \
  | tar -xf - -C "${SNAPSHOT}"
SNAPSHOT="$(cd "${SNAPSHOT}" && pwd -P)"
chmod -R a-w "${SNAPSHOT}"

# The authority build receives only the signed closed-input roots. The full
# ODB snapshot remains available for policy checks, but it is never mounted as
# the Cargo workspace, so an include!/build script cannot read an undeclared
# repository file and influence generated output.
BUILD_SOURCE_PARENT="${TMP_ROOT}/build-source-parent"
BUILD_SNAPSHOT="${BUILD_SOURCE_PARENT}/source"
mkdir -p "${BUILD_SNAPSHOT}"
git -C "${THEYOS_DIR}" archive --format=tar "${HEAD_SHA}" \
  admin/rust claws flake.lock flake.nix nix scripts \
  | tar -xf - -C "${BUILD_SNAPSHOT}"
BUILD_SNAPSHOT="$(cd "${BUILD_SNAPSHOT}" && pwd -P)"
chmod -R a-w "${BUILD_SNAPSHOT}"

# The musl authority build gets an OS-enforced read-only bind mount in the
# pinned OCI image. Native macOS authority builds use sandbox-exec to deny
# writes to the snapshot and Cargo/Rustup homes for every child process. A
# chmod/root-ownership check alone is deliberately not accepted as provenance.
if [[ "${BUILD_TOOL}" != "cross" ]]; then
  if [[ "$(uname -s)" != "Darwin" || ! -x /usr/bin/sandbox-exec ]]; then
    echo "::error::native Phase 0 authority requires the macOS sandbox-exec write boundary"
    exit 1
  fi
fi
TARGET_DIR="${PHASE0_CARGO_TARGET_DIR:-${TMP_ROOT}/target}"

if [[ -e "${TARGET_DIR}" && -n "$(find "${TARGET_DIR}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  echo "::error::canonical Cargo target directory must be empty before the authority build"
  exit 1
fi
mkdir -p "${TARGET_DIR}"
TARGET_DIR="$(cd "${TARGET_DIR}" && pwd -P)"
case "${TARGET_DIR}/" in
  "${SNAPSHOT}/"*)
    echo "::error::canonical Cargo target directory must be outside the ODB snapshot"
    exit 1
    ;;
  "${THEYOS_DIR}/"*)
    echo "::error::canonical Cargo target directory must be outside the mutable checkout"
    exit 1
    ;;
esac
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
  local expected_oid actual_oid
  expected_oid="$(git -C "${THEYOS_DIR}" ls-tree "${HEAD_SHA}" -- "${path}" | awk '{print $3}')"
  actual_oid="$(git -C "${THEYOS_DIR}" hash-object --no-filters "${SNAPSHOT}/${path}")"
  if [[ "${actual_oid}" != "${expected_oid}" ]]; then
    echo "::error file=${path}::ODB snapshot bytes differ from ${HEAD_SHA}"
    exit 1
  fi
}

verify_snapshot_matches_odb() {
  local verification_snapshot="${TMP_ROOT}/source-verification"
  rm -rf "${verification_snapshot}"
  mkdir -p "${verification_snapshot}"
  git -C "${THEYOS_DIR}" archive --format=tar "${HEAD_SHA}" \
    | tar -xf - -C "${verification_snapshot}"
  if ! diff -qr "${SNAPSHOT}" "${verification_snapshot}" >/dev/null; then
    echo "::error::build mutated the ODB-derived source snapshot"
    diff -qr "${SNAPSHOT}" "${verification_snapshot}" || true
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

resolve_executable() {
  local name="$1" resolved
  resolved="$(command -v "${name}" 2>/dev/null || true)"
  if [[ -z "${resolved}" || "${resolved}" != /* || ! -x "${resolved}" ]]; then
    echo "::error::canonical Phase 0 tool is unavailable as an absolute executable: ${name}"
    exit 1
  fi
  printf '%s/%s\n' \
    "$(cd "$(dirname "${resolved}")" && pwd -P)" \
    "$(basename "${resolved}")"
}

is_unsafe_parent_build_env() {
  local name="$1"
  case "${name}" in
    CARGO_TARGET_DIR|PKG_CONFIG_PATH|RUSTUP_TOOLCHAIN) return 1 ;;
    AR|BINDGEN_EXTRA_CLANG_ARGS|CC|CFLAGS|CPP|CPPFLAGS|CXX|CXXFLAGS|\
    DEVELOPER_DIR|DOCKER_OPTS|LD|LDFLAGS|MACOSX_DEPLOYMENT_TARGET|RANLIB|\
    RUSTFLAGS|RUSTDOCFLAGS|SDKROOT|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTDOC|\
    RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_*|CARGO_PROFILE_*|\
    CARGO_TARGET_*|CROSS_*|AR_*|CC_*|CFLAGS_*|CXX_*|CXXFLAGS_*|\
    LDFLAGS_*|PKG_CONFIG_*|*_AR|*_CC|*_CFLAGS|*_CXX|*_CXXFLAGS|*_LD|\
    *_LDFLAGS|*_RANLIB) return 0 ;;
    *) return 1 ;;
  esac
}

# Diagnostic fail-fast for known injection variables. The build authority is
# the positive environment below: every Cargo process starts under env -i and
# the Rust build helper clears its child environment again.
while IFS= read -r name; do
  if is_unsafe_parent_build_env "${name}" && [[ -n "${!name}" ]]; then
    echo "::error::${name} must be unset for the canonical theyos-engine build"
    exit 1
  fi
done < <(compgen -e)

SYSTEM_HOME="${HOME:?HOME is required to locate the pinned toolchain}"
CARGO_HOME_DIR="${PHASE0_CARGO_HOME:-${TMP_ROOT}/cargo-home/home}"
RUSTUP_HOME_DIR="${PHASE0_RUSTUP_HOME:-${SYSTEM_HOME}/.rustup}"
if [[ "${CARGO_HOME_DIR}" != /* || "${RUSTUP_HOME_DIR}" != /* ]]; then
  echo "::error::canonical Cargo and rustup homes must be absolute paths"
  exit 1
fi
case "${CARGO_HOME_DIR}/" in
  "${TARGET_DIR}/"*|"${THEYOS_DIR}/"*|"${SNAPSHOT}/"*)
    echo "::error::canonical Cargo home must be isolated from the target, checkout, and ODB snapshot"
    exit 1
    ;;
esac
for cargo_home_config in \
  "${CARGO_HOME_DIR}/config" \
  "${CARGO_HOME_DIR}/config.toml"; do
  if [[ -e "${cargo_home_config}" || -L "${cargo_home_config}" ]]; then
    echo "::error::canonical theyos-engine build forbids Cargo home config: ${cargo_home_config}"
    exit 1
  fi
done

ancestor_dir="$(dirname "${THEYOS_DIR}")"
while [[ "${ancestor_dir}" != "/" ]]; do
  for ancestor_config in \
    "${ancestor_dir}/.cargo/config" \
    "${ancestor_dir}/.cargo/config.toml"; do
    if [[ -e "${ancestor_config}" || -L "${ancestor_config}" ]]; then
      echo "::error::canonical theyos-engine build forbids Cargo config above the repository"
      exit 1
    fi
  done
  ancestor_dir="$(dirname "${ancestor_dir}")"
done

EXPECTED_RUST="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' \
  "${SNAPSHOT}/admin/rust/rust-toolchain.toml")"
if [[ -z "${EXPECTED_RUST}" ]]; then
  echo "::error::canonical Rust toolchain pin is missing"
  exit 1
fi

ENV_BIN="/usr/bin/env"
if [[ ! -x "${ENV_BIN}" ]]; then
  echo "::error::canonical environment launcher is unavailable: ${ENV_BIN}"
  exit 1
fi
CARGO_BIN="$(resolve_executable cargo)"
RUSTC_BIN="$(resolve_executable rustc)"
RUSTUP_BIN="$(resolve_executable rustup)"
if [[ "${BUILD_TOOL}" == "cross" ]]; then
  BUILD_TOOL_BIN="$(resolve_executable docker)"
else
  BUILD_TOOL_BIN="$(resolve_executable "${BUILD_TOOL}")"
fi
PYTHON_BIN="$(resolve_executable python3)"
CANONICAL_PATH="$(dirname "${RUSTC_BIN}"):$(dirname "${CARGO_BIN}"):$(dirname "${RUSTUP_BIN}"):$(dirname "${BUILD_TOOL_BIN}"):$(dirname "${PYTHON_BIN}"):/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
CLEAN_HOME="${TMP_ROOT}/home"
CLEAN_TMP="${TMP_ROOT}/tmp"
LOCAL_DOCKER_ENV=()
if [[ -n "${PHASE0_DOCKER_HOST:-}" ]]; then
  if [[ "${PHASE0_LOCAL_DIAGNOSTIC:-0}" != "1" \
    || "${PHASE0_DOCKER_HOST}" != unix:///* ]]; then
    echo "::error::DOCKER_HOST is forbidden; only an explicit local Unix-socket diagnostic override is accepted"
    exit 1
  fi
  LOCAL_DOCKER_ENV=("PHASE0_DOCKER_HOST=${PHASE0_DOCKER_HOST}")
fi
if [[ -e "${CARGO_HOME_DIR}" && -n "$(find "${CARGO_HOME_DIR}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  echo "::error::canonical Cargo home must be empty before the authority build"
  exit 1
fi
mkdir -p "${CLEAN_HOME}" "${CLEAN_TMP}" "${TARGET_DIR}"
mkdir -p "${CARGO_HOME_DIR}"
GENERATED_OUTPUT_DIR="${TARGET_DIR}/phase0-generated"
mkdir -p "${GENERATED_OUTPUT_DIR}"
if find "${CARGO_HOME_DIR}" -type l -print -quit 2>/dev/null | grep -q .; then
  echo "::error::canonical Cargo home may not contain symlinks"
  exit 1
fi

NATIVE_FETCH_SANDBOX="${TMP_ROOT}/native-fetch.sb"
NATIVE_BUILD_SANDBOX="${TMP_ROOT}/native-build.sb"
CARGO_HOME_PARENT="$(dirname "${CARGO_HOME_DIR}")"
if [[ "${BUILD_TOOL}" != "cross" ]]; then
  printf '%s\n' \
    '(version 1)' \
    '(allow default)' \
    "(deny file-write* (subpath \"${SNAPSHOT_PARENT}\"))" \
    "(deny file-write* (subpath \"${BUILD_SOURCE_PARENT}\"))" \
    "(deny file-write* (subpath \"${SNAPSHOT}\"))" \
    "(deny file-write* (subpath \"${THEYOS_DIR}\"))" \
    "(deny file-write* (subpath \"${SYSTEM_HOME}\"))" \
    > "${NATIVE_FETCH_SANDBOX}"
  printf '%s\n' \
    '(version 1)' \
    '(allow default)' \
    "(deny file-write* (subpath \"${SNAPSHOT_PARENT}\"))" \
    "(deny file-write* (subpath \"${BUILD_SOURCE_PARENT}\"))" \
    "(deny file-write* (subpath \"${SNAPSHOT}\"))" \
    "(deny file-write* (subpath \"${THEYOS_DIR}\"))" \
    "(deny file-write* (subpath \"${SYSTEM_HOME}\"))" \
    "(deny file-write* (subpath \"${CARGO_HOME_PARENT}\"))" \
    "(deny file-write* (subpath \"${CARGO_HOME_DIR}\"))" \
    "(deny file-write* (subpath \"${RUSTUP_HOME_DIR}\"))" \
    > "${NATIVE_BUILD_SANDBOX}"
fi

run_clean_online() {
  local sandbox_profile=""
  local -a sandbox_command=()
  local -a command_args=("$@")
  if [[ "${BUILD_TOOL}" != "cross" ]]; then
    sandbox_profile="${NATIVE_BUILD_SANDBOX}"
    if [[ "${PHASE0_CARGO_FETCH_PHASE:-0}" == "1" ]]; then
      sandbox_profile="${NATIVE_FETCH_SANDBOX}"
    fi
    sandbox_command=(/usr/bin/sandbox-exec -f "${sandbox_profile}")
  fi
  local -a clean_env=(
    HOME="${CLEAN_HOME}" \
    CARGO_HOME="${CARGO_HOME_DIR}" \
    RUSTUP_HOME="${RUSTUP_HOME_DIR}" \
    TMPDIR="${CLEAN_TMP}" \
    PATH="${CANONICAL_PATH}" \
    LC_ALL=C \
    LANG=C \
    RUSTUP_TOOLCHAIN="${EXPECTED_RUST}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    PHASE0_BUILD_SOURCE_ROOT="${BUILD_SNAPSHOT}" \
    CLAWS_MANIFEST_YML="${SNAPSHOT}/claws/manifest.yml" \
    CLAWS_CATALOG_JSON="${GENERATED_OUTPUT_DIR}/claws-catalog.json" \
    THEYOS_EMOJI_WORDLIST="${SNAPSHOT}/admin/rust/household-rs/data/emoji-security-code-wordlist.csv" \
    THEYOS_PHASE0_CLEAN_ENV=1
  )
  while (( ${#command_args[@]} > 0 )) && [[ "${command_args[0]}" == *=* ]]; do
    clean_env+=("${command_args[0]}")
    command_args=("${command_args[@]:1}")
  done
  if (( ${#LOCAL_DOCKER_ENV[@]} > 0 )); then
    clean_env+=("${LOCAL_DOCKER_ENV[@]}")
  fi
  if [[ "${PHASE0_TARGET:-${TARGET:-}}" == *-apple-darwin \
    && -n "${EXPECTED_DEVELOPER_DIR:-}" ]]; then
    clean_env+=("DEVELOPER_DIR=${EXPECTED_DEVELOPER_DIR}")
  fi
  if (( ${#sandbox_command[@]} > 0 )); then
    "${ENV_BIN}" -i "${clean_env[@]}" "${sandbox_command[@]}" "${command_args[@]}"
  else
    "${ENV_BIN}" -i "${clean_env[@]}" "${command_args[@]}"
  fi
}

run_clean() {
  run_clean_online CARGO_NET_OFFLINE=true "$@"
}

RUSTC_VERBOSE="$(cd "${SNAPSHOT}/admin/rust" && run_clean_online "${RUSTC_BIN}" -vV)"
ACTUAL_RUST="$(printf '%s\n' "${RUSTC_VERBOSE}" | sed -n 's/^release: //p')"
RUSTC_HOST="$(printf '%s\n' "${RUSTC_VERBOSE}" | sed -n 's/^host: //p')"
if [[ -z "${EXPECTED_RUST}" || "${ACTUAL_RUST}" != "${EXPECTED_RUST}" ]]; then
  echo "::error::canonical theyos-engine build requires the pinned Rust toolchain"
  exit 1
fi
HOST_TARGET="${RUSTC_HOST}"
TARGET="${PHASE0_TARGET:-${HOST_TARGET}}"
PUBLISHED_TARGET=true
RUSTC_TOOLCHAIN_BIN="$(run_clean "${RUSTUP_BIN}" which rustc)"
CARGO_TOOLCHAIN_BIN="$(run_clean "${RUSTUP_BIN}" which cargo)"
for toolchain_binary in "${RUSTC_TOOLCHAIN_BIN}" "${CARGO_TOOLCHAIN_BIN}"; do
  if [[ ! -f "${toolchain_binary}" || -L "${toolchain_binary}" ]]; then
    echo "::error::rustup resolved a non-regular toolchain executable"
    exit 1
  fi
done
RUSTC_TOOLCHAIN_SHA256="$(sha256_file "${RUSTC_TOOLCHAIN_BIN}")"
CARGO_TOOLCHAIN_SHA256="$(sha256_file "${CARGO_TOOLCHAIN_BIN}")"

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

XCODE_VERSION=""
XCODE_BUILD=""
MACOS_SDK_VERSION=""
MACOS_SDK_PATH=""
EXPECTED_XCODE_VERSION="${PHASE0_EXPECTED_XCODE_VERSION:-}"
EXPECTED_XCODE_BUILD="${PHASE0_EXPECTED_XCODE_BUILD:-}"
EXPECTED_MACOS_SDK_VERSION="${PHASE0_EXPECTED_MACOS_SDK_VERSION:-}"
EXPECTED_DEVELOPER_DIR="${PHASE0_EXPECTED_DEVELOPER_DIR:-}"
if [[ "${TARGET}" == *-apple-darwin ]]; then
  if [[ -z "${EXPECTED_XCODE_VERSION}" || -z "${EXPECTED_XCODE_BUILD}" \
    || -z "${EXPECTED_MACOS_SDK_VERSION}" || -z "${EXPECTED_DEVELOPER_DIR}" \
    || "${EXPECTED_DEVELOPER_DIR}" != /* ]]; then
    echo "::error::macOS Phase 0 authority requires frozen Xcode and SDK identities"
    exit 1
  fi
  if [[ ! -d "${EXPECTED_DEVELOPER_DIR}" ]]; then
    echo "::error::frozen DEVELOPER_DIR does not exist: ${EXPECTED_DEVELOPER_DIR}"
    exit 1
  fi
  selected_developer_dir="$(DEVELOPER_DIR="${EXPECTED_DEVELOPER_DIR}" xcode-select -p)"
  if [[ "${selected_developer_dir}" != "${EXPECTED_DEVELOPER_DIR}" ]]; then
    echo "::error::xcode-select did not resolve the frozen DEVELOPER_DIR"
    exit 1
  fi
  XCODE_VERSION="$(DEVELOPER_DIR="${EXPECTED_DEVELOPER_DIR}" xcodebuild -version)"
  XCODE_BUILD="$(printf '%s\n' "${XCODE_VERSION}" | sed -n 's/^Build version //p')"
  XCODE_VERSION="$(printf '%s\n' "${XCODE_VERSION}" | sed -n 's/^Xcode //p')"
  MACOS_SDK_PATH="$(DEVELOPER_DIR="${EXPECTED_DEVELOPER_DIR}" xcrun --sdk macosx --show-sdk-path)"
  MACOS_SDK_VERSION="$(DEVELOPER_DIR="${EXPECTED_DEVELOPER_DIR}" xcrun --sdk macosx --show-sdk-version)"
  expected_sdk_path="${EXPECTED_DEVELOPER_DIR}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX${EXPECTED_MACOS_SDK_VERSION}.sdk"
  if [[ "${XCODE_VERSION}" != "${EXPECTED_XCODE_VERSION}" \
    || "${XCODE_BUILD}" != "${EXPECTED_XCODE_BUILD}" \
    || "${MACOS_SDK_VERSION}" != "${EXPECTED_MACOS_SDK_VERSION}" \
    || "${MACOS_SDK_PATH}" != "${expected_sdk_path}" ]]; then
    echo "::error::macOS Phase 0 toolchain identity differs from the frozen Xcode/SDK policy"
    echo "::error::expected Xcode=${EXPECTED_XCODE_VERSION} build=${EXPECTED_XCODE_BUILD} SDK=${EXPECTED_MACOS_SDK_VERSION}"
    echo "::error::actual Xcode=${XCODE_VERSION} build=${XCODE_BUILD} SDK=${MACOS_SDK_VERSION}"
    echo "::error::expected SDK path=${expected_sdk_path} actual=${MACOS_SDK_PATH}"
    exit 1
  fi
fi

TRACKED_PKG_CONFIG_PATH="$(sed -n \
  's/^PKG_CONFIG_PATH = "\([^"]*\)"/\1/p' \
  "${SNAPSHOT}/admin/rust/.cargo/config.toml")"
if ! grep -Fq 'PKG_CONFIG_PATH = ""' "${SNAPSHOT}/admin/rust/.cargo/config.toml"; then
  echo "::error::frozen workspace Cargo config must leave PKG_CONFIG_PATH empty"
  exit 1
fi

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

  if [[ "${count}" -ne 6 ]]; then
    echo "::error file=${BOUNDARY_REL}::signed Phase 0 boundary must contain exactly six closed inputs"
    exit 1
  fi

  for path in \
    "admin/rust" \
    "claws" \
    "flake.lock" \
    "flake.nix" \
    "nix" \
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
  "admin/rust/clippy.toml" \
  "admin/rust/household-rs/Cargo.toml" \
  "admin/rust/household-rs/build.rs" \
  "admin/rust/household-rs/data/emoji-security-code-wordlist.csv" \
  "admin/rust/household-rs/src/lib.rs" \
  "admin/rust/core-rs/build.rs" \
  "admin/rust/server-rs/Cargo.toml" \
  "admin/rust/server-rs/build.rs" \
  "admin/rust/server-rs/src/lib.rs" \
  "admin/rust/server-rs/src/main.rs" \
  "admin/rust/server-rs/src/production_app.rs" \
  "admin/rust/server-rs/src/mobile_api_routes.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_mount.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_runtime.rs" \
  "admin/rust/server-rs/src/claw_share_relay_stream_target_router.rs" \
  "admin/rust/server-rs/src/claw_store_routes.rs" \
  "admin/rust/server-rs/src/state.rs" \
  "admin/rust/server-rs/src/handlers_mobile.rs" \
  "admin/rust/core-rs/src/product_a_phase0.rs" \
  "flake.lock" \
  "flake.nix" \
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

for prohibited_config in \
  ".cargo/config" \
  ".cargo/config.toml" \
  "admin/.cargo/config" \
  "admin/.cargo/config.toml" \
  "admin/rust/.cargo/config"; do
  if git -C "${THEYOS_DIR}" cat-file -e \
      "${HEAD_SHA}:${prohibited_config}" 2>/dev/null; then
    echo "::error::canonical theyos-engine build forbids ancestor Cargo config: ${prohibited_config}"
    exit 1
  fi
done

if git -C "${THEYOS_DIR}" cat-file -e \
    "${HEAD_SHA}:admin/rust/theyos-engine-build-rs/build.rs" 2>/dev/null; then
  echo "::error::the canonical engine build tool must not have a build.rs codegen seam"
  exit 1
fi

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

CANONICAL_REGISTRY_SOURCE="registry+https://github.com/rust-lang/crates.io-index"
TRACKED_RUST_PATHS="${TMP_ROOT}/tracked-rust-paths.nul"
git -C "${THEYOS_DIR}" ls-tree -r -z --name-only "${HEAD_SHA}" -- admin/rust \
  > "${TRACKED_RUST_PATHS}"
if ! run_clean_online "${PYTHON_BIN}" - \
    "${SNAPSHOT}" \
    "${TRACKED_RUST_PATHS}" \
    "${CANONICAL_REGISTRY_SOURCE}" \
    "${TRACKED_PKG_CONFIG_PATH}" <<'PY'; then
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
tracked = pathlib.Path(sys.argv[2]).read_bytes().split(b"\0")
canonical_registry = sys.argv[3]
canonical_pkg_config = sys.argv[4]
manifests = sorted(
    relative.decode("utf-8")
    for relative in tracked
    if relative and relative.endswith(b"/Cargo.toml")
)
if not manifests:
    print("::error::Phase 0 Cargo manifest set is empty", file=sys.stderr)
    raise SystemExit(1)

with (root / "admin/rust/Cargo.lock").open("rb") as stream:
    lock = tomllib.load(stream)
for package in lock.get("package", []):
    source = package.get("source")
    if source is not None and source != canonical_registry:
        print(
            "::error file=admin/rust/Cargo.lock::Phase 0 forbids "
            f"non-canonical Cargo source: {source}",
            file=sys.stderr,
        )
        raise SystemExit(1)

with (root / "admin/rust/.cargo/config.toml").open("rb") as stream:
    cargo_config = tomllib.load(stream)
expected_cargo_config = {"env": {"PKG_CONFIG_PATH": canonical_pkg_config}}
if cargo_config != expected_cargo_config:
    print(
        "::error file=admin/rust/.cargo/config.toml::Phase 0 permits only the "
        "frozen PKG_CONFIG_PATH Cargo environment entry",
        file=sys.stderr,
    )
    raise SystemExit(1)

with (root / "admin/rust/Cross.toml").open("rb") as stream:
    cross_config = tomllib.load(stream)
if cross_config.get("build", {}).get("pre-build") != []:
    print(
        "::error file=admin/rust/Cross.toml::Phase 0 forbids Cross pre-build commands",
        file=sys.stderr,
    )
    raise SystemExit(1)
expected_images = {
    "x86_64-unknown-linux-musl":
        "ghcr.io/cross-rs/x86_64-unknown-linux-musl:0.2.5@sha256:"
        "77db671d8356a64ae72a3e1415e63f547f26d374fbe3c4762c1cd36c7eac7b99",
    "aarch64-unknown-linux-musl":
        "ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5@sha256:"
        "702154f52b2d8091671aa2c84d5582d849f949977228c735ff8462f93cc0e1e4",
}
targets = cross_config.get("target", {})
for target, image in expected_images.items():
    if targets.get(target) != {"image": image}:
        print(
            f"::error file=admin/rust/Cross.toml::Phase 0 cross target is not "
            f"an exact immutable image-only recipe: {target}",
            file=sys.stderr,
        )
        raise SystemExit(1)

for relative in manifests:
    path = root / relative
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    forbidden = sorted({"patch", "replace"}.intersection(document))
    if forbidden:
        print(
            f"::error file={relative}::Phase 0 forbids Cargo override table(s): "
            + ", ".join(forbidden),
            file=sys.stderr,
        )
        raise SystemExit(1)
PY
  echo "::error::Phase 0 Cargo source preflight failed"
  exit 1
fi

# Fetch only after the lockfile and manifests prove that no git/alternate
# source can be contacted. Every subsequent Cargo operation is offline.
PHASE0_CARGO_FETCH_PHASE=1 run_clean_online "${CARGO_BIN}" fetch \
  --manifest-path "${SNAPSHOT}/admin/rust/Cargo.toml" \
  --locked \
  --quiet
if find "${CARGO_HOME_DIR}" -type l -print -quit 2>/dev/null | grep -q .; then
  echo "::error::Cargo fetch created a symlink in the authority Cargo home"
  exit 1
fi
chmod -R a-w "${CARGO_HOME_DIR}"

METADATA_JSON="${TMP_ROOT}/cargo-metadata.json"
run_clean "${CARGO_BIN}" metadata \
  --manifest-path "${SNAPSHOT}/admin/rust/Cargo.toml" \
  --locked \
  --offline \
  --format-version 1 \
  > "${METADATA_JSON}"
if ! jq -e \
  --arg root "${SNAPSHOT}/admin/rust" \
  --arg registry "${CANONICAL_REGISTRY_SOURCE}" '
    .version == 1
    and .workspace_root == $root
    and (.packages | type == "array" and length > 0)
    and all(.packages[];
      has("source")
      and (.source == null or .source == $registry)
      and (.manifest_path | type == "string" and (contains("\n") | not))
      and (.targets | type == "array")
      and all(.targets[];
        (.kind | type == "array")
        and (.src_path | type == "string" and (contains("\n") | not)))
    )
    and all(.packages[] | select(.source == null) | .dependencies[];
      has("source")
      and (if .source == null
        then ((.path | type == "string") and .registry == null)
        else (.source == $registry and .path == null and .registry == null)
      end)
    )
  ' "${METADATA_JSON}" >/dev/null; then
  echo "::error::Cargo metadata contains an unapproved source or multiline path"
  exit 1
fi
while IFS= read -r manifest_path; do
  canonical_manifest="$(cd "$(dirname "${manifest_path}")" && pwd -P)/$(basename "${manifest_path}")"
  case "${canonical_manifest}" in
    "${SNAPSHOT}/admin/rust/"*) ;;
    *)
      echo "::error file=${manifest_path}::local Cargo dependency escapes the closed admin/rust tree"
      exit 1
      ;;
  esac
  manifest_rel="${canonical_manifest#"${SNAPSHOT}/"}"
  require_blob "${manifest_rel}"
done < <(jq -r '.packages[] | select(.source == null) | .manifest_path' "${METADATA_JSON}")

while IFS= read -r dependency_path; do
  canonical_dependency="$(cd "${dependency_path}" && pwd -P)"
  case "${canonical_dependency}/" in
    "${SNAPSHOT}/admin/rust/"*) ;;
    *)
      echo "::error file=${dependency_path}::local Cargo dependency path escapes the closed admin/rust tree"
      exit 1
      ;;
  esac
done < <(jq -r '
  .packages[]
  | select(.source == null)
  | .dependencies[]
  | select(.source == null)
  | .path
' "${METADATA_JSON}")

while IFS= read -r target_path; do
  canonical_target="$(cd "$(dirname "${target_path}")" && pwd -P)/$(basename "${target_path}")"
  case "${canonical_target}" in
    "${SNAPSHOT}/admin/rust/"*) ;;
    *)
      echo "::error file=${target_path}::local Cargo target source escapes the closed admin/rust tree"
      exit 1
      ;;
  esac
  target_rel="${canonical_target#"${SNAPSHOT}/"}"
  require_blob "${target_rel}"
done < <(jq -r '.packages[] | select(.source == null) | .targets[].src_path' "${METADATA_JSON}")

ACTUAL_CUSTOM_BUILDS="${TMP_ROOT}/actual-custom-builds.txt"
jq -r '
  .packages[]
  | select(.source == null)
  | .targets[]
  | select(.kind | index("custom-build"))
  | .src_path
' "${METADATA_JSON}" \
  | while IFS= read -r custom_build; do
      canonical_build="$(cd "$(dirname "${custom_build}")" && pwd -P)/$(basename "${custom_build}")"
      printf '%s\n' "${canonical_build#"${SNAPSHOT}/"}"
    done \
  | LC_ALL=C sort > "${ACTUAL_CUSTOM_BUILDS}"
if ! cmp -s "${EXPECTED_BUILD_SCRIPTS}" "${ACTUAL_CUSTOM_BUILDS}"; then
  echo "::error::Cargo metadata custom-build targets differ from the three reviewed build scripts"
  exit 1
fi

ACTUAL_LOCAL_PROC_MACROS="${TMP_ROOT}/actual-local-proc-macros.txt"
jq -r '
  .packages[]
  | select(.source == null)
  | .targets[]
  | select(.kind | index("proc-macro"))
  | .src_path
' "${METADATA_JSON}" > "${ACTUAL_LOCAL_PROC_MACROS}"
if [[ -s "${ACTUAL_LOCAL_PROC_MACROS}" ]]; then
  echo "::error::Phase 0 forbids local proc-macro codegen targets"
  exit 1
fi

BOUNDARY_MANIFEST="${TMP_ROOT}/phase0-boundary.tsv"
git -C "${THEYOS_DIR}" cat-file blob "${HEAD_SHA}:${BOUNDARY_REL}" > "${BOUNDARY_MANIFEST}"
validate_boundary_manifest "${BOUNDARY_MANIFEST}"

if [[ "$(grep -Fc 'server_rs::production_app::compose(&state, &cfg)' \
      "${SNAPSHOT}/admin/rust/server-rs/src/main.rs")" -ne 1 \
  || "$(grep -Fc 'mobile_claw_vpn_phase0::close_production_app(app)' \
      "${SNAPSHOT}/admin/rust/server-rs/src/production_app.rs")" -ne 1 ]]; then
  echo "::error::production server must use the single Phase 0-closed complete app composer"
  exit 1
fi
CLIPPY_ALLOW_FILE="${SNAPSHOT}/admin/rust/core-rs/src/product_a_phase0.rs"
if [[ "$(grep -Fc '#[allow(clippy::disallowed_methods)]' "${CLIPPY_ALLOW_FILE}")" -ne 2 ]] \
  || grep -RIl --include='*.rs' '#\[allow(clippy::disallowed_methods)\]' \
       "${SNAPSHOT}/admin/rust" \
       | grep -Fvqx -- "${CLIPPY_ALLOW_FILE}"; then
  echo "::error::only the two reviewed Phase 0 wrapper sites may allow disallowed HTTP methods"
  exit 1
fi
if ! awk '
  /#\[allow\(clippy::disallowed_methods\)\]/ { pending = 1; next }
  pending && /pub fn serve</ { serve += 1; pending = 0; next }
  pending && /pub fn serve_with_connect_info</ { connect = 1; pending = 0; next }
  pending && NF { pending = 0 }
  END { exit !(serve == 1 && connect == 1) }
' "${CLIPPY_ALLOW_FILE}"; then
  echo "::error::Phase 0 disallowed-method allowances must be adjacent to the two reviewed wrapper functions"
  exit 1
fi
expected_clippy_methods=$(printf '%s\n' \
  'axum::serve' \
  'hyper::server::conn::http1::Builder::serve_connection' \
  'hyper::server::conn::http2::Builder::serve_connection' \
  'hyper_util::server::conn::auto::Builder::serve_connection' \
  'hyper_util::server::conn::auto::Builder::serve_connection_with_upgrades')
actual_clippy_methods="$({
  sed -n '/^disallowed-methods[[:space:]]*=[[:space:]]*\[/,/^\]/p' \
    "${SNAPSHOT}/admin/rust/clippy.toml"
} | sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*$/\1/p')"
if [[ "${actual_clippy_methods}" != "${expected_clippy_methods}" ]]; then
  echo "::error file=admin/rust/clippy.toml::disallowed-method policy differs from the reviewed exact set"
  exit 1
fi
for forbidden_serve_method in \
  'axum::serve' \
  'hyper::server::conn::http1::Builder::serve_connection' \
  'hyper::server::conn::http2::Builder::serve_connection' \
  'hyper_util::server::conn::auto::Builder::serve_connection' \
  'hyper_util::server::conn::auto::Builder::serve_connection_with_upgrades'; do
  if ! grep -Fq -- "${forbidden_serve_method}" "${SNAPSHOT}/admin/rust/clippy.toml"; then
    echo "::error::clippy disallowed-method policy is missing ${forbidden_serve_method}"
    exit 1
  fi
done
for listener_source in \
  "admin/rust/server-rs/src/main.rs" \
  "admin/rust/server-rs/src/household_listener.rs" \
  "admin/rust/server-rs/src/macos_local_registration_listener.rs" \
  "admin/rust/server-rs/src/install_cli.rs" \
  "admin/rust/llm-proxy-rs/src/bin/theyos-llm-proxy.rs" \
  "admin/rust/server-rs/src/bin/relay_stream_public_relay.rs"; do
  if [[ "$(grep -Fc 'core_rs::phase0_axum_serve!' "${SNAPSHOT}/${listener_source}")" -ne 1 ]]; then
    echo "::error file=${listener_source}::published HTTP listener must use the Phase 0 serve choke-point"
    exit 1
  fi
done

run_clean "${CARGO_BIN}" test \
  --manifest-path "${SNAPSHOT}/admin/rust/Cargo.toml" \
  --locked \
  --offline \
  --package server-rs \
  --test claw_store_wire_contract \
  --no-default-features \
  mobile_claw_vpn_phase0_ \
  -- \
  --test-threads=1 \
  >/dev/null

(
  cd "${SNAPSHOT}/admin/rust"
  run_clean "${CARGO_BIN}" clippy \
    --locked \
    --offline \
    --package server-rs \
    --bin server \
    --package llm-proxy-rs \
    --bin theyos-llm-proxy \
    -- -D warnings -D clippy::disallowed_methods
)

RELEASE_CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
if [[ "$(grep -Fc "${RELEASE_CHECKER_REL}" "${SNAPSHOT}/.github/workflows/release-linux.yml")" -ne 2 \
  || "$(grep -Fc "${RELEASE_CHECKER_REL}" "${SNAPSHOT}/.github/workflows/release-macos.yml")" -ne 1 ]]; then
  echo "::error::every theyos-engine release target must run the Phase 0 checker on its own subject"
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
  || ! grep -Fq "published_executables_sha256" \
    "${SNAPSHOT}/.github/workflows/release-linux.yml" \
  || ! grep -Fq "published_signed_engine_sha256" \
    "${SNAPSHOT}/.github/workflows/release-macos.yml" \
  || ! grep -Fq "PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256" \
    "${SNAPSHOT}/scripts/make.sh"; then
  echo "::error::release provenance does not bind the verified engine to the published package"
  exit 1
fi
for release_subject_binding in \
  'PHASE0_UNSIGNED_STAGE_DIR' \
  'PHASE0_EXPECTED_UNSIGNED_PACKAGE_MANIFEST_SHA256' \
  'no Cargo/build scripts in release packaging'; do
  if ! grep -Fq -- "${release_subject_binding}" "${SNAPSHOT}/scripts/make.sh"; then
    echo "::error::macOS app packaging is missing the unsigned-subject-only binding: ${release_subject_binding}"
    exit 1
  fi
done
release_macos_signing_job="$(sed -n '/^  sign-and-publish-macos:/,/^  update-homebrew-formula:/p' \
  "${SNAPSHOT}/.github/workflows/release-macos.yml")"
if grep -Eq 'actions/checkout@|cargo[[:space:]]|run_engine_build_tool|scripts/make\.sh' \
    <<< "${release_macos_signing_job}"; then
  echo "::error::macOS signing job must consume only the unsigned subject and never checkout or compile source"
  exit 1
fi
for mac_toolchain_file in \
  "${SNAPSHOT}/.github/workflows/owner-present-phase0-compileout.yml" \
  "${SNAPSHOT}/.github/workflows/release-macos.yml"; do
  for mac_toolchain_pin in \
    'PHASE0_EXPECTED_XCODE_VERSION: "16.4"' \
    'PHASE0_EXPECTED_XCODE_BUILD: "16F6"' \
    'PHASE0_EXPECTED_MACOS_SDK_VERSION: "15.5"'; do
    if ! grep -Fq -- "${mac_toolchain_pin}" "${mac_toolchain_file}"; then
      echo "::error file=${mac_toolchain_file}::frozen Xcode/SDK identity is missing"
      exit 1
    fi
  done
done
for nix_binding in \
  '.#theyos-runtime' \
  'nix path-info --recursive --json' \
  'nix flake archive --json' \
  '--offline --no-link --no-write-lock-file' \
  'phase0-nix-store-closure.json' \
  'phase0-nix-input-closure.json' \
  'nix_input_closure_manifest_sha256' \
  'nix_build_offline' \
  'nix_substituters_closed' \
  'flake_lock_sha256' \
  '--no-default-features' \
  'third_target_injection_seam_compiled'; do
  if ! grep -Fq -- "${nix_binding}" "${SNAPSHOT}/.github/workflows/owner-present-phase0-nix-runtime.yml" \
    && ! grep -Fq -- "${nix_binding}" "${SNAPSHOT}/nix/packages/rust-workspace.nix"; then
    echo "::error::Nix runtime Phase 0 binding is missing: ${nix_binding}"
    exit 1
  fi
done
if ! grep -Fq 'phase0-helper-depfile-and-marker-closure-v1' \
    "${SNAPSHOT}/nix/packages/rust-workspace.nix"; then
  echo "::error::Nix helper outputs must carry a depfile/source closure classification"
  exit 1
fi
if grep -Eq 'permissions:|id-token: write|attestations: write' \
    "${SNAPSHOT}/.github/workflows/owner-present-phase0-nix-runtime.yml" \
  && ! grep -Fq 'if: github.event_name == '\''push'\''' \
    "${SNAPSHOT}/.github/workflows/owner-present-phase0-nix-runtime.yml"; then
  echo "::error::Nix attestation credentials must be isolated to a push-only job"
  exit 1
fi
KNOWN_WORKFLOWS="${TMP_ROOT}/known-workflows.txt"
ACTUAL_WORKFLOWS="${TMP_ROOT}/actual-workflows.txt"
printf '%s\n' \
  backend-ci.yml \
  claw-store-contract-ci.yml \
  contracts-cross-repo-sync.yml \
  frontend-ci.yml \
  homebrew-smoke-macos.yml \
  owner-present-phase0-compileout.yml \
  owner-present-phase0-integrity.yml \
  owner-present-phase0-nix-runtime.yml \
  release-linux.yml \
  release-macos.yml \
  | LC_ALL=C sort > "${KNOWN_WORKFLOWS}"
find "${SNAPSHOT}/.github/workflows" -maxdepth 1 -type f \
  \( -name '*.yml' -o -name '*.yaml' \) -exec basename {} \; \
  | LC_ALL=C sort > "${ACTUAL_WORKFLOWS}"
if ! cmp -s "${KNOWN_WORKFLOWS}" "${ACTUAL_WORKFLOWS}"; then
  echo "::error::.github/workflows contains an unclassified publisher or attestation workflow"
  diff -u "${KNOWN_WORKFLOWS}" "${ACTUAL_WORKFLOWS}" || true
  exit 1
fi
while IFS= read -r workflow_path; do
  workflow_name="$(basename "${workflow_path}")"
  if grep -Eq 'contents:[[:space:]]*write|actions/attest-build-provenance@|secrets\.APPLE_' \
      "${workflow_path}" \
    && [[ "${workflow_name}" != "release-linux.yml" \
      && "${workflow_name}" != "release-macos.yml" \
      && "${workflow_name}" != "owner-present-phase0-compileout.yml" \
      && "${workflow_name}" != "owner-present-phase0-nix-runtime.yml" ]]; then
    echo "::error file=.github/workflows/${workflow_name}::unclassified workflow can publish, attest, or consume release credentials"
    exit 1
  fi
done < <(find "${SNAPSHOT}/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print)
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
    "closed-git-inputs-v2" \
  || "$(jq -r '.phase0_artifact_boundary.policy_change_control' "${AUTHORITY_STATUS}")" != \
    "explicit-owner-approved-versioned-transition" \
  || "$(jq -r '.phase0_artifact_boundary.object_identity_update' "${AUTHORITY_STATUS}")" != \
    "per-reviewed-commit-revalidation" \
  || "$(jq -r '.phase0_artifact_boundary.object_identity_authority' "${AUTHORITY_STATUS}")" != \
    "commit-bound-evidence-not-independent-approval" \
  || "$(jq -r '.phase0_artifact_boundary.release_provenance' "${AUTHORITY_STATUS}")" != \
    "checker-on-release-subject-and-final-package-attestation" \
  || "$(jq -r '.phase0_artifact_boundary.staged_products | sort | join(",")' "${AUTHORITY_STATUS}")" != \
    "nix-theyos-runtime,theyos-engine,theyos-llm-proxy" \
  || "$(jq -r '.phase0_artifact_boundary.required_published_targets | sort | join(",")' "${AUTHORITY_STATUS}")" != \
    "aarch64-apple-darwin,aarch64-unknown-linux-musl,nix-theyos-runtime-x86_64-linux,x86_64-unknown-linux-musl" \
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
  run_clean \
    THEYOS_BUILD_GIT_SHA="${HEAD_SHA}" \
    "${CARGO_BIN}" run \
      --manifest-path Cargo.toml \
      --locked \
      --offline \
      --release \
      --package theyos-engine-build-rs \
      -- build "${TARGET}" "${BUILD_TOOL}" >/dev/null
)
verify_snapshot_matches_odb

BINARY_DIR="${TARGET_DIR}/${TARGET}/release"
BINARY="${BINARY_DIR}/server"
DEPFILE="${BINARY_DIR}/server.d"
PROXY_BINARY="${BINARY_DIR}/theyos-llm-proxy"
PROXY_DEPFILE="${BINARY_DIR}/theyos-llm-proxy.d"
STAGED_ENGINE="${PHASE0_STAGED_ENGINE_OUT:-${TMP_ROOT}/theyos-engine}"
if [[ ! -x "${BINARY}" ]]; then
  echo "::error::release server binary was not produced for ${TARGET}"
  exit 1
fi
if [[ ! -f "${DEPFILE}" ]]; then
  echo "::error::release server dependency graph was not produced for ${TARGET}"
  exit 1
fi
if [[ ! -x "${PROXY_BINARY}" || ! -f "${PROXY_DEPFILE}" ]]; then
  echo "::error::release theyos-llm-proxy binary and depfile were not produced for ${TARGET}"
  exit 1
fi
if [[ "${TARGET}" == *-apple-darwin ]]; then
  PUBLISHED_HELPERS=(vmrunner_macos_ipc store-ipc terminal-ipc theyos-ssh theyos-provision-inject)
else
  PUBLISHED_HELPERS=(soyeht vmrunner_ipc fc-ssh store-ipc terminal-ipc imagebuilder)
fi
DEPFILES=("${DEPFILE}" "${PROXY_DEPFILE}")
for helper in "${PUBLISHED_HELPERS[@]}"; do
  if [[ ! -x "${BINARY_DIR}/${helper}" || ! -f "${BINARY_DIR}/${helper}.d" ]]; then
    echo "::error::published helper and depfile are missing for ${TARGET}: ${helper}"
    exit 1
  fi
  DEPFILES+=("${BINARY_DIR}/${helper}.d")
done

(
  cd "${SNAPSHOT}/admin/rust"
  run_clean "${CARGO_BIN}" run \
    --manifest-path Cargo.toml \
    --locked \
    --offline \
    --release \
    --package theyos-engine-build-rs \
    -- stage "${BINARY_DIR}" "${STAGED_ENGINE}"
)
if ! cmp -s "${BINARY}" "${STAGED_ENGINE}"; then
  echo "::error::staged theyos-engine is not byte-identical to server-rs/server"
  exit 1
fi
verify_snapshot_matches_odb

REPO_DEP_INPUTS="${TMP_ROOT}/repo-dep-inputs.nul"
if ! run_clean "${PYTHON_BIN}" - \
    "${SNAPSHOT}" \
    "${BUILD_SNAPSHOT}" \
    "${TARGET_DIR}" \
    "${CARGO_HOME_DIR}" \
    "${RUSTUP_HOME_DIR}" \
    "${DEPFILES[@]}" > "${REPO_DEP_INPUTS}" <<'PY'; then
import os
import pathlib
import sys

snapshot = pathlib.Path(sys.argv[1]).resolve()
build_snapshot = pathlib.Path(sys.argv[2]).resolve()
target_dir = pathlib.Path(sys.argv[3]).resolve()
cargo_home = pathlib.Path(sys.argv[4]).resolve()
rustup_home = pathlib.Path(sys.argv[5]).resolve()
depfiles = [pathlib.Path(value) for value in sys.argv[6:]]

def relative_to(path, root):
    try:
        return path.relative_to(root)
    except ValueError:
        return None

def depfile_tokens(depfile):
    data = depfile.read_bytes().replace(b"\\\r\n", b"").replace(b"\\\n", b"")
    escaped = False
    separator = None
    for index, byte in enumerate(data):
        if escaped:
            escaped = False
        elif byte == 0x5C:
            escaped = True
        elif byte == 0x3A:
            separator = index
            break
    if separator is None:
        print(f"::error::Rust depfile has no target separator: {depfile}", file=sys.stderr)
        raise SystemExit(1)
    tokens = []
    token = bytearray()
    escaped = False
    for byte in data[separator + 1:]:
        if escaped:
            token.append(byte)
            escaped = False
        elif byte == 0x5C:
            escaped = True
        elif byte in b" \t\r\n":
            if token:
                tokens.append(bytes(token))
                token.clear()
        else:
            token.append(byte)
    if escaped:
        token.append(0x5C)
    if token:
        tokens.append(bytes(token))
    return tokens

repo_inputs = set()
for depfile in depfiles:
    for raw in depfile_tokens(depfile):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            print("::error::Rust depfile contains a non-UTF-8 path", file=sys.stderr)
            raise SystemExit(1)
        path = pathlib.Path(text)
        if not path.is_absolute():
            path = snapshot / "admin/rust" / path
        normalized = pathlib.Path(os.path.normpath(path))
        if relative_to(normalized, target_dir) is not None:
            continue
        relative = relative_to(normalized, snapshot)
        if relative is None:
            relative = relative_to(normalized, build_snapshot)
        if relative is None:
            relative = relative_to(normalized, pathlib.Path("/project"))
        if relative is None:
            claws_relative = relative_to(normalized, pathlib.Path("/claws"))
            if claws_relative is not None:
                relative = pathlib.Path("claws") / claws_relative
        if relative is None and relative_to(normalized, cargo_home) is not None:
            continue
        if relative is None and relative_to(normalized, rustup_home) is not None:
            continue
        if relative is None and any(
            relative_to(normalized, pathlib.Path(root)) is not None
            for root in ("/phase0-cargo", "/phase0-rustup", "/phase0-toolchain")
        ):
            continue
        if relative is None:
            print(
                f"::error::Rust depfile input is outside the modeled immutable roots: {normalized}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        relative_text = relative.as_posix()
        if relative_text in {".git/HEAD", ".git/packed-refs"} or relative_text.startswith(".git/refs/heads/"):
            continue
        if relative_text.startswith("admin/rust/target/"):
            continue
        repo_inputs.add(relative_text)

if not repo_inputs:
    print("::error::Rust depfile contains no repository inputs", file=sys.stderr)
    raise SystemExit(1)
for relative in sorted(repo_inputs):
    sys.stdout.buffer.write(relative.encode("utf-8") + b"\0")
PY
  echo "::error::failed to parse the final Rust depfile"
  exit 1
fi

repo_dep_count=0
while IFS= read -r -d '' repo_input; do
  case "${repo_input}" in
    admin/rust/*|claws/*|nix/*|scripts/*|flake.nix|flake.lock) ;;
    *)
      echo "::error file=${repo_input}::production depfile input escapes the six closed Git inputs"
      exit 1
      ;;
  esac
  require_blob "${repo_input}"
  if [[ "${repo_input}" == *.rs \
    && "${repo_input}" != "${PHASE0_REL}" \
    && "${repo_input}" != "admin/rust/core-rs/src/product_a_phase0.rs" ]] \
    && grep -Eq '^[[:space:]]*[^/[:space:]].*axum[[:space:]]*::[[:space:]]*serve[[:space:]]*\(' \
      "${SNAPSHOT}/${repo_input}"; then
    echo "::error file=${repo_input}::production HTTP listeners must use the Phase 0 serve choke-point"
    exit 1
  fi
  repo_dep_count=$((repo_dep_count + 1))
done < "${REPO_DEP_INPUTS}"
if [[ "${repo_dep_count}" -eq 0 ]]; then
  echo "::error::production depfile repository closure is empty"
  exit 1
fi

for required_source in \
  "mobile_claw_vpn_phase0.rs" \
  "production_app.rs" \
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
for depfile in "${DEPFILES[@]}"; do
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
  if grep -Fq "${forbidden_source}" "${depfile}"; then
    echo "::error::retired owner-present effect source entered the ${TARGET} production graph: ${forbidden_source}"
    exit 1
  fi
done
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
  PROXY_CONTRACT_JSON="${TMP_ROOT}/llm-proxy-artifact-contract.json"
  "${PROXY_BINARY}" --owner-present-phase0-contract > "${PROXY_CONTRACT_JSON}"
  if ! jq -e '
      .schema == "theyos-product-a-phase0-http-boundary-v1"
      and .component == "theyos-llm-proxy"
      and .authority == "none"
      and .production_activation == false
      and .allowed_requests == [
        {"method":"GET","path":"/api/v1/mobile/claw-vpn/status"},
        {"method":"HEAD","path":"/api/v1/mobile/claw-vpn/status"}
      ]
    ' "${PROXY_CONTRACT_JSON}" >/dev/null; then
    echo "::error::published theyos-llm-proxy Phase 0 contract is not GET/HEAD status-only"
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

PUBLISHED_EXECUTABLES_JSON="${TMP_ROOT}/published-executables.json"
jq -n '{}' > "${PUBLISHED_EXECUTABLES_JSON}"
record_published_executable() {
  local name="$1" path="$2" classification="$3" next
  next="${TMP_ROOT}/published-executables.next.json"
  jq -S --arg name "${name}" --arg sha256 "$(sha256_file "${path}")" \
    --arg classification "${classification}" \
    '. + {($name): {sha256: $sha256, classification: $classification}}' \
    "${PUBLISHED_EXECUTABLES_JSON}" > "${next}"
  mv "${next}" "${PUBLISHED_EXECUTABLES_JSON}"
}

scan_published_executable() {
  local executable="$1"
  if [[ ! -x "${executable}" ]]; then
    echo "::error::published executable is missing: ${executable}"
    exit 1
  fi
  helper_strings="${TMP_ROOT}/$(basename "${executable}").strings"
  LC_ALL=C strings "${executable}" > "${helper_strings}"
  if grep -Eiq \
      'RevalidatedCapability|ConsumedCapability|PointOfUsePermit|/api/v1/mobile/claw-vpn/(owner-present|owner|offers|sessions|rendezvous)' \
      "${helper_strings}"; then
    echo "::error::published executable contains a Product A authority marker: ${executable}"
    exit 1
  fi
}
scan_published_executable "${PROXY_BINARY}"
for helper in "${PUBLISHED_HELPERS[@]}"; do
  scan_published_executable "${BINARY_DIR}/${helper}"
done
record_published_executable "theyos-engine" "${BINARY}" "phase0-engine-contract"
record_published_executable "theyos-llm-proxy" "${PROXY_BINARY}" "shared-http-get-head-status-boundary"
for helper in "${PUBLISHED_HELPERS[@]}"; do
  record_published_executable "${helper}" "${BINARY_DIR}/${helper}" "out-of-process-helper-no-server-rs-dependency"
done

NORMALIZED_DEPFILE="${TMP_ROOT}/server.normalized.d"
sed \
  -e "s#${SNAPSHOT}#\$SOURCE#g" \
  -e "s#${TARGET_DIR}#\$TARGET#g" \
  "${DEPFILE}" > "${NORMALIZED_DEPFILE}"

ATTESTATION_OUT="${PHASE0_ATTESTATION_OUT:-${TMP_ROOT}/phase0-attestation-${TARGET}.json}"
mkdir -p "$(dirname "${ATTESTATION_OUT}")"
jq -n -S \
  --arg schema "theyos-owner-present-phase0-artifact-attestation-v1" \
  --arg source_sha "${HEAD_SHA}" \
  --arg source_tree "${HEAD_TREE}" \
  --arg target "${TARGET}" \
  --arg build_tool "${BUILD_TOOL}" \
  --arg build_tool_version "$(run_clean "${BUILD_TOOL_BIN}" -V)" \
  --arg rustc "$(run_clean "${RUSTC_BIN}" -Vv)" \
  --arg cargo "$(run_clean "${CARGO_BIN}" -V)" \
  --arg rustc_toolchain_sha256 "${RUSTC_TOOLCHAIN_SHA256}" \
  --arg cargo_toolchain_sha256 "${CARGO_TOOLCHAIN_SHA256}" \
  --arg python "$(run_clean "${PYTHON_BIN}" --version 2>&1)" \
  --arg cargo_config_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/.cargo/config.toml")" \
  --arg cross_config_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/Cross.toml")" \
  --arg cargo_lock_sha256 "$(sha256_file "${SNAPSHOT}/admin/rust/Cargo.lock")" \
  --arg flake_lock_sha256 "$(sha256_file "${SNAPSHOT}/flake.lock")" \
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
  --arg proxy_depfile_sha256 "$(sha256_file "${PROXY_DEPFILE}")" \
  --arg server_sha256 "$(sha256_file "${BINARY}")" \
  --arg theyos_engine_sha256 "$(sha256_file "${STAGED_ENGINE}")" \
  --argjson published_executables "$(cat "${PUBLISHED_EXECUTABLES_JSON}")" \
  --arg xcode_version "${XCODE_VERSION}" \
  --arg xcode_build "${XCODE_BUILD}" \
  --arg expected_xcode_version "${EXPECTED_XCODE_VERSION}" \
  --arg expected_xcode_build "${EXPECTED_XCODE_BUILD}" \
  --arg macos_sdk_version "${MACOS_SDK_VERSION}" \
  --arg expected_macos_sdk_version "${EXPECTED_MACOS_SDK_VERSION}" \
  --arg developer_dir "${EXPECTED_DEVELOPER_DIR}" \
  --arg macos_sdk_path "${MACOS_SDK_PATH}" \
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
    rustc_toolchain_sha256: $rustc_toolchain_sha256,
    cargo_toolchain_sha256: $cargo_toolchain_sha256,
    python: $python,
    cargo_config_sha256: $cargo_config_sha256,
    cross_config_sha256: $cross_config_sha256,
    cargo_lock_sha256: $cargo_lock_sha256,
    flake_lock_sha256: $flake_lock_sha256,
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
    proxy_depfile_sha256: $proxy_depfile_sha256,
    server_sha256: $server_sha256,
    theyos_engine_sha256: $theyos_engine_sha256,
    published_executables: $published_executables,
    xcode_version: $xcode_version,
    xcode_build: $xcode_build,
    expected_xcode_version: $expected_xcode_version,
    expected_xcode_build: $expected_xcode_build,
    macos_sdk_version: $macos_sdk_version,
    expected_macos_sdk_version: $expected_macos_sdk_version,
    developer_dir: $developer_dir,
    macos_sdk_path: $macos_sdk_path,
    published_target: $published_target,
    server_equals_theyos_engine: true,
    owner_present_authority: "none",
    phase: "phase0-compile-out",
    cargo_features: [],
    build_environment_policy: "env-clear-positive-allowlist-v1",
    cargo_source_policy: "local-admin-rust-or-canonical-crates-io-v1",
    cargo_fetch_network: true,
    post_fetch_build_offline: true,
    custom_build_targets: [
      "admin/rust/core-rs/build.rs",
      "admin/rust/household-rs/build.rs",
      "admin/rust/server-rs/build.rs"
    ]
  }' > "${ATTESTATION_OUT}"

echo "Owner-present Phase 0 structural compile-out is closed for ${TARGET}."
echo "Phase 0 attestation: ${ATTESTATION_OUT}"
