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

SYSTEM_HOME="${HOME:?HOME is required to locate the pinned toolchain and Cargo cache}"
CARGO_HOME_DIR="${PHASE0_CARGO_HOME:-${SYSTEM_HOME}/.cargo}"
RUSTUP_HOME_DIR="${PHASE0_RUSTUP_HOME:-${SYSTEM_HOME}/.rustup}"
if [[ "${CARGO_HOME_DIR}" != /* || "${RUSTUP_HOME_DIR}" != /* ]]; then
  echo "::error::canonical Cargo and rustup homes must be absolute paths"
  exit 1
fi
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
  "${THEYOS_DIR}/admin/rust/rust-toolchain.toml")"
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
BUILD_TOOL_BIN="$(resolve_executable "${BUILD_TOOL}")"
PYTHON_BIN="$(resolve_executable python3)"
CANONICAL_PATH="$(dirname "${RUSTC_BIN}"):$(dirname "${CARGO_BIN}"):$(dirname "${BUILD_TOOL_BIN}"):$(dirname "${PYTHON_BIN}"):/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
CLEAN_HOME="${TMP_ROOT}/home"
CLEAN_TMP="${TMP_ROOT}/tmp"
mkdir -p "${CLEAN_HOME}" "${CLEAN_TMP}" "${TARGET_DIR}"

run_clean_online() {
  "${ENV_BIN}" -i \
    HOME="${CLEAN_HOME}" \
    CARGO_HOME="${CARGO_HOME_DIR}" \
    RUSTUP_HOME="${RUSTUP_HOME_DIR}" \
    TMPDIR="${CLEAN_TMP}" \
    PATH="${CANONICAL_PATH}" \
    LC_ALL=C \
    LANG=C \
    RUSTUP_TOOLCHAIN="${EXPECTED_RUST}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    THEYOS_PHASE0_CLEAN_ENV=1 \
    "$@"
}

run_clean() {
  run_clean_online CARGO_NET_OFFLINE=true "$@"
}

RUSTC_VERBOSE="$(cd "${THEYOS_DIR}/admin/rust" && run_clean_online "${RUSTC_BIN}" -vV)"
ACTUAL_RUST="$(printf '%s\n' "${RUSTC_VERBOSE}" | sed -n 's/^release: //p')"
RUSTC_HOST="$(printf '%s\n' "${RUSTC_VERBOSE}" | sed -n 's/^host: //p')"
if [[ -z "${EXPECTED_RUST}" || "${ACTUAL_RUST}" != "${EXPECTED_RUST}" ]]; then
  echo "::error::canonical theyos-engine build requires the pinned Rust toolchain"
  exit 1
fi
HOST_TARGET="${RUSTC_HOST}"
TARGET="${PHASE0_TARGET:-${HOST_TARGET}}"
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

TRACKED_PKG_CONFIG_PATH="$(sed -n \
  's/^PKG_CONFIG_PATH = "\([^"]*\)"/\1/p' \
  "${THEYOS_DIR}/admin/rust/.cargo/config.toml")"
if [[ -z "${TRACKED_PKG_CONFIG_PATH}" ]]; then
  echo "::error::frozen workspace Cargo config must pin PKG_CONFIG_PATH"
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
  "admin/rust/server-rs/src/production_app.rs" \
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
run_clean_online "${CARGO_BIN}" fetch \
  --manifest-path "${SNAPSHOT}/admin/rust/Cargo.toml" \
  --locked \
  --quiet

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
for listener_source in \
  "admin/rust/server-rs/src/main.rs" \
  "admin/rust/server-rs/src/household_listener.rs" \
  "admin/rust/server-rs/src/macos_local_registration_listener.rs" \
  "admin/rust/server-rs/src/install_cli.rs"; do
  if [[ "$(grep -Fc 'phase0_axum_serve!' "${SNAPSHOT}/${listener_source}")" -ne 1 ]]; then
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

REPO_DEP_INPUTS="${TMP_ROOT}/repo-dep-inputs.nul"
if ! run_clean "${PYTHON_BIN}" - \
    "${DEPFILE}" \
    "${SNAPSHOT}" \
    "${TARGET_DIR}" > "${REPO_DEP_INPUTS}" <<'PY'; then
import os
import pathlib
import sys

depfile = pathlib.Path(sys.argv[1])
snapshot = pathlib.Path(sys.argv[2]).resolve()
target_dir = pathlib.Path(sys.argv[3]).resolve()
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
    print("::error::Rust depfile has no target separator", file=sys.stderr)
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

def relative_to(path, root):
    try:
        return path.relative_to(root)
    except ValueError:
        return None

repo_inputs = set()
for raw in tokens:
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
        relative = relative_to(normalized, pathlib.Path("/project"))
    if relative is None:
        claws_relative = relative_to(normalized, pathlib.Path("/claws"))
        if claws_relative is not None:
            relative = pathlib.Path("claws") / claws_relative
    if relative is None:
        continue
    relative_text = relative.as_posix()
    if (
        relative_text in {".git/HEAD", ".git/packed-refs"}
        or relative_text.startswith(".git/refs/heads/")
    ):
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
    .github/*|admin/rust/*|claws/*|scripts/*) ;;
    *)
      echo "::error file=${repo_input}::production depfile input escapes the four closed Git subtrees"
      exit 1
      ;;
  esac
  require_blob "${repo_input}"
  if [[ "${repo_input}" == *.rs \
    && "${repo_input}" != "${PHASE0_REL}" ]] \
    && grep -Eq 'axum[[:space:]]*::[[:space:]]*serve[[:space:]]*\(' \
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
  --arg build_tool_version "$(run_clean "${BUILD_TOOL_BIN}" -V)" \
  --arg rustc "$(run_clean "${RUSTC_BIN}" -Vv)" \
  --arg cargo "$(run_clean "${CARGO_BIN}" -V)" \
  --arg python "$(run_clean "${PYTHON_BIN}" --version 2>&1)" \
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
    python: $python,
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
    cargo_features: [],
    build_environment_policy: "env-clear-positive-allowlist-v1",
    cargo_source_policy: "local-admin-rust-or-canonical-crates-io-v1",
    cargo_net_offline: true,
    custom_build_targets: [
      "admin/rust/core-rs/build.rs",
      "admin/rust/household-rs/build.rs",
      "admin/rust/server-rs/build.rs"
    ]
  }' > "${ATTESTATION_OUT}"

echo "Owner-present Phase 0 structural compile-out is closed for ${TARGET}."
echo "Phase 0 attestation: ${ATTESTATION_OUT}"
