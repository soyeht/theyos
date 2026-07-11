#!/usr/bin/env bash
# Canonical build recipe for the production theyos-engine carrier.
set -euo pipefail

TARGET="${1:?usage: $0 TARGET [cargo|cross]}"
BUILD_TOOL="${2:-cargo}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUST_ROOT="${REPO_ROOT}/admin/rust"
EXPECTED_RUST="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "${RUST_ROOT}/rust-toolchain.toml")"
cd "${RUST_ROOT}"

case "${BUILD_TOOL}" in
  cargo|cross) ;;
  *)
    echo "error: unsupported theyos-engine build tool: ${BUILD_TOOL}" >&2
    exit 1
    ;;
esac

if [[ ! "${TARGET}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "error: invalid Rust target triple: ${TARGET}" >&2
  exit 1
fi

if [[ "$(rustc -V | awk '{print $2}')" != "${EXPECTED_RUST}" ]]; then
  echo "error: production theyos-engine requires rustc ${EXPECTED_RUST}" >&2
  exit 1
fi
for unsafe_env in \
  RUSTFLAGS \
  CARGO_ENCODED_RUSTFLAGS \
  RUSTC_WRAPPER \
  RUSTC_WORKSPACE_WRAPPER; do
  if [[ -n "${!unsafe_env:-}" ]]; then
    echo "error: ${unsafe_env} must be unset for the canonical theyos-engine build" >&2
    exit 1
  fi
done

SOURCE_SHA="${THEYOS_BUILD_GIT_SHA:-$(git -C "${REPO_ROOT}" rev-parse HEAD)}"
if [[ ! "${SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: THEYOS_BUILD_GIT_SHA must be a full lowercase Git SHA" >&2
  exit 1
fi

export THEYOS_BUILD_GIT_SHA="${SOURCE_SHA}"
export CLAWS_MANIFEST_YML="${REPO_ROOT}/claws/manifest.yml"
export THEYOS_EMOJI_WORDLIST="${RUST_ROOT}/household-rs/data/emoji-security-code-wordlist.csv"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false

"${BUILD_TOOL}" build \
  --manifest-path "${RUST_ROOT}/Cargo.toml" \
  --locked \
  --release \
  --target "${TARGET}" \
  --package server-rs \
  --bin server \
  --no-default-features

TARGET_DIR="${CARGO_TARGET_DIR:-${RUST_ROOT}/target}"
BINARY="${TARGET_DIR}/${TARGET}/release/server"
DEPFILE="${TARGET_DIR}/${TARGET}/release/server.d"
if [[ ! -x "${BINARY}" || ! -f "${DEPFILE}" ]]; then
  echo "error: canonical theyos-engine build did not produce server + depfile for ${TARGET}" >&2
  exit 1
fi

printf '%s\n' "${BINARY}"
