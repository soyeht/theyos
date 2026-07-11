#!/usr/bin/env bash
# Hermetic mutation tests for the Phase 0 production compile-out authority.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="${SCRIPT_DIR}/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0-test.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_repo() {
  local root="$1" mode="${2:-closed}"
  mkdir -p \
    "${root}/admin/rust/server-rs/src" \
    "${root}/admin/contracts/mobile-claw-vpn/v1"

  cat > "${root}/admin/rust/Cargo.toml" <<'EOF'
[workspace]
members = ["server-rs"]
resolver = "2"
EOF

  cat > "${root}/admin/rust/server-rs/Cargo.toml" <<'EOF'
[package]
name = "server-rs"
version = "0.0.0"
edition = "2021"

[lib]
name = "server_rs"
path = "src/lib.rs"

[[bin]]
name = "server"
path = "src/main.rs"

[features]
default = []
owner-phase1 = []
EOF

  case "${mode}" in
    closed)
      cat > "${root}/admin/rust/server-rs/src/lib.rs" <<'EOF'
#[cfg(test)]
#[allow(dead_code)]
mod mobile_claw_vpn_owner_present_foundation;

pub fn run() {}
EOF
      ;;
    module)
      cat > "${root}/admin/rust/server-rs/src/lib.rs" <<'EOF'
#[allow(dead_code)]
mod mobile_claw_vpn_owner_present_foundation;

pub fn run() {}
EOF
      ;;
    default_feature)
      cat > "${root}/admin/rust/server-rs/src/lib.rs" <<'EOF'
#[cfg(any(test, feature = "owner-phase1"))]
#[allow(dead_code)]
mod mobile_claw_vpn_owner_present_foundation;

pub fn run() {}
EOF
      perl -0pi -e 's/default = \[\]/default = ["owner-phase1"]/' \
        "${root}/admin/rust/server-rs/Cargo.toml"
      ;;
    *)
      echo "unknown fixture mode: ${mode}" >&2
      exit 1
      ;;
  esac

  cat > "${root}/admin/rust/server-rs/src/mobile_claw_vpn_owner_present_foundation.rs" <<'EOF'
pub fn owner_present_probe() -> &'static str {
    "mesh_c_owner_present_offer_control"
}
EOF

  cat > "${root}/admin/rust/server-rs/src/main.rs" <<'EOF'
fn main() {
    server_rs::run();
}
EOF

  cat > "${root}/admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json" <<'EOF'
{"contract":"soyeht-mobile-claw-vpn-owner-present-success-wire-v1","version":1,"authority_status":"historical-test-only-non-authoritative"}
EOF
  local historical_sha
  historical_sha="$(sha256_file \
    "${root}/admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json")"
  cat > "${root}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json" <<EOF
{
  "contract": "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1",
  "version": 1,
  "phase": "phase0-compile-out",
  "authority": "none",
  "retired_wire": {
    "theyos_path": "admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json",
    "historical_sha256": "${historical_sha}",
    "status": "historical-test-only-non-authoritative",
    "prohibited_production_authority": [
      "proof_token",
      "proof-bearing mint request",
      "owner_present_runtime_activation_v1"
    ]
  },
  "phase1_blocker": {
    "minimum_wire_version": 2,
    "required_shape": "server-held-finish-consume-mint"
  }
}
EOF

  cargo generate-lockfile \
    --manifest-path "${root}/admin/rust/Cargo.toml" \
    >/dev/null

  git -C "${root}" init --quiet
  git -C "${root}" config user.name "phase0-compileout-test"
  git -C "${root}" config user.email "phase0-compileout@example.invalid"
  git -C "${root}" add .
  git -C "${root}" commit --quiet -m fixture
}

expect_failure() {
  local label="$1" expected="$2" mode="${3:-closed}"
  local root="${TMP_ROOT}/${label}"
  write_repo "${root}" "${mode}"
  if "${CHECKER}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
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

closed="${TMP_ROOT}/closed"
write_repo "${closed}"
"${CHECKER}" "${closed}" >/dev/null
echo "PASS production_compileout"

expect_failure module_in_production \
  "owner-present foundation entered the production dependency graph" \
  module

expect_failure default_feature_crossing \
  "owner-present foundation entered the production dependency graph" \
  default_feature

route="${TMP_ROOT}/route"
write_repo "${route}"
cat > "${route}/admin/rust/server-rs/src/main.rs" <<'EOF'
fn main() {
    println!("/api/v1/mobile/claw-vpn/owner-present/start");
}
EOF
git -C "${route}" add .
git -C "${route}" commit --quiet -m route
if "${CHECKER}" "${route}" >"${TMP_ROOT}/route.log" 2>&1; then
  echo "error: checker accepted owner-present route" >&2
  exit 1
fi
grep -Fq "production theyos-engine contains forbidden Phase 0 marker" "${TMP_ROOT}/route.log"
echo "PASS route_artifact_refused"

marker="${TMP_ROOT}/marker"
write_repo "${marker}"
printf '%s\n' '{"contract":"activation"}' > \
  "${marker}/admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
git -C "${marker}" add .
git -C "${marker}" commit --quiet -m marker
if "${CHECKER}" "${marker}" >"${TMP_ROOT}/marker.log" 2>&1; then
  echo "error: checker accepted activation marker" >&2
  exit 1
fi
grep -Fq "Phase 0 forbids an owner-present activation marker" "${TMP_ROOT}/marker.log"
echo "PASS activation_marker_refused"

status_open="${TMP_ROOT}/status-open"
write_repo "${status_open}"
perl -0pi -e 's/"authority": "none"/"authority": "v1"/' \
  "${status_open}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
git -C "${status_open}" add .
git -C "${status_open}" commit --quiet -m status-open
if "${CHECKER}" "${status_open}" >"${TMP_ROOT}/status-open.log" 2>&1; then
  echo "error: checker accepted V1 as production authority" >&2
  exit 1
fi
grep -Fq "Phase 0 authority status is invalid" "${TMP_ROOT}/status-open.log"
echo "PASS v1_authority_refused"

echo "Owner-present Phase 0 compile-out mutation matrix passed."
