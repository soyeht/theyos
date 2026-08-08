#!/usr/bin/env bash
# ODB-backed ownership guard for historical owner-present wire evidence.
# The V1 golden declares every nested cross-repo dependency; this guard verifies
# those pairs plus the authoritative retirement status without trusting either
# checkout.
set -euo pipefail

THEYOS_DIR="${1:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
SOYEHT_IOS_DIR="${2:?usage: $0 THEYOS_DIR SOYEHT_IOS_DIR [BASE_SHA]}"
BASE_SHA="${3:-}"

CONTRACT_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
CONTRACT_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_success_wire_v1.json"
STATUS_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
STATUS_VENDOR_REL="Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
CLOSED_INPUT_ROOTS_REL=".github/owner-present-phase0-closed-input-roots-v1.txt"
RETIREMENT_PRIOR_SHA256="ff9ad533567e29261ecbd8e11e84e9490f1829bd4d2e5b50fe8783dc82b000d1"
RETIREMENT_HISTORICAL_SHA256="55fe55c6f1985103f21e679c5e6227646035e4d03da3e75193cfc9d1eeb45f8f"
API_SHAPES_SOURCE_REL="admin/contracts/mobile-claw-vpn/v1/api_shapes.json"
API_SHAPES_PRIOR_SHA256="7d31e66fd6172c9e7340455e73d0c2b06629b491442428a14c53edd45f49b7a6"
API_SHAPES_HISTORICAL_SHA256="6482badfe02f220e5954ddf0f73385a622d317ba7b9b9d1063562724574f33b4"
if [[ "${OWNER_PRESENT_CONTRACT_GUARD_LOCAL_TEST:-0}" == "1" ]]; then
  RETIREMENT_PRIOR_SHA256="${OWNER_PRESENT_RETIREMENT_PRIOR_SHA256:?local prior digest is required}"
  RETIREMENT_HISTORICAL_SHA256="${OWNER_PRESENT_RETIREMENT_HISTORICAL_SHA256:?local historical digest is required}"
fi
PIN_REL="scripts/cross-repo-contract.sha"
WORKFLOW_REL=".github/workflows/contracts-cross-repo-sync.yml"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

HEAD_SHA="$(git -C "${THEYOS_DIR}" rev-parse HEAD)"
IOS_HEAD_SHA="$(git -C "${SOYEHT_IOS_DIR}" rev-parse HEAD)"

materialize_regular_blob() {
  local repo="$1" commit="$2" path="$3" destination="$4" label="$5"
  local entry mode type object
  entry="$(git -C "${repo}" ls-tree "${commit}" -- "${path}")"
  if [[ -z "${entry}" ]]; then
    return 1
  fi
  read -r mode type object _ <<< "${entry}"
  if [[ "${mode}" != "100644" || "${type}" != "blob" ]]; then
    echo "::error file=${path}::${label} must be a regular 100644 Git blob"
    exit 1
  fi
  git -C "${repo}" cat-file blob "${object}" > "${destination}"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

validate_closed_input_roots() {
  local roots_file="$1" count=0 path
  local seen="${TMP_DIR}/closed-input-roots-seen"
  : > "${seen}"
  while IFS= read -r path || [[ -n "${path}" ]]; do
    if [[ -z "${path}" || "${path}" == \#* || "${path}" == /* \
      || "${path}" == *"../"* || "${path}" == *$'\r'* \
      || -n "$(grep -Fx -- "${path}" "${seen}")" ]]; then
      return 1
    fi
    printf '%s\n' "${path}" >> "${seen}"
    count=$((count + 1))
  done < "${roots_file}"
  (( count >= 8 )) || return 1
  for path in admin/rust admin/contracts/claw-store/v1/contract.json \
    admin/contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json \
    claws flake.lock flake.nix nix scripts; do
    grep -Fqx -- "${path}" "${seen}" || return 1
  done
}

HEAD_CONTRACT="${TMP_DIR}/head-contract"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${CONTRACT_SOURCE_REL}" "${HEAD_CONTRACT}" \
  "historical success fixture"; then
  echo "::error file=${CONTRACT_SOURCE_REL}::historical success fixture is missing"
  exit 1
fi
HEAD_STATUS="${TMP_DIR}/head-status"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${STATUS_SOURCE_REL}" "${HEAD_STATUS}" \
  "authoritative wire status"; then
  echo "::error file=${STATUS_SOURCE_REL}::authoritative wire status is missing"
  exit 1
fi
HEAD_CLOSED_INPUT_ROOTS="${TMP_DIR}/head-closed-input-roots"
if ! materialize_regular_blob \
  "${THEYOS_DIR}" "${HEAD_SHA}" "${CLOSED_INPUT_ROOTS_REL}" "${HEAD_CLOSED_INPUT_ROOTS}" \
  "Phase 0 closed-input roots"; then
  echo "::error file=${CLOSED_INPUT_ROOTS_REL}::Phase 0 closed-input roots are missing"
  exit 1
fi
if ! validate_closed_input_roots "${HEAD_CLOSED_INPUT_ROOTS}"; then
  echo "::error file=${CLOSED_INPUT_ROOTS_REL}::Phase 0 closed-input roots policy is invalid"
  exit 1
fi
if [[ "$(jq -r '.contract' "${HEAD_STATUS}")" != \
    "soyeht-mobile-claw-vpn-owner-present-wire-authority-status-v1" \
  || "$(jq -r '.phase' "${HEAD_STATUS}")" != "phase0-compile-out" \
  || "$(jq -r '.authority' "${HEAD_STATUS}")" != "none" \
  || "$(jq -r '.retired_wire.status' "${HEAD_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_api_shapes.status' "${HEAD_STATUS}")" != \
    "historical-test-only-non-authoritative" \
  || "$(jq -r '.retired_api_shapes.theyos_path' "${HEAD_STATUS}")" != \
    "admin/contracts/mobile-claw-vpn/v1/api_shapes.json" \
  || "$(jq -r '.retired_api_shapes.prior_authoritative_sha256' "${HEAD_STATUS}")" != \
    "${API_SHAPES_PRIOR_SHA256}" \
  || "$(jq -r '.retired_api_shapes.historical_sha256' "${HEAD_STATUS}")" != \
    "${API_SHAPES_HISTORICAL_SHA256}" \
  || "$(jq -r '.retired_wire.prior_authoritative_sha256' "${HEAD_STATUS}")" != \
    "${RETIREMENT_PRIOR_SHA256}" \
  || "$(jq -r '.retired_wire.historical_sha256' "${HEAD_STATUS}")" != \
    "${RETIREMENT_HISTORICAL_SHA256}" \
  || "$(jq -r '.phase0_closed_inputs.roots_path' "${HEAD_STATUS}")" != \
    "${CLOSED_INPUT_ROOTS_REL}" \
  || "$(jq -r '.phase0_closed_inputs.format' "${HEAD_STATUS}")" != \
    "ordered-git-paths-v1" \
  || "$(jq -r '.phase0_closed_inputs.policy_change_control' "${HEAD_STATUS}")" != \
    "trusted-base-append-only-paths" \
  || "$(jq -r '.phase0_closed_inputs.release_provenance' "${HEAD_STATUS}")" != \
    "checker-on-release-subject-and-final-package-attestation" \
  || "$(jq -r '.phase0_closed_inputs.staged_products | sort | join(",")' "${HEAD_STATUS}")" != \
    "nix-theyos-runtime,theyos-engine,theyos-llm-proxy" \
  || "$(jq -r '.phase0_closed_inputs.required_published_targets | sort | join(",")' "${HEAD_STATUS}")" != \
    "aarch64-apple-darwin,aarch64-unknown-linux-musl,nix-theyos-runtime-x86_64-linux,x86_64-unknown-linux-musl" \
  || "$(jq -r '.proof_machinery_change_control.protocol' "${HEAD_STATUS}")" != \
    "soyeht-owner-present-base-owned-land-exact-v1" \
  || "$(jq -r '.proof_machinery_change_control.authority' "${HEAD_STATUS}")" != \
    "trusted-base-integrity-checker" \
  || "$(jq -r '.proof_machinery_change_control.state' "${HEAD_STATUS}")" != "active" \
  || "$(jq -r '.proof_machinery_change_control.maintainer_model' "${HEAD_STATUS}")" != \
    "single-maintainer-agents-share-maintainer-identity" \
  || "$(jq -r '.proof_machinery_change_control.protected_change' "${HEAD_STATUS}")" != \
    "base-policy-shape-plus-exact-head-oid-reseal" \
  || "$(jq -r '.proof_machinery_change_control.frozen_change' "${HEAD_STATUS}")" != \
    "rejected" \
  || "$(jq -r '.proof_machinery_change_control.self_weakening' "${HEAD_STATUS}")" != \
    "trusted-base-checker-validates-head-before-merge" \
  || "$(jq -r '.proof_machinery_change_control.anti_replay' "${HEAD_STATUS}")" != \
    "base-policy-and-exact-head-object-binding" \
  || "$(jq -r '.phase1_blocker.minimum_wire_version' "${HEAD_STATUS}")" != "2" \
  || "$(jq -r '.phase1_blocker.required_shape' "${HEAD_STATUS}")" != \
    "server-held-finish-consume-mint" \
  || "$(sha256_file "${HEAD_CONTRACT}")" != "${RETIREMENT_HISTORICAL_SHA256}" \
  || "$(jq -r '.authority_status' "${HEAD_CONTRACT}")" != \
    "historical-test-only-non-authoritative" ]]; then
  echo "::error file=${STATUS_SOURCE_REL}::wire authority status does not close the exact V1 retirement"
  exit 1
fi

PAIRS=()
while IFS= read -r pair; do
  PAIRS+=("${pair}")
done < <(jq -r '.dependencies[] | [.theyos_path, .ios_path] | @tsv' "${HEAD_CONTRACT}")
PAIRS+=("${CONTRACT_SOURCE_REL}"$'\t'"${CONTRACT_VENDOR_REL}")
PAIRS+=("${STATUS_SOURCE_REL}"$'\t'"${STATUS_VENDOR_REL}")
if [[ "${#PAIRS[@]}" -ne 5 ]]; then
  echo "::error file=${CONTRACT_SOURCE_REL}::expected three dependencies, the historical wire, and its authority status"
  exit 1
fi
if [[ "$(printf '%s\n' "${PAIRS[@]}" | sort -u | wc -l | tr -d ' ')" -ne "${#PAIRS[@]}" ]]; then
  echo "::error file=${CONTRACT_SOURCE_REL}::duplicate cross-repo fixture pair"
  exit 1
fi

PIN_SOURCE="${TMP_DIR}/pin"
if ! materialize_regular_blob \
  "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${PIN_REL}" "${PIN_SOURCE}" \
  "iOS cross-repo pin"; then
  echo "::error file=${PIN_REL}::iOS cross-repo pin is missing"
  exit 1
fi
PIN="$(grep -vE '^[[:space:]]*#' "${PIN_SOURCE}" | tr -d '[:space:]')"
if [[ ! "${PIN}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error file=${PIN_REL}::iOS cross-repo pin must be one lowercase 40-hex commit"
  exit 1
fi
if ! git -C "${THEYOS_DIR}" cat-file -e "${PIN}^{commit}" 2>/dev/null; then
  git -C "${THEYOS_DIR}" fetch --no-tags --depth=1 origin "${PIN}"
fi
if ! git -C "${THEYOS_DIR}" merge-base --is-ancestor "${PIN}" "${HEAD_SHA}" 2>/dev/null; then
  if [[ "$(git -C "${THEYOS_DIR}" rev-parse --is-shallow-repository)" == "true" ]]; then
    git -C "${THEYOS_DIR}" fetch --no-tags --unshallow origin
  else
    git -C "${THEYOS_DIR}" fetch --no-tags origin main
  fi
  if ! git -C "${THEYOS_DIR}" merge-base --is-ancestor "${PIN}" "${HEAD_SHA}"; then
    echo "::error file=${PIN_REL}::iOS pin ${PIN} is not an ancestor of theyos HEAD ${HEAD_SHA}"
    exit 1
  fi
fi

BASE_CONTEXT=0
RETIREMENT_BOOTSTRAP=0
BASE_WORKFLOW="${TMP_DIR}/base-workflow"
if [[ "${BASE_SHA}" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "${BASE_SHA}" != "0000000000000000000000000000000000000000" ]]; then
  BASE_CONTEXT=1
  if ! git -C "${THEYOS_DIR}" cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
    git -C "${THEYOS_DIR}" fetch --no-tags --depth=1 origin "${BASE_SHA}"
  fi
  if ! git -C "${THEYOS_DIR}" show "${BASE_SHA}:${WORKFLOW_REL}" > "${BASE_WORKFLOW}" 2>/dev/null; then
    : > "${BASE_WORKFLOW}"
  fi
  BASE_CONTRACT="${TMP_DIR}/base-contract"
  if materialize_regular_blob \
    "${THEYOS_DIR}" "${BASE_SHA}" "${CONTRACT_SOURCE_REL}" "${BASE_CONTRACT}" \
    "base historical fixture" \
    && [[ "$(sha256_file "${BASE_CONTRACT}")" == "${RETIREMENT_PRIOR_SHA256}" ]] \
    && [[ "$(sha256_file "${HEAD_CONTRACT}")" == "${RETIREMENT_HISTORICAL_SHA256}" ]] \
    && ! git -C "${THEYOS_DIR}" cat-file -e "${BASE_SHA}:${STATUS_SOURCE_REL}" 2>/dev/null; then
    RETIREMENT_BOOTSTRAP=1
  fi
fi

INDEX=0
for pair in "${PAIRS[@]}"; do
  INDEX=$((INDEX + 1))
  IFS=$'\t' read -r source_rel vendor_rel <<< "${pair}"
  if [[ -z "${source_rel}" || -z "${vendor_rel}" \
    || "${source_rel}" == /* || "${vendor_rel}" == /* \
    || "${source_rel}" == *".."* || "${vendor_rel}" == *".."* ]]; then
    echo "::error file=${CONTRACT_SOURCE_REL}::unsafe cross-repo dependency path"
    exit 1
  fi

  head_source="${TMP_DIR}/head-${INDEX}"
  if ! materialize_regular_blob \
    "${THEYOS_DIR}" "${HEAD_SHA}" "${source_rel}" "${head_source}" \
    "authoritative dependency"; then
    echo "::error file=${source_rel}::authoritative dependency is missing"
    exit 1
  fi

  source_new=0
  source_retirement=0
  source_change_control_migration=0
  source_closed_inputs_migration=0
  registration_new=0
  if [[ "${BASE_CONTEXT}" == "1" ]]; then
    base_source="${TMP_DIR}/base-${INDEX}"
    if materialize_regular_blob \
      "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${base_source}" \
      "base dependency"; then
      if ! cmp -s "${base_source}" "${head_source}"; then
        if [[ "${source_rel}" == "${CONTRACT_SOURCE_REL}" \
          && "$(sha256_file "${base_source}")" == "${RETIREMENT_PRIOR_SHA256}" \
          && "$(sha256_file "${head_source}")" == "${RETIREMENT_HISTORICAL_SHA256}" ]]; then
          source_retirement=1
        elif [[ "${source_rel}" == "${API_SHAPES_SOURCE_REL}" \
          && "$(sha256_file "${base_source}")" == "${API_SHAPES_PRIOR_SHA256}" \
          && "$(sha256_file "${head_source}")" == "${API_SHAPES_HISTORICAL_SHA256}" ]]; then
          source_retirement=1
        elif [[ "${source_rel}" == "${STATUS_SOURCE_REL}" ]] \
          && jq -e '
            .proof_machinery_transition == {
              protocol: "soyeht-owner-present-proof-machinery-transition-v1",
              authority: "base-owned-integrity-checker",
              state: "unarmed",
              arming: "github-owner-review-on-exact-arm-commit",
              consumption: "one-shot-exact-tree-and-policy-oid-removes-transition-auth",
              canary: "arm-then-consume-merge-blocked-and-allowed",
              anti_replay: "base-sha-expected-head-tree-generation-one-shot-consumption"
            }
            and .phase0_artifact_boundary.object_identity_update == "per-reviewed-commit-revalidation"
          ' "${base_source}" >/dev/null \
          && [[ "$(jq -S 'del(.proof_machinery_transition, .notes, .phase0_artifact_boundary.object_identity_update)' "${base_source}")" == \
            "$(jq -S 'del(.proof_machinery_change_control, .notes, .phase0_artifact_boundary.object_identity_update)' "${head_source}")" ]] \
          && [[ "$(jq -S '.notes[2:]' "${base_source}")" == \
            "$(jq -S '.notes[2:]' "${head_source}")" ]] \
          && jq -e '
            .notes[0] == "The base-owned policy freezes immutable roots and requires exact head-object resealing for evolvable proof machinery; declarative Cargo inputs and the boundary descriptor are commit-bound evidence, not independent approval."
            and .notes[1] == "The trusted-base checker validates every protected head object without executing pull-request code. The repository has one maintainer identity shared by its agents, so change control records exact objects and never pretends that self-review is an independent security boundary."
          ' "${head_source}" >/dev/null; then
          source_change_control_migration=1
        elif [[ "${source_rel}" == "${STATUS_SOURCE_REL}" ]] \
          && jq -e '
            .phase0_artifact_boundary == {
              theyos_path: "admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv",
              format: "closed-git-inputs-v2",
              policy_change_control: "base-owned-proof-machinery-commit-bound-inputs",
              object_identity_update: "per-commit-revalidation",
              object_identity_authority: "commit-bound-evidence-not-independent-approval",
              release_provenance: "checker-on-release-subject-and-final-package-attestation",
              staged_products: ["nix-theyos-runtime", "theyos-engine", "theyos-llm-proxy"],
              required_published_targets: ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "nix-theyos-runtime-x86_64-linux"]
            }
          ' "${base_source}" >/dev/null \
          && jq -e --arg roots "${CLOSED_INPUT_ROOTS_REL}" '
            .phase0_closed_inputs == {
              roots_path: $roots,
              format: "ordered-git-paths-v1",
              policy_change_control: "trusted-base-append-only-paths",
              release_provenance: "checker-on-release-subject-and-final-package-attestation",
              staged_products: ["nix-theyos-runtime", "theyos-engine", "theyos-llm-proxy"],
              required_published_targets: ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "nix-theyos-runtime-x86_64-linux"]
            }
          ' "${head_source}" >/dev/null \
          && [[ "$(jq -S 'del(.notes, .phase0_artifact_boundary)' "${base_source}")" == \
            "$(jq -S 'del(.notes, .phase0_closed_inputs)' "${head_source}")" ]] \
          && [[ "$(jq -S '.notes[2:]' "${base_source}")" == \
            "$(jq -S '.notes[3:]' "${head_source}")" ]]; then
          source_closed_inputs_migration=1
        else
          echo "::error file=${source_rel}::pinned V1 dependency is immutable; add a new version"
          diff -u "${base_source}" "${head_source}" || true
          exit 1
        fi
      fi
    else
      source_new=1
    fi
    if ! grep -Fq "${source_rel}" "${BASE_WORKFLOW}"; then
      registration_new=1
    fi
  fi

  declared_sha="$(jq -r --arg source "${source_rel}" \
    '.dependencies[]? | select(.theyos_path == $source) | (.sha256 // empty)' \
    "${HEAD_CONTRACT}")"
  if [[ -n "${declared_sha}" && "${declared_sha}" != "$(sha256_file "${head_source}")" ]]; then
    echo "::error file=${CONTRACT_SOURCE_REL}::declared dependency digest differs from ${source_rel}"
    exit 1
  fi

  vendor_source="${TMP_DIR}/vendor-${INDEX}"
  vendor_exists=1
  if ! materialize_regular_blob \
    "${SOYEHT_IOS_DIR}" "${IOS_HEAD_SHA}" "${vendor_rel}" "${vendor_source}" \
    "iOS vendor"; then
    vendor_exists=0
  fi

  if [[ "${source_new}" == "1" ]]; then
    if [[ "${vendor_exists}" == "1" ]]; then
      echo "::error file=${vendor_rel}::vendor exists before its new authoritative source lands"
      exit 1
    fi
    if [[ "${registration_new}" != "1" ]]; then
      echo "::error file=${WORKFLOW_REL}::new source is unexpectedly registered in the base workflow"
      exit 1
    fi
    echo "Bootstrap: ${source_rel} must land in theyos before iOS vendors ${vendor_rel}."
    continue
  fi

  if [[ "${source_retirement}" == "1" ]]; then
    if [[ "${RETIREMENT_BOOTSTRAP}" != "1" ]]; then
      echo "::error file=${source_rel}::V1 retirement is not the exact ordered bootstrap"
      exit 1
    fi
    if [[ "${vendor_exists}" == "1" ]] && ! cmp -s "${base_source}" "${vendor_source}"; then
      echo "::error file=${vendor_rel}::V1 retirement requires the prior iOS vendor until the theyos authority lands"
      exit 1
    fi
    retirement_pinned="${TMP_DIR}/retirement-pinned-${INDEX}"
    if ! materialize_regular_blob \
      "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${retirement_pinned}" \
      "fixture at the trusted PR base" \
      || ! cmp -s "${base_source}" "${retirement_pinned}"; then
      echo "::error file=${source_rel}::V1 retirement requires the exact prior source at the trusted PR base"
      exit 1
    fi
    echo "Retirement bootstrap: historical V1 authority must land in theyos before the iOS repin."
    continue
  fi

  if [[ "${source_change_control_migration}" == "1" ]]; then
    if [[ "${vendor_exists}" != "1" ]] || ! cmp -s "${base_source}" "${vendor_source}"; then
      echo "::error file=${vendor_rel}::change-control migration requires the prior iOS vendor until theyos lands"
      exit 1
    fi
    migration_pinned="${TMP_DIR}/change-control-pinned-${INDEX}"
    if ! materialize_regular_blob \
      "${THEYOS_DIR}" "${PIN}" "${source_rel}" "${migration_pinned}" \
      "authority status at the iOS pin" \
      || ! cmp -s "${vendor_source}" "${migration_pinned}"; then
      echo "::error file=${PIN_REL}::change-control migration requires iOS to remain pinned to its prior vendor"
      exit 1
    fi
    echo "Change-control bootstrap: land theyos before updating the iOS authority-status vendor and pin."
    continue
  fi

  if [[ "${source_closed_inputs_migration}" == "1" ]]; then
    closed_inputs_prior_vendor=0
    if [[ "${vendor_exists}" == "1" ]] && cmp -s "${base_source}" "${vendor_source}"; then
      closed_inputs_prior_vendor=1
    elif [[ "${vendor_exists}" == "1" ]] \
      && jq -e '
        .proof_machinery_transition == {
          protocol: "soyeht-owner-present-proof-machinery-transition-v1",
          authority: "base-owned-integrity-checker",
          state: "unarmed",
          arming: "github-owner-review-on-exact-arm-commit",
          consumption: "one-shot-exact-tree-and-policy-oid-removes-transition-auth",
          canary: "arm-then-consume-merge-blocked-and-allowed",
          anti_replay: "base-sha-expected-head-tree-generation-one-shot-consumption"
        }
        and .phase0_artifact_boundary.object_identity_update == "per-reviewed-commit-revalidation"
      ' "${vendor_source}" >/dev/null \
      && [[ "$(jq -S 'del(.proof_machinery_transition, .notes, .phase0_artifact_boundary.object_identity_update)' "${vendor_source}")" == \
        "$(jq -S 'del(.proof_machinery_change_control, .notes, .phase0_artifact_boundary.object_identity_update)' "${base_source}")" ]] \
      && [[ "$(jq -S '.notes[2:]' "${vendor_source}")" == \
        "$(jq -S '.notes[2:]' "${base_source}")" ]] \
      && jq -e '
        .notes[0] == "The base-owned policy freezes immutable roots and requires exact head-object resealing for evolvable proof machinery; declarative Cargo inputs and the boundary descriptor are commit-bound evidence, not independent approval."
        and .notes[1] == "The trusted-base checker validates every protected head object without executing pull-request code. The repository has one maintainer identity shared by its agents, so change control records exact objects and never pretends that self-review is an independent security boundary."
      ' "${base_source}" >/dev/null; then
      closed_inputs_prior_vendor=1
    fi
    if [[ "${closed_inputs_prior_vendor}" != "1" ]]; then
      echo "::error file=${vendor_rel}::closed-input migration requires the prior iOS vendor until theyos lands"
      exit 1
    fi
    migration_pinned="${TMP_DIR}/closed-input-pinned-${INDEX}"
    if ! materialize_regular_blob \
      "${THEYOS_DIR}" "${PIN}" "${source_rel}" "${migration_pinned}" \
      "authority status at the iOS pin" \
      || ! cmp -s "${vendor_source}" "${migration_pinned}"; then
      echo "::error file=${PIN_REL}::closed-input migration requires iOS to remain pinned to its prior vendor"
      exit 1
    fi
    echo "Closed-input bootstrap: land theyos before updating the iOS authority-status vendor and pin."
    continue
  fi

  if [[ "${vendor_exists}" != "1" ]]; then
    if [[ "${RETIREMENT_BOOTSTRAP}" == "1" ]]; then
      retirement_dependency="${TMP_DIR}/retirement-dependency-${INDEX}"
      if ! materialize_regular_blob \
        "${THEYOS_DIR}" "${BASE_SHA}" "${source_rel}" "${retirement_dependency}" \
        "historical dependency at the trusted PR base" \
        || ! cmp -s "${head_source}" "${retirement_dependency}"; then
        echo "::error file=${source_rel}::missing historical vendor requires a byte-identical source at the trusted PR base"
        exit 1
      fi
      echo "Retirement bootstrap: ${source_rel} may be vendored only after the Phase 0 authority lands."
      continue
    fi
    if [[ "${registration_new}" == "1" ]]; then
      echo "::error file=${vendor_rel}::existing authoritative source must already have a matching vendor before registration"
    else
      echo "::error file=${vendor_rel}::iOS vendor is missing for ${source_rel}"
    fi
    exit 1
  fi

  if [[ "${registration_new}" == "1" ]]; then
    echo "Registration bootstrap will be verified strictly: ${source_rel}"
  fi

  pinned_source="${TMP_DIR}/pinned-${INDEX}"
  if ! materialize_regular_blob \
    "${THEYOS_DIR}" "${PIN}" "${source_rel}" "${pinned_source}" \
    "fixture at the iOS pin"; then
    if [[ "${registration_new}" == "1" ]]; then
      echo "::error file=${PIN_REL}::registration bootstrap pin ${PIN} does not contain ${source_rel}"
    else
      echo "::error file=${PIN_REL}::iOS pin ${PIN} does not contain ${source_rel}"
    fi
    exit 1
  fi
  if ! cmp -s "${pinned_source}" "${vendor_source}"; then
    echo "::error file=${vendor_rel}::vendor differs from its pinned theyos source ${PIN}"
    diff -u "${pinned_source}" "${vendor_source}" || true
    exit 1
  fi
  if ! cmp -s "${head_source}" "${vendor_source}"; then
    echo "::error file=${source_rel}::theyos HEAD differs from the landed iOS vendor"
    diff -u "${head_source}" "${vendor_source}" || true
    exit 1
  fi
  if [[ "${registration_new}" == "1" ]]; then
    echo "Verified strict registration bootstrap: ${source_rel} <-> ${vendor_rel}"
  else
    echo "Verified ODB pair: ${source_rel} <-> ${vendor_rel}"
  fi
done

echo "Mobile owner-present cross-repo contract ownership is closed."
