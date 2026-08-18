#!/usr/bin/env bash
# Mutations for the structural Phase 0 build boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKER_REL=".github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"
WORKFLOW_REL=".github/workflows/owner-present-phase0-compileout.yml"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/theyos-owner-present-phase0-test.XXXXXX")"
trap 'chmod -R u+w "${TMP_ROOT}" 2>/dev/null || true; rm -rf "${TMP_ROOT}"' EXIT

# The structural boundary used to execute its whole mutation matrix in one
# job. External cancellation cut that run after 49 controls, despite the
# workflow's 120-minute YAML timeout. Split it into four bounded shards, but
# make the split a proof rather than four independent partial greens: every
# passing control emits one exact label, each label belongs to exactly one
# shard, and the composer rejects missing, duplicate, skipped, or unexpected
# labels before it permits the route composer to run.
STRUCTURAL_MODE="${PHASE0_STRUCTURAL_MODE:-run}"
STRUCTURAL_SHARD="${PHASE0_STRUCTURAL_SHARD:-all}"
REQUIRE_ALL="${PHASE0_REQUIRE_ALL:-0}"
CONTROL_REPORT="${PHASE0_CONTROL_REPORT:-}"
REPORT_DIR="${PHASE0_CONTROL_REPORT_DIR:-}"
EXECUTION_TRACE="${PHASE0_EXECUTION_TRACE:-}"
EFFECT_TRACE="${PHASE0_EFFECT_TRACE:-}"

CONTROL_LAYOUT=(
  '0:shard_coverage_selftest'
  '0:release_workflow_context_and_push_auth_contract'
  '0:store_reporter_oracle_selftest'
  '0:build_cfg_oracle_selftest'
  '0:release_dev_feature_refused'
  '0:external_cross_container_opts_refused'
  '0:DOCKER_HOST_refused'
  '0:DOCKER_CONTEXT_refused'
  '0:DOCKER_CONFIG_refused'
  '0:phase0_rustup_home_refused'
  '0:path_tool_injection_ignored'
  '0:path_git_injection_ignored'
  '0:path_docker_injection_ignored'
  '0:target_specific_rustflags_refused'
  '0:cargo_home_config_refused'
  '1:module_crossing_refused'
  '1:composer_route_crossing_refused'
  '1:middleware_interception_blocked_before_effect'
  '1:middleware_without_outer_guard_refused'
  '1:main_listener_bypass_refused'
  '1:household_listener_bypass_refused'
  '1:macos_local_listener_bypass_refused'
  '1:install_listener_bypass_refused'
  '1:llm_proxy_listener_bypass_refused'
  '1:relay_public_listener_bypass_refused'
  '1:new_unclosed_listener_refused'
  '1:linked_ip_tunnel_seam_refused'
  '1:generic_ip_tunnel_store_refused'
  '1:build_cfg_crossing_refused'
  '2:build_tool_codegen_refused'
  '2:new_build_script_refused'
  '2:custom_named_build_script_refused'
  '2:local_proc_macro_refused'
  '2:external_include_refused'
  '2:allow_alias_escape_refused'
  '2:absolute_external_include_refused'
  '2:manifest_override_refused'
  '2:cargo_config_override_refused'
  '2:cross_pre_build_refused'
  '2:git_source_dependency_refused'
  '2:environment_clear_removal_refused'
  '2:external_path_dependency_refused'
  '2:ancestor_cargo_config_refused'
  '2:above_repo_cargo_config_refused'
  '2:workspace_cargo_alias_refused'
  '3:release_recipe_drift_refused'
  '3:release_subject_bypass_refused'
  '3:alternate_publisher_refused'
  '3:issuer_bridge_known'
  '3:issuer_bridge_publisher_refused'
  '3:issuer_bridge_other_apple_secret_refused'
  '3:issuer_bridge_apns_capability_refused'
  '3:activation_marker_refused'
  '3:v1_authority_refused'
)

control_shard() {
  local wanted="$1" entry shard control
  for entry in "${CONTROL_LAYOUT[@]}"; do
    shard="${entry%%:*}"
    control="${entry#*:}"
    if [[ "${control}" == "${wanted}" ]]; then
      printf '%s\n' "${shard}"
      return 0
    fi
  done
  echo "error: Phase 0 structural control is not declared: ${wanted}" >&2
  return 1
}

control_selected() {
  local wanted="$1" assigned
  assigned="$(control_shard "${wanted}")"
  [[ "${STRUCTURAL_SHARD}" == all || "${STRUCTURAL_SHARD}" == "${assigned}" ]]
}

expected_controls_for_shard() {
  local wanted_shard="$1" entry
  for entry in "${CONTROL_LAYOUT[@]}"; do
    if [[ "${entry%%:*}" == "${wanted_shard}" ]]; then
      printf '%s\n' "${entry#*:}"
    fi
  done | LC_ALL=C sort
}

expected_controls_all() {
  local entry
  for entry in "${CONTROL_LAYOUT[@]}"; do
    printf '%s\n' "${entry#*:}"
  done | LC_ALL=C sort
}

pass_control() {
  local control="$1" suffix="${2:-}"
  control_shard "${control}" >/dev/null
  control_selected "${control}" || {
    echo "error: unselected control reached pass_control: ${control}" >&2
    exit 1
  }
  if [[ "${ACTIVE_CONTROL:-}" != "${control}" ]]; then
    echo "error: control reported outside its execution gate: ${control}" >&2
    exit 1
  fi
  if [[ -n "${EXECUTION_TRACE}" ]] \
      && ! grep -Fxq -- "${control}" "${EXECUTION_TRACE}"; then
    echo "error: selected control reported without an execution trace: ${control}" >&2
    exit 1
  fi
  if [[ -n "${CONTROL_REPORT}" ]]; then
    printf '%s\n' "${control}" >>"${CONTROL_REPORT}"
  fi
  printf 'PASS %s%s\n' "${control}" "${suffix}"
  unset ACTIVE_CONTROL
}

# Every control body must enter through this gate before it allocates a clone,
# starts a checker, invokes Cargo/Docker, or mutates a fixture.  A shard may
# only trace its declared controls; pass_control then refuses to report a
# label that never entered here.  This is deliberately a gate on execution,
# not a filter on reporting.
begin_control() {
  local control="$1"
  control_shard "${control}" >/dev/null
  control_selected "${control}" || return 1
  if [[ -n "${ACTIVE_CONTROL:-}" ]]; then
    echo "error: control body entered while another control remains active: ${ACTIVE_CONTROL}" >&2
    exit 1
  fi
  if [[ -n "${EXECUTION_TRACE}" ]]; then
    if grep -Fxq -- "${control}" "${EXECUTION_TRACE}"; then
      echo "error: control body entered twice: ${control}" >&2
      exit 1
    fi
    printf '%s\n' "${control}" >>"${EXECUTION_TRACE}"
  fi
  ACTIVE_CONTROL="${control}"
  export ACTIVE_CONTROL
  return 0
}

require_active_control() {
  local active="${ACTIVE_CONTROL:-}" assigned
  if [[ -z "${active}" ]]; then
    echo "error: an effectful structural operation ran outside a selected control" >&2
    exit 1
  fi
  assigned="$(control_shard "${active}")"
  if [[ "${STRUCTURAL_SHARD}" != all && "${assigned}" != "${STRUCTURAL_SHARD}" ]]; then
    echo "error: effectful operation belongs to shard ${assigned}, not selected shard ${STRUCTURAL_SHARD}" >&2
    exit 1
  fi
  if ! control_selected "${active}"; then
    echo "error: active control is not selected: ${active}" >&2
    exit 1
  fi
}

record_effect() {
  local boundary="$1"
  require_active_control
  [[ "${boundary}" =~ ^[a-z0-9_-]+$ ]] || {
    echo "error: invalid effect boundary" >&2
    exit 1
  }
  if [[ -n "${EFFECT_TRACE}" ]]; then
    printf '%s\t%s\n' "${ACTIVE_CONTROL}" "${boundary}" >>"${EFFECT_TRACE}"
  fi
}

# These are intentionally defined before the execution-gate selftest below.
# The selftest calls the same helpers the matrix calls; it must never pass by
# attempting an as-yet undefined shell function.
clone_head() {
  local destination="$1"
  record_effect clone
  git clone --quiet --shared --no-checkout "${REPO_ROOT}" "${destination}"
  git -C "${destination}" checkout --quiet "$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  git -C "${destination}" config user.name "phase0-compileout-test"
  git -C "${destination}" config user.email "phase0-compileout@example.invalid"
}

run_checker() {
  record_effect checker
  if [[ "${PHASE0_BUILD_TOOL:-}" == cross ]]; then
    record_effect docker
  fi
  env -u CARGO_HOME -u RUSTUP_HOME -u PHASE0_RUSTUP_HOME "$@"
}

run_cargo() {
  record_effect cargo
  cargo "$@"
}

run_build_tool() {
  record_effect build-tool
  "${BUILD_TOOL_BIN}" "$@"
}

commit_mutation() {
  local root="$1" label="$2"
  record_effect mutation
  record_effect commit
  git -C "${root}" add -A
  git -C "${root}" commit --quiet -m "${label}"
}

assert_selected_shard_complete() {
  [[ -n "${CONTROL_REPORT}" ]] || return 0
  local expected="${TMP_ROOT}/expected-${STRUCTURAL_SHARD}.txt"
  local actual="${TMP_ROOT}/actual-${STRUCTURAL_SHARD}.txt"
  expected_controls_for_shard "${STRUCTURAL_SHARD}" >"${expected}"
  LC_ALL=C sort "${CONTROL_REPORT}" >"${actual}"
  if [[ -n "$(uniq -d "${actual}")" ]]; then
    echo "error: structural shard emitted a duplicate control" >&2
    exit 1
  fi
  if ! cmp -s "${expected}" "${actual}"; then
    echo "error: structural shard report is not its exact expected control set" >&2
    diff -u "${expected}" "${actual}" || true
    exit 1
  fi
  if [[ -n "${EXECUTION_TRACE}" ]]; then
    local trace="${TMP_ROOT}/trace-${STRUCTURAL_SHARD}.txt"
    LC_ALL=C sort "${EXECUTION_TRACE}" >"${trace}"
    if [[ -n "$(uniq -d "${trace}")" ]] || ! cmp -s "${expected}" "${trace}"; then
      echo "error: structural shard execution trace is not its exact expected control set" >&2
      diff -u "${expected}" "${trace}" || true
      exit 1
    fi
  fi
  if [[ -n "${EFFECT_TRACE}" ]]; then
    local effect_control effect_boundary
    while IFS=$'\t' read -r effect_control effect_boundary || [[ -n "${effect_control}${effect_boundary}" ]]; do
      [[ "${effect_control}" =~ ^[A-Za-z0-9_]+$ && "${effect_boundary}" =~ ^[a-z0-9_-]+$ ]] || {
        echo "error: malformed structural effect trace" >&2
        exit 1
      }
      [[ "$(control_shard "${effect_control}")" == "${STRUCTURAL_SHARD}" ]] || {
        echo "error: structural effect belongs to the wrong shard" >&2
        exit 1
      }
      grep -Fxq -- "${effect_control}" "${expected}" || {
        echo "error: structural effect has no selected control" >&2
        exit 1
      }
    done <"${EFFECT_TRACE}"
  fi
}

verify_shard_reports() {
  local reports="$1" expected="${TMP_ROOT}/coverage-expected.txt"
  local actual="${TMP_ROOT}/coverage-actual.txt" report trace effects shard effect_control effect_boundary
  [[ "${REQUIRE_ALL}" == 1 ]] || {
    echo "error: structural report composition requires PHASE0_REQUIRE_ALL=1" >&2
    return 1
  }
  expected_controls_all >"${expected}"
  : >"${actual}"
  for shard in 0 1 2 3; do
    report="${reports}/structural-shard-${shard}.txt"
    trace="${reports}/structural-shard-${shard}.trace"
    effects="${reports}/structural-shard-${shard}.effects"
    [[ -f "${report}" && -s "${report}" ]] || {
      echo "error: REQUIRE_ALL missing structural shard report ${shard}" >&2
      return 1
    }
    [[ -f "${trace}" && -s "${trace}" ]] || {
      echo "error: REQUIRE_ALL missing structural shard execution trace ${shard}" >&2
      return 1
    }
    if ! cmp -s <(LC_ALL=C sort "${report}") <(LC_ALL=C sort "${trace}"); then
      echo "error: structural shard report and execution trace differ" >&2
      return 1
    fi
    [[ -f "${effects}" ]] || {
      echo "error: REQUIRE_ALL missing structural shard effect trace ${shard}" >&2
      return 1
    }
    while IFS=$'\t' read -r effect_control effect_boundary || [[ -n "${effect_control}${effect_boundary}" ]]; do
      [[ "${effect_control}" =~ ^[A-Za-z0-9_]+$ && "${effect_boundary}" =~ ^[a-z0-9_-]+$ ]] || return 1
      [[ "$(control_shard "${effect_control}")" == "${shard}" ]] || return 1
      grep -Fxq -- "${effect_control}" "${report}" || return 1
    done <"${effects}"
    while IFS= read -r control || [[ -n "${control}" ]]; do
      [[ "${control}" =~ ^[A-Za-z0-9_]+$ ]] || {
        echo "error: unexpected structural shard report record" >&2
        return 1
      }
      [[ "$(control_shard "${control}")" == "${shard}" ]] || {
        echo "error: unexpected structural control in shard report" >&2
        return 1
      }
      printf '%s\n' "${control}" >>"${actual}"
    done <"${report}"
  done
  LC_ALL=C sort -o "${actual}" "${actual}"
  if [[ -n "$(uniq -d "${actual}")" ]]; then
    echo "error: structural shard intersection is non-empty" >&2
    return 1
  fi
  if comm -13 "${expected}" "${actual}" | grep -q .; then
    echo "error: structural shard report contains an unexpected control" >&2
    return 1
  fi
  if comm -23 "${expected}" "${actual}" | grep -q .; then
    echo "error: structural shard reports are missing an expected control" >&2
    return 1
  fi
}

coverage_selftest() {
  local fixture="${TMP_ROOT}/coverage-fixture" expected_label effect_counter saved_shard
  mkdir -p "${fixture}"
  for shard in 0 1 2 3; do
    expected_controls_for_shard "${shard}" >"${fixture}/structural-shard-${shard}.txt"
    cp "${fixture}/structural-shard-${shard}.txt" "${fixture}/structural-shard-${shard}.trace"
    : >"${fixture}/structural-shard-${shard}.effects"
  done
  REQUIRE_ALL=1 verify_shard_reports "${fixture}"
  sed -i.bak '$d' "${fixture}/structural-shard-0.txt"
  rm -f "${fixture}/structural-shard-0.txt.bak"
  if REQUIRE_ALL=1 verify_shard_reports "${fixture}" >/dev/null 2>&1; then
    echo "error: coverage accepted a missing control under REQUIRE_ALL" >&2
    exit 1
  fi
  expected_controls_for_shard 0 >"${fixture}/structural-shard-0.txt"
  cp "${fixture}/structural-shard-0.txt" "${fixture}/structural-shard-0.trace"
  expected_label="$(head -n 1 "${fixture}/structural-shard-0.txt")"
  printf '%s\n' "${expected_label}" >>"${fixture}/structural-shard-1.txt"
  if REQUIRE_ALL=1 verify_shard_reports "${fixture}" >/dev/null 2>&1; then
    echo "error: coverage accepted an intersection or duplicate" >&2
    exit 1
  fi
  expected_controls_for_shard 1 >"${fixture}/structural-shard-1.txt"
  cp "${fixture}/structural-shard-1.txt" "${fixture}/structural-shard-1.trace"
  printf 'unexpected_control\n' >>"${fixture}/structural-shard-2.txt"
  if REQUIRE_ALL=1 verify_shard_reports "${fixture}" >/dev/null 2>&1; then
    echo "error: coverage accepted an unexpected control" >&2
    exit 1
  fi
  expected_controls_for_shard 2 >"${fixture}/structural-shard-2.txt"
  cp "${fixture}/structural-shard-2.txt" "${fixture}/structural-shard-2.trace"
  printf 'SKIP %s\n' "${expected_label}" >>"${fixture}/structural-shard-0.txt"
  if REQUIRE_ALL=1 verify_shard_reports "${fixture}" >/dev/null 2>&1; then
    echo "error: coverage accepted both PASS and SKIP records" >&2
    exit 1
  fi
  expected_controls_for_shard 0 >"${fixture}/structural-shard-0.txt"
  cp "${fixture}/structural-shard-0.txt" "${fixture}/structural-shard-0.trace"
  rm -f "${fixture}/structural-shard-3.txt"
  if REQUIRE_ALL=1 verify_shard_reports "${fixture}" >/dev/null 2>&1; then
    echo "error: coverage accepted a skipped shard under REQUIRE_ALL" >&2
    exit 1
  fi
  # This is an execution, not reporting, probe.  While shard 0 is selected,
  # a shard-3 control must not even enter its body: the counter remains absent.
  # The real mutation helpers additionally enforce this at every clone/checker/
  # Cargo boundary through require_active_control.
  saved_shard="${STRUCTURAL_SHARD}"
  STRUCTURAL_SHARD=0
  effect_counter="${fixture}/unselected-control-effect-count"
  if control_selected issuer_bridge_known; then
    printf 'unexpected execution\n' >"${effect_counter}"
  fi
  if [[ -e "${effect_counter}" ]]; then
    echo "error: an unselected structural control executed during the shard selftest" >&2
    exit 1
  fi
  STRUCTURAL_SHARD="${saved_shard}"
  pass_control shard_coverage_selftest
}

execution_gate_selftest() {
  local fixture="${TMP_ROOT}/execution-gate-fixture" saved_shard marker fake_bin boundary stderr rc
  mkdir -p "${fixture}"
  fake_bin="${fixture}/bin"
  mkdir -p "${fake_bin}"
  marker="${fixture}/excluded-boundary-ran"
  printf '%s\n' '#!/bin/sh' 'touch "$PHASE0_GATE_MARKER"' >"${fake_bin}/cargo"
  printf '%s\n' '#!/bin/sh' 'touch "$PHASE0_GATE_MARKER"' >"${fake_bin}/git"
  chmod 700 "${fake_bin}/cargo" "${fake_bin}/git"

  # Deliberately forge a declared but excluded control.  Each attempted helper
  # must fail before it can create a clone, invoke Cargo/checker/build-tool, or
  # commit a mutation.  The executable sentinels make a false green visible as
  # a filesystem effect, rather than trusting a report counter.
  saved_shard="${STRUCTURAL_SHARD}"
  STRUCTURAL_SHARD=0
  for boundary in cargo checker clone build-tool docker commit; do
    rm -f "${marker}"
    stderr="${fixture}/${boundary}.stderr"
    set +e
    (
      export ACTIVE_CONTROL=issuer_bridge_known PHASE0_GATE_MARKER="${marker}" PATH="${fake_bin}:${PATH}"
      case "${boundary}" in
        cargo) run_cargo --version ;;
        checker) run_checker "${fake_bin}/cargo" --checker ;;
        clone) clone_head "${fixture}/forbidden-clone" ;;
        build-tool) BUILD_TOOL_BIN="${fake_bin}/cargo"; run_build_tool --build-tool ;;
        docker) record_effect docker; "${fake_bin}/cargo" --docker ;;
        commit) commit_mutation "${fixture}" forbidden ;;
      esac
    ) >"${fixture}/${boundary}.stdout" 2>"${stderr}"
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 ]]; then
      echo "error: execution gate accepted excluded ${boundary} boundary" >&2
      exit 1
    fi
    if [[ "${rc}" -ne 1 ]] \
        || ! grep -Fq 'effectful operation belongs to shard 3, not selected shard 0' "${stderr}" \
        || grep -Fq 'command not found' "${stderr}"; then
      echo "error: excluded ${boundary} did not fail by the selected-control guard" >&2
      cat "${stderr}" >&2
      exit 1
    fi
    if [[ -e "${marker}" || -e "${fixture}/forbidden-clone" ]]; then
      echo "error: excluded ${boundary} boundary created or executed an effect" >&2
      exit 1
    fi
  done
  STRUCTURAL_SHARD="${saved_shard}"
  echo "Owner-present Phase 0 excluded-control execution gate passed."
}

source_audit() {
  local source="${BASH_SOURCE[0]}" workflow="${REPO_ROOT}/${WORKFLOW_REL}" required
  # Every process boundary in the matrix is centralized in a helper that calls
  # record_effect, so a control cannot use the expensive paths without an
  # active, selected owner.  Keep this audit textual and fail-closed: a new
  # direct command requires an intentional helper/audit update.
  for required in \
    'clone_head()' 'record_effect clone' \
    'run_checker()' 'record_effect checker' \
    'record_effect docker' \
    'run_cargo()' 'record_effect cargo' \
    'run_build_tool()' 'record_effect build-tool' \
    'commit_mutation()' 'record_effect mutation' 'record_effect commit' \
    'record_effect gh-auth'; do
    grep -Fq -- "${required}" "${source}" || {
      echo "error: execution-gate source audit missing ${required}" >&2
      exit 1
    }
  done
  if grep -nE '^[[:space:]]*(cargo|git)[[:space:]]+(test|check|build|clone|commit|generate-lockfile)' "${source}" \
      | grep -Fv 'cargo "$@"' | grep -Fv 'git clone --quiet' | grep -Fv 'git -C "${root}"' | grep -q .; then
    echo "error: source audit found a direct Cargo/Git structural effect outside a guarded helper" >&2
    exit 1
  fi
  for required in \
    'PHASE0_EXECUTION_TRACE=' 'PHASE0_EFFECT_TRACE=' \
    'Prove excluded controls cannot execute a boundary' \
    'structural-shard-${{ matrix.shard }}.effects'; do
    grep -Fq -- "${required}" "${workflow}" || {
      echo "error: source audit missing structural execution evidence: ${required}" >&2
      exit 1
    }
  done
  echo "Owner-present Phase 0 structural source audit passed."
}

if [[ "${STRUCTURAL_MODE}" == compose ]]; then
  [[ -n "${REPORT_DIR}" ]] || {
    echo "error: structural report composition needs PHASE0_CONTROL_REPORT_DIR" >&2
    exit 1
  }
  verify_shard_reports "${REPORT_DIR}"
  echo "Owner-present Phase 0 structural shard coverage passed."
  exit 0
fi
if [[ "${STRUCTURAL_MODE}" == coverage-selftest ]]; then
  begin_control shard_coverage_selftest
  coverage_selftest
  echo "Owner-present Phase 0 structural shard coverage selftest passed."
  exit 0
fi
if [[ "${STRUCTURAL_MODE}" == execution-gate-selftest ]]; then
  execution_gate_selftest
  source_audit
  exit 0
fi
if [[ "${REQUIRE_ALL}" == 1 ]]; then
  [[ "${STRUCTURAL_SHARD}" =~ ^[0-3]$ && -n "${CONTROL_REPORT}" \
      && -n "${EXECUTION_TRACE}" && -n "${EFFECT_TRACE}" ]] || {
    echo "error: REQUIRE_ALL needs one declared structural shard plus report, execution trace, and effect trace paths" >&2
    exit 1
  }
  : >"${CONTROL_REPORT}"
  : >"${EXECUTION_TRACE}"
  : >"${EFFECT_TRACE}"
fi

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
if control_selected release_workflow_context_and_push_auth_contract; then
begin_control release_workflow_context_and_push_auth_contract
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
for structural_binding in \
  'structural-shard:' \
  'shard: [0, 1, 2, 3]' \
  'PHASE0_REQUIRE_ALL=1' \
  'PHASE0_STRUCTURAL_MODE=compose' \
  'structural-coverage:' \
  'structural-route-composer:' \
  'needs: [structural-shard, structural-coverage]'; do
  if ! grep -Fq -- "${structural_binding}" "${REPO_ROOT}/${WORKFLOW_REL}"; then
    echo "error: structural shard workflow binding is missing: ${structural_binding}" >&2
    exit 1
  fi
done
if [[ "$(grep -Fc 'if: always()' "${REPO_ROOT}/${WORKFLOW_REL}")" -lt 2 ]]; then
  echo "error: structural coverage and route composer must run fail-closed after every shard outcome" >&2
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
record_effect gh-auth
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
pass_control release_workflow_context_and_push_auth_contract
fi
if [[ "${HOST_TARGET}" == *-apple-darwin ]]; then
  PHASE0_EXPECTED_XCODE_VERSION="${PHASE0_EXPECTED_XCODE_VERSION:-$(xcodebuild -version | sed -n 's/^Xcode //p')}"
  PHASE0_EXPECTED_XCODE_BUILD="${PHASE0_EXPECTED_XCODE_BUILD:-$(xcodebuild -version | sed -n 's/^Build version //p')}"
  PHASE0_EXPECTED_MACOS_SDK_VERSION="${PHASE0_EXPECTED_MACOS_SDK_VERSION:-$(xcrun --sdk macosx --show-sdk-version)}"
  PHASE0_EXPECTED_DEVELOPER_DIR="${PHASE0_EXPECTED_DEVELOPER_DIR:-$(xcode-select -p)}"
  export PHASE0_EXPECTED_XCODE_VERSION PHASE0_EXPECTED_XCODE_BUILD \
    PHASE0_EXPECTED_MACOS_SDK_VERSION PHASE0_EXPECTED_DEVELOPER_DIR
fi

prepare_empty_authority_inputs() {
  # The frozen CARGO_HOME is `chmod -R a-w`, so every source cargo copies out of
  # it lands 0444 in the target dir (fs::copy propagates the mode). Clearing the
  # target for the next mutation therefore needs u+w first.
  #
  # What u+w applies to is the build's own OUTPUT directory, which the build has
  # always been allowed to write — it is not a relaxation of the boundary. The
  # read-only posture the boundary actually enforces lives on the INPUTS
  # (SNAPSHOT, BUILD_SNAPSHOT, CARGO_HOME), which stay a-w and are never touched
  # here.
  chmod -R u+w "${AUTHORITY_TARGET}" 2>/dev/null || true
  rm -rf "${AUTHORITY_TARGET}"
  mkdir -p "${AUTHORITY_TARGET}"
}

prepare_route_test_target() {
  # ROUTE_TEST_TARGET is reused across every route command instead of being
  # recreated, because these builds are the expensive ones and the cache is what
  # keeps this suite affordable. Reuse is exactly why it needs u+w: the previous
  # command left 0444 copies behind (same fs::copy propagation as above), and the
  # next one cannot overwrite them — that is the libsqlite3-sys PermissionDenied
  # that killed the build and masked the negative control for 9 commits.
  #
  # Deliberately no `rm -rf`: clearing it would restore correctness by throwing
  # the cache away, which is the fix we are not making. Same scope as above —
  # this is the build's own output dir, and the frozen inputs are untouched.
  mkdir -p "${ROUTE_TEST_TARGET}"
  chmod -R u+w "${ROUTE_TEST_TARGET}" 2>/dev/null || true
}

assert_route_test_verdict() {
  # Used by every negative control in this script that runs a real test, route or
  # not. A non-zero exit from `cargo test` proves nothing on its own here: these
  # tests are SUPPOSED to fail, and a build that dies before libtest ever starts
  # exits non-zero too. Worse, cargo's own diagnostics quote the test name being
  # filtered, so a substring match on that name accepts build death as a semantic
  # negative — a false green in the one control that exists to catch false
  # greens.
  #
  # Only the exact libtest verdict line proves the test ran AND rejected the
  # mutation. It is checked first precisely because it is positive evidence: a
  # test that really failed can never be reclassified as a harness fault by a
  # stray 'error:' in its panic output. Everything else is inconclusive, and is
  # reported as inconclusive — never as success.
  local label="$1" test_name="$2" log="$3"
  if grep -Eq "^test ${test_name} \.\.\. FAILED$" "${log}"; then
    pass_control "${label}_refused"
    return
  fi
  if grep -Fq "failed to run custom build command" "${log}"; then
    echo "error: ${label} HARNESS FAILURE — the build died before libtest started (failed to run custom build command); '${test_name}' never ran, so the negative control is INCONCLUSIVE, not satisfied. Fix the harness, not the expectation." >&2
    cat "${log}" >&2
    exit 1
  fi
  if grep -Eq '^error(\[E[0-9]+\])?: |^error: could not compile ' "${log}"; then
    echo "error: ${label} HARNESS FAILURE — the selected test did not compile, so '${test_name}' never ran. The negative control is INCONCLUSIVE, not satisfied." >&2
    cat "${log}" >&2
    exit 1
  fi
  echo "error: ${label} UNKNOWN — cargo test exited non-zero but the log has no '^test ${test_name} ... FAILED' verdict and no recognizable build failure. The mutation was NOT proven refused; this is inconclusive, never a pass." >&2
  cat "${log}" >&2
  exit 1
}

classify_store_reporter_verdict() {
  # #477. The store mutation is refused through TWO channels and the checker can
  # only ever reach one of them. `check-...compileout.sh` runs `cargo test` long
  # before it reaches its own artifact-contract report, and it is `set -e`: when
  # the mutation makes the test fail, the checker dies at the test and the report
  # line is never printed. The expectation was not stale — the reporter is
  # structurally unreachable. Measured on the real log of job 93385423348: the
  # report string appears 0 times, whole-line and substring alike.
  #
  # Both channels assert the SAME property. The report says the published
  # artifact contract is not status-only; the test asserts on `artifact_contract`
  # that authority is none and the only exposed route is the status one. Accepting
  # either is not a widening — it is naming the second enforcement point of one
  # property.
  #
  # Whole-line FIXED comparison on both PASS channels. Not regex: `...` is three
  # metacharacters, and the forgotten spelling matches any three characters —
  # the exact looseness this suite exists to catch, inside the fix for it.
  #
  # The order below is: the two exact PASS channels, then build death, then
  # recognised compile death, then WRONG_TEST. Two of those relationships are
  # exercised by fixtures in this file; the rest are arrangement.
  #
  #   exact PASS before WRONG_TEST   — moving WRONG_TEST above the PASS channels
  #     turns `verdict_line`, `order_verdict_beats_wrong_test` and
  #     `verdict_survives_cargo_epilogue` red. Its pattern matches OUR name too.
  #   compile before WRONG_TEST      — swapping those two turns
  #     `compile_evidence_beats_wrong_test` red.
  #
  # BUILD currently precedes COMPILE, and no fixture distinguishes that pair:
  # swapping them changes no result here, because the build-death fixture
  # matches none of the compile signatures. No claim is made about it.
  #
  # Precedence alone cannot separate compile death from a wrong test. `^error: `
  # matches cargo's test epilogue `error: test failed, to rerun pass ...`, which
  # accompanied the failing test in the log measured for #477 and which says
  # nothing about compilation. Under that broad pattern the wrong-test fixtures
  # carrying the epilogue classified as compile death and WRONG_TEST did not
  # fire on them — the same structural unreachability #477 exists to fix,
  # reproduced inside the fix. The two branches are therefore separated by
  # EVIDENCE, not by order: only a signature that rustc or cargo emits when a
  # unit fails to build counts as compile death.
  #
  # Pure: echoes a reason and returns a status, paired — 0 with each PASS
  # reason, 1 with each rejection reason. The caller returns on a PASS pair and,
  # only on the others, prints a diagnostic, dumps the log and exits.
  local test_name="$1" checker_line="$2" log="$3"
  if grep -Fxq "${checker_line}" "${log}"; then
    echo PASS_CHECKER
    return 0
  fi
  if grep -Fxq "test ${test_name} ... FAILED" "${log}"; then
    echo PASS_VERDICT
    return 0
  fi
  if grep -Fq "failed to run custom build command" "${log}"; then
    echo HARNESS_FAILURE_BUILD
    return 1
  fi
  if grep -Eq '^error\[E[0-9]+\]: |^error: could not compile |^error: aborting due to |^error: linking with ' "${log}"; then
    echo HARNESS_FAILURE_COMPILE
    return 1
  fi
  if grep -Eq '^test mobile_claw_vpn_phase0_[a-z0-9_]+ \.\.\. FAILED$' "${log}"; then
    echo WRONG_TEST
    return 1
  fi
  echo UNKNOWN
  return 1
}

describe_wrong_test() {
  # The classifier already matched a line; the reader should not have to search
  # the full log dump for the thing a regex found a moment earlier. Print BOTH
  # complete lines — what was expected and what was actually there — because the
  # whole point of this control is that a message must name what happened.
  local test_name="$1" log="$2" observed
  observed="$(grep -Em1 '^test mobile_claw_vpn_phase0_[a-z0-9_]+ \.\.\. FAILED$' "${log}")"
  echo "expected: test ${test_name} ... FAILED"
  echo "observed: ${observed}"
}

selftest_store_reporter() {
  # Durable controls for the classifier above, run before any mutation so a
  # broken oracle costs seconds instead of a full matrix. Synthetic by design:
  # they must keep working with no network, no CI artefact and no external
  # fixture.
  #
  # The fixtures below are written from literals in this function. What differs
  # between them is where the shape came from, and that is worth knowing before
  # reading a green as reassurance.
  #
  # One shape is mirrored from a retained log: the verdict fixture reproduces the
  # line from job 93385423348, the run in which this control failed. The compile
  # signatures are the forms rustc and cargo document; the remaining cases were
  # constructed in review — a carriage return, interleaved stderr, an indented
  # verdict, the report without its annotation, a wrong test. For those, no log
  # is retained here, and nothing is asserted about whether they have occurred.
  #
  # What a green here establishes is narrow and exact: the classifier assigns
  # these reasons and statuses to these bytes. It says nothing about how often
  # any shape appears, or whether one has ever been survived in a real run.
  local dir="${TMP_ROOT}/store-reporter-selftest"
  local name=mobile_claw_vpn_phase0_exposes_only_authenticated_unavailable_status
  local report='::error::published theyos-engine Phase 0 artifact contract is not status-only'
  local verdict="test ${name} ... FAILED"
  local failed=0
  mkdir -p "${dir}"

  _expect() { # case_name expected_reason
    # Reason AND exit status, for every case. Asserting the reason alone left
    # half of the classifier's documented contract untested: at the time, every
    # caller discarded the status with `|| true`, so flipping a rejection's
    # `return 1` to `return 0` changed no verdict anywhere and no control went
    # red. The return value was free to drift out of agreement with the reason
    # it accompanies, and nothing would have said so.
    #
    # This assertion alone already guards the classifier's declared invariant:
    # the selftest runs before the matrix, so a mismatched status stops the run
    # here. Reading the pair in `expect_store_reporter_failure` as well adds
    # something different — detection of a divergence that appears while the
    # matrix is running, reported there as ORACLE FAILURE. Neither path turns a
    # mismatch into an accept.
    #
    # The status is captured through `if`, not `$(... || true)`: the substitution
    # form discards it, `||` would suppress the very thing being measured, and a
    # bare assignment dies under `set -e` before the pair can be inspected.
    local case_name="$1" expected="$2" got rc expected_rc=1
    [[ "${expected}" == PASS_* ]] && expected_rc=0
    if got="$(classify_store_reporter_verdict "${name}" "${report}" "${dir}/${case_name}.log")"; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${got}" != "${expected}" ]]; then
      echo "error: store reporter selftest ${case_name}: expected ${expected}, got ${got}" >&2
      failed=1
    fi
    if [[ "${rc}" -ne "${expected_rc}" ]]; then
      echo "error: store reporter selftest ${case_name}: ${expected} must exit ${expected_rc}, got rc=${rc}" >&2
      failed=1
    fi
  }

  _case() { # name expected line...
    local case_name="$1" expected="$2"
    shift 2
    printf '%s\n' "$@" >"${dir}/${case_name}.log"
    _expect "${case_name}" "${expected}"
  }

  _case report_line              PASS_CHECKER            'Phase 0 authority: snapshot ok' "${report}"
  _case verdict_line             PASS_VERDICT            'running 4 tests' "${verdict}"
  _case build_death              HARNESS_FAILURE_BUILD   "error: failed to run custom build command for \`server-rs\`"
  _case compile_failure          HARNESS_FAILURE_COMPILE "error[E0432]: unresolved import in ${name}"
  _case wrong_test               WRONG_TEST              'test mobile_claw_vpn_phase0_mutation_routes_are_absent ... FAILED'
  _case loose_substring          UNKNOWN                 "note: see test ${name} ... FAILED for details"
  _case indented_verdict         UNKNOWN                 "  ${verdict}"
  _case silent_nonzero           UNKNOWN                 'some unrelated failure'
  # stderr can interleave between libtest's `test NAME ... ` and its `FAILED`,
  # because the harness merges 2>&1 into one file. A split line must never pass.
  _case stderr_interleaved       UNKNOWN                 "test ${name} ... WARN dropping connFAILED"
  # The report without its ::error:: annotation is deliberately NOT a pass: the
  # accepted line is the one the checker actually emits. Fails red, never green.
  _case report_without_annotation UNKNOWN                'published theyos-engine Phase 0 artifact contract is not status-only'
  # Order, observed rather than asserted: each of these logs ALSO matches a later
  # classifier, and must still come out a pass.
  _case order_verdict_beats_wrong_test PASS_VERDICT      "${verdict}" 'test mobile_claw_vpn_phase0_mutation_routes_are_absent ... FAILED'
  # Named for what it pins, not for the ordering it used to justify: cargo's
  # epilogue accompanied the failing test in the log measured for #477 and must
  # not demote that genuine verdict. It still has teeth — moving WRONG_TEST above
  # the positives turns it red — but it no longer distinguishes the compile
  # branch's position.
  _case verdict_survives_cargo_epilogue PASS_VERDICT     "${verdict}" 'error: test failed, to rerun pass `-p server-rs --test claw_store_wire_contract`'
  # Reachability. Cargo printed its epilogue alongside the failing test in the
  # log measured for #477, so a wrong test is expected to arrive carrying it.
  # Under a `^error: ` compile pattern this fixture classified as compile death
  # and WRONG_TEST did not fire on it. The bare case above passes either way —
  # only this one distinguishes them.
  _case wrong_test_with_cargo_epilogue WRONG_TEST        'running 4 tests' \
    'test mobile_claw_vpn_phase0_mutation_routes_are_absent ... FAILED' \
    'failures:' \
    'error: test failed, to rerun pass `-p server-rs --test claw_store_wire_contract`'
  # ...and the narrowing must not cost the precedence it replaced: a recognised
  # compile signature still outranks a stale verdict line in the same log.
  _case compile_evidence_beats_wrong_test HARNESS_FAILURE_COMPILE \
    'test mobile_claw_vpn_phase0_mutation_routes_are_absent ... FAILED' \
    'error: could not compile `server-rs` (test) due to 1 previous error'
  _case compile_without_error_code     HARNESS_FAILURE_COMPILE \
    'error: expected one of `,` or `}`, found `;`' \
    'error: could not compile `server-rs` (test) due to 1 previous error'
  # The epilogue on its own says a test failed without saying which. That is
  # genuinely unknown, and calling it compile death would be the same lie.
  _case cargo_epilogue_alone           UNKNOWN           'running 4 tests' \
    'error: test failed, to rerun pass `-p server-rs --test claw_store_wire_contract`'
  # Both arms of the recogniser, pinned. Narrowing buys reachability for
  # WRONG_TEST and could pay for it by dropping compile signatures that carry no
  # error code and no `could not compile` line; these two constructed
  # compile-signature cases are the forms that would fall outside the narrowed
  # pattern, and they are asserted in the positive direction so the trade is
  # measured rather than assumed.
  _case compile_linker_failure         HARNESS_FAILURE_COMPILE \
    'error: linking with `cc` failed: exit status: 1'
  _case compile_aborting_due_to        HARNESS_FAILURE_COMPILE \
    'error: aborting due to 3 previous errors'

  # Written directly to make the CR line ending explicit at the call site —
  # `_case` can carry one, but it would be invisible among the other arguments.
  # Routed through the same assertion, so the status check covers it too.
  printf 'test %s ... FAILED\r\n' "${name}" >"${dir}/crlf_verdict.log"
  _expect crlf_verdict UNKNOWN

  # The diagnostic itself is a deliverable, so it is asserted like one.
  local expected_diagnostic observed_diagnostic
  expected_diagnostic="expected: test ${name} ... FAILED
observed: test mobile_claw_vpn_phase0_mutation_routes_are_absent ... FAILED"
  observed_diagnostic="$(describe_wrong_test "${name}" "${dir}/wrong_test_with_cargo_epilogue.log")"
  if [[ "${observed_diagnostic}" != "${expected_diagnostic}" ]]; then
    echo "error: store reporter selftest wrong_test_diagnostic: the message does not name both complete lines" >&2
    echo "--- expected ---" >&2; printf '%s\n' "${expected_diagnostic}" >&2
    echo "--- got ---" >&2;      printf '%s\n' "${observed_diagnostic}" >&2
    failed=1
  fi

  unset -f _case _expect
  rm -rf "${dir}"
  if [[ "${failed}" -ne 0 ]]; then
    echo "error: the store reporter oracle is broken; refusing to run the matrix with it." >&2
    exit 1
  fi
  pass_control store_reporter_oracle_selftest
}

expect_store_reporter_failure() {
  # #477 call form: the checker must refuse, and the refusal must be named by
  # one of the two channels above. Never a bare non-zero exit.
  local label="$1" test_name="$2" checker_line="$3" root="$4"
  control_selected "${label}_refused" || return 0
  prepare_empty_authority_inputs
  if PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      run_checker "${root}/${CHECKER_REL}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: checker accepted ${label}" >&2
    exit 1
  fi
  # Reason AND status, matched as a PAIR. Two encodings of one decision diverge
  # silently, and the earlier form here had the `case` deciding while `|| true`
  # discarded the status — so the classifier's `return 1` had no consumer, and
  # flipping any rejection to `return 0` changed nothing anywhere. Asserting the
  # status in the selftest is what closes that: it runs before the matrix, so a
  # mismatched pair stops the run. Reading it here as well adds detection of a
  # divergence that appears once the matrix is under way.
  #
  # Reading it here is not enough on its own either. If the status alone decided, a
  # `WRONG_TEST` that returned 0 would print PASS. Only the six pairs the
  # classifier is defined to produce are acceptable; anything else is the oracle
  # contradicting itself, which is a harder failure than any verdict it could
  # report and is named as such.
  local reason rc
  if reason="$(classify_store_reporter_verdict "${test_name}" "${checker_line}" "${TMP_ROOT}/${label}.log")"; then
    rc=0
  else
    rc=$?
  fi
  case "${reason}:${rc}" in
    PASS_CHECKER:0|PASS_VERDICT:0)
      pass_control "${label}_refused"
      return
      ;;
    HARNESS_FAILURE_BUILD:1)
      echo "error: ${label} HARNESS FAILURE — the build died before the semantic check (failed to run custom build command); the negative control is INCONCLUSIVE, not satisfied. Fix the harness, not the expectation." >&2
      ;;
    HARNESS_FAILURE_COMPILE:1)
      echo "error: ${label} HARNESS FAILURE — the checker did not compile, so neither the artifact contract report nor '${test_name}' could be reached. INCONCLUSIVE, not satisfied." >&2
      ;;
    WRONG_TEST:1)
      echo "error: ${label} WRONG TEST — a mobile_claw_vpn_phase0_ test failed, but not '${test_name}', and the artifact contract report is absent. The mutation was NOT proven refused by the property this control asserts." >&2
      describe_wrong_test "${test_name}" "${TMP_ROOT}/${label}.log" >&2
      ;;
    UNKNOWN:1)
      echo "error: ${label} UNKNOWN — the checker exited non-zero but the log carries neither the exact report line nor the exact '${test_name}' libtest verdict, and no recognizable build failure. Inconclusive, never a pass." >&2
      ;;
    *)
      echo "error: ${label} ORACLE FAILURE — the classifier returned the inconsistent pair (reason='${reason}', rc=${rc}). Every reason it defines pairs with exactly one status: PASS_CHECKER and PASS_VERDICT with 0, HARNESS_FAILURE_BUILD, HARNESS_FAILURE_COMPILE, WRONG_TEST and UNKNOWN with 1. An oracle that contradicts itself cannot adjudicate this mutation; nothing here is a pass." >&2
      ;;
  esac
  cat "${TMP_ROOT}/${label}.log" >&2
  exit 1
}

if control_selected store_reporter_oracle_selftest; then
  begin_control store_reporter_oracle_selftest
  selftest_store_reporter
fi

classify_build_cfg_verdict() {
  # #479. `build_cfg_crossing` injects a write of `src/handlers_misc.rs` into
  # server-rs's build script. The refusal it is testing for IS a build-script
  # panic, so `failed to run custom build command` is this control's success
  # signal and every other control's harness death. The generic helper checks
  # that string first and classifies it unconditionally as harness death, which
  # makes the intended channel unreachable once the matrix arrives here — the
  # same shape as #477, in a different place and for a different reason.
  #
  # The injected build script has TWO panics and they mean opposite things:
  #   "Phase 0 source snapshot was writable"        the write SUCCEEDED — the
  #                                                 boundary did not hold
  #   "Phase 0 source mutation was blocked: <err>"  the write was refused — the
  #                                                 boundary held, this is PASS
  # Both produce the identical cargo wrapper line, so the wrapper line alone
  # cannot tell a held boundary from a broken one. Only the panic text can.
  #
  # SNAPSHOT_WRITABLE is tested first. The two panics are mutually exclusive in
  # a coherent log, so the order is defensive rather than load-bearing on real
  # input; a fixture carrying both is pinned below so the alarming reading wins
  # if they ever co-occur.
  #
  # Acceptance needs three facts together, not one string: the failing package,
  # the panicking build script, and the blocked message. Any one of them alone
  # is satisfied by logs that do not show what this control asserts.
  #
  # Two of the three are exercised: dropping the `server-rs/build.rs` check or
  # loosening the blocked-message pattern each turns fixtures red. Dropping the
  # package name from the first check changes no fixture, because every log that
  # names a foreign package also names that package's build script, and the
  # second check already rejects it. The package name is kept as conjunctive
  # evidence and is recorded here as not currently exercised, rather than
  # given a fixture built to make it look exercised.
  #
  # Matched with anchored patterns, not `grep -Fx`: cargo prints the panic
  # inside its indented `Caused by:` block, so the line is not equal to the
  # message. The alternative would be a substring match, which is the looseness
  # #456 removed. The message text itself carries no regex metacharacters.
  #
  # The error inside the blocked variant is deliberately NOT pinned. What this
  # control asserts is that the write was refused; `Read-only file system` and
  # `Permission denied` are both refusals, and pinning one errno would make the
  # control a report on how the snapshot happens to be protected today.
  local log="$1"
  if grep -Eq '^[[:space:]]*Phase 0 source snapshot was writable$' "${log}"; then
    echo SNAPSHOT_WRITABLE
    return 1
  fi
  if grep -Fq 'failed to run custom build command for `server-rs' "${log}" \
      && grep -Eq '^[[:space:]]*thread .* panicked at server-rs/build\.rs:' "${log}" \
      && grep -Eq '^[[:space:]]*Phase 0 source mutation was blocked: .+$' "${log}"; then
    echo PASS_BUILD_SCRIPT_REFUSAL
    return 0
  fi
  if grep -Fq 'failed to run custom build command' "${log}"; then
    echo HARNESS_FAILURE_BUILD
    return 1
  fi
  if grep -Eq '^error\[E[0-9]+\]: |^error: could not compile |^error: aborting due to |^error: linking with ' "${log}"; then
    echo HARNESS_FAILURE_COMPILE
    return 1
  fi
  echo UNKNOWN
  return 1
}

selftest_build_cfg_reporter() {
  # Durable controls, run before the matrix. Fixtures are written from literals
  # in this function. One shape is mirrored from a retained log: the refusal
  # case reproduces the lines from job 93407238709, the run in which this
  # control was first reached. The rest are constructed here.
  local dir="${TMP_ROOT}/build-cfg-selftest"
  local failed=0
  local pkg='error: failed to run custom build command for `server-rs v0.1.25 (/project/admin/rust/server-rs)`'
  local at="    thread 'main' (7570) panicked at server-rs/build.rs:21:23:"
  mkdir -p "${dir}"

  _bexpect() { # case_name expected_reason
    local case_name="$1" expected="$2" got rc expected_rc=1
    [[ "${expected}" == PASS_* ]] && expected_rc=0
    if got="$(classify_build_cfg_verdict "${dir}/${case_name}.log")"; then rc=0; else rc=$?; fi
    if [[ "${got}" != "${expected}" ]]; then
      echo "error: build cfg selftest ${case_name}: expected ${expected}, got ${got}" >&2
      failed=1
    fi
    if [[ "${rc}" -ne "${expected_rc}" ]]; then
      echo "error: build cfg selftest ${case_name}: ${expected} must exit ${expected_rc}, got rc=${rc}" >&2
      failed=1
    fi
  }
  _bcase() { local case_name="$1" expected="$2"; shift 2
    printf '%s\n' "$@" >"${dir}/${case_name}.log"; _bexpect "${case_name}" "${expected}"; }

  _bcase refusal_readonly    PASS_BUILD_SCRIPT_REFUSAL "${pkg}" "${at}" \
    '    Phase 0 source mutation was blocked: Read-only file system (os error 30)'
  # The property is "the write was refused", not one errno; a differently
  # protected snapshot must still pass.
  _bcase refusal_permission  PASS_BUILD_SCRIPT_REFUSAL "${pkg}" "${at}" \
    '    Phase 0 source mutation was blocked: Permission denied (os error 13)'
  # The boundary did NOT hold. This is the finding this whole matrix exists for
  # and it must never be read as a refusal.
  _bcase snapshot_writable   SNAPSHOT_WRITABLE "${pkg}" "${at}" \
    '    Phase 0 source snapshot was writable'
  _bcase writable_wins_over_blocked SNAPSHOT_WRITABLE "${pkg}" "${at}" \
    '    Phase 0 source snapshot was writable' \
    '    Phase 0 source mutation was blocked: Read-only file system (os error 30)'
  # Each of the three required facts, removed one at a time.
  _bcase wrong_package       HARNESS_FAILURE_BUILD \
    'error: failed to run custom build command for `household-rs v0.1.25 (/project/admin/rust/household-rs)`' \
    "    thread 'main' (7570) panicked at household-rs/build.rs:21:23:" \
    '    Phase 0 source mutation was blocked: Read-only file system (os error 30)'
  _bcase wrong_build_script  HARNESS_FAILURE_BUILD "${pkg}" \
    "    thread 'main' (7570) panicked at core-rs/build.rs:9:5:" \
    '    Phase 0 source mutation was blocked: Read-only file system (os error 30)'
  _bcase no_panic_message    HARNESS_FAILURE_BUILD "${pkg}" "${at}" \
    '    called `Option::unwrap()` on a `None` value'
  # Generic build death with none of our evidence stays harness death.
  _bcase generic_build_death HARNESS_FAILURE_BUILD \
    'error: failed to run custom build command for `libsqlite3-sys v0.30.1`' \
    '    Caused by: PermissionDenied'
  # Looseness this suite has already been bitten by.
  _bcase loose_substring     UNKNOWN \
    'note: the checker prints Phase 0 source mutation was blocked when the snapshot holds'
  # A truncated message is not the refusal: the panic proves an attempt, not an
  # outcome. It lands on generic build death rather than UNKNOWN because the
  # custom-build failure is genuinely present — this expectation was written as
  # UNKNOWN and the selftest corrected it.
  _bcase blocked_without_reason HARNESS_FAILURE_BUILD "${pkg}" "${at}" \
    '    Phase 0 source mutation was blocked:'
  _bcase compile_death       HARNESS_FAILURE_COMPILE \
    'error[E0432]: unresolved import' \
    'error: could not compile `server-rs` (build script) due to 1 previous error'
  _bcase silent_nonzero      UNKNOWN 'some unrelated failure'

  unset -f _bcase _bexpect
  rm -rf "${dir}"
  if [[ "${failed}" -ne 0 ]]; then
    echo "error: the build cfg oracle is broken; refusing to run the matrix with it." >&2
    exit 1
  fi
  pass_control build_cfg_oracle_selftest
}

expect_build_cfg_refusal() {
  # #479 call form. The PASS names the channel it matched, so the next hosted
  # log carries the mechanism instead of only the outcome — the gap #477's
  # receipt left open, where a pass discarded the evidence that produced it.
  local label="$1" root="$2"
  control_selected "${label}_refused" || return 0
  prepare_empty_authority_inputs
  if PHASE0_TARGET="${MUTATION_TARGET}" \
      PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
      PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
      run_checker "${root}/${CHECKER_REL}" "${root}" >"${TMP_ROOT}/${label}.log" 2>&1; then
    echo "error: checker accepted ${label}" >&2
    exit 1
  fi
  local reason rc
  if reason="$(classify_build_cfg_verdict "${TMP_ROOT}/${label}.log")"; then rc=0; else rc=$?; fi
  case "${reason}:${rc}" in
    PASS_BUILD_SCRIPT_REFUSAL:0)
      pass_control "${label}_refused" " (${reason})"
      return
      ;;
    SNAPSHOT_WRITABLE:1)
      echo "error: ${label} BOUNDARY VIOLATED — the build script rewrote src/handlers_misc.rs and reported 'Phase 0 source snapshot was writable'. The published source snapshot is not read-only; this is the condition the mutation exists to detect, not a harness fault." >&2
      ;;
    HARNESS_FAILURE_BUILD:1)
      echo "error: ${label} HARNESS FAILURE — a custom build command died, but not with server-rs's build script reporting that the source mutation was blocked. The intended refusal was not observed, so the control is INCONCLUSIVE, not satisfied." >&2
      ;;
    HARNESS_FAILURE_COMPILE:1)
      echo "error: ${label} HARNESS FAILURE — the mutated tree did not compile, so the build script never attempted the source write. INCONCLUSIVE, not satisfied." >&2
      ;;
    UNKNOWN:1)
      echo "error: ${label} UNKNOWN — the checker exited non-zero but the log carries neither the server-rs build-script refusal nor a recognizable build failure. Inconclusive, never a pass." >&2
      ;;
    *)
      echo "error: ${label} ORACLE FAILURE — the classifier returned the inconsistent pair (reason='${reason}', rc=${rc}). PASS_BUILD_SCRIPT_REFUSAL pairs with 0; SNAPSHOT_WRITABLE, HARNESS_FAILURE_BUILD, HARNESS_FAILURE_COMPILE and UNKNOWN pair with 1. An oracle that contradicts itself cannot adjudicate this mutation." >&2
      ;;
  esac
  cat "${TMP_ROOT}/${label}.log" >&2
  exit 1
}

if control_selected build_cfg_oracle_selftest; then
  begin_control build_cfg_oracle_selftest
  selftest_build_cfg_reporter
fi

expect_checker_failure() {
  local label="$1" expected="$2" root="$3"
  control_selected "${label}_refused" || return 0
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
  pass_control "${label}_refused"
}

expect_checker_failure_any() {
  local label="$1" root="$2"
  control_selected "${label}_refused" || return 0
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
      pass_control "${label}_refused"
      return
    fi
  done
  echo "error: ${label} missed all expected reasons: $*" >&2
  cat "${TMP_ROOT}/${label}.log" >&2
  exit 1
}

expect_route_test_failure() {
  local label="$1" root="$2"
  control_selected "${label}_refused" || return 0
  prepare_route_test_target
  if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
      run_cargo test \
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
  assert_route_test_verdict "${label}" \
    mobile_claw_vpn_phase0_mutation_routes_are_absent \
    "${TMP_ROOT}/${label}.log"
}

run_complete_route_test() {
  local root="$1" log="$2"
  prepare_route_test_target
  CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
    run_cargo test \
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
  control_selected "${label}_refused" || return 0
  if run_complete_route_test "${root}" "${TMP_ROOT}/${label}.log"; then
    echo "error: complete production app accepted ${label}" >&2
    exit 1
  fi
  assert_route_test_verdict "${label}" \
    mobile_claw_vpn_phase0_complete_production_app_rejects_mutation_routes \
    "${TMP_ROOT}/${label}.log"
}

if begin_control release_dev_feature_refused; then
  prepare_route_test_target
  if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
    run_cargo check \
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
  pass_control release_dev_feature_refused
fi

BUILD_TOOL_TARGET="${TMP_ROOT}/build-tool-target"
BUILD_TOOL_BIN="${BUILD_TOOL_TARGET}/release/theyos-engine-build"
ensure_build_tool() {
  [[ -x "${BUILD_TOOL_BIN}" ]] && return 0
  CARGO_TARGET_DIR="${BUILD_TOOL_TARGET}" \
    run_cargo build \
      --manifest-path "${REPO_ROOT}/admin/rust/Cargo.toml" \
      --locked \
      --release \
      --package theyos-engine-build-rs \
      >/dev/null
  [[ -x "${BUILD_TOOL_BIN}" ]] || {
    echo "error: canonical build helper was not produced" >&2
    exit 1
  }
}

if begin_control external_cross_container_opts_refused; then
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
  pass_control external_cross_container_opts_refused
fi

for docker_override in \
  "DOCKER_HOST=tcp://127.0.0.1:1" \
  "DOCKER_CONTEXT=untrusted-context" \
  "DOCKER_CONFIG=${TMP_ROOT}/untrusted-docker-config"; do
  docker_name="${docker_override%%=*}"
  if begin_control "${docker_name}_refused"; then
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
    pass_control "${docker_name}_refused"
  fi
done

if begin_control phase0_rustup_home_refused; then
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
  pass_control phase0_rustup_home_refused
fi

FAKE_TOOL_BIN="${TMP_ROOT}/fake-tool-bin"
GIT_WRAPPER_LOG="${TMP_ROOT}/ambient-git-invoked.log"
ensure_fake_tool_bin() {
  [[ -x "${FAKE_TOOL_BIN}/git" ]] && return 0
  mkdir -p "${FAKE_TOOL_BIN}"
  local fake_tool
  for fake_tool in rustc rustup docker; do
    printf '%s\n' '#!/bin/sh' "echo fake-${fake_tool} >&2" 'exit 99' > "${FAKE_TOOL_BIN}/${fake_tool}"
    chmod 755 "${FAKE_TOOL_BIN}/${fake_tool}"
  done
  printf '%s\n' '#!/bin/sh' 'printf "%s\\n" ambient-git-invoked >> "${GIT_WRAPPER_LOG}"' 'exec /usr/bin/git "$@"' > "${FAKE_TOOL_BIN}/git"
  chmod 755 "${FAKE_TOOL_BIN}/git"
}
if begin_control path_tool_injection_ignored; then
  ensure_fake_tool_bin
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
  pass_control path_tool_injection_ignored
fi

if begin_control path_git_injection_ignored; then
  ensure_fake_tool_bin
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
  pass_control path_git_injection_ignored
fi

if begin_control path_docker_injection_ignored; then
  ensure_fake_tool_bin
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
  pass_control path_docker_injection_ignored
  else
    pass_control path_docker_injection_ignored " (fixed Docker path unavailable on this host)"
  fi
fi

if begin_control target_specific_rustflags_refused; then
  ensure_build_tool
  prepare_route_test_target
  if CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS='--cfg feature="dev_t1_datapath" --cfg feature="dev_claw_share_mint" -C debug-assertions=yes' \
    CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
    run_build_tool build "${HOST_TARGET}" cargo \
    >"${TMP_ROOT}/target-rustflags.log" 2>&1; then
  echo "error: canonical build accepted target-specific Rust flags" >&2
    exit 1
  fi
  grep -Fq \
  "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS must be unset" \
    "${TMP_ROOT}/target-rustflags.log"
  pass_control target_specific_rustflags_refused
fi

if begin_control cargo_home_config_refused; then
  ensure_build_tool
  UNTRUSTED_CARGO_HOME="${TMP_ROOT}/untrusted-cargo-home"
  mkdir -p "${UNTRUSTED_CARGO_HOME}"
  printf '%s\n' '[build]' 'rustflags = ["--cfg", "owner_present_hidden"]' > "${UNTRUSTED_CARGO_HOME}/config.toml"
  prepare_route_test_target
  if CARGO_HOME="${UNTRUSTED_CARGO_HOME}" \
    CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
    run_build_tool build "${HOST_TARGET}" cargo \
    >"${TMP_ROOT}/cargo-home-config.log" 2>&1; then
  echo "error: canonical build accepted a Cargo home config" >&2
    exit 1
  fi
  grep -Fq "canonical theyos-engine build forbids Cargo home config" "${TMP_ROOT}/cargo-home-config.log"
  pass_control cargo_home_config_refused
fi

if control_selected module_crossing_refused; then
begin_control module_crossing_refused
module_crossing="${TMP_ROOT}/module-crossing"
clone_head "${module_crossing}"
perl -0pi -e \
  's/#\[cfg\(any\(test, feature = "dev_t1_datapath"\)\)\]\npub mod claw_vpn_packet_pump;/pub mod claw_vpn_packet_pump;/' \
  "${module_crossing}/admin/rust/server-rs/src/lib.rs"
commit_mutation "${module_crossing}" module-crossing
expect_checker_failure module_crossing \
  "retired owner-present effect source entered the ${MUTATION_TARGET} production graph: claw_vpn_packet_pump.rs" \
  "${module_crossing}"
fi

if control_selected composer_route_crossing_refused; then
begin_control composer_route_crossing_refused
composer_route_crossing="${TMP_ROOT}/composer-route-crossing"
clone_head "${composer_route_crossing}"
perl -0pi -e \
  's/\.merge\(mobile_claw_vpn_phase0::routes\(\)\)/.route("\/claw-vpn\/owner\/grant", post(mobile_claw_vpn_phase0::handle_status))\n        .merge(mobile_claw_vpn_phase0::routes())/' \
  "${composer_route_crossing}/admin/rust/server-rs/src/mobile_api_routes.rs"
commit_mutation "${composer_route_crossing}" composer-route-crossing
expect_route_test_failure composer_route_crossing "${composer_route_crossing}"
fi

if control_selected middleware_interception_blocked_before_effect || control_selected middleware_without_outer_guard_refused; then
if control_selected middleware_interception_blocked_before_effect; then
  begin_control middleware_interception_blocked_before_effect
elif control_selected middleware_without_outer_guard_refused; then
  begin_control middleware_without_outer_guard_refused
fi
middleware_interception="${TMP_ROOT}/middleware-interception"
clone_head "${middleware_interception}"
perl -0pi -e \
  's/(pub async fn public_site_gateway\(\n    State\(state\): State<SharedState>,\n    req: Request<Body>,\n    next: Next,\n\) -> Response \{)/$1\n    if req.uri().path().starts_with("\/api\/v1\/mobile\/claw-vpn\/")\n        \&\& req.uri().path() != "\/api\/v1\/mobile\/claw-vpn\/status"\n    {\n        return StatusCode::OK.into_response();\n    }/' \
  "${middleware_interception}/admin/rust/server-rs/src/public_sites.rs"
if control_selected middleware_interception_blocked_before_effect; then
  if ! run_complete_route_test \
      "${middleware_interception}" \
      "${TMP_ROOT}/middleware-interception-closed.log"; then
  echo "error: outer Phase 0 guard did not precede middleware interception" >&2
  cat "${TMP_ROOT}/middleware-interception-closed.log" >&2
    exit 1
  fi
  pass_control middleware_interception_blocked_before_effect
fi
if control_selected middleware_without_outer_guard_refused; then
begin_control middleware_without_outer_guard_refused
perl -0pi -e \
  's/mobile_claw_vpn_phase0::close_production_app\(app\)/app/' \
  "${middleware_interception}/admin/rust/server-rs/src/production_app.rs"
expect_complete_route_test_failure middleware_without_outer_guard "${middleware_interception}"
fi
fi

while IFS='|' read -r listener_label listener_source; do
  control_selected "${listener_label}_refused" || continue
  begin_control "${listener_label}_refused"
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

if control_selected new_unclosed_listener_refused; then
begin_control new_unclosed_listener_refused
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
fi

if control_selected linked_ip_tunnel_seam_refused; then
begin_control linked_ip_tunnel_seam_refused
linked_ip_tunnel_seam="${TMP_ROOT}/linked-ip-tunnel-seam"
clone_head "${linked_ip_tunnel_seam}"
printf '%s\n' \
  'use crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter;' \
  >> "${linked_ip_tunnel_seam}/admin/rust/server-rs/src/handlers_misc.rs"
commit_mutation "${linked_ip_tunnel_seam}" linked-ip-tunnel-seam
expect_checker_failure linked_ip_tunnel_seam \
  'unresolved import `crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter`' \
  "${linked_ip_tunnel_seam}"
fi

if control_selected generic_ip_tunnel_store_refused; then
begin_control generic_ip_tunnel_store_refused
store_open="${TMP_ROOT}/store-open"
clone_head "${store_open}"
perl -0pi -e \
  's/pub const IP_TUNNEL_RESOURCE_COMPILED: bool = cfg!\(any\(test, feature = "dev_t1_datapath"\)\);/pub const IP_TUNNEL_RESOURCE_COMPILED: bool = true;/' \
  "${store_open}/admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs"
commit_mutation "${store_open}" store-open
expect_store_reporter_failure generic_ip_tunnel_store \
  mobile_claw_vpn_phase0_exposes_only_authenticated_unavailable_status \
  '::error::published theyos-engine Phase 0 artifact contract is not status-only' \
  "${store_open}"
fi

if control_selected build_cfg_crossing_refused; then
begin_control build_cfg_crossing_refused
build_cfg="${TMP_ROOT}/build-cfg"
clone_head "${build_cfg}"
perl -0pi -e \
  's#emit_build_git_sha\(\);#emit_build_git_sha();\n    println!("cargo:rustc-cfg=owner_present_hidden");\n    let source = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/handlers_misc.rs");\n    let bytes = std::fs::read(&source).unwrap();\n    match std::fs::write(&source, &bytes) {\n        Ok(()) => panic!("Phase 0 source snapshot was writable"),\n        Err(error) => panic!("Phase 0 source mutation was blocked: {error}"),\n    }#' \
  "${build_cfg}/admin/rust/server-rs/build.rs"
commit_mutation "${build_cfg}" build-cfg
expect_build_cfg_refusal build_cfg_crossing "${build_cfg}"
fi

if control_selected build_tool_codegen_refused; then
begin_control build_tool_codegen_refused
build_tool_codegen="${TMP_ROOT}/build-tool-codegen"
clone_head "${build_tool_codegen}"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${build_tool_codegen}/admin/rust/theyos-engine-build-rs/build.rs"
commit_mutation "${build_tool_codegen}" build-tool-codegen
expect_checker_failure build_tool_codegen \
  "canonical engine build tool must not have a build.rs codegen seam" \
  "${build_tool_codegen}"
fi

if control_selected new_build_script_refused; then
begin_control new_build_script_refused
new_build_script="${TMP_ROOT}/new-build-script"
clone_head "${new_build_script}"
mkdir -p "${new_build_script}/admin/rust/server-rs/generated"
printf '%s\n' 'fn main() { println!("cargo:rustc-cfg=owner_present_hidden"); }' > \
  "${new_build_script}/admin/rust/server-rs/generated/build.rs"
commit_mutation "${new_build_script}" new-build-script
expect_checker_failure new_build_script \
  "Phase 0 permits exactly the three reviewed in-repo Rust build scripts" \
  "${new_build_script}"
fi

if control_selected custom_named_build_script_refused; then
begin_control custom_named_build_script_refused
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
fi

if control_selected local_proc_macro_refused; then
begin_control local_proc_macro_refused
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
  run_cargo generate-lockfile --quiet
)
commit_mutation "${local_proc_macro}" local-proc-macro
expect_checker_failure local_proc_macro \
  "Phase 0 forbids local proc-macro codegen targets" \
  "${local_proc_macro}"
fi

if control_selected external_include_refused; then
begin_control external_include_refused
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
fi

if control_selected allow_alias_escape_refused; then
begin_control allow_alias_escape_refused
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
fi

if control_selected absolute_external_include_refused; then
begin_control absolute_external_include_refused
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
fi

if control_selected manifest_override_refused; then
begin_control manifest_override_refused
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
fi

if control_selected cargo_config_override_refused; then
begin_control cargo_config_override_refused
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
fi

if control_selected cross_pre_build_refused; then
begin_control cross_pre_build_refused
cross_pre_build="${TMP_ROOT}/cross-pre-build"
clone_head "${cross_pre_build}"
perl -0pi -e \
  's/pre-build = \[\]/pre-build = ["printf owner-present-hidden"]/' \
  "${cross_pre_build}/admin/rust/Cross.toml"
commit_mutation "${cross_pre_build}" cross-pre-build
expect_checker_failure cross_pre_build \
  "Phase 0 forbids Cross pre-build commands" \
  "${cross_pre_build}"
fi

if control_selected git_source_dependency_refused; then
begin_control git_source_dependency_refused
git_source_dependency="${TMP_ROOT}/git-source-dependency"
clone_head "${git_source_dependency}"
perl -0pi -e \
  's~source = "registry\+https://github.com/rust-lang/crates.io-index"~source = "git+file:///tmp/phase0-source#0000000000000000000000000000000000000000"~' \
  "${git_source_dependency}/admin/rust/Cargo.lock"
commit_mutation "${git_source_dependency}" git-source-dependency
expect_checker_failure git_source_dependency \
  "Phase 0 forbids non-canonical Cargo source" \
  "${git_source_dependency}"
fi

if control_selected environment_clear_removal_refused; then
begin_control environment_clear_removal_refused
environment_clear_removed="${TMP_ROOT}/environment-clear-removed"
clone_head "${environment_clear_removed}"
perl -0pi -e 's/    command\.env_clear\(\);/    \/\/ mutation removed env_clear/' \
  "${environment_clear_removed}/admin/rust/theyos-engine-build-rs/src/main.rs"
prepare_route_test_target
if CARGO_TARGET_DIR="${ROUTE_TEST_TARGET}" \
    run_cargo test \
      --manifest-path "${environment_clear_removed}/admin/rust/Cargo.toml" \
      --locked \
      --package theyos-engine-build-rs \
      child_process_environment_is_positive_allowlist \
      >"${TMP_ROOT}/environment-clear-removed.log" 2>&1; then
  echo "error: helper tests accepted removal of env_clear" >&2
  exit 1
fi
# Same class as the route oracles, same script: a bare substring grep for the
# test name accepted build death as a semantic negative here too.
#
# The name carries a `tests::` prefix and the bare name would be WRONG: this test
# lives in `mod tests` in theyos-engine-build-rs/src/main.rs, so libtest prints
# the module path. Confirmed by running the test and reading what libtest
# actually printed, not by reading the source. An anchored pattern that can never
# match would be a guard that stopped guarding, which is the exact defect this
# fix exists to close.
assert_route_test_verdict environment_clear_removal \
  'tests::child_process_environment_is_positive_allowlist' \
  "${TMP_ROOT}/environment-clear-removed.log"
fi

if control_selected external_path_dependency_refused; then
begin_control external_path_dependency_refused
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
  run_cargo generate-lockfile --quiet
)
commit_mutation "${external_path_dependency}" external-path-dependency
expect_checker_failure_any external_path_dependency \
  "${external_path_dependency}" \
  "local Cargo dependency escapes the closed admin/rust tree" \
  "local Cargo dependency path escapes the closed admin/rust tree" \
  'failed to read `/project/outside-phase0/Cargo.toml`'
fi

if control_selected ancestor_cargo_config_refused; then
begin_control ancestor_cargo_config_refused
ancestor_cargo_config="${TMP_ROOT}/ancestor-cargo-config"
clone_head "${ancestor_cargo_config}"
mkdir -p "${ancestor_cargo_config}/.cargo"
printf '%s\n' '[net]' 'retry = 2' > "${ancestor_cargo_config}/.cargo/config.toml"
commit_mutation "${ancestor_cargo_config}" ancestor-cargo-config
expect_checker_failure ancestor_cargo_config \
  "canonical theyos-engine build forbids ancestor Cargo config" \
  "${ancestor_cargo_config}"
fi

if control_selected above_repo_cargo_config_refused; then
begin_control above_repo_cargo_config_refused
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
fi

if control_selected workspace_cargo_alias_refused; then
begin_control workspace_cargo_alias_refused
workspace_cargo_alias="${TMP_ROOT}/workspace-cargo-alias"
clone_head "${workspace_cargo_alias}"
printf '%s\n' '[net]' 'retry = 2' > \
  "${workspace_cargo_alias}/admin/rust/.cargo/config"
commit_mutation "${workspace_cargo_alias}" workspace-cargo-alias
expect_checker_failure workspace_cargo_alias \
  "canonical theyos-engine build forbids ancestor Cargo config: admin/rust/.cargo/config" \
  "${workspace_cargo_alias}"
fi

if control_selected release_recipe_drift_refused; then
begin_control release_recipe_drift_refused
recipe_drift="${TMP_ROOT}/recipe-drift"
clone_head "${recipe_drift}"
recipe_source="${recipe_drift}/admin/rust/theyos-engine-build-rs/src/main.rs"
if [[ "$(grep -Fc '        "--no-default-features",' "${recipe_source}")" -ne 1 ]]; then
  echo "error: release_recipe_drift expected exactly one canonical --no-default-features argv entry" >&2
  exit 1
fi
perl -0pi -e \
  's/        "--no-default-features",/        "--features",\n        "dev_t1_datapath",/ or die "release recipe anchor did not change\n"' \
  "${recipe_source}"
# This mutation must create two argv entries. A single string containing a
# space is rejected by Cargo's CLI before the production feature guard runs,
# so it would test malformed argument construction instead of recipe drift.
if grep -Fq '"--features dev_t1_datapath"' "${recipe_source}" \
    || [[ "$(grep -Fc '        "--features",' "${recipe_source}")" -ne 1 ]] \
    || [[ "$(grep -Fc '        "dev_t1_datapath",' "${recipe_source}")" -ne 1 ]] \
    || grep -Fq '        "--no-default-features",' "${recipe_source}"; then
  echo "error: release_recipe_drift did not produce the exact two-entry Cargo feature argv" >&2
  exit 1
fi
commit_mutation "${recipe_drift}" recipe-drift
expect_checker_failure release_recipe_drift \
  "production server binary cannot be built with DEV/test features" \
  "${recipe_drift}"
fi

if control_selected release_subject_bypass_refused; then
begin_control release_subject_bypass_refused
release_subject_bypass="${TMP_ROOT}/release-subject-bypass"
clone_head "${release_subject_bypass}"
perl -0pi -e \
  's#bash \.github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout\.sh#true#g' \
  "${release_subject_bypass}/.github/workflows/release-linux.yml"
commit_mutation "${release_subject_bypass}" release-subject-bypass
expect_checker_failure release_subject_bypass \
  "every theyos-engine release target must run the Phase 0 checker on its own subject" \
  "${release_subject_bypass}"
fi

if control_selected alternate_publisher_refused; then
begin_control alternate_publisher_refused
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
fi

# The issuer bridge is deliberately classified by authority rather than pinned
# byte-for-byte. The unmodified workflow is the positive control; independent
# mutations prove that its filename alone does not grant publishing or access
# to another Apple credential.
if control_selected issuer_bridge_known; then
begin_control issuer_bridge_known
issuer_bridge_known="${TMP_ROOT}/issuer-bridge-known"
clone_head "${issuer_bridge_known}"
prepare_empty_authority_inputs
if ! PHASE0_TARGET="${MUTATION_TARGET}" \
    PHASE0_BUILD_TOOL="${MUTATION_BUILD_TOOL}" \
    PHASE0_CARGO_TARGET_DIR="${AUTHORITY_TARGET}" \
    run_checker "${issuer_bridge_known}/${CHECKER_REL}" "${issuer_bridge_known}" \
      >"${TMP_ROOT}/issuer-bridge-known.log" 2>&1; then
  echo "error: checker rejected the property-classified issuer bridge" >&2
  cat "${TMP_ROOT}/issuer-bridge-known.log" >&2
  exit 1
fi
pass_control issuer_bridge_known
fi

if control_selected issuer_bridge_publisher_refused; then
begin_control issuer_bridge_publisher_refused
issuer_bridge_publisher="${TMP_ROOT}/issuer-bridge-publisher"
clone_head "${issuer_bridge_publisher}"
perl -0pi -e \
  's/(permissions:\n)/$1  contents: write\n/' \
  "${issuer_bridge_publisher}/.github/workflows/provision-ios-notary-issuer.yml"
commit_mutation "${issuer_bridge_publisher}" issuer-bridge-publisher
expect_checker_failure issuer_bridge_publisher \
  "issuer bridge must not publish or mint attestations" \
  "${issuer_bridge_publisher}"
fi

if control_selected issuer_bridge_other_apple_secret_refused; then
begin_control issuer_bridge_other_apple_secret_refused
issuer_bridge_other_apple_secret="${TMP_ROOT}/issuer-bridge-other-apple-secret"
clone_head "${issuer_bridge_other_apple_secret}"
perl -0pi -e \
  's/(      SOURCE_ISSUER:.*\n)/$1      FORBIDDEN_APPLE_SECRET: \$\{\{ secrets.APPLE_NOTARY_KEY_P8_BASE64 \}\}\n/' \
  "${issuer_bridge_other_apple_secret}/.github/workflows/provision-ios-notary-issuer.yml"
commit_mutation "${issuer_bridge_other_apple_secret}" issuer-bridge-other-apple-secret
expect_checker_failure issuer_bridge_other_apple_secret \
  "issuer bridge must consume exactly the allowed source issuer and temporary token secrets" \
  "${issuer_bridge_other_apple_secret}"
fi

if control_selected issuer_bridge_apns_capability_refused; then
begin_control issuer_bridge_apns_capability_refused
issuer_bridge_apns_capability="${TMP_ROOT}/issuer-bridge-apns-capability"
clone_head "${issuer_bridge_apns_capability}"
perl -0pi -e \
  's/(      SOURCE_ISSUER:.*\n)/$1      FORBIDDEN_CAPABILITY: SOYEHT_APNS_P8_BASE64\n/' \
  "${issuer_bridge_apns_capability}/.github/workflows/provision-ios-notary-issuer.yml"
commit_mutation "${issuer_bridge_apns_capability}" issuer-bridge-apns-capability
expect_checker_failure issuer_bridge_apns_capability \
  "issuer bridge must not reference APNs credentials or capabilities" \
  "${issuer_bridge_apns_capability}"
fi

if control_selected activation_marker_refused; then
begin_control activation_marker_refused
marker="${TMP_ROOT}/marker"
clone_head "${marker}"
printf '%s\n' '{"contract":"activation"}' > \
  "${marker}/admin/contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json"
commit_mutation "${marker}" marker
expect_checker_failure activation_marker \
  "Phase 0 forbids an owner-present activation marker" \
  "${marker}"
fi

if control_selected v1_authority_refused; then
begin_control v1_authority_refused
status_open="${TMP_ROOT}/status-open"
clone_head "${status_open}"
perl -0pi -e 's/"authority": "none"/"authority": "v1"/' \
  "${status_open}/admin/contracts/mobile-claw-vpn/v1/owner_present_wire_authority_status_v1.json"
commit_mutation "${status_open}" status-open
expect_checker_failure v1_authority \
  "Phase 0 authority status is invalid" \
  "${status_open}"
fi

if control_selected shard_coverage_selftest; then
  begin_control shard_coverage_selftest
  coverage_selftest
fi
assert_selected_shard_complete
echo "Owner-present Phase 0 structural mutation matrix passed."
