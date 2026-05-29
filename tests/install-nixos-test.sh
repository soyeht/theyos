#!/usr/bin/env bash
#
# Unit tests for ./install-nixos robustness behavior.
#
# These tests NEVER run nixos-rebuild. They either:
#   (a) source install-nixos in library-only mode (THEYOS_INSTALL_LIB_ONLY=1)
#       and call individual functions, overriding has_tty / NIX_DIR as needed; or
#   (b) run the full script for the early, side-effect-free paths (--help,
#       --dry-run, unknown flag) which exit before any rebuild.
#
# Pure bash, no external dependencies. Run: bash tests/install-nixos-test.sh

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../install-nixos"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1" >&2; }

assert_eq() { # desc expected actual
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected [$2], got [$3])"; fi
}
assert_contains() { # desc haystack needle
    if printf '%s' "$2" | grep -qF -- "$3"; then pass "$1"; else fail "$1 (missing [$3] in: $2)"; fi
}
assert_not_contains() { # desc haystack needle
    if printf '%s' "$2" | grep -qF -- "$3"; then fail "$1 (unexpected [$3])"; else pass "$1"; fi
}

mk_tmp_nixdir() { mktemp -d "${TMPDIR:-/tmp}/install-nixos-test.XXXXXX"; }

# ── 1. --help is side-effect-free and OS-agnostic ────────────────────────────
# Runs the full script. Must exit 0 with usage, must NOT reach the NixOS
# preflight (i.e. must NOT error "requires NixOS") and must NOT mention running
# nixos-rebuild.
test_help() {
    local out rc
    out="$(bash "$SCRIPT" --help 2>&1)"; rc=$?
    assert_eq "--help exits 0" "0" "$rc"
    assert_contains "--help prints usage" "$out" "Usage: ./install-nixos"
    assert_not_contains "--help does not hit NixOS preflight" "$out" "requires NixOS"
    assert_not_contains "--help does not run nixos-rebuild" "$out" "Building NixOS configuration"
}

# ── 1b. unknown flag fails clearly ───────────────────────────────────────────
test_unknown_flag() {
    local out rc
    out="$(bash "$SCRIPT" --bogus 2>&1)"; rc=$?
    assert_eq "unknown flag exits 1" "1" "$rc"
    assert_contains "unknown flag names the option" "$out" "unknown option: --bogus"
}

# ── 1c. --access-mode validates its value ────────────────────────────────────
test_bad_access_mode() {
    local out rc
    out="$(bash "$SCRIPT" --access-mode wat 2>&1)"; rc=$?
    assert_eq "invalid --access-mode exits 1" "1" "$rc"
    assert_contains "invalid --access-mode message" "$out" "invalid --access-mode: wat"
}

# ── 2. no-TTY first run without --access-mode fails loudly ───────────────────
test_no_tty_no_flag_fails() {
    local dir stdout stderr rc errfile
    dir="$(mk_tmp_nixdir)"            # empty: no host.nix → first run
    errfile="$(mktemp)"
    stdout="$(
        THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"
        NIX_DIR="$dir"
        ARG_ACCESS_MODE=""
        has_tty() { return 1; }       # force non-interactive
        resolve_access_mode 2>"$errfile"
    )"; rc=$?
    stderr="$(cat "$errfile")"; rm -f "$errfile"
    assert_eq "no-tty/no-flag returns 2" "2" "$rc"
    # The resolved mode is the ONLY thing on stdout; empty means no silent default.
    assert_eq "no-tty/no-flag picks no mode (no silent local default)" "" "$stdout"
    assert_contains "no-tty/no-flag message names --access-mode" "$stderr" "--access-mode"
}

# ── 3. no-TTY with --access-mode tailscale resolves ──────────────────────────
test_no_tty_with_flag_proceeds() {
    local out rc
    out="$(
        THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"
        NIX_DIR="$(mk_tmp_nixdir)"
        ARG_ACCESS_MODE="tailscale"
        has_tty() { return 1; }
        resolve_access_mode
    )"; rc=$?
    assert_eq "flag tailscale returns 0" "0" "$rc"
    assert_eq "flag tailscale resolves to tailscale" "tailscale" "$out"
}

# ── 4. existing host.nix is respected, printed, and conflicts fail ───────────
test_existing_host_nix() {
    local dir out rc
    dir="$(mk_tmp_nixdir)"
    printf '  accessMode = "tailscale";\n' > "$dir/host.nix"

    # 4a: no flag → echoes existing mode
    out="$(
        THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"
        NIX_DIR="$dir"; ARG_ACCESS_MODE=""
        resolve_access_mode
    )"; rc=$?
    assert_eq "existing host.nix returns 0" "0" "$rc"
    assert_eq "existing host.nix reuses accessMode" "tailscale" "$out"

    # 4b: matching flag → still fine
    out="$(
        THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"
        NIX_DIR="$dir"; ARG_ACCESS_MODE="tailscale"
        resolve_access_mode
    )"; rc=$?
    assert_eq "matching flag returns 0" "0" "$rc"

    # 4c: conflicting flag → returns 3 with guidance
    out="$(
        THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"
        NIX_DIR="$dir"; ARG_ACCESS_MODE="local"
        resolve_access_mode 2>&1
    )"; rc=$?
    assert_eq "conflicting flag returns 3" "3" "$rc"
    assert_contains "conflict message explains it" "$out" "conflicts with the existing nix/host.nix"
    assert_contains "conflict message tells user how to fix" "$out" "remove nix/host.nix"
}

# ── 5. --dry-run is real and side-effect-free ────────────────────────────────
# Full script run; dry-run exits 0 before preflight/re-exec/rebuild, so it works
# on any OS. Must not create host.nix in the (empty) target NIX_DIR.
test_dry_run() {
    local dir out rc
    dir="$(mk_tmp_nixdir)"
    out="$(THEYOS_NIX_DIR="$dir" bash "$SCRIPT" --dry-run --access-mode tailscale 2>&1)"; rc=$?
    assert_eq "--dry-run exits 0" "0" "$rc"
    assert_contains "--dry-run announces no changes" "$out" "DRY RUN — no changes will be made"
    assert_contains "--dry-run shows the rebuild command" "$out" "nixos-rebuild switch --flake"
    assert_contains "--dry-run reports access mode" "$out" "accessMode=tailscale"
    assert_not_contains "--dry-run does not build" "$out" "Building NixOS configuration"
    if [ -f "$dir/host.nix" ]; then
        fail "--dry-run wrote host.nix (should be side-effect-free)"
    else
        pass "--dry-run wrote no host.nix"
    fi
}

# ── 6. SIGINT guidance is phase-accurate and safe ────────────────────────────
# Unit-test on_interrupt directly per phase (no fragile process-signal harness).
test_on_interrupt() {
    local out rc

    # on_interrupt writes to stderr and exits 130, so merge stderr→stdout ON the
    # call (it never returns to a later redirection line).
    out="$( THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"; INSTALL_PHASE="configure"; on_interrupt 2>&1 )"; rc=$?
    assert_eq "interrupt during configure exits 130" "130" "$rc"
    assert_contains "configure: reports system unchanged" "$out" "running system is unchanged"
    assert_contains "configure: says idempotent re-run" "$out" "idempotent"
    assert_not_contains "configure: does not claim success" "$out" "installed successfully"

    out="$( THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"; INSTALL_PHASE="rebuild"; on_interrupt 2>&1 )"; rc=$?
    assert_eq "interrupt during rebuild exits 130" "130" "$rc"
    assert_contains "rebuild: explains atomic activation" "$out" "atomic"

    out="$( THEYOS_INSTALL_LIB_ONLY=1 source "$SCRIPT"; INSTALL_PHASE="postapply"; on_interrupt 2>&1 )"; rc=$?
    assert_eq "interrupt during postapply exits 130" "130" "$rc"
    assert_contains "postapply: notes theyOS already activated" "$out" "already activated"
}

# ── 7. pairing runs as the soyeht service account ───────────────────────────
# The bootstrap token is owned by `soyeht` (0600); the auto-pair step must run
# as that account, not the operator's login. Static guard against a regression
# back to a non-privileged `soyeht pair` that always fails the QR at install end.
test_pair_runs_as_service_account() {
    local body
    body="$(cat "$SCRIPT")"
    assert_contains "auto-pair runs as soyeht service account" "$body" 'sudo -u soyeht "$(command -v soyeht)" pair'
    # The fallback hint must point at a command that actually works (sudo).
    assert_contains "pair fallback hint uses sudo" "$body" 'Run "sudo soyeht pair" later'
}

# ── run ──────────────────────────────────────────────────────────────────────
main() {
    printf 'install-nixos unit tests\n\n'
    test_help
    test_unknown_flag
    test_bad_access_mode
    test_no_tty_no_flag_fails
    test_no_tty_with_flag_proceeds
    test_existing_host_nix
    test_dry_run
    test_on_interrupt
    test_pair_runs_as_service_account
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ]
}

main "$@"
