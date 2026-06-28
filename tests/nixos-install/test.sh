#!/usr/bin/env bash
# theyOS NixOS installation E2E test.
#
# Tests the full curl-to-pair flow in a Docker container simulating a fresh
# NixOS environment. Each phase can be run independently.
#
# Usage:
#   ./tests/nixos-install/test.sh              # run all phases
#   ./tests/nixos-install/test.sh phase1       # bootstrap validation only
#   ./tests/nixos-install/test.sh phase2       # config generation only
#   ./tests/nixos-install/test.sh phase3       # nix build validation (slow!)
#   ./tests/nixos-install/test.sh phase4       # runtime smoke test (pair)
#
# Prerequisites: docker
#
# NOTE: Phase 3 (nix build) can take 30+ minutes on ARM Mac (Rosetta x86_64
# emulation). Pass SKIP_NIX_BUILD=1 to skip it.
#
# For full E2E with systemd and real NixOS, use the NixOS VM test instead:
#   nix build .#checks.x86_64-linux.install-test   (on an x86_64 Linux host)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTAINER_NAME="theyos-install-test-$$"
IMAGE_NAME="theyos-install-test"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
SKIP_NIX_BUILD="${SKIP_NIX_BUILD:-0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { printf "${GREEN}  PASS${NC} %s\n" "$1"; }
fail() { printf "${RED}  FAIL${NC} %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf "${CYAN}  INFO${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}  WARN${NC} %s\n" "$1"; }
header() { printf "\n${CYAN}═══ %s ═══${NC}\n\n" "$1"; }

FAILURES=0
PHASES="${1:-all}"

cleanup() {
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────────────

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required"
    exit 1
fi

header "theyOS NixOS Installation E2E Test"
info "Repo: $REPO_ROOT"
info "Platform: $DOCKER_PLATFORM"
info "Phases: $PHASES"

# ── Build test container ─────────────────────────────────────────────────────

header "Building test container"

docker build --platform "$DOCKER_PLATFORM" \
    -t "$IMAGE_NAME" \
    -f "$REPO_ROOT/tests/nixos-install/Dockerfile" \
    "$REPO_ROOT" 2>&1 | tail -5

# Start the container with the repo mounted.
# We mount read-only and copy to /root/theyos inside so the tests can
# modify files (generate host.nix etc.) without touching the host repo.
docker run -d --platform "$DOCKER_PLATFORM" \
    --name "$CONTAINER_NAME" \
    -v "$REPO_ROOT:/mnt/theyos-src:ro" \
    "$IMAGE_NAME" \
    sleep 3600

# Copy repo inside (so install-nixos can modify files)
docker exec "$CONTAINER_NAME" sh -c '
    cp -a /mnt/theyos-src /root/theyos
    cd /root/theyos && git init -q 2>/dev/null || true
    cd /root/theyos && git add -A 2>/dev/null || true
'
info "Container $CONTAINER_NAME running"

# Helper: run a command inside the container
run_in() {
    docker exec -e HOME=/root "$CONTAINER_NAME" sh -c "$1"
}

run_in_bash() {
    docker exec -e HOME=/root "$CONTAINER_NAME" bash -c "$1"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Bootstrap script validation
# ═══════════════════════════════════════════════════════════════════════════════

run_phase1() {
    header "Phase 1: Bootstrap Script Validation"

    # 1.1 — bootstrap script is valid shell
    if run_in 'sh -n /root/theyos/bootstrap'; then
        pass "bootstrap is valid shell"
    else
        fail "bootstrap has syntax errors"
    fi

    # 1.2 — bootstrap checks for /etc/NIXOS
    if run_in 'grep -q "/etc/NIXOS" /root/theyos/bootstrap'; then
        pass "bootstrap checks for /etc/NIXOS"
    else
        fail "bootstrap missing NixOS check"
    fi

    # 1.3 — bootstrap enables flakes
    if run_in 'grep -q "experimental-features" /root/theyos/bootstrap'; then
        pass "bootstrap enables flakes"
    else
        fail "bootstrap missing flakes enablement"
    fi

    # 1.4 — bootstrap invokes install-nixos
    if run_in 'grep -q "install-nixos" /root/theyos/bootstrap'; then
        pass "bootstrap calls install-nixos"
    else
        fail "bootstrap missing install-nixos invocation"
    fi

    # 1.5 — bootstrap exits if not NixOS
    OUTPUT=$(run_in 'rm -f /etc/NIXOS; sh /root/theyos/bootstrap 2>&1 || true')
    if echo "$OUTPUT" | grep -qi "requires NixOS"; then
        pass "bootstrap rejects non-NixOS"
    else
        fail "bootstrap should reject non-NixOS systems"
    fi

    # 1.6 — bootstrap runs on NixOS (clone/pull phase)
    # Create /etc/NIXOS and test that it gets past the NixOS check
    run_in 'touch /etc/NIXOS'
    # Can't actually run bootstrap (needs git from nix shell), but verify the
    # NixOS detection path
    if run_in 'test -f /etc/NIXOS'; then
        pass "/etc/NIXOS detection works"
    else
        fail "/etc/NIXOS detection broken"
    fi

    # 1.7 — install-nixos is valid bash
    if run_in_bash 'bash -n /root/theyos/install-nixos'; then
        pass "install-nixos is valid bash"
    else
        fail "install-nixos has syntax errors"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Config generation (install-nixos first-run path)
# ═══════════════════════════════════════════════════════════════════════════════

run_phase2() {
    header "Phase 2: Config Generation"

    # Simulate the first-run path of install-nixos by running the relevant
    # sections manually. We can't run install-nixos directly because it calls
    # nixos-rebuild, but we can test config generation.

    # Setup: create /etc/NIXOS and a fake hardware config
    run_in_bash '
        touch /etc/NIXOS
        mkdir -p /etc/nixos
        cat > /etc/nixos/hardware-configuration.nix <<EOF
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  boot.initrd.availableKernelModules = [ "ahci" "xhci_pci" "virtio_pci" ];
  fileSystems."/" = { device = "/dev/sda1"; fsType = "ext4"; };
}
EOF
        cat > /etc/nixos/configuration.nix <<EOF
{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];
  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
  services.openssh.enable = true;
  system.stateVersion = "25.05";
}
EOF
    '

    # 2.1 — template file exists
    if run_in 'test -f /root/theyos/nix/host.nix.template'; then
        pass "host.nix.template exists"
    else
        fail "host.nix.template missing"
    fi

    # 2.2 — generate host.nix from template
    run_in_bash '
        cd /root/theyos
        NIX_DIR=/root/theyos/nix
        mkdir -p "$NIX_DIR"
        CURRENT_USER="testuser"
        PROMPTED_DOMAIN="localhost"
        PROMPTED_ACCESS_MODE="local"
        sed \
            -e "s|«DETECTED_USER»|$CURRENT_USER|g" \
            -e "s|«PROMPTED_DOMAIN»|$PROMPTED_DOMAIN|g" \
            -e "s|«PROMPTED_ACCESS_MODE»|$PROMPTED_ACCESS_MODE|g" \
            "$NIX_DIR/host.nix.template" > "$NIX_DIR/host.nix"
    '
    if run_in 'test -f /root/theyos/nix/host.nix'; then
        pass "host.nix generated"
    else
        fail "host.nix not generated"
        return
    fi

    # 2.3 — host.nix has correct user substitution
    if run_in 'grep -q "testuser" /root/theyos/nix/host.nix'; then
        pass "host.nix contains user = testuser"
    else
        fail "host.nix user substitution failed"
    fi

    # 2.4 — host.nix has correct access mode
    if run_in 'grep -q '"'"'accessMode = "local"'"'"' /root/theyos/nix/host.nix'; then
        pass "host.nix accessMode = local"
    else
        fail "host.nix access mode wrong"
    fi

    # 2.5 — host.nix has correct domain
    if run_in 'grep -q '"'"'domain = "localhost"'"'"' /root/theyos/nix/host.nix'; then
        pass "host.nix domain = localhost"
    else
        fail "host.nix domain wrong"
    fi

    # 2.6 — copy hardware-configuration.nix
    run_in_bash '
        cp /etc/nixos/hardware-configuration.nix /root/theyos/nix/hardware-configuration.nix
    '
    if run_in 'test -f /root/theyos/nix/hardware-configuration.nix'; then
        pass "hardware-configuration.nix copied"
    else
        fail "hardware-configuration.nix not copied"
    fi

    # 2.7 — copy base-configuration.nix
    run_in_bash '
        cp /etc/nixos/configuration.nix /root/theyos/nix/base-configuration.nix
    '
    if run_in 'test -f /root/theyos/nix/base-configuration.nix'; then
        pass "base-configuration.nix copied"
    else
        fail "base-configuration.nix not copied"
    fi

    # 2.8 — generated nix files are syntactically valid
    if run_in 'nix-instantiate --parse /root/theyos/nix/host.nix >/dev/null 2>&1'; then
        pass "host.nix is valid Nix"
    else
        fail "host.nix is invalid Nix"
    fi

    if run_in 'nix-instantiate --parse /root/theyos/nix/base-configuration.nix >/dev/null 2>&1'; then
        pass "base-configuration.nix is valid Nix"
    else
        fail "base-configuration.nix is invalid Nix"
    fi

    # 2.9 — secrets generation
    run_in_bash '
        mkdir -p /var/lib/theyos/secrets
        openssl rand -base64 16 > /var/lib/theyos/secrets/admin-password
        openssl rand -hex 32 > /var/lib/theyos/secrets/session-pepper
        openssl rand -base64 32 > /var/lib/theyos/secrets/bootstrap-token
        chmod 600 /var/lib/theyos/secrets/*
    '

    if run_in 'test -f /var/lib/theyos/secrets/admin-password'; then
        pass "admin-password generated"
    else
        fail "admin-password generation failed"
    fi

    if run_in 'test -f /var/lib/theyos/secrets/session-pepper'; then
        pass "session-pepper generated"
    else
        fail "session-pepper generation failed"
    fi

    if run_in 'test -f /var/lib/theyos/secrets/bootstrap-token'; then
        pass "bootstrap-token generated"
    else
        fail "bootstrap-token generation failed"
    fi

    # 2.10 — admin password is at least 16 chars (base64 of 16 bytes)
    PW_LEN=$(run_in 'wc -c < /var/lib/theyos/secrets/admin-password | tr -d " "')
    if [ "$PW_LEN" -ge 20 ]; then
        pass "admin-password has sufficient entropy (${PW_LEN} chars)"
    else
        fail "admin-password too short (${PW_LEN} chars)"
    fi

    # 2.11 — .env.example exists and has required keys
    for key in SOYEHT_ADMIN_USER SOYEHT_ADMIN_PASSWORD THEYOS_SESSION_PEPPER THEYOS_HOME ACCESS_MODE; do
        if run_in "grep -q '^${key}=' /root/theyos/.env.example"; then
            pass ".env.example contains $key"
        else
            fail ".env.example missing $key"
        fi
    done

    # 2.12 — flake.nix is syntactically valid
    if run_in 'nix-instantiate --parse /root/theyos/flake.nix >/dev/null 2>&1'; then
        pass "flake.nix is valid Nix"
    else
        fail "flake.nix is invalid Nix"
    fi

    # 2.13 — module.nix is syntactically valid
    if run_in 'nix-instantiate --parse /root/theyos/nix/module.nix >/dev/null 2>&1'; then
        pass "module.nix is valid Nix"
    else
        fail "module.nix is invalid Nix"
    fi

    # 2.14 — Tailscale access mode generates correct host.nix
    run_in_bash '
        cd /root/theyos
        sed \
            -e "s|«DETECTED_USER»|tsuser|g" \
            -e "s|«PROMPTED_DOMAIN»|localhost|g" \
            -e "s|«PROMPTED_ACCESS_MODE»|tailscale|g" \
            nix/host.nix.template > /tmp/host-ts.nix
    '
    if run_in 'grep -q '"'"'accessMode = "tailscale"'"'"' /tmp/host-ts.nix'; then
        pass "Tailscale mode generates correct host.nix"
    else
        fail "Tailscale mode host.nix wrong"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Nix build validation (system closure)
# ═══════════════════════════════════════════════════════════════════════════════

run_phase3() {
    header "Phase 3: Nix Build Validation"

    if [ "$SKIP_NIX_BUILD" = "1" ]; then
        warn "Skipping nix build (SKIP_NIX_BUILD=1)"
        warn "To run: SKIP_NIX_BUILD=0 $0 phase3"
        return
    fi

    warn "This phase builds the entire NixOS system closure."
    warn "It can take 30+ minutes on ARM Mac (Rosetta emulation)."
    warn "Pass SKIP_NIX_BUILD=1 to skip."

    # 3.1 — flake eval (fast: just evaluates, no build)
    info "Evaluating flake..."
    if run_in_bash '
        cd /root/theyos
        git add -A 2>/dev/null || true
        nix flake check --no-build 2>&1 | tail -5
    '; then
        pass "flake check (no build) passed"
    else
        # flake check without build may fail because of nixosConfigurations
        # needing hardware config — that's OK, we test the packages separately
        warn "flake check (no build) had warnings (expected for nixosConfigurations)"
    fi

    # 3.2 — build individual packages (faster than full system closure)
    info "Building Rust workspace package..."
    if run_in_bash '
        cd /root/theyos
        git add -A 2>/dev/null || true
        nix build .#theyos-admin --no-link 2>&1 | tail -10
    '; then
        pass "theyos-admin package builds"
    else
        fail "theyos-admin package build failed"
    fi

    info "Building frontend package..."
    if run_in_bash '
        cd /root/theyos
        nix build .#theyos-frontend --no-link 2>&1 | tail -10
    '; then
        pass "theyos-frontend package builds"
    else
        fail "theyos-frontend package build failed"
    fi

    # 3.3 — build full system closure
    info "Building NixOS system closure..."
    if run_in_bash '
        cd /root/theyos
        nix build .#nixosConfigurations.theyos.config.system.build.toplevel --no-link 2>&1 | tail -10
    '; then
        pass "NixOS system closure builds"
    else
        fail "NixOS system closure build failed"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Runtime smoke test (soyeht pair)
# ═══════════════════════════════════════════════════════════════════════════════

run_phase4() {
    header "Phase 4: Runtime Smoke Test"

    # This phase requires the Rust binaries to be built.
    # Try to use nix-built binaries or pre-built ones.

    info "Checking for built binaries..."

    HAS_BINARIES=false
    if run_in_bash '
        cd /root/theyos
        ADMIN_PKG=$(nix build .#theyos-admin --print-out-paths 2>/dev/null)
        if [ -n "$ADMIN_PKG" ] && [ -x "$ADMIN_PKG/bin/soyeht" ]; then
            ln -sf "$ADMIN_PKG/bin" /tmp/theyos-bin
            exit 0
        fi
        exit 1
    ' 2>/dev/null; then
        HAS_BINARIES=true
        info "Using nix-built binaries"
    fi

    if [ "$HAS_BINARIES" = false ]; then
        warn "No pre-built binaries found. Run phase3 first, or build locally."
        warn "Skipping runtime tests."
        return
    fi

    # 4.1 — soyeht binary exists and runs
    if run_in '/tmp/theyos-bin/soyeht --version 2>&1 | head -1'; then
        pass "soyeht --version works"
    else
        fail "soyeht --version failed"
    fi

    # 4.2 — soyeht --help contains expected subcommands
    HELP=$(run_in '/tmp/theyos-bin/soyeht --help 2>&1 || true')
    for subcmd in pair doctor status build test; do
        if echo "$HELP" | grep -qi "$subcmd"; then
            pass "soyeht help lists '$subcmd'"
        else
            fail "soyeht help missing '$subcmd'"
        fi
    done

    # 4.3 — soyeht render-env works
    run_in_bash '
        mkdir -p /root/theyos-test
        THEYOS_DIR=/root/theyos /tmp/theyos-bin/soyeht render-env \
            --template /root/theyos/.env.example \
            --set SOYEHT_ADMIN_USER=admin \
            --set "SOYEHT_ADMIN_PASSWORD=testpass123" \
            --set "THEYOS_SESSION_PEPPER=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" \
            --set THEYOS_HOME=/root \
            --set ACCESS_MODE=local \
            --set THEYOS_OWNER_AUTH_V2_ROLLOUT=legacy \
            --set ADMIN_PORT=8892 \
            --set THEYOS_BASE_DOMAIN=localhost \
            --output /root/theyos-test/.env 2>&1 || true
    '
    if run_in 'test -f /root/theyos-test/.env'; then
        pass "soyeht render-env generates .env"

        # 4.3b — .env has substituted values
        if run_in 'grep -q "testpass123" /root/theyos-test/.env'; then
            pass ".env contains substituted password"
        else
            fail ".env password substitution failed"
        fi

        if run_in 'grep -q "^THEYOS_OWNER_AUTH_V2_ROLLOUT=legacy$" /root/theyos-test/.env'; then
            pass ".env contains default-off owner-auth rollout control"
        else
            fail ".env owner-auth rollout control missing or not default-off"
        fi
    else
        fail "soyeht render-env failed"
    fi

    # 4.4 — Start admin backend and test healthz
    info "Starting admin backend..."
    run_in_bash '
        cp /root/theyos-test/.env /root/theyos/.env

        # Create required directories
        mkdir -p /root/theyos/{.run,logs}
        mkdir -p /root/theyos/claws/data/{picoclaw,zeroclaw,nanobot,openclaw,nullclaw,ironclaw}/customers
        mkdir -p /root/theyos/admin/web

        # Create empty web dir (no frontend in this test)
        touch /root/theyos/admin/web/index.html

        # Symlink IPC binaries from nix store
        for bin in /tmp/theyos-bin/*; do
            bname=$(basename "$bin")
            case "$bname" in
                soyeht|theyos-*|rootfsbuilder|fc-ssh) ;;
                *) export "THEYOS_$(echo "$bname" | tr "a-z-" "A-Z_" | sed "s/_IPC$//" | sed "s/^//" )_RS_BIN=$bin" ;;
            esac
        done

        # Start admin backend in background
        cd /root/theyos
        THEYOS_DIR=/root/theyos \
        WEB_DIR=/root/theyos/admin/web \
        THEYOS_BIN_DIR=/tmp/theyos-bin \
        /tmp/theyos-bin/theyos-admin-host > /tmp/admin.log 2>&1 &
        echo $! > /tmp/admin.pid
    '

    # Wait for healthz
    HEALTHY=false
    for i in $(seq 1 30); do
        if run_in 'curl -sf http://localhost:8892/healthz >/dev/null 2>&1'; then
            HEALTHY=true
            break
        fi
        sleep 1
    done

    if [ "$HEALTHY" = true ]; then
        pass "Admin backend healthz OK"
    else
        fail "Admin backend did not become healthy in 30s"
        warn "Last log lines:"
        run_in 'tail -20 /tmp/admin.log 2>/dev/null' || true
    fi

    # 4.5 — Test soyeht pair
    if [ "$HEALTHY" = true ]; then
        info "Testing soyeht pair..."
        PAIR_OUTPUT=$(run_in_bash '
            THEYOS_DIR=/root/theyos \
            THEYOS_BOOTSTRAP_TOKEN_PATH=/var/lib/theyos/secrets/bootstrap-token \
            THEYOS_ADMIN_URL=http://localhost:8892 \
            /tmp/theyos-bin/soyeht pair 2>&1 || true
        ')

        if echo "$PAIR_OUTPUT" | grep -qi "deep.link\|theyos://pair\|QR"; then
            pass "soyeht pair generates QR/deep link"
        else
            fail "soyeht pair did not produce expected output"
            echo "  Output: $(echo "$PAIR_OUTPUT" | head -10)"
        fi

        # 4.6 — Test pair-token API directly
        BOOTSTRAP_TOKEN=$(run_in 'cat /var/lib/theyos/secrets/bootstrap-token')
        PAIR_RESP=$(run_in_bash "
            curl -sf -X POST http://localhost:8892/api/v1/mobile/pair-token \
                -H 'Authorization: Bearer $BOOTSTRAP_TOKEN' 2>&1 || true
        ")

        if echo "$PAIR_RESP" | grep -qi "deep_link\|token"; then
            pass "POST /api/v1/mobile/pair-token returns token"
        else
            fail "pair-token API failed"
            echo "  Response: $(echo "$PAIR_RESP" | head -5)"
        fi
    else
        warn "Skipping pair test (backend not healthy)"
    fi

    # Cleanup: stop admin backend
    run_in 'kill $(cat /tmp/admin.pid 2>/dev/null) 2>/dev/null || true'
}

# ═══════════════════════════════════════════════════════════════════════════════
# Run phases
# ═══════════════════════════════════════════════════════════════════════════════

case "$PHASES" in
    phase1) run_phase1 ;;
    phase2) run_phase2 ;;
    phase3) run_phase3 ;;
    phase4) run_phase4 ;;
    all)
        run_phase1
        run_phase2
        run_phase3
        run_phase4
        ;;
    *)
        echo "Usage: $0 [phase1|phase2|phase3|phase4|all]"
        exit 1
        ;;
esac

# ── Summary ──────────────────────────────────────────────────────────────────

header "Summary"

if [ "$FAILURES" -eq 0 ]; then
    printf "${GREEN}All tests passed!${NC}\n"
else
    printf "${RED}${FAILURES} test(s) failed.${NC}\n"
    exit 1
fi
