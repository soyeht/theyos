#!/bin/sh
# install-linux.sh — Soyeht engine installer for Linux (x86_64 / aarch64).
#
# Usage:
#   curl -fsSL https://soyeht.com/install | sh
#   # or for a specific version:
#   SOYEHT_VERSION=0.2.0 sh install-linux.sh
#
# Environment variables (all optional):
#   SOYEHT_VERSION     — engine version to install (default: latest from soyeht.com/VERSION)
#   SOYEHT_INSTALL_DIR — base install directory (default: ~/.local/share/Soyeht)
#   SOYEHT_LINGER      — "yes" to enable systemd linger without prompting (CI / automation)
#
# Requirements:
#   - curl or wget
#   - sha256sum (from coreutils; on macOS use shasum -a 256)
#   - systemd (user session)
#   - tar, gzip
#
# POSIX-compatible (busybox sh / dash / bash). No external deps beyond
# standard Linux userland.
#
# This script is IDEMPOTENT: running it a second time upgrades an existing
# installation to the requested version.
#
# T039 implementation (Phase 4). Skeleton only at Phase 1 — filled in at Phase 4.

set -eu

# ── Constants ────────────────────────────────────────────────────────────────

SOYEHT_BASE_URL="${SOYEHT_BASE_URL:-https://soyeht.com}"
SOYEHT_INSTALL_DIR="${SOYEHT_INSTALL_DIR:-$HOME/.local/share/Soyeht}"
ENGINE_DIR="$SOYEHT_INSTALL_DIR/engine"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_NAME="soyeht-engine.service"
HOUSEHOLD_PORT="8091"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { printf 'soyeht: %s\n' "$*" >&2; }
die()  { printf 'soyeht: ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\033[1;32m➜\033[0m %s\n' "$*"; }

# Detect CPU architecture.
detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "x86_64" ;;
        aarch64) echo "aarch64" ;;
        arm64)   echo "aarch64" ;;
        *)       die "Unsupported architecture: $(uname -m). Soyeht supports x86_64 and aarch64." ;;
    esac
}

# Require a command to be on PATH; die with a helpful message if not found.
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1. Install it and re-run."
}

# Download a URL to a local file using curl or wget.
download() {
    url="$1"; dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --waitretry=2 -O "$dest" "$url"
    else
        die "Neither curl nor wget found. Install one and re-run."
    fi
}

# Verify sha256 of a file against a sidecar .sha256 file.
verify_sha256() {
    file="$1"; sidecar="${file}.sha256"
    expected=$(awk '{print $1}' "$sidecar")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        die "sha256sum / shasum not found. Cannot verify download integrity."
    fi
    [ "$expected" = "$actual" ] || die "SHA256 mismatch for $(basename "$file"). Download may be corrupt."
}

# ── Firewall check (informational only — never auto-modifies rules) ──────────
#
# Per FR-038: emit a message if UFW or firewalld is active. Soyeht uses
# Tailscale for peer discovery; opening ports is optional (and not
# recommended on Internet-facing servers). We only inform.
check_firewall() {
    ufw_active=0
    firewalld_active=0

    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null | grep -q "^Status: active" && ufw_active=1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet firewalld 2>/dev/null && firewalld_active=1 || true
    fi

    if [ "$ufw_active" = "1" ] || [ "$firewalld_active" = "1" ]; then
        printf '\n'
        printf '⚠️  Firewall detectado.\n'
        printf '   Soyeht escuta nas portas %s (household) e 8892 (admin).\n' "$HOUSEHOLD_PORT"
        printf '   Como sua casa é descoberta via Tailscale (tailscale0),\n'
        printf '   você NÃO precisa abrir as portas para a internet pública.\n'
        printf '   Se quiser permitir descoberta também na rede local (não recomendado\n'
        printf '   para servidor exposto), rode:\n'
        if [ "$ufw_active" = "1" ]; then
            printf '     sudo ufw allow %s/tcp\n' "$HOUSEHOLD_PORT"
            printf '     sudo ufw allow 8892/tcp\n'
        fi
        if [ "$firewalld_active" = "1" ]; then
            printf '     sudo firewall-cmd --permanent --add-port=%s/tcp\n' "$HOUSEHOLD_PORT"
            printf '     sudo firewall-cmd --permanent --add-port=8892/tcp\n'
            printf '     sudo firewall-cmd --reload\n'
        fi
        printf '\n'
    fi
}

# ── Systemd unit writer ───────────────────────────────────────────────────────

write_systemd_unit() {
    engine_bin="$1"
    mkdir -p "$SYSTEMD_USER_DIR"
    cat > "$SYSTEMD_USER_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=Soyeht Engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$engine_bin
Environment=THEYOS_DIR=$SOYEHT_INSTALL_DIR
Environment=THEYOS_HOUSEHOLD_PORT=$HOUSEHOLD_PORT
Environment=XDG_DATA_HOME=%h/.local/share
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
}

# ── Linger prompt ─────────────────────────────────────────────────────────────

prompt_linger() {
    if [ "${SOYEHT_LINGER:-}" = "yes" ]; then
        return 0  # automation: skip prompt
    fi
    # In CI or piped installs /dev/tty may not exist; default to no-linger.
    if [ ! -r /dev/tty ]; then
        return 1
    fi
    printf '\nManter Soyeht ativo mesmo deslogado? (s/N): '
    read -r answer </dev/tty
    case "$answer" in
        s|S|y|Y|sim|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    info "Instalando Soyeht..."

    require_cmd tar

    ARCH="$(detect_arch)"
    log "Architecture: $ARCH"

    # Resolve version.
    if [ -z "${SOYEHT_VERSION:-}" ]; then
        tmp_ver="$(mktemp)"
        download "$SOYEHT_BASE_URL/VERSION" "$tmp_ver" 2>/dev/null || true
        SOYEHT_VERSION="$(cat "$tmp_ver" 2>/dev/null | tr -d '[:space:]')"
        rm -f "$tmp_ver"
        [ -n "$SOYEHT_VERSION" ] || die "Could not determine latest version. Set SOYEHT_VERSION= and retry."
    fi
    log "Version: $SOYEHT_VERSION"

    TARBALL_NAME="theyos-engine-${SOYEHT_VERSION}-linux-${ARCH}.tar.gz"
    TARBALL_URL="$SOYEHT_BASE_URL/dist/linux-${ARCH}/$TARBALL_NAME"
    SHA256_URL="${TARBALL_URL}.sha256"

    # Download to a temp directory.
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Baixando $TARBALL_NAME..."
    download "$TARBALL_URL" "$TMP_DIR/$TARBALL_NAME"
    download "$SHA256_URL" "$TMP_DIR/${TARBALL_NAME}.sha256"

    info "Verificando sha256..."
    verify_sha256 "$TMP_DIR/$TARBALL_NAME"

    # Install.
    mkdir -p "$ENGINE_DIR"
    info "Extraindo para $ENGINE_DIR..."
    tar xzf "$TMP_DIR/$TARBALL_NAME" -C "$ENGINE_DIR"

    ENGINE_BIN="$ENGINE_DIR/theyos-engine"
    chmod +x "$ENGINE_BIN"

    # Write systemd unit.
    write_systemd_unit "$ENGINE_BIN"
    info "Serviço systemd criado em $SYSTEMD_USER_DIR/$SERVICE_NAME"

    # Reload + enable.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable --now "$SERVICE_NAME"
        info "Soyeht Engine ativado e iniciado."
    else
        info "systemctl não encontrado — inicie manualmente: $ENGINE_BIN"
    fi

    # Firewall check (informational).
    check_firewall

    # Linger prompt.
    if prompt_linger; then
        sudo loginctl enable-linger "$USER"
        info "Linger ativado — Soyeht será iniciado automaticamente no boot."
    fi

    info "Instalação concluída. Acesse o painel em http://127.0.0.1:8892"
}

main "$@"
