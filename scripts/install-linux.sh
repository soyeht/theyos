#!/bin/sh
# install-linux.sh — Soyeht engine installer for Linux (x86_64 / aarch64).
#
# Usage:
#   curl -fsSL https://soyeht.com/install | sh
#   # or for a specific version:
#   SOYEHT_VERSION=0.2.0 sh install-linux.sh
#
# Environment variables (all optional):
#   SOYEHT_VERSION     — engine version to install (default: latest release)
#   SOYEHT_INSTALL_DIR — base install directory (default: ~/.local/share/Soyeht)
#   SOYEHT_BASE_URL    — primary download base URL (default: https://soyeht.com)
#   SOYEHT_GITHUB_REPO — GitHub fallback repo (default: soyeht/theyos)
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
SOYEHT_GITHUB_REPO="${SOYEHT_GITHUB_REPO:-soyeht/theyos}"
SOYEHT_INSTALL_DIR="${SOYEHT_INSTALL_DIR:-$HOME/.local/share/Soyeht}"
ENGINE_DIR="$SOYEHT_INSTALL_DIR/engine"
RECEIPT_FILE="$SOYEHT_INSTALL_DIR/install-receipt"
LINGER_MARKER="$SOYEHT_INSTALL_DIR/.linger-enabled-by-soyeht"
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

# Download a URL to a local file using curl or wget. Returns non-zero when the
# source is unavailable so callers can try a fallback.
try_download() {
    url="$1"; dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --waitretry=2 -O "$dest" "$url"
    else
        die "Neither curl nor wget found. Install one and re-run."
    fi
}

download() {
    url="$1"; dest="$2"
    try_download "$url" "$dest" || die "Could not download $url"
}

download_first() {
    dest="$1"; shift
    for url in "$@"; do
        if try_download "$url" "$dest"; then
            log "Downloaded: $url"
            return 0
        fi
    done
    die "Could not download $(basename "$dest") from any release source."
}

github_release_tag() {
    case "$1" in
        v*) printf '%s\n' "$1" ;;
        *) printf 'v%s\n' "$1" ;;
    esac
}

version_without_v() {
    case "$1" in
        v*) printf '%s\n' "${1#v}" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

latest_version_from_github() {
    dest="$1"
    api_url="${SOYEHT_GITHUB_API_URL:-https://api.github.com/repos/$SOYEHT_GITHUB_REPO/releases/latest}"
    try_download "$api_url" "$dest" || return 1
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dest" | head -1
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
Environment=THEYOS_HOME=$SOYEHT_INSTALL_DIR
Environment=THEYOS_STATE_DIR=$SOYEHT_INSTALL_DIR/state
Environment=ADMIN_PORT=8892
Environment=ADDR=0.0.0.0:8892
Environment=THEYOS_SQLITE_DB=$SOYEHT_INSTALL_DIR/theyos.db
Environment=THEYOS_SESSION_DB=$SOYEHT_INSTALL_DIR/theyos.sessions.db
Environment=THEYOS_JOBS_DB=$SOYEHT_INSTALL_DIR/jobs-rs.db
Environment=THEYOS_RATELIMIT_DB=$SOYEHT_INSTALL_DIR/ratelimit-rs.db
Environment=THEYOS_CONVERSATIONS_DIR=$SOYEHT_INSTALL_DIR/conversations
Environment=THEYOS_BIN_DIR=$ENGINE_DIR
Environment=THEYOS_VMRUNNER_RS_BIN=$ENGINE_DIR/vmrunner_ipc
Environment=THEYOS_STORE_RS_BIN=$ENGINE_DIR/store-ipc
Environment=THEYOS_TERMINAL_RS_BIN=$ENGINE_DIR/terminal-ipc
Environment=THEYOS_IMAGEBUILDER_BIN=$ENGINE_DIR/imagebuilder
Environment=THEYOS_VM_ASSETS_DIR=$SOYEHT_INSTALL_DIR/vms
Environment=THEYOS_VM_STATE_DIR=$SOYEHT_INSTALL_DIR/vms
Environment=THEYOS_SNAPSHOTS_DIR=$SOYEHT_INSTALL_DIR/snapshots
Environment=FIRECRACKER_STATE_DIR=$SOYEHT_INSTALL_DIR/firecracker/instances
Environment=FIRECRACKER_CTL=$ENGINE_DIR/fc-ssh
Environment=FIRECRACKER_BIN=$SOYEHT_INSTALL_DIR/firecracker/bin/firecracker
Environment=FIRECRACKER_KERNEL_IMAGE=$SOYEHT_INSTALL_DIR/firecracker/assets/vmlinux-6.1.155
Environment=FIRECRACKER_BASE_ROOTFS=$SOYEHT_INSTALL_DIR/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4
Environment=FIRECRACKER_SSH_KEY=$SOYEHT_INSTALL_DIR/firecracker/assets/ubuntu-24.04-root.id_rsa
Environment=FIRECRACKER_SSH_PUBKEY=$SOYEHT_INSTALL_DIR/firecracker/assets/ubuntu-24.04-root.id_rsa.pub
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
    case "${SOYEHT_LINGER:-}" in
        yes|YES|true|TRUE|1) return 0 ;;
        no|NO|false|FALSE|0) return 1 ;;
    esac
    # In CI or piped installs /dev/tty may not exist; default to no-linger.
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
        return 1
    fi
    printf '\nManter Soyeht ativo mesmo deslogado? (s/N): ' >/dev/tty
    if ! IFS= read -r answer </dev/tty; then
        return 1
    fi
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
        try_download "$SOYEHT_BASE_URL/VERSION" "$tmp_ver" 2>/dev/null || true
        SOYEHT_VERSION="$(cat "$tmp_ver" 2>/dev/null | tr -d '[:space:]')"
        if [ -z "$SOYEHT_VERSION" ]; then
            SOYEHT_VERSION="$(latest_version_from_github "$tmp_ver" 2>/dev/null | tr -d '[:space:]' || true)"
        fi
        rm -f "$tmp_ver"
        [ -n "$SOYEHT_VERSION" ] || die "Could not determine latest version from $SOYEHT_BASE_URL or GitHub. Set SOYEHT_VERSION= and retry."
    fi
    SOYEHT_VERSION="$(version_without_v "$SOYEHT_VERSION")"
    log "Version: $SOYEHT_VERSION"

    TARBALL_NAME="theyos-engine-${SOYEHT_VERSION}-linux-${ARCH}.tar.gz"
    TARBALL_URL="$SOYEHT_BASE_URL/dist/linux-${ARCH}/$TARBALL_NAME"
    SHA256_URL="${TARBALL_URL}.sha256"
    GITHUB_TAG="$(github_release_tag "$SOYEHT_VERSION")"
    GITHUB_RELEASE_URL="https://github.com/$SOYEHT_GITHUB_REPO/releases/download/$GITHUB_TAG/$TARBALL_NAME"
    GITHUB_SHA256_URL="${GITHUB_RELEASE_URL}.sha256"

    # Download to a temp directory.
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Baixando $TARBALL_NAME..."
    download_first "$TMP_DIR/$TARBALL_NAME" "$TARBALL_URL" "$GITHUB_RELEASE_URL"
    download_first "$TMP_DIR/${TARBALL_NAME}.sha256" "$SHA256_URL" "$GITHUB_SHA256_URL"

    info "Verificando sha256..."
    verify_sha256 "$TMP_DIR/$TARBALL_NAME"

    # Install.
    mkdir -p "$SOYEHT_INSTALL_DIR"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
    fi

    NEW_ENGINE_DIR="$SOYEHT_INSTALL_DIR/.engine.new.$$"
    OLD_ENGINE_DIR="$SOYEHT_INSTALL_DIR/.engine.old.$$"
    rm -rf "$NEW_ENGINE_DIR" "$OLD_ENGINE_DIR"
    mkdir -p "$NEW_ENGINE_DIR"
    info "Extraindo para $NEW_ENGINE_DIR..."
    tar xzf "$TMP_DIR/$TARBALL_NAME" -C "$NEW_ENGINE_DIR"
    if [ ! -f "$NEW_ENGINE_DIR/theyos-engine" ] && [ -f "$NEW_ENGINE_DIR/server-rs" ]; then
        mv "$NEW_ENGINE_DIR/server-rs" "$NEW_ENGINE_DIR/theyos-engine"
    fi
    if [ ! -f "$NEW_ENGINE_DIR/theyos-engine" ] && [ -f "$NEW_ENGINE_DIR/server" ]; then
        mv "$NEW_ENGINE_DIR/server" "$NEW_ENGINE_DIR/theyos-engine"
    fi
    [ -f "$NEW_ENGINE_DIR/theyos-engine" ] || die "Package did not contain theyos-engine."
    for bin in theyos-engine vmrunner_ipc fc-ssh store-ipc terminal-ipc imagebuilder; do
        [ -f "$NEW_ENGINE_DIR/$bin" ] && chmod +x "$NEW_ENGINE_DIR/$bin"
    done
    if [ -d "$ENGINE_DIR" ]; then
        mv "$ENGINE_DIR" "$OLD_ENGINE_DIR"
    fi
    mv "$NEW_ENGINE_DIR" "$ENGINE_DIR"
    rm -rf "$OLD_ENGINE_DIR"

    ENGINE_BIN="$ENGINE_DIR/theyos-engine"

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
        printf 'enabled_by=soyeht\nuser=%s\n' "$USER" > "$LINGER_MARKER"
        info "Linger ativado — Soyeht será iniciado automaticamente no boot."
    fi

    {
        printf 'version=%s\n' "$SOYEHT_VERSION"
        printf 'arch=%s\n' "$ARCH"
        printf 'install_dir=%s\n' "$SOYEHT_INSTALL_DIR"
        printf 'engine_dir=%s\n' "$ENGINE_DIR"
        printf 'service=%s\n' "$SERVICE_NAME"
        printf 'unit_file=%s\n' "$SYSTEMD_USER_DIR/$SERVICE_NAME"
        printf 'installed_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } > "$RECEIPT_FILE"

    info "Instalação concluída. Acesse o painel em http://127.0.0.1:8892"
}

main "$@"
