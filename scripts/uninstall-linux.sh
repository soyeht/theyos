#!/bin/sh
# uninstall-linux.sh - remove the Soyeht Linux tarball/systemd install.
set -eu

SOYEHT_INSTALL_DIR="${SOYEHT_INSTALL_DIR:-$HOME/.local/share/Soyeht}"
ENGINE_DIR="$SOYEHT_INSTALL_DIR/engine"
RECEIPT_FILE="$SOYEHT_INSTALL_DIR/install-receipt"
LINGER_MARKER="$SOYEHT_INSTALL_DIR/.linger-enabled-by-soyeht"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_NAME="soyeht-engine.service"
UNIT_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME"

AUTO_YES=0
DRY_RUN=0
KEEP_DATA=0
FAILURES=""

usage() {
    cat <<'EOF'
Usage: scripts/uninstall-linux.sh [--yes] [--dry-run] [--keep-data]

Removes the Soyeht Linux engine, user systemd unit, install receipt, optional
linger marker, and all runtime state created by the tarball installer. Use
--keep-data to leave customer/VM data in place while still removing the engine.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --yes|-y) AUTO_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --keep-data) KEEP_DATA=1 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'soyeht: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
    shift
done

log() { printf 'soyeht: %s\n' "$*" >&2; }
warn() { printf 'soyeht: WARN: %s\n' "$*" >&2; }

run_cmd() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'dry-run:'
        for arg in "$@"; do printf ' %s' "$arg"; done
        printf '\n'
        return 0
    fi
    "$@"
}

can_sudo() {
    command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1
}

confirm() {
    [ "$AUTO_YES" = 1 ] && return 0
    [ "$DRY_RUN" = 1 ] && return 0
    printf 'This will uninstall Soyeht from this Linux user. Type "uninstall" to continue: '
    read -r answer
    [ "$answer" = "uninstall" ] || { printf 'Aborted.\n'; exit 1; }
}

remove_path() {
    path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    if [ "$DRY_RUN" = 1 ]; then
        run_cmd rm -rf "$path"
        return 0
    fi
    if run_cmd rm -rf "$path"; then
        log "removed $path"
    elif can_sudo && run_cmd sudo rm -rf "$path"; then
        log "removed $path with sudo"
    else
        warn "could not remove $path"
        FAILURES="${FAILURES}
$path"
    fi
}

remove_symlink_into_install_dir() {
    path="$1"
    [ -L "$path" ] || return 0
    target="$(readlink "$path" 2>/dev/null || true)"
    case "$target" in
        "$SOYEHT_INSTALL_DIR"/*|"$ENGINE_DIR"/*) remove_path "$path" ;;
    esac
}

stop_service() {
    if command -v systemctl >/dev/null 2>&1; then
        run_cmd systemctl --user disable --now "$SERVICE_NAME" 2>/dev/null || true
        run_cmd systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
    fi
}

disable_linger_if_owned() {
    [ -f "$LINGER_MARKER" ] || return 0
    command -v loginctl >/dev/null 2>&1 || return 0
    if command -v sudo >/dev/null 2>&1; then
        run_cmd sudo loginctl disable-linger "$USER" || warn "could not disable linger for $USER"
    else
        warn "sudo not found; leaving systemd linger enabled for $USER"
    fi
}

remove_files() {
    remove_path "$UNIT_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        run_cmd systemctl --user daemon-reload 2>/dev/null || true
    fi

    remove_symlink_into_install_dir "$HOME/.local/bin/soyeht"
    remove_symlink_into_install_dir "$HOME/.local/bin/theyos"
    remove_symlink_into_install_dir "$HOME/.local/bin/theyos-engine"

    if [ "$KEEP_DATA" = 1 ]; then
        remove_path "$ENGINE_DIR"
        remove_path "$SOYEHT_INSTALL_DIR/.engine.new.$$"
        remove_path "$SOYEHT_INSTALL_DIR/.engine.old.$$"
        remove_path "$RECEIPT_FILE"
        remove_path "$LINGER_MARKER"
    else
        remove_path "$SOYEHT_INSTALL_DIR"
        remove_path "${XDG_DATA_HOME:-$HOME/.local/share}/theyos"
        remove_path "${XDG_CONFIG_HOME:-$HOME/.config}/theyos"
        remove_path "${XDG_CACHE_HOME:-$HOME/.cache}/theyos"
        remove_path "${XDG_STATE_HOME:-$HOME/.local/state}/theyos"
        remove_path "$HOME/.theyos"
        remove_path "$HOME/firecracker"
        remove_path "/tmp/theyos.db"
        remove_path "/tmp/theyos.db-shm"
        remove_path "/tmp/theyos.db-wal"
        remove_path "/tmp/theyos.sessions.db"
        remove_path "/tmp/theyos.sessions.db-shm"
        remove_path "/tmp/theyos.sessions.db-wal"
        remove_path "/tmp/theyos-sessions.db"
        remove_path "/tmp/theyos-sessions.db-shm"
        remove_path "/tmp/theyos-sessions.db-wal"
        remove_path "/tmp/jobs-rs.db"
        remove_path "/tmp/jobs-rs.db-shm"
        remove_path "/tmp/jobs-rs.db-wal"
        remove_path "/tmp/ratelimit-rs.db"
        remove_path "/tmp/ratelimit-rs.db-shm"
        remove_path "/tmp/ratelimit-rs.db-wal"
    fi
}

verify_no_residuals() {
    residuals=""
    [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ] && residuals="${residuals}
$UNIT_FILE"

    if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        residuals="${residuals}
active $SERVICE_NAME"
    fi

    if [ "$KEEP_DATA" = 1 ]; then
        [ -e "$ENGINE_DIR" ] || [ -L "$ENGINE_DIR" ] && residuals="${residuals}
$ENGINE_DIR"
    else
        for path in "$SOYEHT_INSTALL_DIR" "${XDG_DATA_HOME:-$HOME/.local/share}/theyos" "${XDG_CONFIG_HOME:-$HOME/.config}/theyos" "${XDG_CACHE_HOME:-$HOME/.cache}/theyos" "${XDG_STATE_HOME:-$HOME/.local/state}/theyos" "$HOME/.theyos" "$HOME/firecracker" /tmp/theyos.db /tmp/theyos.db-shm /tmp/theyos.db-wal /tmp/theyos.sessions.db /tmp/theyos.sessions.db-shm /tmp/theyos.sessions.db-wal /tmp/theyos-sessions.db /tmp/theyos-sessions.db-shm /tmp/theyos-sessions.db-wal /tmp/jobs-rs.db /tmp/jobs-rs.db-shm /tmp/jobs-rs.db-wal /tmp/ratelimit-rs.db /tmp/ratelimit-rs.db-shm /tmp/ratelimit-rs.db-wal; do
            [ -e "$path" ] || [ -L "$path" ] && residuals="${residuals}
$path"
        done
    fi

    if [ -n "$FAILURES" ] || [ -n "$residuals" ]; then
        printf 'soyeht: ERROR: residual artifacts remain:\n%s\n%s\n' "$FAILURES" "$residuals" >&2
        return 1
    fi
    log "verification passed: no known Soyeht Linux artifacts remain"
}

main() {
    confirm
    stop_service
    disable_linger_if_owned
    remove_files
    [ "$DRY_RUN" = 1 ] || verify_no_residuals
    log "uninstall complete"
}

main "$@"
