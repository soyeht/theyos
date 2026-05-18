#!/bin/sh
# Recovery entrypoint for Linux installs.
#
# The product uninstaller is `soyeht uninstall`. This script exists only for
# bootstrap/recovery cases where a user needs a curl-able endpoint.
set -eu

SOYEHT_INSTALL_DIR="${SOYEHT_INSTALL_DIR:-$HOME/.local/share/Soyeht}"
ENGINE_DIR="$SOYEHT_INSTALL_DIR/engine"

find_soyeht() {
    if command -v soyeht >/dev/null 2>&1; then
        cli="$(command -v soyeht)"
        if [ -x "$cli" ]; then
            printf '%s\n' "$cli"
            return 0
        fi
    fi

    if [ -x "$ENGINE_DIR/soyeht" ]; then
        printf '%s\n' "$ENGINE_DIR/soyeht"
        return 0
    fi

    return 1
}

if cli="$(find_soyeht)"; then
    exec "$cli" uninstall "$@"
fi

if [ -f "$ENGINE_DIR/uninstall-release-linux.sh" ]; then
    exec sh "$ENGINE_DIR/uninstall-release-linux.sh" "$@"
fi

printf 'soyeht: ERROR: Soyeht CLI not found.\n' >&2
printf 'soyeht: Install or repair Soyeht, then run: soyeht uninstall\n' >&2
exit 1
