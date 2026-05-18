#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export HOME="$TMP/home"
export XDG_CONFIG_HOME="$HOME/.config"
export PATH="$TMP/bin:$PATH"
mkdir -p "$HOME" "$TMP/bin" "$TMP/dist"

cat > "$TMP/bin/systemctl" <<'SH'
#!/usr/bin/env sh
printf 'systemctl %s\n' "$*" >> "$TEST_LOG"
for arg in "$@"; do
  if [ "$arg" = "is-active" ]; then exit 1; fi
done
exit 0
SH
chmod +x "$TMP/bin/systemctl"

cat > "$TMP/bin/sudo" <<'SH'
#!/usr/bin/env sh
printf 'sudo %s\n' "$*" >> "$TEST_LOG"
exit 0
SH
chmod +x "$TMP/bin/sudo"

cat > "$TMP/bin/loginctl" <<'SH'
#!/usr/bin/env sh
printf 'loginctl %s\n' "$*" >> "$TEST_LOG"
exit 0
SH
chmod +x "$TMP/bin/loginctl"

cat > "$TMP/bin/curl" <<'SH'
#!/usr/bin/env sh
dest=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; dest="$1" ;;
    http*) url="$1" ;;
  esac
  shift
done
[ -n "$dest" ] || exit 2
base="$(basename "$url")"
cp "$FIXTURE_DIR/$base" "$dest"
SH
chmod +x "$TMP/bin/curl"

mkdir -p "$TMP/package"
cat > "$TMP/package/theyos-engine" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat > "$TMP/package/soyeht" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "uninstall" ]; then
  shift
  self="$0"
  if command -v readlink >/dev/null 2>&1; then
    target="$(readlink "$0" 2>/dev/null || true)"
    [ -n "$target" ] && self="$target"
  fi
  exec "$(dirname "$self")/uninstall-linux.sh" "$@"
fi
printf 'fake soyeht: unsupported command: %s\n' "${1:-}" >&2
exit 2
SH
cp "$REPO_DIR/scripts/uninstall-linux.sh" "$TMP/package/uninstall-linux.sh"
chmod +x "$TMP/package/soyeht" "$TMP/package/uninstall-linux.sh"
chmod +x "$TMP/package/theyos-engine"
(cd "$TMP/package" && tar czf "$TMP/dist/theyos-engine-9.9.9-linux-aarch64.tar.gz" theyos-engine soyeht uninstall-linux.sh)
shasum -a 256 "$TMP/dist/theyos-engine-9.9.9-linux-aarch64.tar.gz" > "$TMP/dist/theyos-engine-9.9.9-linux-aarch64.tar.gz.sha256"
cp "$TMP/dist/theyos-engine-9.9.9-linux-aarch64.tar.gz" "$TMP/dist/theyos-engine-9.9.9-linux-x86_64.tar.gz"
cp "$TMP/dist/theyos-engine-9.9.9-linux-aarch64.tar.gz.sha256" "$TMP/dist/theyos-engine-9.9.9-linux-x86_64.tar.gz.sha256"

export TEST_LOG="$TMP/systemctl.log"
export FIXTURE_DIR="$TMP/dist"
export SOYEHT_VERSION=9.9.9
export SOYEHT_BASE_URL=https://fixture.invalid
export SOYEHT_INSTALL_DIR="$HOME/.local/share/Soyeht"
export SOYEHT_LINGER=yes

sh "$REPO_DIR/scripts/install-linux.sh"

test -x "$SOYEHT_INSTALL_DIR/engine/theyos-engine"
test -x "$SOYEHT_INSTALL_DIR/engine/soyeht"
test -x "$SOYEHT_INSTALL_DIR/engine/uninstall-linux.sh"
test "$(readlink "$HOME/.local/bin/soyeht")" = "$SOYEHT_INSTALL_DIR/engine/soyeht"
test -f "$SOYEHT_INSTALL_DIR/install-receipt"
test -f "$SOYEHT_INSTALL_DIR/.linger-enabled-by-soyeht"
grep -q 'Environment=THEYOS_HOME=' "$XDG_CONFIG_HOME/systemd/user/soyeht-engine.service"
grep -q 'Environment=THEYOS_SNAPSHOTS_DIR=' "$XDG_CONFIG_HOME/systemd/user/soyeht-engine.service"
grep -q 'Environment=FIRECRACKER_STATE_DIR=' "$XDG_CONFIG_HOME/systemd/user/soyeht-engine.service"
grep -q 'enable --now soyeht-engine.service' "$TEST_LOG"

"$HOME/.local/bin/soyeht" uninstall --yes

test ! -e "$SOYEHT_INSTALL_DIR"
test ! -e "$HOME/.local/bin/soyeht"
test ! -e "$XDG_CONFIG_HOME/systemd/user/soyeht-engine.service"
grep -q 'disable --now soyeht-engine.service' "$TEST_LOG"
grep -q 'sudo loginctl disable-linger' "$TEST_LOG"

: > "$TEST_LOG"
export SOYEHT_LINGER=no

sh "$REPO_DIR/scripts/install-linux.sh"

test -x "$SOYEHT_INSTALL_DIR/engine/theyos-engine"
test -x "$SOYEHT_INSTALL_DIR/engine/soyeht"
test -f "$SOYEHT_INSTALL_DIR/install-receipt"
test ! -e "$SOYEHT_INSTALL_DIR/.linger-enabled-by-soyeht"
grep -q 'enable --now soyeht-engine.service' "$TEST_LOG"

"$HOME/.local/bin/soyeht" uninstall --yes

test ! -e "$SOYEHT_INSTALL_DIR"
test ! -e "$HOME/.local/bin/soyeht"
test ! -e "$XDG_CONFIG_HOME/systemd/user/soyeht-engine.service"
