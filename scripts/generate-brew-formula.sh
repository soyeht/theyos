#!/usr/bin/env sh
# Update the Homebrew formula with the current release version + SHA256
#
# This script reads the version from admin/rust/soyeht-rs/Cargo.toml
# and patches homebrew/Formula/theyos.rb in place.
#
# Usage:
#   ./scripts/generate-brew-formula.sh [--dry-run]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo "${GREEN}[INFO]${NC} $1"; }
warn() { echo "${YELLOW}[WARN]${NC} $1"; }

# Parse arguments
DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    info "Dry run mode - will not write files"
fi

# Extract version from Cargo.toml
CARGO_TOML="${REPO_ROOT}/admin/rust/soyeht-rs/Cargo.toml"
if [ ! -f "${CARGO_TOML}" ]; then
    echo "Error: ${CARGO_TOML} not found"
    exit 1
fi

VERSION=$(grep "^version" "${CARGO_TOML}" | sed 's/version = "\(.*\)"/\1/')
if [ -z "${VERSION}" ]; then
    echo "Error: Could not extract version from ${CARGO_TOML}"
    exit 1
fi

info "Extracted version: ${VERSION}"

# Output formula file
FORMULA_FILE="${REPO_ROOT}/homebrew/Formula/theyos.rb"

# Skip regeneration when the formula is the deprecation stub.
# Stub uses `url "data:,"` + a trailing comment which breaks the version/url/sha
# regex sub! pattern. The stub intentionally has no real download URL since the
# `def install` block runs `odie` to redirect users to https://soyeht.com/install.
# Detection sentinel: the deprecation stub has 'DEPRECATED' in its `desc` line.
if grep -q '^  desc ".*DEPRECATED' "${FORMULA_FILE}"; then
    info "Formula is a deprecation stub — skipping version/url/sha regeneration"
    info "  (see homebrew/Formula/theyos.rb header for Constitution-IV rationale)"
    exit 0
fi

# Check if there's a built tarball to compute SHA256
PLATFORM="macos-arm64"
DIST_DIR="${REPO_ROOT}/dist/${PLATFORM}"
PKG_NAME="theyos-${VERSION}-${PLATFORM}"
TARBALL="${DIST_DIR}/${PKG_NAME}.tar.gz"
FORMULA_URL="https://github.com/soyeht/theyos/releases/download/v${VERSION}/${PKG_NAME}.tar.gz"

SHA256_PLACEHOLDER="PLACEHOLDER_ARM64_SHA256"

if [ -f "${TARBALL}" ]; then
    info "Found tarball: ${TARBALL}"
    if command -v shasum >/dev/null 2>&1; then
        SHA256=$(shasum -a 256 "${TARBALL}" | awk '{print $1}')
        info "Computed SHA256: ${SHA256}"
        SHA256_PLACEHOLDER="${SHA256}"
    else
        warn "shasum not found - using placeholder SHA256"
    fi
else
    warn "No tarball found at ${TARBALL} - using placeholder SHA256"
fi

UPDATED_FORMULA="$(ruby - "${FORMULA_FILE}" "${VERSION}" "${FORMULA_URL}" "${SHA256_PLACEHOLDER}" <<'RUBY'
formula_path, version, url, sha = ARGV
content = File.read(formula_path)

content.sub!(/^  version ".+"$/, "  version \"#{version}\"") or abort("Could not find version line in #{formula_path}")
content.sub!(/^  url ".+"$/, "  url \"#{url}\"") or abort("Could not find url line in #{formula_path}")
content.sub!(/^  sha256 ".+"$/, "  sha256 \"#{sha}\"") or abort("Could not find sha256 line in #{formula_path}")

print content
RUBY
)"

# Write or display the formula
if [ "$DRY_RUN" = true ]; then
    info "Would update: ${FORMULA_FILE}"
    echo ""
    echo "=== Updated Formula ==="
    echo "${UPDATED_FORMULA}"
else
    printf '%s\n' "${UPDATED_FORMULA}" > "${FORMULA_FILE}"
    info "Updated formula metadata in: ${FORMULA_FILE}"

    if command -v ruby >/dev/null 2>&1; then
        ruby -c "${FORMULA_FILE}" >/dev/null 2>&1
        info "✓ Formula syntax is valid"
    fi
fi

info "Version: ${VERSION}"
info "URL: ${FORMULA_URL}"
info "SHA256: ${SHA256_PLACEHOLDER}"

if [ "${SHA256_PLACEHOLDER}" = "PLACEHOLDER_ARM64_SHA256" ]; then
    warn "Note: SHA256 is a placeholder. Build the tarball first:"
    warn "  ./scripts/make.sh package"
    warn "  ./scripts/generate-brew-formula.sh"
fi
