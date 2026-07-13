#!/usr/bin/env bash
# theyOS build script - Unified build for macOS
# This script compiles all Rust binaries for the current platform

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUST_DIR="${REPO_ROOT}/admin/rust"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo "${GREEN}[INFO]${NC} $1"; }
warn() { echo "${YELLOW}[WARN]${NC} $1"; }
error() { echo "${RED}[ERROR]${NC} $1"; exit 1; }

run_engine_build_tool() {
    local system_home="${HOME:?HOME is required}"
    local cargo_home="${PHASE0_CARGO_HOME:-${system_home}/.cargo}"
    local rustup_home="${PHASE0_RUSTUP_HOME:-${system_home}/.rustup}"
    for cargo_config in "${cargo_home}/config" "${cargo_home}/config.toml"; do
        if [ -e "${cargo_config}" ] || [ -L "${cargo_config}" ]; then
            error "canonical theyos-engine build forbids Cargo home config"
        fi
    done
    local cargo_bin
    cargo_bin="$(command -v cargo)"
    local canonical_path
    canonical_path="$(dirname "${cargo_bin}"):${cargo_home}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
    local clean_root
    clean_root="$(mktemp -d "${TMPDIR:-/tmp}/theyos-engine-build.XXXXXX")"
    local expected_rust
    expected_rust="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "${RUST_DIR}/rust-toolchain.toml")"
    local source_sha
    source_sha="$(git -C "${REPO_ROOT}" rev-parse HEAD)"

    mkdir -p "${clean_root}/home" "${clean_root}/tmp"
    local status=0
    env -i \
        HOME="${clean_root}/home" \
        CARGO_HOME="${cargo_home}" \
        RUSTUP_HOME="${rustup_home}" \
        TMPDIR="${clean_root}/tmp" \
        PATH="${canonical_path}" \
        LC_ALL=C \
        LANG=C \
        RUSTUP_TOOLCHAIN="${expected_rust}" \
        CARGO_TARGET_DIR="${RUST_DIR}/target" \
        CARGO_NET_OFFLINE=true \
        THEYOS_PHASE0_CLEAN_ENV=1 \
        THEYOS_BUILD_GIT_SHA="${source_sha}" \
        "${cargo_bin}" run \
        --manifest-path "${RUST_DIR}/Cargo.toml" \
        --locked \
        --offline \
        --release \
        --package theyos-engine-build-rs \
        -- "$@" || status=$?
    rm -rf "${clean_root}"
    return "${status}"
}

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Darwin)
            if [ "$(uname -m)" = "arm64" ]; then
                echo "macos-arm64"
            else
                echo "macos-intel"
            fi
            ;;
        Linux)
            echo "linux"
            ;;
        *)
            error "Unsupported platform: $(uname -s)"
            ;;
    esac
}

PLATFORM=$(detect_platform)
info "Building for platform: ${PLATFORM}"

# Change to Rust directory
cd "${RUST_DIR}"

# Build targets
build_binaries() {
    info "Building Rust binaries..."

    # Common release flags
    RELEASE_FLAGS="--release --workspace"

    # Build all workspace members
    info "Building workspace..."
    cargo build ${RELEASE_FLAGS}

    # Collect binaries
    local target_dir="target/release"
    local stage_dir="${REPO_ROOT}/.deploy-staging/${PLATFORM}"

    rm -rf "${stage_dir}"
    mkdir -p "${stage_dir}"

    # Copy binaries to staging
    info "Staging binaries to ${stage_dir}..."

    # Core binaries
    for bin in \
        soyeht \
        theyos \
        theyos-admin-host \
        server \
        theyos-ssh \
        init_macos_guest \
        executor_ipc \
        store-ipc \
        terminal-ipc \
        vmrunner_macos_ipc \
        theyos-provision-inject
    do
        if [ -f "${target_dir}/${bin}" ]; then
            cp "${target_dir}/${bin}" "${stage_dir}/"
            info "  ✓ ${bin}"
        else
            warn "  ✗ ${bin} not found (may be platform-specific)"
        fi
    done

    # Linux-specific binaries
    if [ "${PLATFORM}" = "linux" ]; then
        if [ -f "${target_dir}/vmrunner_ipc" ]; then
            cp "${target_dir}/vmrunner_ipc" "${stage_dir}/"
            info "  ✓ vmrunner_ipc (Linux)"
        fi
    fi

    info "Build complete! Binaries staged in: ${stage_dir}"
}

# Codesign every macOS Mach-O in `stage_dir`.
#
# Two modes, gated by THEYOS_CODESIGN_IDENTITY env var:
#
# - **Developer ID** (`THEYOS_CODESIGN_IDENTITY` set, e.g.
#   `Developer ID Application: Sample Developer (TEAM_ID)`):
#   sign with hardened runtime + Apple Timestamp + explicit
#   `com.soyeht.theyos.<bin>` identifier so the DesignatedRequirement
#   stays stable across rebuilds (`anchor apple generic and identifier "..."
#   and certificate leaf [...]`). Required for notarization.
#
# - **Ad-hoc** (`THEYOS_CODESIGN_IDENTITY` unset): linker-signed binaries
#   keep their default ad-hoc signature; only `vmrunner_macos_ipc` gets
#   the VZ entitlement layered on. This preserves dev-loop fast iteration
#   without forcing every contributor to set up a Developer ID cert.
#
# In Developer ID mode, the cdhash-bound Keychain ACL bug
# (`docs/followup-secure-enclave-codesign-acl-on-upgrade.md`) is
# resolved because the ACL anchors to the cert leaf + identifier, both
# of which are stable across builds.
codesign_macos_binaries() {
    if [ "${PLATFORM}" != "macos-arm64" ] && [ "${PLATFORM}" != "macos-intel" ]; then
        return 0
    fi

    # The legacy `package` command builds from the ambient workspace and has
    # no Phase 0 subject manifest. Keep it useful for ad-hoc development, but
    # make it impossible for that path to create a real signed/notarized
    # artifact. Production signing is only available through
    # `package-soyeht-mac`, which verifies the complete Phase 0 subject first.
    if [ -n "${THEYOS_CODESIGN_IDENTITY:-}" ] || \
        [ -n "${APPLE_NOTARY_KEY_P8:-}" ] || \
        [ -n "${APPLE_NOTARY_KEY_ID:-}" ] || \
        [ -n "${APPLE_NOTARY_ISSUER_ID:-}" ]; then
        error "legacy package cannot perform real macOS signing/notarization; use package-soyeht-mac with a verified Phase 0 subject"
    fi

    local stage_dir="${REPO_ROOT}/.deploy-staging/${PLATFORM}"
    local entitlements="${SCRIPT_DIR}/entitlements/vmrunner-macos.entitlements"

    local sign_id="-"
    local sign_args="--force"
    local mode="ad-hoc"
    if [ -n "${THEYOS_CODESIGN_IDENTITY:-}" ]; then
        sign_id="${THEYOS_CODESIGN_IDENTITY}"
        sign_args="--force --timestamp --options runtime"
        mode="Developer ID"
        info "Codesigning macOS binaries with Developer ID: ${sign_id}"
    else
        info "Codesigning macOS binaries ad-hoc (THEYOS_CODESIGN_IDENTITY unset)"
    fi

    # Common binaries: hardened runtime + explicit identifier when Developer ID,
    # plain ad-hoc otherwise.
    for bin in \
        soyeht \
        theyos \
        theyos-admin-host \
        server \
        theyos-ssh \
        init_macos_guest \
        executor_ipc \
        store-ipc \
        terminal-ipc \
        theyos-provision-inject
    do
        if [ -f "${stage_dir}/${bin}" ]; then
            if [ "${mode}" = "Developer ID" ]; then
                codesign ${sign_args} \
                    --identifier "com.soyeht.theyos.${bin}" \
                    -s "${sign_id}" \
                    "${stage_dir}/${bin}"
            else
                # Ad-hoc: skip identifier override (would invalidate the
                # linker-signed default) and skip --timestamp/--options runtime
                # (not honored for ad-hoc).
                :
            fi
            [ "${mode}" = "Developer ID" ] && info "  ✓ ${bin} signed (${mode})"
        fi
    done

    # vmrunner_macos_ipc: VZ entitlement is mandatory regardless of mode
    # (without it, Virtualization.framework throws Obj-C exception → Rust abort,
    # see memory feedback_codesign_vz_entitlement.md).
    if [ -f "${stage_dir}/vmrunner_macos_ipc" ]; then
        if [ ! -f "${entitlements}" ]; then
            warn "Entitlements file not found: ${entitlements}"
            warn "  vmrunner_macos_ipc will not be codesigned — VMs may fail to start"
            return 0
        fi
        if [ "${mode}" = "Developer ID" ]; then
            codesign ${sign_args} \
                --identifier "com.soyeht.theyos.vmrunner_macos_ipc" \
                --entitlements "${entitlements}" \
                -s "${sign_id}" \
                "${stage_dir}/vmrunner_macos_ipc"
        else
            # Ad-hoc: keep prior behavior (only entitlement, default identifier).
            codesign --force --entitlements "${entitlements}" \
                -s "${sign_id}" \
                "${stage_dir}/vmrunner_macos_ipc"
        fi
        info "  ✓ vmrunner_macos_ipc signed (${mode}, com.apple.security.virtualization)"
    fi
}

# Notarize the staged binaries via Apple's notarytool.
#
# Submits a ZIP of `stage_dir` (Apple requires ZIP/PKG/DMG, not tar.gz),
# waits for "Accepted" or rejects with diagnostic. Stapling is intentionally
# skipped: standalone Mach-O executables (no .app bundle) cannot have
# notarization tickets stapled to them — Gatekeeper validates online via
# the cert chain.
#
# The ZIP we submit and the tar.gz we distribute contain the **same** signed
# Mach-Os. No re-signing happens between notarization and tarball creation.
#
# Skipped (with info-level log) when:
# - THEYOS_CODESIGN_IDENTITY is unset (ad-hoc binaries can't be notarized)
# - APPLE_NOTARY_KEY_P8 / APPLE_NOTARY_KEY_ID / APPLE_NOTARY_ISSUER_ID env vars
#   aren't all set
notarize_macos() {
    if [ "${PLATFORM}" != "macos-arm64" ] && [ "${PLATFORM}" != "macos-intel" ]; then
        return 0
    fi
    if [ -n "${THEYOS_CODESIGN_IDENTITY:-}" ] || \
        [ -n "${APPLE_NOTARY_KEY_P8:-}" ] || \
        [ -n "${APPLE_NOTARY_KEY_ID:-}" ] || \
        [ -n "${APPLE_NOTARY_ISSUER_ID:-}" ]; then
        error "legacy package cannot notarize an ambient build; use package-soyeht-mac with a verified Phase 0 subject"
    fi
    if [ -z "${THEYOS_CODESIGN_IDENTITY:-}" ]; then
        info "Skipping notarization (THEYOS_CODESIGN_IDENTITY unset; ad-hoc binaries can't be notarized)"
        return 0
    fi
    if [ -z "${APPLE_NOTARY_KEY_P8:-}" ] || [ -z "${APPLE_NOTARY_KEY_ID:-}" ] || [ -z "${APPLE_NOTARY_ISSUER_ID:-}" ]; then
        warn "Skipping notarization: APPLE_NOTARY_KEY_P8 / APPLE_NOTARY_KEY_ID / APPLE_NOTARY_ISSUER_ID must all be set"
        warn "  Expected for tagged release builds; safe to skip on local dev."
        return 0
    fi

    local stage_dir="${REPO_ROOT}/.deploy-staging/${PLATFORM}"
    local zip_path="${REPO_ROOT}/.deploy-staging/theyos-notarize.zip"

    info "Creating notarization ZIP: ${zip_path}"
    rm -f "${zip_path}"
    ditto -c -k --keepParent "${stage_dir}" "${zip_path}"

    info "Submitting to Apple notarytool (typically 1-3 minutes)..."
    xcrun notarytool submit "${zip_path}" \
        --key "${APPLE_NOTARY_KEY_P8}" \
        --key-id "${APPLE_NOTARY_KEY_ID}" \
        --issuer "${APPLE_NOTARY_ISSUER_ID}" \
        --wait

    rm -f "${zip_path}"
    info "✓ Notarization Accepted (Mach-Os in ${stage_dir} are bytewise identical to notarized payload)"
}

# Run tests
run_tests() {
    info "Running tests..."
    cargo test --workspace
    info "✓ Tests passed"
}

# Run clippy
run_clippy() {
    info "Running clippy..."
    cargo clippy --workspace -- -D warnings
    info "✓ Clippy passed"
}

# Create distribution package
package() {
    info "Creating distribution package..."

    # Extract version from Cargo.toml
    local cargo_toml="${REPO_ROOT}/admin/rust/soyeht-rs/Cargo.toml"
    local version=$(grep "^version" "${cargo_toml}" | sed 's/version = "\(.*\)"/\1/')

    if [ -z "${version}" ]; then
        warn "Could not extract version from Cargo.toml, using 0.0.0"
        version="0.0.0"
    fi

    local stage_dir="${REPO_ROOT}/.deploy-staging/${PLATFORM}"
    local dist_dir="${REPO_ROOT}/dist/${PLATFORM}"
    local pkg_name="theyos-${version}-${PLATFORM}"

    mkdir -p "${dist_dir}"

    # Copy built frontend to staging
    local web_dir="${REPO_ROOT}/admin/web"
    if [ -d "${web_dir}" ] && [ "$(ls -A "${web_dir}" 2>/dev/null)" ]; then
        cp -r "${web_dir}" "${stage_dir}/web"
        info "  + web/ (frontend assets)"
    else
        warn "No frontend build at admin/web/ — run: cd admin/frontend && npm ci && npm run build"
    fi

    # Copy entitlements alongside the binaries. Historically used by the
    # Homebrew formula's install-time codesign; that step is now removed
    # (entitlement is baked into the codesigned vmrunner_macos_ipc instead),
    # but the file still ships for reference + diagnostic.
    if [ -f "${SCRIPT_DIR}/entitlements/vmrunner-macos.entitlements" ]; then
        cp "${SCRIPT_DIR}/entitlements/vmrunner-macos.entitlements" "${stage_dir}/"
        info "  + vmrunner-macos.entitlements"
    fi

    # Sign the staged Mach-Os (Developer ID when env var set, ad-hoc otherwise).
    codesign_macos_binaries

    # Submit ZIP for notarization (no-op when Developer ID env var unset).
    # Must run after codesign and before tarball creation: the bytes Apple
    # accepts are exactly the bytes we ship.
    notarize_macos

    # Create tarball — same signed Mach-Os that were notarized above.
    cd "${stage_dir}"
    tar czf "${dist_dir}/${pkg_name}.tar.gz" .
    info "✓ Package created: ${dist_dir}/${pkg_name}.tar.gz"
    info "  Version: ${version}"
}

# T082 — Package macOS engine into Soyeht.app/Contents/Helpers/.
#
# Builds server-rs for macOS arm64, codesigns it with the existing Developer ID
# mechanism, writes engine-version.txt, and copies the result into
# dist/macos-arm64/Soyeht.app/Contents/Helpers/ ready for the .app bundle.
# The Sparkle appcast.xml and DMG wrapping are handled by the CI release job.
#
# Engine version is derived from `git describe --tags --always`.
package_soyeht_mac() {
    if [ "${PLATFORM}" != "macos-arm64" ]; then
        error "package-soyeht-mac requires macos-arm64 — binary is aarch64 and output goes to dist/macos-arm64/ (current platform: ${PLATFORM})"
    fi

    local sign_id="${THEYOS_CODESIGN_IDENTITY:-}"
    local has_notary_credentials="${APPLE_NOTARY_KEY_P8:-}${APPLE_NOTARY_KEY_ID:-}${APPLE_NOTARY_ISSUER_ID:-}"
    if [ -n "${sign_id}" ] || [ -n "${has_notary_credentials}" ]; then
        if [ -z "${THEYOS_RELEASE:-}" ]; then
            error "real macOS signing/notarization requires THEYOS_RELEASE and a Phase 0 unsigned subject"
        fi
        if [ -z "${PHASE0_UNSIGNED_STAGE_DIR:-}" ] || \
            [ -z "${PHASE0_EXPECTED_UNSIGNED_PACKAGE_MANIFEST_SHA256:-}" ] || \
            [ -z "${PHASE0_EXPECTED_PHASE0_ATTESTATION_SHA256:-}" ]; then
            error "real macOS signing/notarization requires the complete Phase 0 subject binding"
        fi
    fi

    local version
    if [ -n "${THEYOS_RELEASE:-}" ]; then
        if [ -z "${PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256:-}" ]; then
            error "THEYOS_RELEASE requires PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256"
        fi
        # Release path: require an exact tag. Fails early if actions/checkout
        # did not fetch tags or HEAD is not tagged — avoids shipping "dev" builds.
        version=$(git -C "${REPO_ROOT}" describe --tags --exact-match 2>/dev/null) || \
            error "THEYOS_RELEASE is set but HEAD is not on a tag; aborting release package"
    else
        version=$(git -C "${REPO_ROOT}" describe --tags --always 2>/dev/null || echo "dev")
    fi

    local helpers_dir="${REPO_ROOT}/dist/macos-arm64/Soyeht.app/Contents/Helpers"
    local target_dir="${REPO_ROOT}/admin/rust/target/aarch64-apple-darwin/release"
    local unsigned_stage="${PHASE0_UNSIGNED_STAGE_DIR:-}"
    local package_manifest=""
    local phase0_manifest_verified=0
    if [ -n "${THEYOS_RELEASE:-}" ]; then
        if [ -z "${unsigned_stage}" ] || \
            [ -z "${PHASE0_EXPECTED_UNSIGNED_PACKAGE_MANIFEST_SHA256:-}" ] || \
            [ -z "${PHASE0_EXPECTED_PHASE0_ATTESTATION_SHA256:-}" ]; then
            error "THEYOS_RELEASE requires the complete Phase 0 unsigned subject binding"
        fi
        package_manifest="${unsigned_stage}/phase0-package-manifest.json"
        if [ ! -f "${package_manifest}" ]; then
            error "Phase 0 unsigned package manifest is missing: ${package_manifest}"
        fi
        local package_manifest_sha256
        package_manifest_sha256=$(shasum -a 256 "${package_manifest}" | awk '{print $1}')
        if [ "${package_manifest_sha256}" != "${PHASE0_EXPECTED_UNSIGNED_PACKAGE_MANIFEST_SHA256}" ]; then
            error "unsigned macOS package manifest differs from the Phase 0 verified subject"
        fi
        local attestation_sha256 manifest_attestation_sha256
        attestation_sha256=$(shasum -a 256 "${unsigned_stage}/phase0-build-attestation.json" | awk '{print $1}')
        manifest_attestation_sha256=$(jq -r '.phase0_attestation_sha256 // empty' "${package_manifest}")
        if [ "${attestation_sha256}" != "${PHASE0_EXPECTED_PHASE0_ATTESTATION_SHA256}" ] || \
            [ "${manifest_attestation_sha256}" != "${attestation_sha256}" ]; then
            error "unsigned package manifest is not bound to the verified Phase 0 attestation"
        fi
        if ! jq -e '
            (.executables | keys | sort) == [
                "store-ipc",
                "terminal-ipc",
                "theyos-engine",
                "theyos-provision-inject",
                "theyos-ssh",
                "vmrunner_macos_ipc"
            ]
            and (.package_files["vmrunner-macos.entitlements"].unsigned_sha256
              | test("^[0-9a-f]{64}$"))
        ' "${package_manifest}" >/dev/null; then
            error "unsigned macOS package manifest does not describe the exact app subject"
        fi
        phase0_manifest_verified=1
    fi
    local source_dir="${target_dir}"
    if [ -n "${unsigned_stage}" ]; then
        source_dir="${unsigned_stage}"
    fi
    local entitlements="${source_dir}/vmrunner-macos.entitlements"
    mkdir -p "${helpers_dir}"

    if [ -n "${unsigned_stage}" ]; then
        info "Using the prebuilt Phase 0 unsigned macOS subject (no Cargo/build scripts in release packaging)"
    else
        info "Building app engine helpers for macOS arm64 (engine version: ${version})..."
        run_engine_build_tool build aarch64-apple-darwin cargo >/dev/null
        (cd "${REPO_ROOT}/admin/rust" && cargo build --release \
            --target aarch64-apple-darwin \
            -p soyeht-rs \
            -p store-rs \
            -p terminal-rs \
            -p vmrunner-macos-rs)
    fi

    copy_helper() {
        local source_name="$1"
        local dest_name="$2"
        local source_path="${source_dir}/${source_name}"
        if [ ! -f "${source_path}" ]; then
            error "required helper binary not found at: ${source_path}"
        fi
        cp "${source_path}" "${helpers_dir}/${dest_name}"
        info "  + ${dest_name}"
    }

    # Canonical alias: server-rs/server is the shipped theyos-engine.
    if [ -n "${unsigned_stage}" ]; then
        copy_helper "theyos-engine" "theyos-engine"
    else
        run_engine_build_tool stage "${target_dir}" "${helpers_dir}/theyos-engine"
    fi
    if [ -n "${PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256:-}" ]; then
        local staged_engine_sha256
        staged_engine_sha256=$(shasum -a 256 "${helpers_dir}/theyos-engine" | awk '{print $1}')
        if [ "${staged_engine_sha256}" != "${PHASE0_EXPECTED_UNSIGNED_ENGINE_SHA256}" ]; then
            error "unsigned staged theyos-engine differs from the Phase 0 verified subject"
        fi
        info "  + unsigned theyos-engine matches Phase 0 subject"
    fi
    copy_helper "theyos-ssh" "theyos-ssh"
    copy_helper "store-ipc" "store-ipc"
    copy_helper "terminal-ipc" "terminal-ipc"
    copy_helper "vmrunner_macos_ipc" "vmrunner_macos_ipc"
    # Privileged APFS provisioning helper used by Soyeht.app onboarding to
    # mount the macOS guest disk image with `-o owners` and write provision
    # files as `root:wheel`. Built as part of `-p vmrunner-macos-rs`, but it
    # was previously omitted from this copy block, leaving the release
    # tarball without it. Soyeht.app rejects bundles missing this binary.
    copy_helper "theyos-provision-inject" "theyos-provision-inject"

    if [ -n "${unsigned_stage}" ]; then
        while IFS=$'\t' read -r helper expected; do
            actual=$(shasum -a 256 "${helpers_dir}/${helper}" | awk '{print $1}')
            if [ "${actual}" != "${expected}" ]; then
                error "unsigned helper differs from the Phase 0 package manifest: ${helper}"
            fi
        done < <(jq -r '.executables | to_entries[] | [.key,.value.unsigned_sha256] | @tsv' "${package_manifest}")
        expected_entitlements=$(jq -r '.package_files["vmrunner-macos.entitlements"].unsigned_sha256' "${package_manifest}")
        actual_entitlements=$(shasum -a 256 "${entitlements}" | awk '{print $1}')
        if [ "${actual_entitlements}" != "${expected_entitlements}" ]; then
            error "unsigned macOS entitlements differ from the Phase 0 package manifest"
        fi
    fi

    printf '%s' "${version}" > "${helpers_dir}/engine-version.txt"
    info "  + engine-version.txt (${version})"

    if [ ! -f "${entitlements}" ]; then
        error "Entitlements file not found: ${entitlements}"
    fi
    cp "${entitlements}" "${helpers_dir}/vmrunner-macos.entitlements"

    sign_helper() {
        local bin="$1"
        local identifier="$2"
        local entitlements_path="$3"
        local bin_path="${helpers_dir}/${bin}"

        if [ -n "${sign_id}" ]; then
            if [ -n "${entitlements_path}" ]; then
                codesign --force --options runtime --timestamp \
                    --identifier "${identifier}" \
                    --entitlements "${entitlements_path}" \
                    --sign "${sign_id}" \
                    "${bin_path}"
            else
                codesign --force --options runtime --timestamp \
                    --identifier "${identifier}" \
                    --sign "${sign_id}" \
                    "${bin_path}"
            fi
        elif [ -n "${entitlements_path}" ]; then
            codesign --force --entitlements "${entitlements_path}" \
                --sign - \
                "${bin_path}"
        else
            codesign --force --sign - "${bin_path}"
        fi

        info "  ✓ ${bin} signed"
    }

    if [ -n "${sign_id}" ] || [ -n "${has_notary_credentials}" ]; then
        if [ "${phase0_manifest_verified}" -ne 1 ]; then
            error "real macOS signing/notarization is not allowed without a verified Phase 0 subject"
        fi
    fi
    if [ -n "${sign_id}" ]; then
        info "Codesigning Soyeht app helpers with Developer ID: ${sign_id}"
    else
        info "Codesigning Soyeht app helpers ad-hoc (THEYOS_CODESIGN_IDENTITY unset)"
    fi
    sign_helper "theyos-engine" "com.soyeht.theyos.theyos-engine" ""
    sign_helper "theyos-ssh" "com.soyeht.theyos.theyos-ssh" ""
    sign_helper "store-ipc" "com.soyeht.theyos.store-ipc" ""
    sign_helper "terminal-ipc" "com.soyeht.theyos.terminal-ipc" ""
    sign_helper "vmrunner_macos_ipc" "com.soyeht.theyos.vmrunner_macos_ipc" "${entitlements}"
    # provision-inject does not need VM entitlements; it elevates via sudo
    # at runtime to mount the guest disk and write root-owned files.
    sign_helper "theyos-provision-inject" "com.soyeht.theyos.theyos-provision-inject" ""

    # Notarize the signed binary. Required for Gatekeeper on machines that don't
    # have the Developer ID cert in their trust store. Gracefully no-ops when any
    # Apple credential is absent (dev workflow / CI without secrets).
    if [ -n "${sign_id}" ] \
        && [ -n "${APPLE_NOTARY_KEY_P8:-}" ] \
        && [ -n "${APPLE_NOTARY_KEY_ID:-}" ] \
        && [ -n "${APPLE_NOTARY_ISSUER_ID:-}" ]; then
        local notarize_zip="${REPO_ROOT}/.notarize-soyeht-engine.zip"
        rm -f "${notarize_zip}"
        info "Creating notarization ZIP: ${notarize_zip}"
        ditto -c -k --keepParent "${helpers_dir}" "${notarize_zip}"
        info "Submitting to Apple notarytool (typically 1-3 minutes)..."
        xcrun notarytool submit "${notarize_zip}" \
            --key "${APPLE_NOTARY_KEY_P8}" \
            --key-id "${APPLE_NOTARY_KEY_ID}" \
            --issuer "${APPLE_NOTARY_ISSUER_ID}" \
            --wait
        rm -f "${notarize_zip}"
        # Staple the Gatekeeper ticket to the app bundle so offline validation works.
        # NOTE: package_soyeht_mac only produces Soyeht.app/Contents/Helpers/theyos-engine
        # (a partial bundle for agente-front to consume) — NOT a complete .app with
        # Info.plist + MacOS/<main_binary>. Stapler exits 66 on partial bundles.
        # Standalone Mach-O binaries can't be stapled either (per Apple docs); the
        # engine relies on Gatekeeper's online ticket lookup. The agente-front side
        # builds the complete .app and staples it there.
        local app_bundle="${REPO_ROOT}/dist/macos-arm64/Soyeht.app"
        if [ -d "${app_bundle}" ] && [ -f "${app_bundle}/Contents/Info.plist" ]; then
            xcrun stapler staple "${app_bundle}"
            info "  ✓ Gatekeeper ticket stapled to Soyeht.app"
        else
            info "  ⚠ Skipping stapler (no complete .app bundle here; engine is notarized,"
            info "    Gatekeeper validates online — agente-front staples the full .app)"
        fi
        info "  ✓ Notarization accepted"
    else
        info "Skipping notarization (Developer ID credentials not fully set)"
    fi

    info "✓ package-soyeht-mac complete: ${helpers_dir}"
}

# T083 — Cross-compile Linux engine binaries for x86_64 and ARM64.
#
# Produces two tarballs in dist/linux-<arch>/:
#   theyos-engine-<version>-linux-<arch>.tar.gz
#   theyos-engine-<version>-linux-<arch>.tar.gz.sha256
#
# Requires explicitly provisioned target toolchains. The Phase 0 release
# workflow uses its pinned OCI recipe and this helper never discovers an
# ambient Cross CLI.
package_engine_linux() {
    local version
    version=$(git -C "${REPO_ROOT}" describe --tags --always 2>/dev/null || echo "dev")

    local rust_dir="${REPO_ROOT}/admin/rust"
    local dist_base="${REPO_ROOT}/dist"

    for arch in x86_64 aarch64; do
        local rust_target="${arch}-unknown-linux-musl"
        local dist_dir="${dist_base}/linux-${arch}"
        local pkg_name="theyos-engine-${version}-linux-${arch}"

        info "Building the Phase 0 authority subject for ${rust_target}..."
        local authority_root="${dist_base}/.phase0-authority-${arch}"
        local authority_target="${authority_root}/target"
        local authority_attestation="${authority_root}/attestation.json"
        local authority_engine="${authority_root}/theyos-engine"
        rm -rf "${authority_root}"
        mkdir -p "${authority_target}"
        PHASE0_TARGET="${rust_target}" \
        PHASE0_BUILD_TOOL=cross \
        PHASE0_CARGO_TARGET_DIR="${authority_target}" \
        PHASE0_RUN_ARTIFACT_DIRECT=1 \
        PHASE0_ATTESTATION_OUT="${authority_attestation}" \
        PHASE0_STAGED_ENGINE_OUT="${authority_engine}" \
            bash "${REPO_ROOT}/.github/scripts/check-mobile-claw-vpn-owner-present-phase0-compileout.sh"

        # Binary name is `server` per server-rs/Cargo.toml [[bin]] config.
        local soyeht_src="${authority_target}/${rust_target}/release/soyeht"
        if [ ! -f "${soyeht_src}" ]; then
            error "soyeht CLI not found at: ${soyeht_src} (expected from soyeht-rs crate)"
        fi

        mkdir -p "${dist_dir}"

        local stage="${dist_base}/.linux-stage-${arch}"
        rm -rf "${stage}"
        mkdir -p "${stage}"
        cp "${authority_engine}" "${stage}/theyos-engine"
        cp "${soyeht_src}" "${stage}/soyeht"
        cp "${REPO_ROOT}/scripts/uninstall-linux.sh" "${stage}/uninstall-linux.sh"
        chmod +x "${stage}/soyeht" "${stage}/uninstall-linux.sh"
        printf '%s' "${version}" > "${stage}/engine-version.txt"

        local tarball="${dist_dir}/${pkg_name}.tar.gz"
        (cd "${stage}" && tar czf "${tarball}" .)
        sha256sum "${tarball}" > "${tarball}.sha256"
        rm -rf "${stage}"
        rm -rf "${authority_root}"

        info "  ✓ ${tarball}"
        info "  ✓ ${tarball}.sha256"
    done

    info "✓ package-engine-linux complete"
}

# Generate Homebrew formula
generate_brew_formula() {
    info "Generating Homebrew formula from Cargo.toml..."

    local generator_script="${SCRIPT_DIR}/generate-brew-formula.sh"

    if [ ! -f "${generator_script}" ]; then
        error "Formula generator not found: ${generator_script}"
    fi

    # Run the generator script
    "${generator_script}"
}

# Main commands
case "${1:-build}" in
    build)
        build_binaries
        ;;
    test)
        run_tests
        ;;
    clippy)
        run_clippy
        ;;
    package)
        build_binaries
        package
        ;;
    package-soyeht-mac)
        package_soyeht_mac
        ;;
    package-engine-linux)
        package_engine_linux
        ;;
    brew)
        generate_brew_formula
        ;;
    all)
        run_clippy
        run_tests
        build_binaries
        package
        ;;
    clean)
        info "Cleaning build artifacts..."
        cargo clean --workspace
        rm -rf "${REPO_ROOT}/.deploy-staging"
        rm -rf "${REPO_ROOT}/dist"
        info "✓ Clean complete"
        ;;
    *)
        echo "Usage: $0 {build|test|clippy|package|package-soyeht-mac|package-engine-linux|brew|all|clean}"
        echo ""
        echo "Commands:"
        echo "  build                - Build all binaries"
        echo "  test                 - Run tests"
        echo "  clippy               - Run clippy linter"
        echo "  package              - Create distribution package (legacy)"
        echo "  package-soyeht-mac   - Build + codesign macOS engine into Soyeht.app/Contents/Helpers/ (T082)"
        echo "  package-engine-linux - Cross-compile Linux engine binaries for x86_64 + ARM64 (T083)"
        echo "  brew                 - Generate Homebrew formula"
        echo "  all                  - Run clippy, test, build, and package"
        echo "  clean                - Clean build artifacts"
        exit 1
        ;;
esac
