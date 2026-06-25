# macOS Runner Artifact Posture

Scope: how the macOS runner installs each claw's binary inside a guest VM, and
the provenance posture (version pin + integrity verification) of each method.

Source of truth: `admin/rust/vmrunner-macos-rs/src/installer_plan_macos.rs`
(`macos_install_command`). The macOS base disk image is sha256-verified
separately (`vmrunner-macos-rs/src/lib.rs`); this document is only about the
per-claw binaries layered on top of that base image at provisioning time.

This is a different path from the Linux artifact registry (golden rootfs +
`latest.json` + sha256, HTTPS-only). The Linux installer plan
(`admin/rust/vmrunner-rs/src/installer_plan.rs`) already version-pins/resolves
and uses hardened curl; the macOS guest-binary path is being brought in line in
stages.

## Current status

Transport hardened, 6 of 7 claws version-pinned, and ironclaw additionally
verifies an upstream sha256. Every `curl` fetch uses:

    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2

This forces HTTPS (no protocol downgrade), requires TLS >= 1.2, and retries
transient failures.

picoclaw, nullclaw, ironclaw, nanobot, zeroclaw and openclaw are pinned to the
version from `claws/manifest.yml`, read at build/run time via
`core_rs::manifest::get` (single source of truth). The pinned download
tag/package was verified to exist upstream with the expected macOS-arm64 asset.

hermes-agent is NOT pinned: it is installed from a HEAD `git clone` and upstream
uses date-based tags, so pinning it needs an installer rework (HEAD -> tagged
clone), tracked separately. It stays on HEAD and remains in the guard test's
allow-list until then.

ironclaw is the only claw that verifies an integrity checksum: it downloads the
upstream `ironclaw-aarch64-apple-darwin.tar.gz.sha256` and runs `shasum -a 256 -c`
before extracting (fail-closed on mismatch). The other claws have no checksum
verification yet (see the checksum follow-up).

## Per-claw posture

| Claw         | Install method                                | Version pin            | Integrity            | Status    |
|--------------|-----------------------------------------------|------------------------|----------------------|-----------|
| picoclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.2.5`)    | TLS transport only   | pinned    |
| nullclaw     | curl GitHub `releases/download/v<ver>` bin    | manifest (`v2026.3.1`) | TLS transport only   | pinned    |
| ironclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.12.0`)   | upstream sha256 verified | pinned + checksum |
| nanobot      | `pip3 install nanobot-ai==<ver>`              | manifest (`0.1.5`)     | registry transport only | pinned |
| zeroclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.8.1`)    | TLS transport only   | pinned    |
| openclaw     | `npm install -g openclaw@<ver>`               | manifest (`2026.6.10`) | registry transport only | pinned |
| hermes-agent | `git clone --depth 1` HEAD + pip -e + npm     | none (HEAD)            | git transport only   | blocked   |

zeroclaw and openclaw were pinned in S11-D-1: their stale manifest versions
(`0.1.9`, `2026.4.6`) were corrected to the current upstream latest the installer
already resolved to (`v0.8.1`, `2026.6.10`) - a freeze, not an upgrade - and the
installer now embeds the manifest version.

Remaining blocked reason (verified read-only):
- hermes-agent: upstream uses date-based tags (e.g. `v2026.6.19`); manifest
  `0.7.0` does not map to any tag or commit, and the install is a HEAD
  `git clone`, so pinning needs an installer rework (HEAD -> tagged clone).

Notes:
- "TLS transport only" / "git transport only" / "registry transport only" mean
  the download channel is authenticated, but for hermes-agent we do NOT pin a
  version and do NOT verify a checksum on our side; the artifact is whatever
  HEAD currently resolves to and can change between provisions.
- For the pinned claws, pinning intentionally freezes the version. The current
  manifest versions are behind upstream latest, so pinning trades "always
  newest" for "reproducible"; bump the manifest version to move a pinned claw.
- ironclaw's upstream tag format migrated from `v<version>` to
  `ironclaw-v<version>`; the pinned `v0.12.0` still resolves, but a future
  manifest bump for ironclaw must re-verify the tag format.

## Version pin follow-up

Only hermes-agent remains unpinned. Pinning it requires correcting
`claws/manifest.yml` `0.7.0` to a real date tag (e.g. `2026.6.19`) AND reworking
the installer from a HEAD `git clone` to a tagged clone - more than a manifest
edit, so it is a separate slice. Verify the chosen tag exists before pinning.

## Checksum follow-up

ironclaw is done: it downloads the upstream
`ironclaw-aarch64-apple-darwin.tar.gz.sha256` and runs `shasum -a 256 -c` (the
macOS guest ships `shasum`, not coreutils `sha256sum`) before extracting,
fail-closed on mismatch. A manifest version bump must re-verify the `.sha256`
the same way the tarball tag is re-verified.

picoclaw, nullclaw and zeroclaw are version-pinned but do NOT publish a per-asset
checksum, so verifying them needs a theyos-side checksum store (artifact
infrastructure that does not exist yet). openclaw rides npm's built-in registry
integrity. hermes-agent is unpinned (separate follow-up) and builds from source.

Out of scope here and tracked elsewhere: `latest.json` signing, the engine
software-keys flag, the Swift client, and Product A / nvpn.
