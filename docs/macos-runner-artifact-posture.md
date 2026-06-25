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

Transport hardened, 4 of 7 claws version-pinned, and ironclaw additionally
verifies an upstream sha256. Every `curl` fetch uses:

    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2

This forces HTTPS (no protocol downgrade), requires TLS >= 1.2, and retries
transient failures.

picoclaw, nullclaw, ironclaw and nanobot are pinned to the version from
`claws/manifest.yml`, read at build/run time via `core_rs::manifest::get`
(single source of truth). The pinned download tag/package was verified to exist
upstream with the expected macOS-arm64 asset.

zeroclaw, openclaw and hermes-agent are NOT pinned: their manifest version has
no matching upstream release, so pinning them would 404 / break the install.
They stay on `latest`/HEAD and remain in the guard test's allow-list until their
manifest versions are corrected (a separate manifest-curation task).

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
| zeroclaw     | curl GitHub `releases/latest/download` tar.gz | none (latest)          | TLS transport only   | blocked   |
| openclaw     | `npm install -g openclaw` (no version)        | none                   | registry transport only | blocked |
| hermes-agent | `git clone --depth 1` HEAD + pip -e + npm     | none (HEAD)            | git transport only   | blocked   |

Blocked reasons (manifest version vs upstream, verified read-only):
- zeroclaw: manifest `0.1.9` has no `v0.1.9` release tag (upstream latest is
  `v0.8.1`).
- openclaw: manifest `2026.4.6` is not a published npm version (latest is
  `2026.6.10`).
- hermes-agent: upstream uses date-based tags (e.g. `v2026.6.19`); manifest
  `0.7.0` does not map to any tag or commit.

Notes:
- "TLS transport only" / "git transport only" / "registry transport only" mean
  the download channel is authenticated, but for the blocked claws we do NOT
  pin a version and do NOT verify a checksum on our side; the artifact is
  whatever `latest`/HEAD currently resolves to and can change between provisions.
- For the pinned claws, pinning intentionally freezes the version. The current
  manifest versions are behind upstream latest, so pinning trades "always
  newest" for "reproducible"; bump the manifest version to move a pinned claw.
- ironclaw's upstream tag format migrated from `v<version>` to
  `ironclaw-v<version>`; the pinned `v0.12.0` still resolves, but a future
  manifest bump for ironclaw must re-verify the tag format.

## Version pin follow-up

Pin the remaining 3 (zeroclaw, openclaw, hermes-agent). This is blocked on
correcting their `claws/manifest.yml` versions to values that exist upstream
(a real release tag / npm version / git tag-or-commit), then applying the same
manifest-derived pin. Verify per claw that the corrected version maps to an
existing macOS-arm64 asset before pinning - `latest` masks those mismatches.

## Checksum follow-up

ironclaw is done: it downloads the upstream
`ironclaw-aarch64-apple-darwin.tar.gz.sha256` and runs `shasum -a 256 -c` (the
macOS guest ships `shasum`, not coreutils `sha256sum`) before extracting,
fail-closed on mismatch. A manifest version bump must re-verify the `.sha256`
the same way the tarball tag is re-verified.

picoclaw and nullclaw do not publish per-asset checksums, so they would need a
theyos-side checksum store (artifact infrastructure that does not exist yet).
zeroclaw, openclaw and hermes-agent are blocked on version-pinning first.

Out of scope here and tracked elsewhere: `latest.json` signing, the engine
software-keys flag, the Swift client, and Product A / nvpn.
