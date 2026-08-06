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
and uses hardened curl; the macOS guest-binary path does not.

That difference is stated as a fact, not as a stage in a migration. The sentence
here used to say the macOS path was "being brought in line in stages", which
described an intent from a plan that no longer exists — and an unowned intent in
a posture document reads to the next reader as work already scheduled.

## Current status

Transport hardened, all 7 claws version-pinned, and four claws (ironclaw +
picoclaw/nullclaw/zeroclaw) verify a sha256. Every `curl` fetch uses:

    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2

This forces HTTPS (no protocol downgrade), requires TLS >= 1.2, and retries
transient failures.

All seven claws are pinned to the version from `claws/manifest.yml`, read at
build/run time via `core_rs::manifest::get` (single source of truth). The pinned
download tag/package was verified to exist upstream with the expected macOS-arm64
asset.

hermes-agent pins its git tag (`git clone --branch v<ver>`) and verifies the
checked-out commit against a theyos-pinned commit SHA (the tag is mutable, the
commit is not), so a re-pointed tag fails closed before building. This is still a
partial pin: only the source commit is frozen - its pip/npm build dependencies
still resolve at build time, and there is no build checksum.

Four claws verify an integrity checksum before extracting (fail-closed on
mismatch): ironclaw against its upstream `.sha256`, and picoclaw, nullclaw and
zeroclaw against a theyos-pinned sha256 (their upstream publishes none). nanobot
and openclaw rely on pip/npm registry integrity; hermes-agent builds from source.

## Per-claw posture

| Claw         | Install method                                | Version pin            | Integrity            | Status    |
|--------------|-----------------------------------------------|------------------------|----------------------|-----------|
| picoclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.2.5`)    | theyos-pinned sha256 verified | pinned + checksum |
| nullclaw     | curl GitHub `releases/download/v<ver>` bin    | manifest (`v2026.3.1`) | theyos-pinned sha256 verified | pinned + checksum |
| ironclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.12.0`)   | upstream sha256 verified | pinned + checksum |
| nanobot      | `pip3 install nanobot-ai==<ver>`              | manifest (`0.1.5`)     | registry transport only | pinned |
| zeroclaw     | curl GitHub `releases/download/v<ver>` tar.gz | manifest (`v0.8.1`)    | theyos-pinned sha256 verified | pinned + checksum |
| openclaw     | `npm install -g openclaw@<ver>`               | manifest (`2026.6.10`) | registry transport only | pinned |
| hermes-agent | `git clone --branch v<ver>` tag + commit verify + pip -e + npm | manifest (`2026.6.19`) | git tag + commit-SHA verified (source build) | pinned (partial) |

zeroclaw and openclaw were pinned in S11-D-1: their stale manifest versions
(`0.1.9`, `2026.4.6`) were corrected to the current upstream latest the installer
already resolved to (`v0.8.1`, `2026.6.10`) - a freeze, not an upgrade - and the
installer now embeds the manifest version.

hermes-agent was pinned in S11-D-2: manifest `0.7.0` (which mapped to no tag) was
corrected to the date tag `2026.6.19`, and the installer reworked from a HEAD
`git clone` to a tagged clone (`git clone --branch`, plus fetch + checkout the
tag for existing repos, fail-closed on a missing tag). Unlike S11-D-1 this is a
real move from HEAD back to the latest release tag (HEAD was ahead of the tag),
accepted to eliminate HEAD drift.

Notes:
- "TLS transport only" / "git transport only" / "registry transport only" mean
  the download channel is authenticated. No claw verifies a per-asset checksum
  except ironclaw; the pinned-but-unchecksummed claws rely on transport plus the
  version/tag pin.
- For the pinned claws, pinning intentionally freezes the version. The current
  manifest versions are behind upstream latest, so pinning trades "always
  newest" for "reproducible"; bump the manifest version to move a pinned claw.
- ironclaw's upstream tag format migrated from `v<version>` to
  `ironclaw-v<version>`; the pinned `v0.12.0` still resolves, but a future
  manifest bump for ironclaw must re-verify the tag format.

## Version pin follow-up

Done: all seven macOS claws are version-pinned. hermes-agent's pin is partial
(source commit verified, but pip/npm build deps still float). A manifest version
bump for any claw must re-verify the upstream tag/package before landing - and
re-pin the sha256 (ironclaw + picoclaw/nullclaw/zeroclaw) or the commit SHA
(hermes-agent) accordingly.

## Checksum follow-up

ironclaw is done: it downloads the upstream
`ironclaw-aarch64-apple-darwin.tar.gz.sha256` and runs `shasum -a 256 -c` (the
macOS guest ships `shasum`, not coreutils `sha256sum`) before extracting,
fail-closed on mismatch. A manifest version bump must re-verify the `.sha256`
the same way the tarball tag is re-verified.

Done (S11-E): picoclaw, nullclaw and zeroclaw publish no upstream per-asset
checksum, so the installer verifies each downloaded asset against a theyos-pinned
sha256 held in `MACOS_PINNED_SHA256` (`installer_plan_macos.rs`), keyed by
`(claw, version, sha256)`. Each digest was computed once from the pinned release
asset; a guard test asserts each pinned version tracks the manifest, so a version
bump must recompute the sha256 (and the install fails-closed on a stale one).
openclaw rides npm's built-in registry integrity. hermes-agent is pinned to its
git tag (S11-D-2) but builds from source, so it has no checksum either.

Out of scope here and tracked elsewhere: `latest.json` signing, the engine
software-keys flag, the Swift client, and Product A / nvpn.
