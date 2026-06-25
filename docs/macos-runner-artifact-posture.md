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
and uses hardened curl; the macOS guest-binary path lagged behind.

## Current status

Transport hardened only. Every `curl` fetch now uses:

    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2

This forces HTTPS (no protocol downgrade), requires TLS >= 1.2, and retries
transient failures. No version pinning or checksum verification was added.
A guard test (`installer_plan_macos.rs` tests module) asserts the full curl
flag set and keeps an explicit allow-list of the claws that are still unpinned,
so a new unpinned claw fails CI until it is pinned or acknowledged.

## Per-claw posture

| Claw         | Install method                                   | Version pin   | Integrity            | Risk   |
|--------------|--------------------------------------------------|---------------|----------------------|--------|
| picoclaw     | curl GitHub `releases/latest/download` tar.gz    | none (latest) | TLS transport only   | medium |
| zeroclaw     | curl GitHub `releases/latest/download` tar.gz    | none (latest) | TLS transport only   | medium |
| nullclaw     | curl GitHub `releases/latest/download` bin       | none (latest) | TLS transport only   | medium |
| ironclaw     | curl GitHub `releases/latest/download` tar.gz    | none (latest) | TLS transport only   | medium |
| hermes-agent | `git clone --depth 1` HEAD + pip -e + npm        | none (HEAD)   | git transport only   | medium |
| nanobot      | `pip3 install nanobot-ai` (no version)           | none          | registry transport only | medium |
| openclaw     | `npm install -g openclaw` (no version)           | none          | registry transport only | medium |

Notes:
- "TLS transport only" / "git transport only" / "registry transport only" mean
  the download channel is authenticated (HTTPS / the registry's transport), but
  we do NOT pin a version and we do NOT verify the artifact against a checksum
  on our side. The installed artifact is whatever the upstream `latest`/HEAD or
  the unversioned package currently resolves to, and it can change silently
  between provisions.
- For pip/npm the package name is unversioned, so the resolved version is not
  reproducible. Do not assume the package manager closes the integrity gap for
  us: there is no theyos-side version pin and no theyos-side artifact checksum.

## Version pin follow-up

Replace `releases/latest/download` with `releases/download/<tag>` derived from
`claws/manifest.yml` `version:` per claw, pin pip/npm (`nanobot-ai==<v>`,
`openclaw@<v>`), and pin hermes-agent to a tag or commit instead of HEAD.
Requires per-claw verification that the manifest version maps to an existing
macOS-arm64 release asset and the correct tag format - latest masks those
mismatches today.

## Checksum follow-up

Verify the downloaded artifact against an expected sha256, mirroring the Linux
installer plan's `sha256sum -c` pattern. Requires either an upstream-published
checksum file per release or a theyos-side checksum store (artifact
infrastructure that does not exist yet).

Out of scope here and tracked elsewhere: `latest.json` signing, the engine
software-keys flag, the Swift client, and Product A / nvpn.
