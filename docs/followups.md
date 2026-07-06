# Follow-ups

Open issues and known blockers worth resolving in their own branches. One
markdown file per issue under `docs/followup-*.md`; this file is just the
index. Add a row when you discover a bug that's out of scope for the branch
you're on, remove the row when the dedicated doc is deleted (issue resolved).

| Slug | Issue |
|---|---|
| [phase3-cross-repo-contract-drift](followup-phase3-cross-repo-contract-drift.md) | iSoyehtTerm's `pair-machine-url.md` is missing `anchor_secret` (B7); contract file naming has drifted between repos. T094 passes; T099 byte-for-byte fails until iSoyehtTerm syncs. |
| [secure-enclave-codesign-acl-on-upgrade](followup-secure-enclave-codesign-acl-on-upgrade.md) | Re-built daemon binary fails Keychain ACL on SE-backed identity items because each ad-hoc-signed build has a new cdhash. Blocks `brew upgrade theyos` on SE-default installs. Workaround: `THEYOS_FORCE_SOFTWARE_KEYS=1`. Real fix needs stable Developer ID signing or per-version Keychain namespace. |
| [release-pipeline-cleanup](followup-release-pipeline-cleanup.md) | R9-A: `notarize_macos()` in make.sh is dead code for the release path (legacy `package()` only); cosmetic cleanup. R9-B: `.notarize-soyeht-engine.zip` not removed on notarytool failure — add `trap` or pre-rm. Both LOW, non-blocking. |
| [llm-proxy-protecthome](followup-llm-proxy-protecthome.md) | `theyos-llm-proxy.service` ships without `ProtectHome`/`ReadWritePaths`/`BindPaths` because systemd sets up the unit's mount namespace before `ExecStartPre` and the bind sources don't yet exist on first boot. Three v1.1 fixes documented (StateDirectory, separate prepare.service, or TemporaryFileSystem). |
| [ios-claw-installability-fields](followup-ios-claw-installability-fields.md) | PR #88 added `installable`/`unavailable_reason_code`/`unavailable_reason` to the catalog (top-level) and `reasons.unavailable_reason_code` to the install-error envelope. iOS must consume `installable` to hide/disable Install and `unavailable_reason_code` for localized copy. Backend is additive/non-breaking; this is a product-quality follow-up, not a compatibility blocker. |
| [release-bundle-stale-engine](followup-release-bundle-stale-engine.md) | After reboot, the installed `Soyeht.app` re-launches the engine embedded in its bundle, which can lag `theyos main`. Release/DMG must embed current-`main` `theyos-engine` + `vmrunner_macos_ipc` and keep app ⇄ helper ⇄ engine in lockstep (build + version-stamp + CI gate). Release-blocker for the next DMG; not blocking the failure-scope PR. |
| [admin-ui-pairing](followup-admin-ui-pairing.md) | Pair a device from the admin web panel (no CLI, no sudo): `POST /api/v1/mobile/pair-token` is admin-session-authed and `QrModal.tsx` exists, so the panel can mint + show a pairing QR with no on-disk secret read. Apple-grade complement to the CLI/installer fix in cli-secrets-permission-ux. Frontend, not scheduled. |
| [recovery-consume-save-atomicity](followup-recovery-consume-save-atomicity.md) | R1-B recovery-consume no-brick depends on `HouseholdAuthState::save()` remaining a single atomic blob for both owner authority logs. Add a save() comment and regression guard so a future split-log persistence refactor cannot create a partial durable Add/Consume brick. |
| [macos-local-attestation-policy](followup-macos-local-attestation-policy.md) | A-now native macOS platform-passkey attestation is deferred after hardware smoke: synced passkeys do not produce the Apple Anonymous/device-bound proof required for active local finish. Local finish remains inert unless a future STOP defines a new proof surface; product direction is Local Workspace plus Secure/Upgrade with iPhone before fan-out. |
| [owner-auth-strong-tier-minting](followup-owner-auth-strong-tier-minting.md) | US-13 strong owner tier cannot be minted by the current pair-device nonce-prover path. Secure/Upgrade with iPhone now has App-Attest-specific schema, transcript vectors, backend proof verification, durable replay, and a reviewed default-off runtime minter wrapper. Production flip remains a separate activation decision. |
| [approved-online-signal](followup-approved-online-signal.md) | The current presence channel reports reactive authenticated connectivity (`presence_ready`), not an explicit result of the Secure/Upgrade with iPhone ceremony. Decide reactive-only vs a versioned approved/denied signal before promising immediate Mac approved/online UX. |
| [product-a-per-claw-vpn-t1-pre-e2e-carry-evidence](product-a-per-claw-vpn-t1-pre-e2e-carry-evidence.md) | Non-live evidence checklist for T1 pre-E2E carries: audit sink durability/rotation, fixed audit path, HMAC export redaction, default-off guard, and client-side `IpTunnel` boundary. |
| [t1-iptunnel-dev-client-runner](followup-t1-iptunnel-dev-client-runner.md) | Real T1-T4 dev-host validation still needs a reviewed dev-only `IpTunnel` runner; current tooling validates offer shape offline and keeps `friend-cli` rejecting `IpTunnel` before connecting. |

## Conventions

- **Naming:** `followup-<short-slug>.md` so `ls docs/followup-*` lists them all.
- **Per-doc structure:** symptom → reproduction env → what works vs. fails →
  likely causes → diagnostic recipe → workarounds → files of interest. Match
  the existing follow-up doc as a template.
- **Why a doc, not just a GitHub issue:** docs travel with the branch and
  survive repo migrations; issues are easier to lose track of. If a follow-up
  also has a tracking issue upstream, link to it from the doc.
- **When you fix it:** delete the doc and remove the row from this index in
  the same commit that ships the fix.
