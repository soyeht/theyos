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
