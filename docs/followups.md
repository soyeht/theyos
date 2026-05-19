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
