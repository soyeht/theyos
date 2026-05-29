# Follow-up: installed app re-copies a stale engine from its bundle after reboot

**Severity:** release-blocker (data/UX correctness for shipped builds) — does
NOT block the current `fix/guest-image-failure-scope` PR, but must be resolved
before the next DMG/release goes out.

## Symptom

During the macOS-claw QA on macStudio (2026-05-29): after rebooting the Mac to
clear a VZ host-limit leak, the `com.soyeht.engine` LaunchAgent came back up
running an **older** `theyos-engine` than current `main` — the binary embedded
in the installed `Soyeht.app` bundle, not a build of the latest source. The app
had re-copied / re-launched the bundled engine on session login.

The practical consequence: a fix that lives only in `theyos main` (e.g. the
boot-scoped failure reconciliation in this PR) is **not** exercised by the
installed app until the bundle itself is rebuilt with current `main`. Any
local-build validation must overwrite the bundled binaries first, or it tests
stale code.

## Reproduction environment

- Host: macStudio, `Soyeht.app` installed (Homebrew-path install), engine run as
  a per-user-session LaunchAgent
  (`/Applications/Soyeht.app/Contents/Library/LaunchAgents/com.soyeht.engine.plist`,
  `RunAtLoad`).
- Trigger: reboot → GUI login → LaunchAgent auto-starts the **bundled** engine.

## What works vs. what fails

- **Works:** the engine/app/tailscale auto-recover on login; the runtime is
  healthy.
- **Fails:** the recovered engine is whatever was embedded at install time. The
  bundle is the source of truth for the running binary, and it can lag `main`.
  There is no guarantee `app` ⇄ `helper` (`vmrunner_macos_ipc`) ⇄ `engine`
  (`theyos-engine`) are all from the same `main` revision.

## Likely cause

The release/packaging path embeds engine + helper binaries into the app bundle
at build time. If the DMG is cut from a tree behind `main`, or the three
artifacts are built/stamped independently, the installed bundle ships a stale or
mismatched engine. On reboot the LaunchAgent faithfully re-runs that stale
bundled binary.

## What the fix needs (next release)

1. **Embed current `theyos main`**: the DMG/bundle build must compile
   `theyos-engine` and `vmrunner_macos_ipc` from the same `main` revision being
   shipped, and stamp that revision into the bundle (e.g. a version/commit file)
   for verification.
2. **Keep app ⇄ helper ⇄ engine in lockstep**: all three artifacts from one
   build; add a startup sanity check that logs (or refuses) a version mismatch
   between the app and the engine/helper it launches.
3. **Validation gate**: before publishing a DMG, assert the bundled engine's
   stamped revision == the release tag's revision (CI check in the release
   pipeline).

## Workaround (for local dev/QA today)

Overwrite the bundled binaries with a fresh local build before validating
(the Mac-dev deploy path), so the LaunchAgent runs current-`main` code instead
of the stale bundled engine. See the "Mac dev deploy" note.

## Files of interest

- Release/packaging: `admin/.../make.sh` (release path), DMG/bundle assembly.
- LaunchAgent: `Soyeht.app/Contents/Library/LaunchAgents/com.soyeht.engine.plist`.
- Bundled binaries: `Soyeht.app/Contents/.../theyos-engine`, `vmrunner_macos_ipc`.

## Related

- Discovered while fixing `fix/guest-image-failure-scope` (boot-scoped
  `host_vm_limit_reached` reconciliation). That PR's local validation must run
  against a freshly-built engine, not the stale bundled one.
- Adjacent release-pipeline hygiene: [release-pipeline-cleanup](followup-release-pipeline-cleanup.md).
