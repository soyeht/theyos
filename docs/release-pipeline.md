# Release pipeline (macOS)

This is caio's runbook for cutting a `vX.Y.Z` release of theyos.

The release process is mostly automated by `.github/workflows/release-macos.yml`,
which triggers on `v*` tag pushes. This doc covers the **one-time setup** for
that workflow, the **per-release** steps that run before tagging, and the
**troubleshooting** notes for the things Apple's notarization service tends to
reject on first run.

## One-time setup

### 1. Apple Developer ID Application certificate

1. Sign in to <https://developer.apple.com> → Certificates, Identifiers
   & Profiles.
2. Create a **Developer ID Application** certificate (NOT Mac Installer
   or Mac App Store).
3. Open Keychain Access on the Mac, find the cert + its private
   key under "login" keychain, right-click → **Export 2 items…**, save
   as `theyos-developer-id.p12` with a strong password.
4. Note the **Team ID** (10-char identifier visible at
   <https://developer.apple.com/account/#!/membership>) and the cert's
   full **identity name** (looks like `Developer ID Application: Sample Developer (TEAM_ID)`).

### 2. App-specific password for notarization

1. Visit <https://appleid.apple.com> → Sign-In and Security → App-Specific
   Passwords → Generate.
2. Label it `theyos-notarytool`.
3. Save the generated password (it's shown once).

For local builds, store as a notarytool profile in the Mac's keychain so
`make.sh` can use `--keychain-profile theyos-notary-profile`:
```sh
xcrun notarytool store-credentials theyos-notary-profile \
  --apple-id "<your Apple ID email>" \
  --team-id "<TEAM_ID>" \
  --password "<app-specific password>"
```

### 3. GitHub repository secrets

Settings → Secrets and variables → Actions → Repository secrets:

| Secret | Value |
|---|---|
| `APPLE_DEVELOPER_ID_P12_BASE64` | Output of `base64 -i theyos-developer-id.p12` (no line breaks) |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | The .p12 export password from step 1.3 |
| `APPLE_ID` | Your Apple ID email |
| `APPLE_ID_APP_PASSWORD` | App-specific password from step 2.3 |
| `APPLE_TEAM_ID` | 10-char Team ID |
| `APPLE_CODESIGN_IDENTITY` | `Developer ID Application: Sample Developer (TEAM_ID)` |

The workflow rejects builds when any are missing.

## Per-release steps

### Bump Cargo workspace version

`scripts/generate-brew-formula.sh` reads the version from
`admin/rust/soyeht-rs/Cargo.toml`, so the **tag must match the Cargo
version** (the workflow asserts this and fails fast on mismatch). Use
the existing helper:

```sh
# Bumps every release-versioned admin/rust/*/Cargo.toml + refreshes Cargo.lock
bash /tmp/phase-c-version-bump.sh   # if still around from prior release;
                                    # otherwise bump them by hand — see below.
cargo build -p server-rs --release
```

**What to bump.** Three things, and missing any one of them fails CI:

1. the repo-root `VERSION` file;
2. every *release-versioned* `admin/rust/*/Cargo.toml`;
3. `Cargo.lock`, refreshed from those manifests.

The root `VERSION` is easy to forget because it is not a manifest and does not
live under `admin/rust`. `core-rs`'s
`manifest::tests::root_version_matches_workspace_crate_version` asserts it
equals the workspace crate version, so omitting it turns
`Build & Test (Rust)` red — a required check.

Not all workspace members are on the release train. Bump exactly those already
carrying the *current* release version, and leave the rest alone:

```sh
cat VERSION                                     # must move too
cd admin/rust
grep -l '^version = "<current>"' */Cargo.toml   # the set to bump
grep -l '^version = "0.1.0"'     */Cargo.toml   # never touched by a release
```

Derive the set each time rather than trusting a remembered count — crates get
added and removed, and a hardcoded number silently goes stale. (This line used
to say "18 files"; it was 19 by the 0.1.25 release, and the stale number had
survived at least one release unnoticed.)

Prove the bump by counting rather than reading: zero manifests left at the old
version, the expected number at the new one, the `0.1.0` set byte-identical to
what it was before, and the root `VERSION` matching. In `Cargo.lock`, expect
one version entry per bumped crate — which is one `-old` / `+new` *pair* per
crate in the diff, so twice that many changed lines — and no other package
touched. Beware a total that merely looks close: an unrelated dependency can
sit at the same version by coincidence, so count the diff, not the file.

Land the version bump as a tiny PR on `main` ahead of tagging.

### Tag and push

```sh
git fetch origin main
git checkout main && git pull --ff-only
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The push triggers `release-macos.yml`. Watch the run at
<https://github.com/soyeht/theyos/actions>.

### What the workflow does

1. **Check out** at the tag commit.
2. **Verify** Cargo version matches tag (fail-fast).
3. **Import** the Developer ID .p12 into an ephemeral keychain. The
   keychain is destroyed at end of job; the .p12 never lands on disk
   outside the runner's tmp.
4. **Build + sign + notarize + package** by running `./scripts/make.sh
   package`. Internally:
   - `cargo build --release --workspace`
   - Stage binaries to `.deploy-staging/macos-arm64/`
   - `codesign --force --timestamp --options runtime --identifier
     com.soyeht.theyos.<bin> -s "$THEYOS_CODESIGN_IDENTITY"` on each
     Mach-O.
   - For `vmrunner_macos_ipc`: same plus `--entitlements
     vmrunner-macos.entitlements`.
   - `ditto -c -k --keepParent .deploy-staging/macos-arm64
     theyos-notarize.zip`
   - `xcrun notarytool submit --apple-id ... --team-id ... --password ...
     --wait` (typically 1-3 min).
   - `tar -czf dist/macos-arm64/theyos-X.Y.Z-macos-arm64.tar.gz`
5. **Verify** signature on a sample binary (extract `server` from the
   tarball, codesign-verify, grep for Developer ID + identifier +
   hardened runtime markers).
6. **`gh release create`** with the tarball.
7. **Regenerate** the Homebrew formula (`generate-brew-formula.sh`).
8. **Commit** the formula update back to `main` with `[skip ci]`.

### After the workflow finishes

1. Verify the release at <https://github.com/soyeht/theyos/releases>.
2. Verify the formula updated at `homebrew/Formula/theyos.rb` on `main`.
3. **Smoke-install** on a clean Mac (or VM) you don't have theyos on yet:
   ```sh
   brew untap soyeht/tap; brew tap soyeht/tap
   brew install soyeht/tap/theyos
   theyos start
   ```
   Daemon should start cleanly. **First-run** with no household identity
   will create one; SE-default installs will create an SE-backed
   identity that subsequent rebuilds can re-read because the ACL is
   bound to the Developer ID cert (not cdhash).
4. Per memory `feedback_deploy_devs_before_bignix.md`, run
   `sudo soyeht update` on **devs** (canary) before promoting to
   bignix.

## Troubleshooting

### "Notarization failed" with hardened-runtime error

Check that `make.sh` codesign step uses `--options runtime` for every
Mach-O. Notarization rejects any binary missing the hardened runtime
flag.

### "Invalid certificate" or "Code object is not signed at all"

The .p12 import in the ephemeral keychain failed silently. Common
causes:
- Wrong keychain partition list — fix:
  `security set-key-partition-list -S apple-tool:,apple: -s -k
  $KEYCHAIN_PASSWORD build.keychain`.
- Cert is expired (Apple Developer Program annual renewal lapsed).
- Wrong Team ID in `APPLE_TEAM_ID` secret.

### "App-specific password was revoked"

Apple revokes app-specific passwords if the underlying Apple ID password
is changed. Regenerate at <https://appleid.apple.com>, update the
`APPLE_ID_APP_PASSWORD` GitHub secret, and re-trigger the workflow via
`workflow_dispatch`.

### Tag pushed but workflow didn't run

Check the tag matches the `v*` pattern. `release-macos.yml` only
triggers on tags starting with `v`. Use `gh workflow run release-macos.yml
-f tag=vX.Y.Z` to manually re-trigger.

### Cargo version doesn't match tag

The pre-flight check fails. Either:
- Retag at the right commit: `git tag -d vX.Y.Z; git push origin
  :refs/tags/vX.Y.Z; <bump Cargo>; <commit>; git tag vX.Y.Z; git push
  origin vX.Y.Z`.
- Or change the tag to match the Cargo version and use that.

## Phase 3 machine-join SE carve-out

Even with Developer ID code-signing, the macOS Secure Enclave is
**incompatible with Phase 3 machine-join** because the Shamir/ECDH
shard decryption (`specs/003-machine-join/spec.md:80`) requires the
raw `M_priv` scalar that SE refuses to export.

For any install that participates in Phase 3, the daemon must run with
`THEYOS_FORCE_SOFTWARE_KEYS=1` set in the launchd plist:

```sh
/usr/libexec/PlistBuddy -c \
  "Add :EnvironmentVariables:THEYOS_FORCE_SOFTWARE_KEYS string 1" \
  /opt/homebrew/opt/theyos/homebrew.mxcl.theyos.plist
```

`scripts/make.sh` does NOT set this for the user — it's part of the
post-install bootstrap (or manual setup) on each host. Document this
behavior in the user-facing install docs before promoting v0.1.6+ to
SE-default users.

A future "threshold-signature primitive that operates on the SE handle
without exporting bytes" would lift this carve-out; until then, Phase 3
hosts on macOS use file-based keys.

## Cert rotation (annual)

Apple Developer ID certs expire after **1 year**. To rotate:

1. Renew the Apple Developer Program subscription before lapse.
2. Generate a new Developer ID Application certificate (the old one stays
   valid for already-signed binaries; new signatures use the new cert).
3. Re-export as `.p12`, update the `APPLE_DEVELOPER_ID_P12_BASE64` and
   `APPLE_DEVELOPER_ID_P12_PASSWORD` secrets.
4. The cert's identity name may include a sequence number now (e.g.
   `Developer ID Application: Sample Developer (TEAM_ID) [2]`); update
   `APPLE_CODESIGN_IDENTITY` if so.
5. Cut a no-op release to verify the new cert chain works end-to-end.
