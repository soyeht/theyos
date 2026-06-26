# Artifact Signing Runbook

How theyos signs claw artifact manifests (`latest.json`) and how the client
verifies them. Operational companion to the P0.1 signing code (verifier +
keyring + `sign-manifest` + resolver mechanics).

Audience: the theyos maintainer / release operator. **End users never handle
keys** - they receive the pinned public key inside the app and verification is
automatic, exactly like an OS trusting its vendor's update-signing key.

## Why (threat model)

- The runtime installs prebuilt claw rootfs images discovered via `latest.json`
  from a central registry: `https://raw.githubusercontent.com/soyeht/theyos/main/artifacts`.
- HTTPS authenticates the transport, but not a compromised registry/CDN, a
  compromised GitHub repo, or a rogue publisher.
- A detached P-256 signature over the **exact** `latest.json` bytes lets every
  client reject a tampered manifest even if GitHub / the CDN is compromised.
- The publisher (theyos maintainer) signs; every client verifies with a pinned
  public key. This is defense-in-depth on top of the existing HTTPS-only fetch.

## The production key

- `key_id`: `artifact-prod-p256-2026q2` (a stable label; baked into every
  signature and pinned in the client. Change it only before the first pin - after
  that, changing it means re-signing every manifest and shipping a client update.)
- algorithm: `p256_ecdsa_sha256_raw` (ECDSA P-256, SHA-256, raw `r||s` signature).
- public key (SEC1 compressed, 33 bytes, base64 - NOT secret, pinned in client):

      A+5hT7nQ+uckDKxwl8ym9kfxWcS+0A7tOG+0MDbAoWU/

- Generated and verified 2026-06-25 on the builder machine: the canonical
  re-extract matched this value and an `openssl pkeyutl` round-trip printed
  `Signature Verified Successfully` (public matches private).

### Generate a keypair (already done; kept here for rotation)

    # private key - stays on the builder machine, NEVER committed
    openssl ecparam -name prime256v1 -genkey -noout -out artifact-signing.key

    # public key as SEC1 compressed (33 bytes), base64 - this is what gets pinned
    openssl ec -in artifact-signing.key -pubout -conv_form compressed -outform DER \
      2>/dev/null | tail -c 33 | base64

### Verify a public key matches its private key

    printf 'theyos-roundtrip' > /tmp/t.bin
    openssl pkeyutl -sign -inkey artifact-signing.key -in /tmp/t.bin -out /tmp/t.sig
    openssl ec -in artifact-signing.key -pubout -out /tmp/pub.pem 2>/dev/null
    openssl pkeyutl -verify -pubin -inkey /tmp/pub.pem -in /tmp/t.bin -sigfile /tmp/t.sig
    # expect: Signature Verified Successfully

## Custody of the private key

- The private key (`artifact-signing.key`) lives ONLY on the builder machine -
  the machine that runs `scripts/publish-claw-artifact.sh` and `git push`es the
  repo. (Confirmed 2026-06-25: the key was generated on that machine.)
- `chmod 600`. Keep an encrypted offline backup (password manager or encrypted
  volume).
- NEVER commit it to the repo. NEVER sync it to cloud storage in plaintext.
- It is NOT a GitHub Actions secret today, because publishing is a manual script
  plus `git push`, not a workflow. Move it to a CI secret only if/when publishing
  becomes a workflow.
- Loss -> you cannot sign new releases; you must rotate (new key, re-pin, ship a
  client update). Keep the backup.
- Leak -> an attacker can forge an accepted `latest.json`; rotate immediately and
  revoke the old `key_id` in the client keyring.

## The signer command

`imagebuilder sign-manifest` does NOT hold the key. It calls an external signer
via `--signer-cmd` (or `THEYOS_ARTIFACT_SIGNER_CMD`). The signer:

- reads the exact payload (`domain || latest.json bytes`) on stdin,
- produces an ECDSA P-256 / SHA-256 signature in RAW form (64 bytes, `r||s`),
- prints it base64url (no padding) on a single stdout line.

`openssl` alone emits a DER-encoded signature, not raw `r||s`, so
`python3 scripts/sign_artifact_manifest_p256.py` converts DER to raw and prints
the base64url signature. The wrapper signs the stdin payload as-is; the caller
already applied the domain separator.

Default builder-machine usage:

    THEYOS_ARTIFACT_SIGNING_KEY=/path/to/artifact-signing.key \
      ./scripts/publish-claw-artifact.sh <claw>

`--dry-run` also signs and verifies the manifest, so it still needs either
`THEYOS_ARTIFACT_SIGNING_KEY` for the default signer or an explicit
`THEYOS_ARTIFACT_SIGNER_CMD` test signer.

## Where signing fits in the publish flow

`scripts/publish-claw-artifact.sh` (run from the builder machine):

    1. imagebuilder rebuild --force <claw>     # build the golden
    2. shrink rootfs.ext4 -> rootfs.ext4.zst
    3. imagebuilder publish-manifest <claw> .. # -> latest.json
    3b. imagebuilder sign-manifest <latest.json> \
          --key-id artifact-prod-p256-2026q2 \
          --signer-cmd "<signer>"              # -> latest.json.sig.json
    3c. imagebuilder verify-manifest-signature <latest.json>
          --signature <latest.json.sig.json>    # verify against production pin
    4. gh release upload <tag> <.zst>           # .zst -> GitHub Releases
    5.  cp BOTH latest.json AND latest.json.sig.json ; git add both ; commit
    6. git push                                 # -> raw.githubusercontent.com

## Rollout (publish-first, activate-second - do NOT invert)

The registry currently holds 8 UNSIGNED `latest.json` (ironclaw, openclaw,
nanobot, nullclaw, zeroclaw, picoclaw, hermes-agent, noclaw; x86_64-linux).
Flipping the client to "require a signature" before those are signed would break
every prebuilt install. Order:

    1. [done] Build the signer wrapper + wire sign-manifest into the publish script.
    2. [operator] Backfill: sign all 8 existing latest.json, commit the .sig.json,
       git push. Verify the pushed raw.githubusercontent.com bytes. Use:

           THEYOS_ARTIFACT_SIGNING_KEY=/path/to/artifact-signing.key \
             ./scripts/backfill-artifact-manifest-signatures.sh --stage

       Then commit, push, pull the pushed commit on a clean checkout, and run:

           ./scripts/check-artifact-signature-rollout.sh

       That helper first verifies the committed local `.sig.json` files, then
       downloads each live `latest.json` and `latest.json.sig.json` pair from
       the registry URL and verifies the exact served bytes against the
       production public pin.
    3. [done] Pin the public key + key_id in the client keyring.
    4. [code] Hard-cut: wire the install resolver to
       `ArtifactTrustConfig::production_for_install()`, making remote registries
       Required and loopback/local explicit dev/test. Merge/deploy only after
       step 2 is fully pushed and verified.

A downgrade lever (revert step 4) must stay available until the signed registry
is proven stable in production.

## Rotation

1. Generate a new keypair on the builder machine; pick a new `key_id`.
2. Add the new public key as the keyring `next` key (client update); keep the old
   as `current`. Both are accepted during the overlap window.
3. Re-sign and push every `latest.json` with the new key.
4. Promote `next` to `current`; move the old `key_id` to the revocation denylist;
   ship the client update.

## Current status (2026-06-25)

DONE and pushed:

- `core-rs/src/artifact_signature.rs` - detached-signature verifier.
- `core-rs/src/artifact_trust.rs` - keyring (current/next/revoked), trust mode,
  and pinned production public key.
- `imagebuilder sign-manifest` - produces `latest.json.sig.json` from an external
  signer.
- `imagebuilder verify-manifest-signature` - verifies `latest.json` +
  `latest.json.sig.json` against the production pin.
- `server-rs/src/artifact_resolver.rs` - verify-before-parse, the
  `ArtifactResolver::for_install` seam, and the hard-cut install policy
  `ArtifactTrustConfig::production_for_install()`. After this hard-cut is
  deployed, remote registries require `latest.json.sig.json`; loopback/local
  registries remain explicit dev/test exceptions.
- `scripts/sign_artifact_manifest_p256.py` - builder-machine signer wrapper.
- `scripts/publish-claw-artifact.sh` - signs and verifies manifests before
  upload/commit.
- `scripts/backfill-artifact-manifest-signatures.sh` - signs and verifies the
  existing registry manifests without rebuilding/uploading artifacts.
- `scripts/check-artifact-signature-rollout.sh` - runs the local committed
  signature check and the live raw registry check after backfill/push.
- `scripts/verify-artifact-manifest-signature-urls.sh` - verifies the pushed
  raw registry bytes before the Required hard-cut.

PENDING (in order): operator backfill of the 8 manifests, raw URL verification,
Linux/CI compile verification of the install-worker call site, and deployment of
the Required hard-cut after the signed registry is proven.
