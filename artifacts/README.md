# Artifact Manifests

This directory contains `latest.json` manifests for pre-built claw artifacts.

Layout:
```
artifacts/
  <claw>/
    <arch>/
      latest.json    ← ArtifactManifest pointing to GitHub Release asset
```

The runtime backend discovers artifacts by fetching:
```
https://raw.githubusercontent.com/soyeht/theyos/main/artifacts/<claw>/<arch>/latest.json
```

The actual rootfs.ext4.zst files are stored as GitHub Release assets, not in this directory.

Published by `scripts/publish-claw-artifact.sh` from the builder machine.
