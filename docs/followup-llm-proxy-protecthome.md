# Follow-up: re-enable `ProtectHome` + namespace isolation on `theyos-llm-proxy`

Identified in PR #73 code review (Aurora v1). The systemd unit at
`nix/modules/llm-proxy.nix` ships **without** `ProtectHome`,
`ReadWritePaths`, or `BindPaths` in v1. Hardening parity with the rest
of the platform is deferred — not because it's risky, but because
each fix touches the directory-bootstrap story.

## Symptom / issue

In an earlier slice the unit had:

```nix
ProtectHome = "read-only";
ReadWritePaths = [ "${userHome}/.theyos" ];
BindPaths = [ ... ];
```

On a fresh `nixos-rebuild switch`, the unit failed with
`status=226/NAMESPACE: Failed to set up mount namespacing`. Root cause:
systemd sets up the unit's mount namespace **before** `ExecStartPre`
runs, and `$HOME/.theyos/*` did not yet exist on first boot — so the
bind sources resolved to "non-existent path" and namespace setup
aborted. On devs we additionally observed that
`systemd-tmpfiles-setup.service` is broken (exit 73, never re-ran
across reboots) so the directories the unit expects are never created
even though `systemd.tmpfiles.rules` declares them.

`ProtectHome="tmpfs"` was tried as a workaround and also broke
`BindPaths` (the tmpfs over `/home` made the bind sources unresolvable
from inside the namespace).

## What works in v1

The unit still ships these hardening directives:
`ProtectSystem=strict`, `ProtectKernelTunables=true`,
`ProtectKernelModules=true`, `ProtectControlGroups=true`,
`ProtectHostname=true`, `ProtectKernelLogs=true`,
`ProtectClock=true`, `NoNewPrivileges=true`, `LockPersonality=true`,
`RestrictAddressFamilies=[AF_UNIX AF_INET AF_INET6]`,
`RestrictNamespaces=true`, `RestrictRealtime=true`,
`RestrictSUIDSGID=true`, `SystemCallArchitectures=native`,
`SystemCallFilter=[@system-service ~@privileged ~@resources]`.

The blast radius of a compromised proxy is approximately equal to a
compromise of `cfg.user` directly (since the proxy runs as that user
without `ProtectHome`). Documented in the v1 threat model in
`docs/llm-proxy.md`.

## Three real fixes (pick one)

1. **Move state to `/var/lib/theyos-llm` + use `StateDirectory=`.**
   systemd creates `StateDirectory` paths *pre-namespace* and chowns
   them to the unit's user, so the bind problem disappears. Cost: a
   one-shot migration script for users with credentials already at
   `~/.theyos/keystore/`.
2. **Separate `theyos-llm-proxy-prepare.service` running as root with
   `ProtectHome=false` that just `install -d`'s the directories, then
   `Requires=`/`Before=` the main unit.** No state migration; main
   unit gets full hardening. Cost: two unit files instead of one.
3. **`TemporaryFileSystem=/home` with explicit `BindPaths` for every
   subdir we need pre-populated.** Same isolation as `ProtectHome`
   without the bind-source problem. Cost: every new subdir under
   `~/.theyos/` becomes a unit-file edit.

Option 2 is probably the cleanest — keeps the state in `$HOME` (so
CLI-OAuth providers' OAuth state stays where the CLIs expect it) and
gets full namespace isolation back on the main unit.

## Files of interest

- `nix/modules/llm-proxy.nix:209-256` — the disabled directives + the
  inline comment that names the three fix paths
- `docs/llm-proxy.md` — v1 threat-model section that documents the
  blast-radius equivalence
