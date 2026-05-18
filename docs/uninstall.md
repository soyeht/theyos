# Uninstall theyOS / Soyeht

There is one user-facing uninstall command:

```bash
soyeht uninstall
```

That command detects the install model and runs the correct cleanup path:

- Linux release/curl install
- repo-managed NixOS install
- local developer/source checkout install

Compatibility helpers in the repository are not user-facing uninstallers.
They exist so `soyeht uninstall` and the recovery endpoint can handle
different install models without exposing multiple choices to users or agents.

## Options

```bash
soyeht uninstall --keep-data
soyeht uninstall --dry-run
soyeht uninstall --yes
```

`--keep-data` removes services and binaries but preserves customer/VM data.
`--dry-run` shows the action without removing anything. `--yes` skips the
confirmation prompt for automation.

## Recovery

If the `soyeht` binary is missing or damaged, use the recovery endpoint:

```bash
curl -fsSL https://soyeht.com/uninstall | sh
```

That script locates the installed `soyeht` binary and delegates to
`soyeht uninstall`.
