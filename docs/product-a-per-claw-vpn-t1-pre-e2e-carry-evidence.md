# Product A per-Claw VPN T1 pre-E2E carry evidence

This checklist records the non-live evidence that must stay green before a
future T1-T4 E2E activation PR. It is not owner authorization, not production
activation, and not permission for a live run.

Use it to verify the preparatory carries before reviewing any PR that wires real
T1 evidence or starts dev-host packet validation.

## Required Non-Live Checks

Run the full local bundle:

```sh
scripts/check-t1-preflight-default-off.py
```

The bundle must include the following direct carry checks, not only mount-level
smoke coverage:

| carry | required filter | proof required |
|---|---|---|
| Audit sink durability / fsync | `t1_spooled_audit_sink` | Each accepted audit record is flushed and `sync_data`ed; sync failures fail closed before treating the event as accepted. |
| Retention / rotation | `t1_spooled_audit_sink` | Rotation occurs before the reviewed byte cap is exceeded, parent metadata is synced after rotation, oversized records are rejected, and only the bounded retained files remain. |
| Fixed safe path / canonical ancestors | `t1_audit_log_path` | The audit path is the fixed `claw-vpn-t1-audit/audit.jsonl` suffix under an absolute canonical current-user-owned `0700` root; relative roots, `..`, symlink ancestors, file roots, and shared roots are rejected. |
| FD-relative safe open | `t1_spooled_audit_sink` | Parent components are walked with fd-relative `openat`/`mkdirat`, parent/intermediate symlinks are rejected, and the log file is opened relative to the validated parent fd with `O_NOFOLLOW`. |
| HMAC/keyed off-host export redaction | `t1_audit_export_jsonl` | Export JSONL uses HMAC-SHA-256 keyed subject hashes, changes when the key changes, omits local pseudonymous hashes, omits raw subject identifiers, and redacts the export key in `Debug`. |
| Mount default-off and evidence failure modes | `mounted_t1_iptunnel_router` | Missing, stale, invalid, incomplete, or wrong-SHA evidence remains unavailable; invalid audit root fails closed before build inputs or launcher execution. |
| Source guard | `product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired` | Guard relaxations remain narrow; mount uses only current-build evidence loading and does not synthesize present preflight or call unreviewed loader/parser symbols. |
| Client-side non-live boundary | `rejects_iptunnel_before_connecting` in `friend-cli-rs` and `t1-iptunnel-dev-runner-rs` tests | `friend-cli` still rejects `IpTunnel` before connecting, while the dev runner only validates member-scoped offer shape offline. |

## What Remains For The Activation PR

These items cannot be proven by the non-live bundle and must be reviewed for the
exact activation PR and artifact SHA:

- owner authorization record with `production_activation=false`;
- real owner/rollback/hardware references with content verification, not only
  non-empty strings;
- reviewed rollback artifact and restore operation;
- dev-host hardware T1-T4 evidence;
- export key source, rotation, retention, and privacy policy for any off-host
  audit export;
- source guard re-trip and narrow relaxation for the exact mount-to-gate
  crossing;
- explicit live-run approval for `Soyeht Dev.app` only.

Until those activation gates are satisfied, the correct state is: code and
tooling may be reviewed as non-live preparation, but T1 live-run remains blocked.
