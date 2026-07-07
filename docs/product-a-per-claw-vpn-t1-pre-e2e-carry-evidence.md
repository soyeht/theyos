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
| Owner authorization record shape | `owner-authorization-validator-tests` | The offline validator accepts only a PR/SHA-bound dev-host owner record with `production_activation=false`, required owner sentence, stop authority, rollback reference, redaction policy, and neutral topology; incomplete or privacy-unsafe records fail closed without printing values or paths. |
| Rollback evidence shape | `rollback-evidence-validator-tests` | The offline validator accepts only a PR/SHA-bound prebuilt rollback record with restore operation, redacted env snapshot, route/interface cleanup, relay stop, baseline health check, no rebuild dependency, and production excluded; incomplete or privacy-unsafe records fail closed without printing values or paths. |
| Hardware evidence pack shape | `hardware-evidence-pack-validator-tests` | The offline validator accepts only a complete-shaped PR/SHA-bound T1-T4 pack with production excluded, checked T1/T2/T3/T4 items, rollback, owner authorization, and reference content verification; the preflight JSON validator can also follow all three private refs with `--check-private-refs`; incomplete packs fail closed without printing values or paths. |
| Audit export policy shape | `audit-export-policy-validator-tests` | The offline validator accepts only a PR/SHA-bound dev-host export policy with `production_activation=false`, reviewed export-key source, key rotation and retention, bounded export data retention, raw subject omission, local pseudonymous hash omission, off-host destination review, and production excluded; incomplete or privacy-unsafe policies fail closed without printing values or paths. |
| Source guard | `product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired` | Guard relaxations remain narrow; mount uses only current-build evidence loading and does not synthesize present preflight or call unreviewed loader/parser symbols. |
| Client-side dev-runner boundary | `rejects_iptunnel_before_connecting` in `friend-cli-rs` and `t1-iptunnel-dev-runner-rs` tests | `friend-cli` still rejects `IpTunnel` before connecting, while the dev runner accepts only member-scoped offers and requires explicit dev-host acknowledgement before the session-open seam. The runner validates the authenticated `TunnelAck` metadata and reports only presence/redacted status plus non-sensitive MTU; it still has no local TUN/utun, route install, packet-pump, or production-app control path. The ack metadata is not treated as final VPN route/interface configuration, and any target open against an activated dev host remains under the #281 dev-host gate. |

## What Remains For The Activation PR

These items cannot be proven by the non-live bundle and must be reviewed for the
exact activation PR and artifact SHA:

- owner authorization record with `production_activation=false`;
- real owner/rollback/hardware references with content verification, not only
  non-empty strings;
- reviewed rollback artifact and restore operation;
- dev-host hardware T1-T4 evidence;
- export key source, rotation, retention, and privacy policy for any off-host
  audit export, with
  `scripts/validate-t1-audit-export-policy.py <sha> <policy> --expected-pr <number>`
  used as a shape/privacy check before content review;
- source guard re-trip and narrow relaxation for the exact mount-to-gate
  crossing;
- explicit live-run approval for `Soyeht Dev.app` only.

Until those activation gates are satisfied, the correct state is: code and
tooling may be reviewed as non-live preparation, but T1 live-run remains blocked.
