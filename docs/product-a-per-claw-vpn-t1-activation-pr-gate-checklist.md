# Product A per-Claw VPN T1 activation PR gate checklist

This checklist is the required review gate for the first PR that wires real T1
preflight evidence into the mount. It is not authorization by itself, does not
permit a T1 live-run, and does not replace the readiness runbook or the owner
authorization record.

Before using this checklist, confirm the non-live carry evidence in
`docs/product-a-per-claw-vpn-t1-pre-e2e-carry-evidence.md` still matches the
current code and bundle.

Use neutral aliases only in public text. Keep real hostnames, account names,
device names, IPs, relay endpoints, local paths, packet bytes, logs, screenshots
with identifiers, secrets, keys, and raw evidence in ignored local files or a
private review store.

## Scope

The activation PR is the first PR that may cross the boundary from default-off
preparation to reviewed dev-host wiring. It must remain dev-host-only and must
exclude production activation, production deployment, production state, and the
installed shipping app.

The PR must not be merged or used for live T1-T4 validation unless every gate
below has explicit review evidence for the exact PR head and commit SHA.

## Required Evidence

- Exact PR number, commit SHA, and build artifact hash.
- Owner authorization record for the same PR and commit SHA, with
  `production_activation=false` and scope `dev-host T1-T4 only`.
- Owner authorization shape validation with
  `scripts/validate-t1-owner-authorization.py <sha> <owner-record> --expected-pr <number>`.
  This proves only that the private record is complete-shaped and privacy-safe
  to review; it is not owner authorization by itself.
- Prebuilt rollback artifact reference for the same commit SHA; build-local or
  post-failure rollback is not sufficient.
- Rollback evidence shape validation with
  `scripts/validate-t1-rollback-evidence.py <sha> <rollback-record> --expected-pr <number>`.
  This proves only that rollback material is complete-shaped for review; it
  does not prove the restore artifact or operation is correct.
- Hardware evidence pack reference for T1-T4 on dev hosts, using neutral
  aliases and documentation-safe addresses.
- Hardware evidence pack shape validation with
  `scripts/validate-t1-hardware-evidence-pack.py <sha> <pack> --expected-pr <number>`.
  This only proves the pack is complete-shaped for review; it does not replace
  content verification of the referenced owner, rollback, hardware, or run
  evidence.
- Private preflight evidence JSON that validates with
  `scripts/validate-t1-preflight-evidence-record.py <sha> <record> --check-root-dir --check-private-refs --expected-pr <number>`.
  The private-ref check follows `owner_authorization_ref`, `rollback_ref`, and
  `hardware_evidence_ref` without printing paths or values; it is still a
  shape/privacy check, not content attestation.
- Clean `scripts/check-t1-preflight-default-off.py` result on the base before
  the activation diff is reviewed. The bundle must include the direct audit
  carry filters for durability/rotation (`t1_spooled_audit_sink`), fixed
  path/canonical-root validation (`t1_audit_log_path`), and HMAC/keyed export
  redaction (`t1_audit_export_jsonl`), not only the mount-level smoke.

## Reference Content Verification

The activation review must verify the content of each private reference, not
only that the reference string is non-empty or non-placeholder:

- `owner_authorization_ref` points to the real owner authorization record for
  the exact PR and commit SHA.
- `rollback_ref` points to the reviewed prebuilt rollback artifact and restore
  operation.
- `hardware_evidence_ref` points to the reviewed T1-T4 evidence pack for the
  same artifact.

The Rust loader and offline validator are shape checks. They do not prove that a
reference points to the artifact it names.

## Wiring Boundary

- The mount may only consume evidence from a fresh SHA-bound record for the
  exact artifact under review.
- The `audit_root` used by the mount must come from that evidence record and
  must be bound to the reviewed owner-controlled root for the same artifact.
- The audit log open path must keep the fixed suffix selector, canonical root
  validation, fd-relative traversal, and `O_NOFOLLOW` protections.
- The reviewed audit sink durability and retention behavior must stay in force:
  each accepted record is flushed and `sync_data`ed, rotation occurs before the
  reviewed byte cap is exceeded, the parent directory is synced after rotation
  metadata changes, and only the bounded retained files are kept.
- The source guard is expected to trip when mount-to-gate wiring appears. Any
  guard relaxation must be narrow, named, and limited to the reviewed caller and
  evidence symbols.
- The activation PR must not weaken the default-off guard invariants for
  unrelated paths: mount missing-preflight count, `::new` bans outside reviewed
  modules, and loader-symbol confinement remain review items.
- Export/HMAC code must remain unwired to off-host export unless the same PR
  also carries a reviewed export-key source, rotation policy, retention policy,
  and privacy review.

## Runtime and Product Gates

- Use only `Soyeht Dev.app`, dev profile, and dev hosts. Never touch
  `/Applications/Soyeht.app`, production engine state, production launch agents,
  production relays, or production service identifiers.
- The live-run launcher must use bounded runtime limits, route cleanup, packet
  pump cleanup, and stop authority from the readiness runbook.
- Route scope must remain one target claw `/32`; no default route, LAN route,
  engine route, or other-claw route may use the tunnel.
- Any reviewer or operator can stop the run. Stop conditions from the readiness
  runbook are hard failures and require rollback before another attempt.
- Product sign-off is separate from technical readiness. Dev-host validation is
  not shipping approval.

## Required Reviews

Before merge or live use, collect explicit ACKs for the exact PR head:

- architecture/boundary review for the mount, startup, router, and source guard
  boundary crossing;
- tests/CI/regression review for unit, guard, bundle, and CI coverage;
- claim/docs/guard/privacy review for wording, evidence handling, and public
  redaction;
- security/adversarial/unsafe review for path traversal, `openat`/`renameat` /
  `unlinkat` surfaces, durability, cleanup, logging, and activation bypasses;
- checklist/product-risk review for rollback, hardware T1-T4 evidence, stop
  authority, product scope, and merge readiness.

Reviewer ACKs are not owner authorization. Owner authorization is the explicit
record named above and expires when the PR head or artifact SHA changes.

## Merge and Run Separation

Merge readiness and live-run readiness are separate decisions:

- A code PR may be merged only after byte-pinned review, required checks, source
  guard review, and all lens ACKs for the exact head.
- A live T1-T4 run may start only after the merged or frozen artifact still
  matches the reviewed SHA-bound authorization record and every runtime gate in
  this checklist and the readiness runbook is satisfied.
- Admin override is not a substitute for failed or missing checks on activation
  code.

If any checklist item is missing, stale, or indirectly evidenced, stop before
live validation and open a follow-up slice.
