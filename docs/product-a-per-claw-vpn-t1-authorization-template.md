# Product A per-Claw VPN T1 authorization and evidence template

This template is the fillable artifact for the T1 readiness runbook. It does
not authorize activation by itself. A T1 run is authorized only when the owner
fills the authorization record for an exact PR and commit SHA, attaches or links
the rollback artifact, and the reviewers accept the hardware evidence for that
same artifact.

Use neutral aliases and documentation-safe addresses only. Do not paste real
hostnames, account names, device names, LAN IPs, tailnet IPs, relay endpoints,
local paths, secrets, packet bytes, frame payloads, screenshots with real
identifiers, or logs containing real identifiers into this file or a PR.

## Authorization Record

| field | value |
|---|---|
| Artifact | PR `<number>`, commit `<sha>`, build artifact hash `<hash>` |
| Scope | `dev-host T1-T4 only`; production explicitly excluded |
| Production activation | `production_activation=false` |
| Topology | Engine-dev `<engine-alpha>`, Claw-A `<claw-alpha>`, Device-D `<device-alpha>`, Relay-R `<relay-alpha>`, Member-M1 `<member-alpha>` |
| Time window | `<UTC start>` through `<UTC end>` |
| Operator | `<operator-alpha>` |
| Rollback artifact | `<rollback artifact id>` at `<private artifact location>` |
| Data policy | Public logs/screenshots/evidence use neutral aliases and redact raw local details |
| Stop authority | Any reviewer or operator may stop the run immediately |
| Owner sentence | `I authorize dev-host per-Claw VPN T1-T4 validation for <artifact>; I do not authorize production activation.` |

If any field is missing, the run is not authorized. If the PR head or commit
SHA changes, this record expires and the owner must issue a new record for the
new artifact.

## Preflight Evidence Record

Fill this JSON only after the owner authorization, rollback artifact, hardware
evidence, and audit export policy references below exist for the same exact
artifact SHA. This record is input for the reviewed T1 evidence loader; it is
not authorization by itself and it must not be wired into the mount until the
activation PR reviews the caller and source-guard changes.

Keep the real `audit_root` value in the private activation record or secret
store. Public PR text may identify it only by neutral alias/reference. The
loader requires an absolute, normal path, and the later mount wiring must still
validate that root with the canonical path helper and open the audit log through
the fd-relative `O_NOFOLLOW` traversal.

```json
{
  "schema": "per_claw_vpn_t1_preflight_evidence_v1",
  "artifact_sha": "<exact-40-hex-artifact-sha>",
  "scope": "dev-host T1-T4 only",
  "production_activation": false,
  "owner_authorization": true,
  "rollback": true,
  "hardware_t1_t4": true,
  "owner_authorization_ref": "<owner-authorization-record-ref>",
  "rollback_ref": "<prebuilt-rollback-artifact-ref>",
  "hardware_evidence_ref": "<sanitized-t1-t4-evidence-pack-ref>",
  "audit_export_policy_ref": "<audit-export-policy-ref>",
  "audit_root": "<private-absolute-normal-0700-audit-root>"
}
```

The activation PR must verify that each reference points to the real reviewed
artifact it names; the loader only checks that the references are non-empty and
that the SHA, scope, production flag, booleans, and audit-root shape are valid.
`audit_export_policy_ref` is followed by the offline validator for shape/privacy
review; it is not an authorization to export audit data off host.
Before opening the activation PR, prepare and validate the private record
locally without printing its values:

```sh
scripts/prepare-t1-preflight-evidence-record.py \
  <exact-40-hex-artifact-sha>

scripts/validate-t1-owner-authorization.py \
  <exact-40-hex-artifact-sha> \
  <private-owner-authorization-record> \
  --expected-pr <number>

scripts/validate-t1-rollback-evidence.py \
  <exact-40-hex-artifact-sha> \
  <private-rollback-evidence-record> \
  --expected-pr <number>

scripts/validate-t1-audit-export-policy.py \
  <exact-40-hex-artifact-sha> \
  <private-audit-export-policy> \
  --expected-pr <number>

scripts/validate-t1-preflight-evidence-record.py \
  <exact-40-hex-artifact-sha> \
  .env.t1-preflight-evidence.json \
  --check-root-dir \
  --check-private-refs \
  --expected-pr <number>
```

The prepare helper creates or updates the private draft and audit root, then
prints only status plus missing field names such as `owner_authorization_ref`,
`rollback_ref`, `hardware_evidence_ref`, and `audit_export_policy_ref`. It does
not print private ref values, it does not verify the referenced artifacts, and
it does not authorize activation.

The `.env.t1-preflight-evidence.json` file name is ignored by the repository's
`.gitignore`; keep the filled record private.

Before asking for any activation review, run the non-live local default-off
bundle:

```sh
scripts/check-t1-preflight-default-off.py
```

That bundle only runs Python helper/validator tests for the private owner,
rollback, preflight, and hardware shapes, Rust default-off tests, audit sink
carry tests for durability/rotation/fixed-path/HMAC export, the `friend-cli`
`IpTunnel` rejection tests, and the dev-runner offline offer validator; it does
not open TUN/utun, install routes, launch runtime, or touch production.

## Rollback Readiness

| check | evidence |
|---|---|
| Previous known-good dev engine artifact is available | `<artifact id/hash>` |
| Restore command or service operation is documented privately | `<private reference>` |
| Dev-service environment snapshot exists with secrets removed/redacted | `<private reference>` |
| Linux route cleanup procedure is ready | `<private reference>` |
| macOS route cleanup procedure is ready | `<private reference>` |
| Linux TUN cleanup procedure is ready | `<private reference>` |
| macOS utun cleanup procedure is ready | `<private reference>` |
| Relay/process stop procedure is ready | `<private reference>` |
| Baseline health verification checklist is ready | `<private reference>` |

Rollback is not ready if it depends on rebuilding locally after a failed run.

## Hardware Evidence Pack

Required metadata:

| field | value |
|---|---|
| Artifact | PR `<number>`, commit `<sha>`, build artifact hash `<hash>` |
| Host OS | `<Linux/macOS major version only>` |
| Role | `<Engine-dev/Claw-A/Device-D/Relay-R>` |
| Clock | `<UTC start>` through `<UTC end>` |
| Operator | `<operator-alpha>` |
| Authorization | `<authorization record link/reference>` |
| Rollback | `<rollback artifact link/reference>` |

Evidence rows:

| ID | evidence |
|---|---|
| T1 interface up | Before/during/after interface snapshot with neutral interface alias and documentation-safe addresses; confirms clean removal on exit |
| T2 tunnel plumbing | ICMP and TCP echo success from Device-D to Claw-A over Relay-R, with neutral endpoint labels only |
| T3 route scope | Before/during/after route snapshots proving only Claw-A `/32` uses the tunnel; LAN, engine, and other-claw routes do not |
| T4 fail-closed plumbing | Relay-R interruption followed by tunnel shutdown, route cleanup, no half-open interface, and dev engine health restored or rollback executed |

Negative observations required for the evidence pack:

- no default route through the tunnel;
- no route to the claw host LAN through the tunnel;
- no route to another claw through the tunnel;
- no route to the engine address through the tunnel;
- no raw `TunnelFrame` payload bytes in logs;
- no real hostnames, account names, device names, LAN IPs, tailnet IPs, relay
  endpoints, secrets, local paths, or packet/frame payloads in public evidence.

Before using the hardware pack as `hardware_evidence_ref`, validate its shape
without printing private values:

```sh
scripts/validate-t1-hardware-evidence-pack.py \
  <exact-40-hex-artifact-sha> \
  <private-hardware-evidence-pack> \
  --expected-pr <number>
```

Then keep the same private paths in `owner_authorization_ref`, `rollback_ref`,
`hardware_evidence_ref`, and `audit_export_policy_ref`, and rerun the preflight
evidence validator with `--check-private-refs`. That chained check does not
print private paths or values; it only proves the referenced private artifacts
are complete-shaped for review.

These validators check that the private artifacts are complete-shaped for
review. They do not prove the referenced artifacts are real or correct;
reviewers must still verify the content of the owner, rollback, hardware, and
run evidence before activation.

## Stop Record

If any stop condition triggers, fill this section and stop the run. Do not patch
live state and continue in the same window.

| field | value |
|---|---|
| Stop time | `<UTC timestamp>` |
| Stop authority | `<reviewer/operator alias>` |
| Trigger | `<stop condition>` |
| Sanitized evidence captured | `<link/reference>` |
| Rollback action executed | `<artifact/operation reference>` |
| Post-rollback interface check | `<clean/not clean>` |
| Post-rollback route check | `<clean/not clean>` |
| Dev engine health after rollback | `<baseline/restored/failed>` |
