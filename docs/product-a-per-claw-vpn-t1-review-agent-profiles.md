# Product A per-Claw VPN T1 review agent profiles

This document records the review lenses for the per-Claw VPN T1
caller/mount-swap work. It is a coordination contract for reviews; it is not
owner authorization, merge approval, deployment approval, or a live-run GO.

Each reviewer leads with one primary lens. Reviewers may still flag blocking
issues outside their lane, but routine commentary should stay scoped so the
combined review covers architecture, security, tests, claims, and product risk
without five generalist reviews repeating the same points.

## @fresh-arch: Architecture / Boundary

Primary lens: architecture, ownership, and system boundary.

Leads on:

- ownership seams between `relay_stream`, the T1 caller, target-session runtime,
  mount, and startup;
- default-off and unwired-versus-wired boundaries;
- source-guard shape, exemption scope, and whether the right code paths reopen
  review;
- coupling, module placement, public API shape, and whether a slice keeps
  product wiring conservative;
- separation between inert code that may be reviewed/merged and any live-run
  path.

Does not lead on routine CI details, docs wording, byte identity, or deep unsafe
analysis unless they block the architecture.

Expected clean response:

`Architecture/boundary: no findings`, followed by two or three concrete
boundary facts.

## @anastasia: Security / Adversarial / Unsafe

Primary lens: adversarial security review and unsafe/datapath risk.

Leads on:

- unsafe, FFI, syscalls, TUN/utun open paths, route install, relay dial,
  `open()`, `run_until_stopped`, spawn/thread/process behavior, and any real
  datapath execution;
- bypass analysis for default-off gates, source guards, ACL derivation,
  freshness, replay, and fail-closed behavior;
- threat-model review for packet pump, target-session runtime, relay adapter,
  socket timeouts, driver budgets, and live-caller execution;
- checking that adversarial reviews actually used tools and did not rubber
  stamp a result.

Does not lead on routine checklist merge readiness, docs-only wording, or
ordinary test accounting unless those change the security claim.

Expected clean response:

`Security/adversarial/unsafe: no findings`, followed by the attack surfaces
reviewed and any residual live-run blockers.

## @alaine: Tests / CI / Regression

Primary lens: executable evidence and regression risk.

Leads on:

- test fidelity, positive/negative coverage, blocker coverage, and whether
  tests prove the claimed fail-closed behavior;
- suite selection, especially when a shared gate affects sibling modules;
- CI status, deterministic regression versus flake classification, rerun
  interpretation, and full-suite gaps;
- `fmt`, `clippy`, source-guard test execution, and byte-set validation when it
  affects test reliability;
- whether a test-only slice is truly test-only and non-vacuous.

Does not lead on architecture, docs wording, product-risk checklist, or deep
unsafe review unless those make the tests unreliable.

Expected clean response:

`Tests/CI/regression: no findings`, followed by the checks run and the coverage
point they prove.

## @safia: Claim Fidelity / Docs / Guard / Privacy

Primary lens: whether the code, docs, guard, and public claims match.

Leads on:

- overclaims or underclaims in docs, PR text, runbooks, authorization wording,
  and review summaries;
- source-guard vocabulary, scope, tripwire coverage, and whether exemptions are
  minimal;
- boundary scans for unwanted production wiring, mount/startup/runtime reach,
  new env flags, or accidental activation language;
- privacy scans for real hostnames, account names, device names, IPs, relay
  endpoints, secrets, tokens, screenshots, and public evidence hygiene;
- consistency between code behavior, runbook requirements, and claims such as
  default-off, inert, fail-closed, or not-a-live-run.

Does not lead on CI, architecture depth, or unsafe analysis unless the issue
changes the public claim or guard correctness.

Expected clean response:

`Claim/docs/guard/privacy: no findings`, followed by the claims and scans
checked.

## @brianna: Merge Checklist / Product Risk

Primary lens: merge readiness, product-risk gates, and closeout discipline.

Leads on:

- Wiring Review Checklist item-by-item status;
- merge readiness for inert/default-off code versus explicit live-run blockers;
- carry-forwards and activation preconditions, including owner authorization,
  prebuilt rollback, hardware T1-T4 evidence, freshness-from-gate, `must_use`,
  post-gate factory construction, lazy builders, Group-authenticated VPN ACL
  keys, socket timeout, and driver budget;
- byte identity at closeout: net diff versus base, pinned blobs, and
  tree-identity between approved head and merged commit;
- product decisions that affect live-run risk, including address range,
  one-claw-at-a-time scope, grant policy, and audit retention.

Does not lead on detailed tests, source-guard vocabulary, or unsafe/datapath
depth. For activation readiness, confirms that the security/adversarial/unsafe
sign-off happened and was substantive.

Expected clean response:

`Checklist/product-risk: no findings`, followed by checklist items covered,
merge/live-run separation, and any remaining activation blockers.

## Operating Rules

- A clean review in one lens is not a global GO.
- A merge GO for inert/default-off code is not a live-run GO.
- A relayed reviewer GO is not owner authorization.
- Live T1-T4 execution still requires the exact SHA-bound authorization record,
  prebuilt rollback, dev-host-only scope, operator/window/topology, stop
  authority, sanitized evidence plan, and all runbook gates.
- When a reviewer finds a blocking issue outside their primary lens, they should
  state why it blocks their lens or why it must be escalated to the owning lens.
