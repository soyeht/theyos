# Owner-Mesh Rendezvous Security Contract — Addendum S1–S3 (v1)

Author/authority: safia (security gate, peça-5 owner-mesh rendezvous).
Purpose: re-persist in-repo, clone-reproducible, the S1–S3 addendum to the
10-invariant rendezvous security contract (I1–I10, delivered 2026-07-17, adopted
verbatim by jovian). Re-persisted because the original /tmp draft was lost —
same volatility lesson as db6ecf37 / wire-encoding-v1 / R0b companion: a norm that
gates work must live in-repo, byte-anchored, not in volatile /tmp.
This file's raw SHA-256 is the freeze anchor; safia holds byte-GO authority over
its content. jovian/alaine commit safia's exact bytes (path+commit+sha), never
paraphrase.

## S1 — R1 signaling is a first-class attested published-target (authority=none)

Every RUNNING owner-mesh signaling surface MUST be a first-class published-target
carrying the SAME mechanical authority=none Phase-0 attestation required for F.2a —
never smuggled behind a dev-mint (e.g. dev_claw_share_mint) nor escaping the
Phase-0 attestation boundary. Rationale: the F.2 packaging NO-GO was an EFFECTFUL
capability shipping without the authority=none attestation; R1 must not repeat it
(R1 and F.2a share the Phase-0 attestation pattern).

Rejection criterion: any signaling EXECUTABLE reachable in a shipped artifact whose
build does not carry the authority=none Phase-0 attestation → NO-GO.

Scope clarification (grounds the R1a/R1b split, 2026-07-22): the ATTESTED SURFACE
S1 protects is the RUNNING signaling BINARY. A pure inert codec LIBRARY — no
`[[bin]]`, no IO, structurally unreachable (the R1a inertness bar) — is NOT a
running surface and is S1-NEUTRAL: it has zero runtime effect standalone and
becomes a surface only when statically linked into the signaling binary, whose
published-target attestation then TRANSITIVELY covers the codec's bytes
(supply-chain integrity of the parser preserved at the point it becomes reachable).
Binding condition on any R1b: the signaling binary's directive MUST attest the
COMPOSED binary INCLUDING the linked codec, and no path may make the codec an
execution-surface except via that attested binary.

## S2 — protocol corpus carries a frozen negative matrix

The R0b/wire rendezvous corpus MUST include a NEGATIVE matrix mirroring the DP
negative_contract, frozen by raw SHA-256 before any serializing consumer:
(a) a hostile signaling server extracts NO identity;
(b) a forged address-hint fails clean — no amplification, uniform silence (D-A);
(c) rendezvous-id replay is barred;
(d) mode-injection is refused (the server never commands relay/direct).
Realized: `owner_mesh_rendezvous_corpus_v1.json`, raw SHA-256
4983391605379d7423ff19c6f9d10cd18b58b11b973df748d5423fa6bd503a47 / 43113 bytes
@ a8891dc5 (main); byte-GO 2026-07-22.

## S3 — direct LAN is datapath; the inert/effective boundary lands atomic

Direct LAN IS a datapath, not a control channel. The MOMENT a slice moves a real
site byte (R3 client direct-first, or any effective transport), the #315 atomic
preconditions — signed/pinned baseMeshPublicKeyHex + tested App-Group
Dev≠Release — MUST land in the SAME merge. The R2-inert / R3-effective boundary is
what the security gate polices: inert design/codec slices carry NO effectful
primitive (no mint, no consume-set, no authority, no transport); the FIRST
effective byte carries the full atomic proof. A slice that moves a byte without the
atomic proof in the same merge → NO-GO.
