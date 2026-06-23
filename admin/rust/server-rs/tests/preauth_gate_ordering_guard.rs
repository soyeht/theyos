//! P7-D (PR-D1) — pre-auth gate-ordering guard. Test-only; NO runtime change,
//! NO 429, NO new `rate_limiter.check`, NO `ConnectInfo` extractor.
//!
//! The expensive pre-auth handlers (bootstrap / pair-machine) have no rate
//! limiter today; their `DoS` mitigation is defense-in-depth ORDERING — a CHEAP
//! gate (bootstrap/window state, token cache-take, loopback / tailnet IP) runs
//! BEFORE the EXPENSIVE work (keygen / P256 verify / ECDH shard decrypt /
//! external callback), so a request that fails the cheap gate is shed before any
//! expensive work runs. This guard pins that ordering: a refactor that moves the
//! expensive work ahead of the cheap gate (re-opening a `DoS` amplification) fails
//! here. It adds no limiter and changes no runtime/auth/wire — it only freezes
//! the existing order, source-level, P7-A / P7-C style.
//!
//! Scope note: cheap / boundary-gated pre-auth endpoints (seed, local/stage,
//! anchor-handoff, local/anchor) are explicitly classified out of the
//! expensive-ordering set below, with the reason each needs no invariant.

use std::fs;
use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(file: &str) -> String {
    fs::read_to_string(src_dir().join(file)).unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

/// Source of `pub async fn {name}` up to the next top-level fn / test module.
fn handler_body<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("pub async fn {name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("handler `{name}` not found"));
    let rest = &source[start + marker.len()..];
    let end = [
        "\npub async fn ",
        "\npub fn ",
        "\nasync fn ",
        "\nfn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    &rest[..end]
}

/// An expensive pre-auth handler whose cheap gate must precede its expensive work.
struct Ordering {
    handler: &'static str,
    file: &'static str,
    /// Substring that marks the cheap gate (must appear first).
    cheap_gate: &'static str,
    /// Substring that marks the expensive work (must appear AFTER the gate).
    expensive_work: &'static str,
    why: &'static str,
}

const EXPENSIVE_PREAUTH: &[Ordering] = &[
    Ordering {
        handler: "post_initialize",
        file: "handlers_bootstrap.rs",
        cheap_gate: "BootstrapState::Uninitialized",
        expensive_work: "bootstrap_or_load",
        why: "keygen (bootstrap_or_load) must run only after the bootstrap-state gate",
    },
    Ordering {
        handler: "post_accept_household",
        file: "handlers_bootstrap.rs",
        cheap_gate: "BootstrapState::Uninitialized",
        expensive_work: "prepare_accept_household",
        why: "keygen (prepare_accept_household) must run only after the state gate",
    },
    Ordering {
        handler: "post_accept_household_confirm",
        file: "handlers_bootstrap.rs",
        cheap_gate: "BootstrapState::ReadyForNaming",
        expensive_work: "confirm_accept_household",
        why: "P256 signature verify (confirm_accept_household) must run only after the state gate",
    },
    Ordering {
        handler: "post_claim_setup_invitation",
        file: "handlers_bootstrap.rs",
        cheap_gate: "cache_take",
        expensive_work: "callback_verify_blocking",
        why: "the external callback (callback_verify_blocking) must run only after the atomic token cache-take",
    },
    Ordering {
        handler: "local_finalize_handler",
        file: "handlers_pair_machine.rs",
        cheap_gate: "PairMachineState::Committed",
        expensive_work: "decrypt_from_peer",
        why: "ECDH shard decryption (decrypt_from_peer) must run only after the pairing-window state gate",
    },
];

/// Cheap / boundary-gated pre-auth endpoints intentionally OUTSIDE the
/// expensive-ordering set, with the reason no ordering invariant is needed.
const CHEAP_OR_BOUNDARY_GATED: &[(&str, &str, &str)] = &[
    (
        "local_seed_handler",
        "handlers_pair_machine.rs",
        "cheap: nonce-prefix cache lookup; no keygen/crypto/shard work",
    ),
    (
        "anchor_handoff_handler",
        "handlers_pair_machine.rs",
        "tailnet-IP gated (classify_source) + cheap cached read",
    ),
    (
        "post_pair_machine_local_stage",
        "handlers_bootstrap.rs",
        "loopback-only ACL (local daemon); not remotely reachable",
    ),
    (
        "local_anchor_handler",
        "handlers_pair_machine.rs",
        "anchor_secret constant-time gate; key derivation is light (point decompress + hash) and interleaved — documented, not strictly ordered here",
    ),
];

#[test]
fn expensive_preauth_runs_cheap_gate_before_expensive_work() {
    for inv in EXPENSIVE_PREAUTH {
        let src = read(inv.file);
        let body = handler_body(&src, inv.handler);
        let gate = body.find(inv.cheap_gate).unwrap_or_else(|| {
            panic!(
                "{} ({}) must contain its cheap gate `{}` — {}",
                inv.handler, inv.file, inv.cheap_gate, inv.why
            )
        });
        let expensive = body.find(inv.expensive_work).unwrap_or_else(|| {
            panic!(
                "{} ({}) must contain its expensive work `{}` — {}",
                inv.handler, inv.file, inv.expensive_work, inv.why
            )
        });
        assert!(
            gate < expensive,
            "{} ({}): the cheap gate `{}` MUST run before the expensive work `{}` ({}). \
             A refactor moving expensive work ahead of the gate re-opens a pre-auth DoS \
             amplification — keep the gate first.",
            inv.handler,
            inv.file,
            inv.cheap_gate,
            inv.expensive_work,
            inv.why
        );
    }
}

#[test]
fn cheap_or_boundary_gated_handlers_are_classified_and_present() {
    for (handler, file, _reason) in CHEAP_OR_BOUNDARY_GATED {
        let src = read(file);
        assert!(
            src.contains(&format!("fn {handler}")),
            "classified cheap/boundary-gated handler `{handler}` not found in {file} — table is stale"
        );
    }
}
