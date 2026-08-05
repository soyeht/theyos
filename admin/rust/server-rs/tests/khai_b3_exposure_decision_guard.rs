//! B-3: the exposure decision for `PairMachineInstallRestartRequired`.
//!
//! The variant was added to the post-onboarding or-pattern arm of
//! `HouseholdExposurePolicy::allows` by a single compiler-forced line. That
//! line is a DECISION about what an install-interrupted household exposes,
//! and at the freeze it was asserted by nothing: the variant appeared exactly
//! once in `household_listener.rs` (the arm itself) and in zero exposure
//! assertions anywhere in the tree.
//!
//! # The decision (@ilia, 2026-08-05)
//!
//! Entering install-restart-required from onboarding must NOT grant Mesh.
//!
//! Exposure policy is a function of the STATE ALONE — `allows()` does not know
//! where the household came from. So the class set for
//! `PairMachineInstallRestartRequired` has to be safe from *every* legal
//! predecessor, and the only set that satisfies that is their INTERSECTION:
//!
//! | predecessor                      | classes                      |
//! |----------------------------------|------------------------------|
//! | `Uninitialized`/`ReadyForNaming` | Loopback + Lan + Tailscale   |
//! | `NamedAwaitingPair`              | Loopback + Tailscale + Mesh  |
//! | **intersection**                 | **Loopback + Tailscale**     |
//!
//! Hence its own arm: `Loopback + Tailscale`. No Lan, no Mesh. It does not
//! inherit Lan from onboarding either — an interrupted install is not a
//! household in onboarding, and must not gain anything by accident in either
//! direction.
//!
//! **Rule: entering `PairMachineInstallRestartRequired` never widens the
//! exposed set relative to any legal predecessor.**
//!
//! # Why it matters (the transitive path)
//!
//! `ProcessStartupToken` closes "who may start the router". It does not close
//! "what changes exposure after the state changes". `refresh_loop` polls the
//! state and re-derives bind targets through the same policy on a timer, and
//! `sync_interface_targets` RECONCILES — it can OPEN targets, not only close
//! them. (`sync_exposure_policy` at 500 ms only shuts disallowed targets down;
//! that direction is harmless.) So widening the class set here makes a
//! household that never completed onboarding reachable on a new class, on a
//! timer, with no router restart and nothing for the startup token to catch.
//!
//! # Strength of the evidence — do not read this as one executed chain
//!
//! - The transition table permitting `Uninitialized | ReadyForNaming |
//!   NamedAwaitingPair -> PairMachineInstallRestartRequired`: **executed**, by
//!   `legal_predecessors_list_matches_the_transition_table` below.
//! - The class set widening across that transition: **executed**, by
//!   `entering_install_restart_required_never_widens_the_exposed_class_set`.
//! - That `handlers_pair_machine.rs` actually performs the transition (`:529`,
//!   and `:586` which also writes the in-memory `bs_lock`): **read, not
//!   executed**.
//! - That `sync_interface_targets` opens targets on the refresh tick: **read,
//!   not executed**.
//!
//! The executed half is the half that decides whether widening exists; the
//! read half only establishes reachability, from two explicit call sites.
//!
//! # Declared severity limit
//!
//! `classify_local_address` returns `InterfaceClass::Mesh` only when
//! `fact.ownership == VerifiedMesh` AND `is_verified_local_mesh_address(fact)`,
//! and quarantines unverified candidates. So the widening materialises only on
//! a host with Product A mesh active and a provider-attested address — it is
//! not universal exposure. Deliberately NOT closed by observation: doing so
//! would mean fabricating a `VerifiedMesh` fact, and this goal forbids mixing
//! Product A / nvpn into this delivery.

use household_rs::bootstrap_state::BootstrapState;
use server_rs::household_listener::{HouseholdExposurePolicy, InterfaceClass};

const ALL_CLASSES: [InterfaceClass; 4] = [
    InterfaceClass::Loopback,
    InterfaceClass::Lan,
    InterfaceClass::Tailscale,
    InterfaceClass::Mesh,
];

const ALL_STATES: [BootstrapState; 6] = [
    BootstrapState::Uninitialized,
    BootstrapState::ReadyForNaming,
    BootstrapState::NamedAwaitingPair,
    BootstrapState::PairMachineInstallRestartRequired,
    BootstrapState::Ready,
    BootstrapState::Recovering,
];

/// Every transition INTO `PairMachineInstallRestartRequired` that
/// `BootstrapState::transition` permits.
const LEGAL_PREDECESSORS_OF_INSTALL_RESTART: [BootstrapState; 3] = [
    BootstrapState::Uninitialized,
    BootstrapState::ReadyForNaming,
    BootstrapState::NamedAwaitingPair,
];

/// The decided policy, exhaustive by construction.
///
/// Adding a `BootstrapState` variant makes THIS FUNCTION fail to compile
/// (E0004), so a new state cannot become un-covered by quietly joining an
/// or-pattern somewhere else — which is exactly how this defect arrived.
/// Deliberately a `match` with no wildcard: `matches!`, `==` and `if let` are
/// not exhaustiveness-checked.
fn expected_exposure(state: BootstrapState, class: InterfaceClass) -> bool {
    match state {
        // Onboarding: LAN allowed so first-launch setup works locally; no Mesh
        // (no trust established yet).
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => matches!(
            class,
            InterfaceClass::Loopback | InterfaceClass::Lan | InterfaceClass::Tailscale
        ),
        // Post-onboarding: no LAN HTTP, Mesh permitted.
        BootstrapState::NamedAwaitingPair | BootstrapState::Ready | BootstrapState::Recovering => {
            matches!(
                class,
                InterfaceClass::Loopback | InterfaceClass::Tailscale | InterfaceClass::Mesh
            )
        }
        // Interrupted install: the intersection of every legal predecessor.
        // Written literally rather than inherited from any other arm.
        BootstrapState::PairMachineInstallRestartRequired => {
            matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
        }
    }
}

fn allowed_classes(state: BootstrapState) -> Vec<InterfaceClass> {
    ALL_CLASSES
        .into_iter()
        .filter(|class| HouseholdExposurePolicy::allows(state, *class))
        .collect()
}

#[test]
fn install_restart_required_exposure_is_pinned_not_inherited() {
    for class in ALL_CLASSES {
        assert_eq!(
            HouseholdExposurePolicy::allows(
                BootstrapState::PairMachineInstallRestartRequired,
                class
            ),
            expected_exposure(BootstrapState::PairMachineInstallRestartRequired, class),
            "exposure for PairMachineInstallRestartRequired/{class:?} is not what this \
             guard pins; the or-pattern arm decided it without an assertion"
        );
    }
}

#[test]
fn every_bootstrap_state_exposure_is_pinned() {
    for state in ALL_STATES {
        for class in ALL_CLASSES {
            assert_eq!(
                HouseholdExposurePolicy::allows(state, class),
                expected_exposure(state, class),
                "exposure drifted for {state:?}/{class:?}"
            );
        }
    }
}

/// Guard against the transition table and this file disagreeing.
///
/// If `transition` stops permitting one of these, this test must be updated
/// deliberately rather than silently covering a transition that no longer
/// exists — or missing one that newly does.
#[test]
fn legal_predecessors_list_matches_the_transition_table() {
    for state in ALL_STATES {
        let permitted = state
            .transition(BootstrapState::PairMachineInstallRestartRequired)
            .is_ok();
        let listed = LEGAL_PREDECESSORS_OF_INSTALL_RESTART.contains(&state)
            || state == BootstrapState::PairMachineInstallRestartRequired;
        assert_eq!(
            permitted, listed,
            "transition table and this test disagree about {state:?} -> \
             PairMachineInstallRestartRequired"
        );
    }
}

/// THE rule: entering install-restart-required never widens the exposed set
/// relative to any legal predecessor.
///
/// A reexec/install-restart is a recovery step, not a promotion.
#[test]
fn entering_install_restart_required_never_widens_the_exposed_class_set() {
    let after = allowed_classes(BootstrapState::PairMachineInstallRestartRequired);
    for before in LEGAL_PREDECESSORS_OF_INSTALL_RESTART {
        let had = allowed_classes(before);
        let gained: Vec<_> = after
            .iter()
            .filter(|class| !had.contains(class))
            .copied()
            .collect();
        assert!(
            gained.is_empty(),
            "{before:?} -> PairMachineInstallRestartRequired GAINS {gained:?}: \
             refresh_loop re-derives bind targets from this same policy on a timer, \
             so the household becomes reachable on a class it was not reachable on \
             before, without the router ever being restarted"
        );
    }
}

/// The two arms must be DISTINGUISHABLE by test, or "install-interrupted
/// exposes the same as Ready" is a claim no test can refute.
#[test]
fn install_restart_required_is_distinguishable_from_ready() {
    let pmirr = BootstrapState::PairMachineInstallRestartRequired;

    assert!(
        !HouseholdExposurePolicy::allows(pmirr, InterfaceClass::Mesh),
        "an interrupted install must not be bindable on Mesh"
    );
    assert!(
        HouseholdExposurePolicy::allows(BootstrapState::Ready, InterfaceClass::Mesh),
        "control: a fully Ready household IS bindable on Mesh, so the assertion above \
         is about the state and not about Mesh being denied globally"
    );

    // Belt and braces: remote terminal attach stays denied for this state by a
    // second, independent condition (`allows_terminal_attach_peer` requires
    // `== Ready` for Mesh). Asserted so that if the bind policy above is ever
    // relaxed, attach does not silently follow it.
    assert!(
        !HouseholdExposurePolicy::allows_terminal_attach_peer(pmirr, InterfaceClass::Mesh),
        "a household whose install was interrupted must not accept a remote Mesh \
         terminal attach: attach is effectful and the install is not finished"
    );
    assert!(
        HouseholdExposurePolicy::allows_terminal_attach_peer(
            BootstrapState::Ready,
            InterfaceClass::Mesh
        ),
        "control for the attach assertion"
    );

    // It must not inherit onboarding's LAN either.
    assert!(
        !HouseholdExposurePolicy::allows(pmirr, InterfaceClass::Lan),
        "an interrupted install must not expose LAN HTTP"
    );
}
