//! B-3: the exposure decision for `PairMachineInstallRestartRequired`.
//!
//! The variant was added to the post-onboarding or-pattern arm of
//! `HouseholdExposurePolicy::allows_with` by a single compiler-forced line. That
//! line is a DECISION about what an install-interrupted household exposes,
//! and at the freeze it was asserted by nothing: the variant appeared exactly
//! once in `household_listener.rs` (the arm itself) and in zero exposure
//! assertions anywhere in the tree.
//!
//! # The decision (@ilia, 2026-08-05)
//!
//! Entering install-restart-required from onboarding must NOT grant Mesh.
//!
//! Exposure policy is a function of the STATE (and, since 2026-09-05, the
//! pair-device window) ALONE — it does not know where the household came
//! from. So the class set for
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
//! them. (`sync_exposure_policy_with` at 500 ms only shuts disallowed targets
//! down; that direction is harmless.) So widening the class set here makes a
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
//! # Addendum (2026-09-05): the pair-device window
//!
//! `allows_with` grew a second input (`PairingWindow`, see
//! `household_listener`) that admits `Lan` in the three post-onboarding states
//! while a pair-device window is open -- situation 2 of the owner's
//! two-situation rule, "quando a pessoa colocar add iphone". The pinned table
//! below is therefore a function of state x class x WINDOW, and every test
//! here runs both positions: the closed column is the table that shipped, byte
//! for byte, and the open column is the only widening the rule allows.
//! `PairMachineInstallRestartRequired` is unreachable by the window in either
//! column, which is what keeps the never-widens rule true on both.
//!
//! The window replaced an environment switch that briefly lived on this
//! branch. The difference that matters to this guard: the switch was a
//! process-wide `OnceLock`, so an env-backed `allows()` could read it and a
//! test could not drive both columns in one binary. The window position is an
//! argument with no env-backed sibling, so every assertion below is a plain
//! function call.
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
use server_rs::household_listener::{HouseholdExposurePolicy, InterfaceClass, PairingWindow};

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

/// Both positions of the pair-device window, so every table below is asserted
/// twice rather than once against whichever situation the process is in.
const BOTH_WINDOW_POSITIONS: [PairingWindow; 2] = [PairingWindow::Closed, PairingWindow::Open];

/// The decided policy, exhaustive by construction.
///
/// Adding a `BootstrapState` variant makes THIS FUNCTION fail to compile
/// (E0004), so a new state cannot become un-covered by quietly joining an
/// or-pattern somewhere else — which is exactly how this defect arrived.
/// Deliberately a `match` with no wildcard: `matches!`, `==` and `if let` are
/// not exhaustiveness-checked.
fn expected_exposure(state: BootstrapState, class: InterfaceClass, window: PairingWindow) -> bool {
    match state {
        // INSTALL (situation 1): LAN allowed so first-launch setup works
        // locally; no Mesh (no trust established yet). The pairing window is
        // irrelevant here — LAN is already on.
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => matches!(
            class,
            InterfaceClass::Loopback | InterfaceClass::Lan | InterfaceClass::Tailscale
        ),
        // Post-onboarding: Mesh permitted, and LAN HTTP only while a
        // pair-device window is open (situation 2, ADD IPHONE).
        // `PairingWindow::Closed` is the `Default` and what every caller with
        // no window to consult gets.
        BootstrapState::NamedAwaitingPair | BootstrapState::Ready | BootstrapState::Recovering => {
            match class {
                InterfaceClass::Loopback | InterfaceClass::Tailscale | InterfaceClass::Mesh => true,
                InterfaceClass::Lan => window.is_open(),
            }
        }
        // Interrupted install: the intersection of every legal predecessor.
        // Written literally rather than inherited from any other arm, and
        // deliberately not reachable by the pairing window.
        BootstrapState::PairMachineInstallRestartRequired => {
            matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
        }
    }
}

fn allowed_classes(state: BootstrapState, window: PairingWindow) -> Vec<InterfaceClass> {
    ALL_CLASSES
        .into_iter()
        .filter(|class| HouseholdExposurePolicy::allows_with(state, *class, window))
        .collect()
}

#[test]
fn install_restart_required_exposure_is_pinned_not_inherited() {
    for window in BOTH_WINDOW_POSITIONS {
        for class in ALL_CLASSES {
            assert_eq!(
                HouseholdExposurePolicy::allows_with(
                    BootstrapState::PairMachineInstallRestartRequired,
                    class,
                    window
                ),
                expected_exposure(
                    BootstrapState::PairMachineInstallRestartRequired,
                    class,
                    window
                ),
                "exposure for PairMachineInstallRestartRequired/{class:?} at \
                 pairing_window={window:?} is not what this guard pins; the or-pattern \
                 arm decided it without an assertion"
            );
        }
    }
}

#[test]
fn every_bootstrap_state_exposure_is_pinned() {
    for window in BOTH_WINDOW_POSITIONS {
        for state in ALL_STATES {
            for class in ALL_CLASSES {
                assert_eq!(
                    HouseholdExposurePolicy::allows_with(state, class, window),
                    expected_exposure(state, class, window),
                    "exposure drifted for {state:?}/{class:?} at pairing_window={window:?}"
                );
            }
        }
    }
}

/// The default this repo ships is the closed column.
///
/// `PairingWindow` has no environment read, no parse and no fallible
/// construction, so the only ways to reach the open column are to hold a live
/// pair-device window and observe it open, or to write `PairingWindow::Open`
/// in source. `Default` is where a call site that forgot to thread a window
/// lands, and it must be the table that shipped -- otherwise a forgotten
/// argument silently puts a Ready household on the Wi-Fi.
#[test]
fn the_shipped_default_is_the_closed_column() {
    assert_eq!(
        PairingWindow::default(),
        PairingWindow::Closed,
        "a caller with no pair-device window to consult must get exactly what a \
         Ready household exposed before the window reached this policy"
    );
    for state in ALL_STATES {
        for class in ALL_CLASSES {
            assert_eq!(
                HouseholdExposurePolicy::allows_with(state, class, PairingWindow::default()),
                expected_exposure(state, class, PairingWindow::Closed),
                "the default window position disagrees with the closed column for \
                 {state:?}/{class:?}"
            );
        }
    }
}

/// The pairing window may move post-onboarding LAN and nothing else.
///
/// Stated as a difference between the two columns rather than as a list of
/// allowed cells, so a future arm that consults `pairing_window` for some
/// other class fails here instead of quietly shipping.
#[test]
fn the_pairing_window_moves_only_post_onboarding_lan() {
    for state in ALL_STATES {
        for class in ALL_CLASSES {
            let closed = HouseholdExposurePolicy::allows_with(state, class, PairingWindow::Closed);
            let open = HouseholdExposurePolicy::allows_with(state, class, PairingWindow::Open);
            let post_onboarding_lan = class == InterfaceClass::Lan
                && matches!(
                    state,
                    BootstrapState::NamedAwaitingPair
                        | BootstrapState::Ready
                        | BootstrapState::Recovering
                );
            if post_onboarding_lan {
                assert!(
                    !closed,
                    "{state:?}/Lan must be denied while no pair-device window is open"
                );
                assert!(
                    open,
                    "{state:?}/Lan must be admitted while a pair-device window is open"
                );
            } else {
                assert_eq!(
                    closed, open,
                    "{state:?}/{class:?} moved with the pairing window; the window is \
                     scoped to post-onboarding LAN and must reach nothing else"
                );
            }
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
    // Asserted in BOTH window positions: an open window adds `Lan` to two of
    // the three predecessor sets, so the intersection this arm must stay
    // inside GROWS. The arm itself does not, which is the whole point.
    for window in BOTH_WINDOW_POSITIONS {
        let after = allowed_classes(BootstrapState::PairMachineInstallRestartRequired, window);
        for before in LEGAL_PREDECESSORS_OF_INSTALL_RESTART {
            let had = allowed_classes(before, window);
            let gained: Vec<_> = after
                .iter()
                .filter(|class| !had.contains(class))
                .copied()
                .collect();
            assert!(
                gained.is_empty(),
                "{before:?} -> PairMachineInstallRestartRequired GAINS {gained:?} at \
                 pairing_window={window:?}: refresh_loop re-derives bind targets from \
                 this same policy on a timer AND on every pair-device window event, so \
                 the household becomes reachable on a class it was not reachable on \
                 before, without the router ever being restarted"
            );
        }
    }
}

/// The two arms must be DISTINGUISHABLE by test, or "install-interrupted
/// exposes the same as Ready" is a claim no test can refute.
#[test]
fn install_restart_required_is_distinguishable_from_ready() {
    let pmirr = BootstrapState::PairMachineInstallRestartRequired;

    assert!(
        !HouseholdExposurePolicy::allows_with(pmirr, InterfaceClass::Mesh, PairingWindow::Closed),
        "an interrupted install must not be bindable on Mesh"
    );
    assert!(
        HouseholdExposurePolicy::allows_with(
            BootstrapState::Ready,
            InterfaceClass::Mesh,
            PairingWindow::Closed
        ),
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

    // It must not inherit onboarding's LAN either, in either window position.
    // An interrupted install is a recovery step; somebody adding a phone to a
    // working household says nothing about a broken one.
    for window in BOTH_WINDOW_POSITIONS {
        assert!(
            !HouseholdExposurePolicy::allows_with(pmirr, InterfaceClass::Lan, window),
            "an interrupted install must not expose LAN HTTP at pairing_window={window:?}"
        );
    }
}
