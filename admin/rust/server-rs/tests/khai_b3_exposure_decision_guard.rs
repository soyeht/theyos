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
//! # Addendum (2026-09-04): the owner LAN switch
//!
//! `allows` grew an owner opt-in (`THEYOS_HOUSEHOLD_LAN_PAIRING`, see
//! `LanPairing`) that admits `Lan` in the three post-onboarding states. The
//! pinned table below is therefore a function of state x class x SWITCH, and
//! every test here runs both positions: the closed column is the table that
//! shipped, byte for byte, and the open column is the only widening the owner
//! can ask for. `PairMachineInstallRestartRequired` is unreachable by the
//! switch in either column, which is what keeps the never-widens rule true on
//! both.
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
use server_rs::household_listener::{HouseholdExposurePolicy, InterfaceClass, LanPairing};

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

/// Both positions of the owner LAN switch, so every table below is asserted
/// twice rather than once against whatever the environment happens to say.
const BOTH_SWITCH_POSITIONS: [LanPairing; 2] = [LanPairing::Closed, LanPairing::Open];

/// The decided policy, exhaustive by construction.
///
/// Adding a `BootstrapState` variant makes THIS FUNCTION fail to compile
/// (E0004), so a new state cannot become un-covered by quietly joining an
/// or-pattern somewhere else — which is exactly how this defect arrived.
/// Deliberately a `match` with no wildcard: `matches!`, `==` and `if let` are
/// not exhaustiveness-checked.
fn expected_exposure(state: BootstrapState, class: InterfaceClass, lan: LanPairing) -> bool {
    match state {
        // Onboarding: LAN allowed so first-launch setup works locally; no Mesh
        // (no trust established yet). The owner switch is irrelevant here —
        // LAN is already on.
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => matches!(
            class,
            InterfaceClass::Loopback | InterfaceClass::Lan | InterfaceClass::Tailscale
        ),
        // Post-onboarding: Mesh permitted, and LAN HTTP only if the owner
        // opened it. `LanPairing::Closed` is the shipped default and the value
        // every unrecognised spelling parses to.
        BootstrapState::NamedAwaitingPair | BootstrapState::Ready | BootstrapState::Recovering => {
            match class {
                InterfaceClass::Loopback | InterfaceClass::Tailscale | InterfaceClass::Mesh => true,
                InterfaceClass::Lan => lan.is_open(),
            }
        }
        // Interrupted install: the intersection of every legal predecessor.
        // Written literally rather than inherited from any other arm, and
        // deliberately not reachable by the owner switch.
        BootstrapState::PairMachineInstallRestartRequired => {
            matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
        }
    }
}

fn allowed_classes(state: BootstrapState, lan: LanPairing) -> Vec<InterfaceClass> {
    ALL_CLASSES
        .into_iter()
        .filter(|class| HouseholdExposurePolicy::allows_with(state, *class, lan))
        .collect()
}

#[test]
fn install_restart_required_exposure_is_pinned_not_inherited() {
    for lan in BOTH_SWITCH_POSITIONS {
        for class in ALL_CLASSES {
            assert_eq!(
                HouseholdExposurePolicy::allows_with(
                    BootstrapState::PairMachineInstallRestartRequired,
                    class,
                    lan
                ),
                expected_exposure(
                    BootstrapState::PairMachineInstallRestartRequired,
                    class,
                    lan
                ),
                "exposure for PairMachineInstallRestartRequired/{class:?} at \
                 lan_pairing={lan:?} is not what this guard pins; the or-pattern arm \
                 decided it without an assertion"
            );
        }
    }
}

#[test]
fn every_bootstrap_state_exposure_is_pinned() {
    for lan in BOTH_SWITCH_POSITIONS {
        for state in ALL_STATES {
            for class in ALL_CLASSES {
                assert_eq!(
                    HouseholdExposurePolicy::allows_with(state, class, lan),
                    expected_exposure(state, class, lan),
                    "exposure drifted for {state:?}/{class:?} at lan_pairing={lan:?}"
                );
            }
        }
    }
}

/// The default this repo ships is the closed column, and the env-backed
/// `allows` is nothing but `allows_with` under the resolved switch.
///
/// Two claims in one test because they fail together: if `allows` ever grew a
/// second input, or if `LanPairing::default()` moved, the shipped posture
/// would stop being the table above without any arm changing.
#[test]
fn the_shipped_default_is_the_closed_column() {
    assert_eq!(
        LanPairing::default(),
        LanPairing::Closed,
        "an engine with no THEYOS_HOUSEHOLD_LAN_PAIRING set must expose exactly what \
         it exposed before the switch existed"
    );
    let resolved = LanPairing::from_env();
    for state in ALL_STATES {
        for class in ALL_CLASSES {
            assert_eq!(
                HouseholdExposurePolicy::allows(state, class),
                expected_exposure(state, class, resolved),
                "env-backed allows() disagrees with the pinned table for \
                 {state:?}/{class:?} at the resolved switch {resolved:?}"
            );
        }
    }
}

/// The switch may move post-onboarding LAN and nothing else.
///
/// Stated as a difference between the two columns rather than as a list of
/// allowed cells, so a future arm that consults `lan_pairing` for some other
/// class fails here instead of quietly shipping.
#[test]
fn the_owner_switch_moves_only_post_onboarding_lan() {
    for state in ALL_STATES {
        for class in ALL_CLASSES {
            let closed = HouseholdExposurePolicy::allows_with(state, class, LanPairing::Closed);
            let open = HouseholdExposurePolicy::allows_with(state, class, LanPairing::Open);
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
                    "{state:?}/Lan must be denied while the switch is closed"
                );
                assert!(
                    open,
                    "{state:?}/Lan must be admitted once the owner opens it"
                );
            } else {
                assert_eq!(
                    closed, open,
                    "{state:?}/{class:?} moved with the owner LAN switch; the switch is \
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
    // Asserted in BOTH switch positions: opening LAN adds `Lan` to two of the
    // three predecessor sets, so the intersection this arm must stay inside
    // GROWS. The arm itself does not, which is the whole point.
    for lan in BOTH_SWITCH_POSITIONS {
        let after = allowed_classes(BootstrapState::PairMachineInstallRestartRequired, lan);
        for before in LEGAL_PREDECESSORS_OF_INSTALL_RESTART {
            let had = allowed_classes(before, lan);
            let gained: Vec<_> = after
                .iter()
                .filter(|class| !had.contains(class))
                .copied()
                .collect();
            assert!(
                gained.is_empty(),
                "{before:?} -> PairMachineInstallRestartRequired GAINS {gained:?} at \
                 lan_pairing={lan:?}: refresh_loop re-derives bind targets from this \
                 same policy on a timer, so the household becomes reachable on a class \
                 it was not reachable on before, without the router ever being restarted"
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
        !HouseholdExposurePolicy::allows_with(pmirr, InterfaceClass::Mesh, LanPairing::Closed),
        "an interrupted install must not be bindable on Mesh"
    );
    assert!(
        HouseholdExposurePolicy::allows_with(
            BootstrapState::Ready,
            InterfaceClass::Mesh,
            LanPairing::Closed
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

    // It must not inherit onboarding's LAN either, in either switch position.
    // An interrupted install is a recovery step; the owner opting into LAN
    // pairing for a working household says nothing about a broken one.
    for lan in BOTH_SWITCH_POSITIONS {
        assert!(
            !HouseholdExposurePolicy::allows_with(pmirr, InterfaceClass::Lan, lan),
            "an interrupted install must not expose LAN HTTP at lan_pairing={lan:?}"
        );
    }
}
