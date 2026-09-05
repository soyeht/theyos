//! Household-endpoint listener.
//!
//! Binds a fresh axum router to concrete loopback / LAN / Tailnet / verified
//! Mesh addresses, then narrows the live set by [`HouseholdExposurePolicy`].
//!
//! # The two situations the home is visible on the local network
//!
//! The owner's rule, in his words: "ela aparece no wifi na instalação, ou
//! quando a pessoa colocar add iphone". There is no environment switch and no
//! operator setting. LAN HTTP is admitted in exactly two situations and
//! withdrawn otherwise:
//!
//! 1. INSTALL -- the household has not been set up yet (`uninitialized`,
//!    `ready_for_naming`): loopback + LAN + Tailnet, so first-launch setup
//!    works on the Wi-Fi with no tailnet at all. This is the arm that already
//!    shipped and it is unchanged.
//! 2. ADD IPHONE -- an "Add iPhone" window is open ([`PairingWindow::Open`]):
//!    `named_awaiting_pair` / `ready` / `recovering` admit LAN on top of
//!    loopback + Tailnet + verified Mesh, for as long as that window lasts.
//!    Before this existed a `ready` household never bound a LAN address, so a
//!    phone with no Tailscale had nothing to dial and could not be added at
//!    all.
//!
//! Situation 2 is the OR of two facts, because the ceremony has two shapes and
//! only one of them mints a token:
//!
//! - a `PairDeviceWindow` is open -- the engine minted the offer, so an open
//!   token IS the statement that somebody is adding a phone; and
//! - the Mac declared an "Add iPhone" sheet open
//!   ([`crate::local_network_visibility`]) -- the Mac minted the offer itself
//!   (`MacPairingAdvertisement`), so the engine holds no token to read and has
//!   to be TOLD. That route takes no token, mints nothing, and is loopback-only.
//!
//! Either fact opens the same [`PairingWindow::Open`] position, and both have
//! to be shut for LAN to be withdrawn. Keeping them as one position rather than
//! two policy arms is deliberate: "is the home visible right now" must have one
//! answer, not one per mechanism.
//!
//! Outside those two, post-onboarding exposure is loopback + Tailnet +
//! verified Mesh and nothing else -- byte for byte what a closed window and a
//! `ready` engine exposed before. An interrupted install
//! (`pair_machine_install_restart_required`) gets loopback + Tailnet in BOTH
//! window positions and is reachable by neither situation.
//!
//! The token half is [`household_rs::pair_device::PairDeviceWindow`], the same
//! object the Bonjour TXT records already follow. It carries a TTL, and it
//! closes when the phone consumes it, when the owner closes it, or when that
//! TTL runs out.
//!
//! Who opens the token half, read on 2026-09-05 rather than assumed:
//! - `handlers_bootstrap::get_bootstrap_pair_device_uri` (`GET
//!   /bootstrap/pair-device-uri`) -- `get_or_mint`, so it opens a window or
//!   renews the one already open. This is the FIRST-OWNER route.
//! - `handlers_bootstrap::post_pair_device_reissue` and `post_initialize`, and
//!   `install_cli::mint_pair_device_uri` on the install path.
//! - NOT the by-code sibling (`POST /bootstrap/pair-device-uri/by-code`) and
//!   NOT `handlers_pair_device::initiate`: both are retrieve-only by design,
//!   so that a guesser cannot force a fresh nonce per attempt.
//!
//! MEASURED against the Dev engine on 2026-09-05, and the reason the second
//! fact had to exist: every one of those minting routes gates on
//! `BootstrapState::NamedAwaitingPair` (Gate 2 of the URI route, Gate 2 of
//! reissue) or on the install states. On a household that is already set up,
//! the Mac's "Add iPhone" sheet asked `GET /bootstrap/pair-device-uri` and got
//! `404` with `device_count=1` -- the first-owner answer. So NOTHING opened an
//! engine-side window, the policy saw `Closed`, and the LAN never bound: a
//! phone with no Tailscale had no address to dial. That gap is what
//! [`crate::local_network_visibility`] closes, and it closes it WITHOUT
//! minting: `POST /bootstrap/pair-device/reissue` would have minted a second
//! token and made the six words on the Mac's screen disagree with the ones the
//! phone expects.
//!
//! [`HouseholdExposurePolicy`] never reads either object, a clock or a store:
//! the window position arrives as an argument ([`PairingWindow`]). That purity
//! is why every cell of the exposure table is pinned by test in BOTH positions
//! rather than in whichever one the process happened to be in.
//!
//! ## How the listener learns the window opened or closed
//!
//! [`refresh_loop`] owns the reconciliation. It holds BOTH facts' broadcast
//! subscriptions AND re-reads both on its 500 ms tick, so neither direction
//! depends on a single mechanism:
//!
//! - OPEN: `mint_token` / `get_or_mint` send `PairDeviceWindowState::Open`,
//!   and `POST /bootstrap/local-network-visibility/open` sends
//!   `LocalNetworkVisibilityState::Open`; either subscription arm wakes and
//!   [`sync_interface_targets`] binds the LAN addresses immediately -- no
//!   timer is waited on, the delay is the bind itself. If that send never
//!   arrives -- a lagged subscriber drops messages, and a process that came up
//!   while a window was already open was never sent one -- the 500 ms tick
//!   observes the same open position and binds, because the widening asks
//!   whether the LAN is bound rather than whether the position just changed.
//!   Worst case: 500 ms.
//! - CLOSED: consume and close send `PairDeviceWindowState::Closed`, and
//!   `POST /bootstrap/local-network-visibility/close` sends
//!   `LocalNetworkVisibilityState::Closed`; the subscription arm withdraws the
//!   LAN listener at once. The explicit close is why the visibility route has
//!   one at all: the sheet closing is a real event, and waiting out a TTL
//!   would leave the LAN bound for minutes after the person is done.
//! - EXPIRED: the pair-device window's own TTL task
//!   (`PairDeviceWindow::spawn_ttl_cleanup`) sends `Closed` when the token
//!   expires. [`crate::local_network_visibility::LocalNetworkVisibility`]
//!   deliberately runs NO such task, so its expiry emits no event. Neither
//!   needs one: [`PairingWindow::observe`] reports `Closed` for an expired
//!   token (`PairToken::is_expired` is checked on every read) and for an
//!   expired visibility grant (its deadline is compared on every read), and
//!   narrowing runs on every pass rather than on an edge. The stated bound for
//!   expiry in either fact is one 500 ms tick, no restart.
//!
//! The 60 s interface refresh is not part of either bound; it exists to pick
//! up a Tailscale or Wi-Fi address that appeared later, and it re-reads the
//! window too so it can never re-open what the policy has withdrawn.
//!
//! ## What an unpaired LAN peer actually gets while the window is open
//!
//! Read handler by handler on 2026-09-04, over every router merged onto the
//! household port in `household_bootstrap::bootstrap_household`, and re-read
//! on 2026-09-05 for the routes this section had wrong. An earlier version of
//! this comment claimed such a peer "gets 401/403, not a session". The second
//! half is true; the first half was wrong. Four surfaces answer 200 with no
//! credential at all:
//!
//! - `GET /api/v1/household/identity` (`handlers_household::get_identity`) has
//!   no auth extractor and no peer ACL. On a Ready engine it returns 200 with
//!   `hh_id`, `hh_pub_b64` -- the household's public key -- the household
//!   NAME, and `created_at`. An open window publishes that to anyone on the
//!   Wi-Fi. It is public-key material and a label, not authority: nothing in
//!   the pairing ceremony treats knowledge of them as proof of anything. But
//!   it is a real disclosure, and it now lasts as long as the window rather
//!   than as long as the process.
//! - `GET /bootstrap/status` is documented "No auth required" and returns 200
//!   with `hh_id`, the engine version, the platform, uptime, `device_count`,
//!   the guest-image phase, and `host_label` -- the human-readable Mac name.
//! - `GET /health` and `GET /healthz` return 200 with the engine version and
//!   platform.
//! - `POST /api/v1/household/device-pairing/request`
//!   (`handlers_device_pairing::device_pairing_request_handler`) takes no `PoP`
//!   and no peer ACL: a LAN peer can enqueue a pending pairing request, which
//!   appends a `DevicePairRequest` owner event and so raises the approval
//!   prompt on the owner's devices. The store caps it (429
//!   `device_pairing_request_limit`) and the token it returns is inert until
//!   the owner approves, so this is a prompt an unpaired peer can raise, not
//!   access it can take. That prompt IS the ceremony the window exists for.
//!
//! Three more answer without a peer ACL but demand a secret:
//! - `POST /api/v1/household/pair-device/confirm` needs the nonce from the
//!   pairing URI plus a signature over it.
//! - `POST /api/v1/claw-share/claim` is deliberately anonymous but verifies an
//!   owner-signed invite (`engine_handle_claim`; failures are 401
//!   `signature_rejected`).
//! - `GET /api/v1/household/device-pairing/{request_id}`
//!   (`handlers_device_pairing::device_pairing_poll_handler`) -- MISSED by the
//!   earlier audit, which listed only the `request` half of this pair. It has
//!   no auth extractor and no peer ACL; the only gate is the `?token=` query,
//!   compared in constant time against the token
//!   `POST .../device-pairing/request` minted for that `request_id`, with a
//!   wrong or unknown token collapsing to the same 404
//!   `device_pairing_request_not_found`. Holding that token is the whole
//!   gate, and it is weaker than "the requester was handed it": the request
//!   half dedupes pending records by `d_pub`
//!   (`handlers_device_pairing.rs`, `insert_pending`), so anyone who can
//!   present a pending device's public key is handed that record's existing
//!   `request_id` and token back. Once the owner approves, this anonymous GET is
//!   what returns `hh_id`, `p_id` and the issued `person_cert_cbor` /
//!   `device_cert_cbor`. It is the delivery half of the ceremony, and it is
//!   reachable over LAN whenever the request half is.
//!
//! Everything else on the port stays shut to a LAN peer, and none of it moves
//! with the window:
//! - the routes that hand out the first-owner pairing URI keep their OWN
//!   loopback-or-Tailnet peer ACL and answer a bare 404 to a LAN peer:
//!   `handlers_pair_device::initiate`,
//!   `handlers_bootstrap::get_bootstrap_pair_device_uri` and its by-code
//!   sibling. Those gates were written because bind-time exposure was never an
//!   admission check.
//! - `post_reachability_echo` answers 403 outside loopback-or-Tailnet;
//!   `POST /bootstrap/pair-machine/local/stage` and `/bootstrap/pair-device/
//!   reissue` are loopback-only; `/pair-machine/anchor-handoff` is
//!   Tailnet-only; the `claw-share/relay-offer/*` trio is loopback-only
//!   (`relay_offer_peer_allowed`).
//! - `POST /bootstrap/local-network-visibility/open` and `.../close`
//!   (`crate::local_network_visibility`) -- the route that opens situation 2
//!   for a Mac that minted its own offer. Listed here because this audit is a
//!   complete map of the port and not a list of the scary entries, and this
//!   one is on the port whenever the household router is: it is
//!   LOOPBACK-ONLY, so it is NOT LAN-reachable at all, and a LAN peer gets the
//!   bare 404 a missing route gives (same hiding contract as `stage` and
//!   `reissue`). It carries no token, reads no identity, has no bootstrap-state
//!   gate, and its whole effect is to set or clear one deadline that this
//!   module's policy then interprets. The consequence to read off it is the
//!   FIRST half of this audit: for the life of that deadline, a
//!   post-onboarding household hands a LAN peer everything listed above as
//!   reachable while the window is open.
//! - `POST /bootstrap/claim-setup-invitation` answers 409 unless the engine is
//!   `Uninitialized`; `/bootstrap/accept-household` and `/bootstrap/initialize`
//!   answer 409 outside `Uninitialized`/`ReadyForNaming`. The
//!   `/pair-machine/local/{seed,anchor,finalize}` trio answers 401 unless the
//!   pair-machine window is open AND the caller presents the QR-only nonce or
//!   `anchor_secret`; `anchor` and `finalize` additionally re-check
//!   `bootstrap_allows_local_pair_machine`. So a Ready engine hands a LAN peer
//!   nothing here.
//! - the effectful household routes all demand a proof-of-possession signature
//!   under a device cert the owner issued and answer 401 without one, but they
//!   do NOT all reach it through the same function. An earlier version of this
//!   comment said `household_auth::authorize_request` for the whole list; three
//!   of those families never call it, and naming a gate a handler does not run
//!   is how a comment stops being evidence. Read on 2026-09-05:
//!   - `snapshot`, `machines`, `guest-image` and the `owner-events`
//!     long-poll/approve/decline routes do run
//!     `household_auth::authorize_request`.
//!   - claws, instances, terminals and workspaces run
//!     `household_auth::authorize_request_with_actor` through the shared
//!     `handlers_household_claws::authorize` wrapper, which folds every failure
//!     into a bare 401.
//!   - the roster routes (`currency`, `evidence`) run
//!     `household_auth::authorize_roster_read`, which admits the owner OR a
//!     delegated household device and answers 401 `unauthenticated` otherwise.
//!   - the `owner-webauthn` enrollment routes run
//!     `household_auth::authorize_owner_auth_enroll_initial_request` and reject
//!     through `reject_owner_webauthn_registration` -> 401.
//! - `POST /bootstrap/teardown` has no peer ACL but needs a P-256 signature
//!   validated against this engine's own live `hh_id`/`m_id`.
//! - [`HouseholdExposurePolicy::allows_terminal_attach_peer`] answers `false`
//!   for LAN in every state and in both window positions, so remote terminal
//!   attach -- the one directly effectful surface -- gains nothing from an open
//!   window.
//!
//! Net, stated plainly: an open "Add iPhone" window -- by either fact -- does
//! not hand a LAN peer a session. It does publish the household id, household
//! public key, household name and Mac label to the local network for the life
//! of the window, lets an unpaired peer raise a pairing prompt, and -- once the
//! owner approves that prompt -- lets the holder of the returned token collect
//! its certificates.
//!
//! MEASURED 2026-09-04 in `engine.log`: a Ready engine logged exactly four
//! `bootstrap.endpoint.live` binds -- Tailnet v4/v6 plus loopback v4/v6 -- on
//! port 8091, and no `192.168.x`. A phone with no Tailscale had no address to
//! dial, so `Connect` failed with zero requests arriving. That is the failure
//! situation 2 clears, and it clears it only while the owner has the window
//! open.
//!
//! Refuses wildcard `0.0.0.0` / `::` per FR-008. Refreshes the active address
//! set every 60 s and reconciles state and window changes every 500 ms.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, http::StatusCode};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::{PairDeviceWindow, PairDeviceWindowState};
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{info, warn};

use crate::local_network_visibility::{LocalNetworkVisibility, LocalNetworkVisibilityState};

const INTERFACE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const POLICY_SYNC_INTERVAL: Duration = Duration::from_millis(500);
const MESH_SUBNET_ENV: &str = "THEYOS_MESH_SUBNET";
const PRODUCT_A_MESH_NETWORK: Ipv4Addr = Ipv4Addr::new(10, 44, 0, 0);
const PRODUCT_A_MESH_PREFIX_LEN: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceClass {
    Loopback,
    Lan,
    Tailscale,
    Mesh,
}

impl InterfaceClass {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Lan => "lan",
            Self::Tailscale => "tailscale",
            Self::Mesh => "mesh",
        }
    }

    /// Bonjour is intentionally limited to local-network discovery and
    /// Tailnet. A configured mesh address is reachable directly but must not
    /// leak its /32 through a LAN multicast announcement.
    #[must_use]
    pub fn is_bonjour_advertisable(self) -> bool {
        matches!(self, Self::Lan | Self::Tailscale)
    }
}

/// Situation 2 of the two-situation rule, as a value.
///
/// The `Open` position is not an operator setting and not an environment
/// variable. It is the OR of two observed facts:
///
/// - the household's [`PairDeviceWindow`] is open -- the same window the
///   pairing URI, the pair code and the Bonjour TXT records already run on.
///   The engine minted the offer, consuming or closing it ends it, and its TTL
///   ends it unattended; and
/// - the Mac declared an "Add iPhone" sheet open
///   ([`LocalNetworkVisibility`]). Used when the Mac minted the offer itself,
///   so the engine holds no token to read. It ends on an explicit close or on
///   its own deadline.
///
/// It is a plain `Copy` enum on purpose. [`HouseholdExposurePolicy`] must be
/// answerable from a test with no clock, no filesystem and no tokio runtime,
/// so the only thing that ever reads the live facts is
/// [`PairingWindow::observe`], at the reconciliation sites that own the
/// listener. Everything downstream of that takes the answer as an argument.
///
/// `Closed` is the `Default`, so a caller that has no window to consult --
/// and a future call site that forgets to thread one through -- gets the
/// narrow post-onboarding set, not the wide one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PairingWindow {
    /// No pair-device window. Post-onboarding LAN HTTP stays withdrawn.
    #[default]
    Closed,
    /// A pair-device window is open: LAN joins the post-onboarding class set
    /// for as long as it lasts.
    Open,
}

impl PairingWindow {
    /// Read both live facts.
    ///
    /// One function taking both rather than one per fact, and no single-fact
    /// sibling: a call site that consults only the token half would answer
    /// `Closed` on a Ready household whose owner is standing there with the
    /// sheet open -- which is precisely the bug this branch exists to fix. The
    /// signature is what stops that from being reintroduced quietly.
    ///
    /// Expiry-aware in both halves without a timer of its own.
    /// `PairDeviceWindow::is_open` answers `false` for a token whose TTL has
    /// passed (`PairToken::is_expired` is checked on every read), and
    /// `LocalNetworkVisibility::is_open` compares its deadline on every read.
    /// So a reconciler that calls this on a tick withdraws an expired window's
    /// LAN listener even in a process where no TTL task ever ran -- for
    /// instance one that adopted a persisted snapshot at startup instead of
    /// minting.
    pub async fn observe(window: &PairDeviceWindow, visibility: &LocalNetworkVisibility) -> Self {
        // Short-circuit is fine and deliberate: both are cheap lock reads, and
        // either fact alone is enough to be in situation 2.
        if window.is_open().await || visibility.is_open().await {
            Self::Open
        } else {
            Self::Closed
        }
    }

    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Log field value, so the engine log states the posture it acted on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
        }
    }
}

/// Pure transport exposure policy for household listener and Bonjour surfaces.
///
/// This is intentionally independent from interface names and socket binding:
/// callers provide already-classified targets, and the policy only decides which
/// classes are allowed for the current bootstrap state.
pub struct HouseholdExposurePolicy;

impl HouseholdExposurePolicy {
    /// The decision, with the pairing-window position passed in rather than
    /// read. There is deliberately no window-free sibling: a caller that
    /// cannot say which situation it is in has to write
    /// [`PairingWindow::Closed`] and mean it.
    #[must_use]
    pub fn allows_with(
        state: BootstrapState,
        class: InterfaceClass,
        pairing_window: PairingWindow,
    ) -> bool {
        match state {
            BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => matches!(
                class,
                InterfaceClass::Loopback | InterfaceClass::Lan | InterfaceClass::Tailscale
            ),
            // An interrupted install gets its OWN arm, and deliberately the
            // narrowest one. `allows` is a function of the state alone -- it
            // cannot see which state we arrived from -- so this set has to be
            // safe from *every* legal predecessor. The transition table admits
            // `Uninitialized | ReadyForNaming | NamedAwaitingPair` into this
            // state, whose sets are {Loopback, Lan, Tailscale} and
            // {Loopback, Tailscale, Mesh}. Their intersection is
            // {Loopback, Tailscale}, and that is what this arm may grant.
            //
            // Sharing `Ready`'s arm was measurably wrong, not merely untidy: a
            // household that never completed onboarding gained `Mesh` on
            // entering this state, applied by the 60 s `sync_interface_targets`
            // refresh without the router ever restarting. The or-pattern let a
            // new variant inherit `Ready`'s exposure with nobody deciding it.
            //
            // Rule, so the next variant does not repeat this: entering
            // `PairMachineInstallRestartRequired` must never widen the exposed
            // class set relative to any legal predecessor.
            //
            // `pairing_window` deliberately does not reach this arm. With the
            // window open the predecessor sets become {Loopback, Lan,
            // Tailscale} and {Loopback, Lan, Tailscale, Mesh}, whose
            // intersection grows to include Lan -- so this arm stays a strict
            // subset either way and the rule above holds in both positions.
            // An interrupted install is a recovery step, not a household
            // somebody is currently adding a phone to.
            BootstrapState::PairMachineInstallRestartRequired => {
                matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
            }
            BootstrapState::NamedAwaitingPair
            | BootstrapState::Ready
            | BootstrapState::Recovering => match class {
                InterfaceClass::Loopback | InterfaceClass::Tailscale | InterfaceClass::Mesh => true,
                // The ONLY class the pairing window can move, and only here.
                // `Closed` reproduces the shipped set exactly; `Open` is
                // situation 2 -- what gives a phone with no Tailnet address
                // something to dial while somebody is adding it.
                InterfaceClass::Lan => pairing_window.is_open(),
            },
        }
    }

    /// Direct remote terminal attachment is an effectful household operation,
    /// so a Mesh peer is stricter than a listener bind: it is admitted only
    /// after the household is fully `Ready`. Loopback and Tailnet retain the
    /// existing exposure policy for their class.
    ///
    /// LAN answers `false` in every state and is NOT wired to
    /// [`PairingWindow`]: binding the port so a phone can be added is a
    /// different decision from letting a LAN peer drive somebody's terminal,
    /// and only the first one was asked for.
    ///
    /// The `PairingWindow::Closed` below is therefore not an assumption about
    /// the household. The three arms that consult it are Mesh, Loopback and
    /// Tailscale, and the window moves `Lan` and nothing else, so the argument
    /// is provably unobservable here -- pinned by
    /// `terminal_attach_is_denied_on_lan_in_every_state_and_window_position`.
    #[must_use]
    pub fn allows_terminal_attach_peer(state: BootstrapState, class: InterfaceClass) -> bool {
        let bound = |class| Self::allows_with(state, class, PairingWindow::Closed);
        match class {
            InterfaceClass::Mesh => state == BootstrapState::Ready && bound(class),
            InterfaceClass::Loopback | InterfaceClass::Tailscale => bound(class),
            InterfaceClass::Lan => false,
        }
    }

    /// The bind set for a state, with the pairing-window position supplied so
    /// a test can assert both in one process.
    #[must_use]
    pub fn allowed_targets_with(
        state: BootstrapState,
        targets: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
        pairing_window: PairingWindow,
    ) -> Vec<(IpAddr, InterfaceClass)> {
        targets
            .into_iter()
            .filter(|(_, class)| Self::allows_with(state, *class, pairing_window))
            .collect()
    }

    /// Targets that may be advertised through Bonjour after the listener
    /// policy has allowed them. Mesh addresses remain direct-connect only.
    #[must_use]
    pub fn bonjour_targets_with(
        state: BootstrapState,
        targets: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
        pairing_window: PairingWindow,
    ) -> Vec<(IpAddr, InterfaceClass)> {
        Self::allowed_targets_with(state, targets, pairing_window)
            .into_iter()
            .filter(|(_, class)| class.is_bonjour_advertisable())
            .collect()
    }
}

/// The one Product A IPv4 allocation this listener may ever expose as Mesh.
///
/// The raw environment variable is deliberately not an authority for an
/// arbitrary CIDR. It is only an input that must parse to this exact,
/// canonical allocation before it can participate in a typed exposure
/// decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrustedMeshSubnet {
    network: Ipv4Addr,
    prefix_len: u8,
}

const PRODUCT_A_MESH_SUBNET: TrustedMeshSubnet = TrustedMeshSubnet {
    network: PRODUCT_A_MESH_NETWORK,
    prefix_len: PRODUCT_A_MESH_PREFIX_LEN,
};

impl TrustedMeshSubnet {
    #[must_use]
    const fn product_a() -> Self {
        PRODUCT_A_MESH_SUBNET
    }

    #[must_use]
    fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = ipv4_mask(self.prefix_len);
        u32::from(ip) & mask == u32::from(self.network) & mask
    }

    #[must_use]
    fn overlaps_network(self, network: Ipv4Addr, prefix_len: u8) -> bool {
        let mask = ipv4_mask(if self.prefix_len < prefix_len {
            self.prefix_len
        } else {
            prefix_len
        });
        u32::from(self.network) & mask == u32::from(network) & mask
    }
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MeshExposureInput {
    Absent,
    Raw(String),
    NonUnicode,
}

impl MeshExposureInput {
    fn from_env() -> Self {
        match std::env::var_os(MESH_SUBNET_ENV) {
            None => Self::Absent,
            Some(raw) => match raw.into_string() {
                Ok(raw) => Self::Raw(raw),
                Err(_) => Self::NonUnicode,
            },
        }
    }

    #[cfg(test)]
    fn raw(raw: Option<&str>) -> Self {
        raw.map_or(Self::Absent, |raw| Self::Raw(raw.to_owned()))
    }
}

/// Stable, fail-closed reasons that a mesh exposure input or local inventory
/// cannot authorize Mesh classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshExposureError {
    Empty,
    Whitespace,
    Syntax,
    InvalidPrefix,
    UnsupportedAddressFamily,
    NonCanonicalNetwork,
    UniversalRange,
    BroadPrivateRange,
    TailnetRange,
    LoopbackRange,
    LinkLocalRange,
    UntrustedAllocation,
    LocalOverlap,
    InvalidLocalInventory,
    NonUnicode,
}

impl MeshExposureError {
    #[cfg(test)]
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Whitespace => "whitespace",
            Self::Syntax => "syntax",
            Self::InvalidPrefix => "invalid_prefix",
            Self::UnsupportedAddressFamily => "unsupported_address_family",
            Self::NonCanonicalNetwork => "noncanonical_network",
            Self::UniversalRange => "universal_range",
            Self::BroadPrivateRange => "broad_private_range",
            Self::TailnetRange => "tailnet_range",
            Self::LoopbackRange => "loopback_range",
            Self::LinkLocalRange => "link_local_range",
            Self::UntrustedAllocation => "untrusted_allocation",
            Self::LocalOverlap => "local_overlap",
            Self::InvalidLocalInventory => "invalid_local_inventory",
            Self::NonUnicode => "non_unicode",
        }
    }
}

/// Validated configuration authority. This intentionally contains no generic
/// CIDR: only the narrow Product A allocation can be enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshExposureConfig {
    Disabled,
    Enabled(TrustedMeshSubnet),
    Rejected(MeshExposureError),
}

impl MeshExposureConfig {
    #[must_use]
    fn from_input(input: MeshExposureInput) -> Self {
        match input {
            MeshExposureInput::Absent => Self::Disabled,
            MeshExposureInput::NonUnicode => Self::Rejected(MeshExposureError::NonUnicode),
            MeshExposureInput::Raw(raw) => match parse_trusted_mesh_subnet(&raw) {
                Ok(subnet) => Self::Enabled(subnet),
                Err(error) => Self::Rejected(error),
            },
        }
    }

    #[must_use]
    const fn trusted_subnet(self) -> Option<TrustedMeshSubnet> {
        match self {
            Self::Enabled(subnet) => Some(subnet),
            Self::Disabled | Self::Rejected(_) => None,
        }
    }

    #[cfg(test)]
    #[must_use]
    const fn error(self) -> Option<MeshExposureError> {
        match self {
            Self::Rejected(error) => Some(error),
            Self::Disabled | Self::Enabled(_) => None,
        }
    }
}

fn parse_trusted_mesh_subnet(raw: &str) -> Result<TrustedMeshSubnet, MeshExposureError> {
    if raw.is_empty() {
        return Err(MeshExposureError::Empty);
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(MeshExposureError::Whitespace);
    }

    let mut pieces = raw.split('/');
    let Some(network_text) = pieces.next() else {
        return Err(MeshExposureError::Syntax);
    };
    let Some(prefix_text) = pieces.next() else {
        return Err(MeshExposureError::Syntax);
    };
    if pieces.next().is_some() || network_text.is_empty() || prefix_text.is_empty() {
        return Err(MeshExposureError::Syntax);
    }

    let network = network_text
        .parse::<IpAddr>()
        .map_err(|_| MeshExposureError::Syntax)?;
    let IpAddr::V4(network) = network else {
        return Err(MeshExposureError::UnsupportedAddressFamily);
    };
    let prefix_len = prefix_text
        .parse::<u8>()
        .map_err(|_| MeshExposureError::InvalidPrefix)?;
    if prefix_len > 32 || prefix_text != prefix_len.to_string() {
        return Err(MeshExposureError::InvalidPrefix);
    }
    if u32::from(network) & ipv4_mask(prefix_len) != u32::from(network) {
        return Err(MeshExposureError::NonCanonicalNetwork);
    }

    let subnet = TrustedMeshSubnet {
        network,
        prefix_len,
    };
    if subnet == TrustedMeshSubnet::product_a() {
        return Ok(subnet);
    }

    Err(rejected_mesh_subnet_error(subnet))
}

fn rejected_mesh_subnet_error(subnet: TrustedMeshSubnet) -> MeshExposureError {
    if subnet.prefix_len == 0 {
        MeshExposureError::UniversalRange
    } else if subnet.network.octets() == [10, 0, 0, 0] && subnet.prefix_len == 8
        || subnet.network.octets() == [172, 16, 0, 0] && subnet.prefix_len == 12
        || subnet.network.octets() == [192, 168, 0, 0] && subnet.prefix_len == 16
    {
        MeshExposureError::BroadPrivateRange
    } else if subnet.network.octets() == [100, 64, 0, 0] && subnet.prefix_len == 10 {
        MeshExposureError::TailnetRange
    } else if subnet.network.octets() == [127, 0, 0, 0] && subnet.prefix_len == 8 {
        MeshExposureError::LoopbackRange
    } else if subnet.network.octets() == [169, 254, 0, 0] && subnet.prefix_len == 16 {
        MeshExposureError::LinkLocalRange
    } else {
        MeshExposureError::UntrustedAllocation
    }
}

/// Ownership is a fact supplied by the local interface inventory, never an
/// inference from a private address, CIDR membership, or suggestive name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalAddressOwnership {
    Loopback,
    Tailnet,
    Lan,
    VerifiedMesh,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalAddressFact {
    interface_name: String,
    ip: IpAddr,
    prefix_len: u8,
    ownership: LocalAddressOwnership,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LocalInterfaceInventory {
    addresses: Vec<LocalAddressFact>,
}

impl LocalInterfaceInventory {
    /// The system adapter intentionally emits no `VerifiedMesh` facts. Main
    /// has no reviewed runtime provider that can attest a real verified-Mesh TUN, so
    /// this is fail-closed until such a provider is introduced separately.
    #[must_use]
    fn from_system() -> Self {
        let mut addresses = Vec::new();
        if let Ok(interface_addresses) = if_addrs::get_if_addrs() {
            for interface in interface_addresses {
                let interface_name = interface.name;
                let (ip, prefix_len) = match interface.addr {
                    if_addrs::IfAddr::V4(address) => (
                        IpAddr::V4(address.ip),
                        ipv4_prefix_len_from_netmask(address.netmask),
                    ),
                    if_addrs::IfAddr::V6(address) => (
                        IpAddr::V6(address.ip),
                        ipv6_prefix_len_from_netmask(address.netmask),
                    ),
                };
                addresses.push(LocalAddressFact {
                    interface_name,
                    ip,
                    prefix_len,
                    ownership: unverified_local_ownership(ip),
                });
            }
        }
        Self { addresses }
    }
}

fn ipv4_prefix_len_from_netmask(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    let Ok(prefix_len) = u8::try_from(bits.count_ones()) else {
        return 33;
    };
    if bits == ipv4_mask(prefix_len) {
        prefix_len
    } else {
        33
    }
}

fn ipv6_prefix_len_from_netmask(netmask: Ipv6Addr) -> u8 {
    let bits = u128::from(netmask);
    let Ok(prefix_len) = u8::try_from(bits.count_ones()) else {
        return 129;
    };
    let expected = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };
    if bits == expected { prefix_len } else { 129 }
}

fn unverified_local_ownership(ip: IpAddr) -> LocalAddressOwnership {
    if ip.is_loopback() {
        LocalAddressOwnership::Loopback
    } else if crate::tailnet_address::is_tailnet_ip(ip) {
        LocalAddressOwnership::Tailnet
    } else if is_lan(&ip) {
        LocalAddressOwnership::Lan
    } else {
        LocalAddressOwnership::Other
    }
}

/// Resolved once from typed configuration plus an inventory snapshot, then
/// shared by target classification and the Ready-state source gate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MeshExposureDecision {
    config: MeshExposureConfig,
    verified_local_addresses: Vec<IpAddr>,
    quarantined_subnet: Option<TrustedMeshSubnet>,
}

impl MeshExposureDecision {
    #[must_use]
    fn resolve(config: MeshExposureConfig, inventory: &LocalInterfaceInventory) -> Self {
        let Some(subnet) = config.trusted_subnet() else {
            return Self {
                config,
                verified_local_addresses: Vec::new(),
                quarantined_subnet: None,
            };
        };

        if inventory
            .addresses
            .iter()
            .any(|fact| !has_valid_prefix_len(fact))
        {
            return Self {
                config: MeshExposureConfig::Rejected(MeshExposureError::InvalidLocalInventory),
                verified_local_addresses: Vec::new(),
                quarantined_subnet: Some(subnet),
            };
        }
        if inventory.addresses.iter().any(|fact| {
            fact.ownership != LocalAddressOwnership::VerifiedMesh
                && local_fact_overlaps_mesh_subnet(fact, subnet)
        }) {
            return Self {
                config: MeshExposureConfig::Rejected(MeshExposureError::LocalOverlap),
                verified_local_addresses: Vec::new(),
                quarantined_subnet: Some(subnet),
            };
        }

        let mut verified_local_addresses: Vec<IpAddr> = inventory
            .addresses
            .iter()
            .filter(|fact| {
                fact.ownership == LocalAddressOwnership::VerifiedMesh
                    && matches!(fact.ip, IpAddr::V4(ip) if subnet.contains(ip))
            })
            .map(|fact| fact.ip)
            .collect();
        verified_local_addresses.sort_unstable();
        verified_local_addresses.dedup();

        Self {
            config,
            verified_local_addresses,
            quarantined_subnet: Some(subnet),
        }
    }

    #[must_use]
    fn is_active(&self) -> bool {
        self.config.trusted_subnet().is_some() && !self.verified_local_addresses.is_empty()
    }

    #[must_use]
    fn is_verified_local_mesh_address(&self, fact: &LocalAddressFact) -> bool {
        self.is_active()
            && fact.ownership == LocalAddressOwnership::VerifiedMesh
            && self.verified_local_addresses.contains(&fact.ip)
    }

    #[must_use]
    fn quarantines_unverified_local_mesh_candidate(&self, fact: &LocalAddressFact) -> bool {
        fact.ownership != LocalAddressOwnership::VerifiedMesh
            && self
                .quarantined_subnet
                .is_some_and(|subnet| matches!(fact.ip, IpAddr::V4(ip) if subnet.contains(ip)))
    }

    #[must_use]
    fn allows_remote_mesh_peer(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(ip) = ip else {
            return false;
        };
        self.is_active()
            && self
                .config
                .trusted_subnet()
                .is_some_and(|subnet| subnet.contains(ip))
    }
}

fn has_valid_prefix_len(fact: &LocalAddressFact) -> bool {
    match fact.ip {
        IpAddr::V4(_) => fact.prefix_len <= 32,
        IpAddr::V6(_) => fact.prefix_len <= 128,
    }
}

fn local_fact_overlaps_mesh_subnet(fact: &LocalAddressFact, subnet: TrustedMeshSubnet) -> bool {
    match fact.ip {
        IpAddr::V4(ip) => subnet.overlaps_network(ip, fact.prefix_len),
        IpAddr::V6(_) => false,
    }
}

#[derive(Clone, Debug)]
struct HouseholdListenerContext {
    inventory: LocalInterfaceInventory,
    mesh: MeshExposureDecision,
}

impl HouseholdListenerContext {
    #[must_use]
    fn from_input(input: MeshExposureInput, inventory: LocalInterfaceInventory) -> Self {
        let config = MeshExposureConfig::from_input(input);
        let mesh = MeshExposureDecision::resolve(config, &inventory);
        Self { inventory, mesh }
    }

    #[must_use]
    fn from_system() -> Self {
        Self::from_input(
            MeshExposureInput::from_env(),
            LocalInterfaceInventory::from_system(),
        )
    }
}

/// Enumerate the active concrete interface addresses we want to bind.
#[must_use]
pub fn enumerate_bind_targets() -> Vec<(IpAddr, InterfaceClass)> {
    let context = HouseholdListenerContext::from_system();
    enumerate_bind_targets_with_context(&context)
}

fn enumerate_bind_targets_with_context(
    context: &HouseholdListenerContext,
) -> Vec<(IpAddr, InterfaceClass)> {
    let mut targets = BTreeMap::from([
        (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), InterfaceClass::Loopback),
    ]);

    for fact in &context.inventory.addresses {
        if fact.ip.is_loopback() || is_link_local(&fact.ip) {
            continue;
        }
        if let Some(class) = classify_local_address(fact, &context.mesh) {
            targets.entry(fact.ip).or_insert(class);
        }
    }

    targets.into_iter().collect()
}

fn classify_local_address(
    fact: &LocalAddressFact,
    mesh: &MeshExposureDecision,
) -> Option<InterfaceClass> {
    // A typed Mesh ownership fact must never fall through to LAN when mesh
    // exposure is disabled or rejected. That would make an unactivated Mesh
    // interface visible during onboarding (and therefore Bonjour-advertisable)
    // merely because its address happens to be private.
    if fact.ownership == LocalAddressOwnership::VerifiedMesh {
        return mesh
            .is_verified_local_mesh_address(fact)
            .then_some(InterfaceClass::Mesh);
    }
    // With a valid configured Product A allocation, an address inside that
    // allocation is not allowed to fall back to LAN until the reviewed
    // provider attests it as `VerifiedMesh`. This keeps a real-but-unverified
    // tunnel address out of onboarding binds and Bonjour as well as Ready.
    if mesh.quarantines_unverified_local_mesh_candidate(fact) {
        return None;
    }
    if crate::tailnet_address::is_tailnet_ip(fact.ip) {
        return Some(InterfaceClass::Tailscale);
    }
    is_lan(&fact.ip).then_some(InterfaceClass::Lan)
}

/// Refuse-wildcard guard: assert the bound socket's local addr is not a
/// wildcard. Returns the resolved listener.
async fn bind_concrete(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    if local.ip().is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to listen on wildcard 0.0.0.0/::",
        ));
    }
    Ok(listener)
}

/// Shared bookkeeping for the spawn / refresh loop. The set of currently
/// bound addresses is exposed via a clone-able handle so the Bonjour
/// publisher can advertise exactly the addresses a peer can actually
/// reach.
struct BoundTarget {
    class: InterfaceClass,
    shutdown: oneshot::Sender<()>,
}

#[derive(Clone, Default)]
pub struct BoundSet {
    inner: Arc<Mutex<HashMap<IpAddr, BoundTarget>>>,
}

impl BoundSet {
    /// Snapshot of currently bound addresses paired with the interface
    /// class enumerator's classification at the moment of binding.
    pub async fn snapshot(&self) -> Vec<IpAddr> {
        self.inner.lock().await.keys().copied().collect()
    }

    /// Snapshot of currently bound addresses with their interface classes.
    pub async fn snapshot_targets(&self) -> Vec<(IpAddr, InterfaceClass)> {
        self.inner
            .lock()
            .await
            .iter()
            .map(|(ip, target)| (*ip, target.class))
            .collect()
    }

    async fn insert(&self, ip: IpAddr, class: InterfaceClass, shutdown: oneshot::Sender<()>) {
        self.inner
            .lock()
            .await
            .insert(ip, BoundTarget { class, shutdown });
    }

    async fn remove(&self, ip: IpAddr) -> Option<BoundTarget> {
        self.inner.lock().await.remove(&ip)
    }
}

fn spawn_listener_task(
    router: Router,
    listener: TcpListener,
    addr: SocketAddr,
    shutdown_rx: oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        if let Err(e) = core_rs::phase0_axum_serve!(listener, router, connect_info = SocketAddr)
            .with_graceful_shutdown(shutdown)
            .await
        {
            warn!(
                stage = "household_listener.serve_failed",
                address = %addr,
                error = %e,
            );
        }
    });
}

async fn bind_allowed_target(
    router: &Router,
    port: u16,
    bound: &BoundSet,
    ip: IpAddr,
    class: InterfaceClass,
    source: &'static str,
) -> Option<(IpAddr, InterfaceClass)> {
    let addr = SocketAddr::new(ip, port);
    match bind_concrete(addr).await {
        Ok(listener) => {
            info!(
                stage = "bootstrap.endpoint.live",
                address = %addr,
                interface_class = class.as_str(),
                result = "ok",
                source,
            );
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            bound.insert(ip, class, shutdown_tx).await;
            spawn_listener_task(router.clone(), listener, addr, shutdown_rx);
            Some((ip, class))
        }
        Err(e) => {
            warn!(
                stage = "bootstrap.endpoint.bind_failed",
                address = %addr,
                interface_class = class.as_str(),
                error = %e,
                source,
            );
            None
        }
    }
}

async fn shutdown_bound_target(bound: &BoundSet, ip: IpAddr, reason: &'static str) {
    if let Some(target) = bound.remove(ip).await {
        let class = target.class;
        let _ = target.shutdown.send(());
        info!(
            stage = "household_listener.address_removed",
            address = %ip,
            interface_class = class.as_str(),
            reason,
        );
    }
}

async fn bootstrap_state(bootstrap: &Arc<RwLock<BootstrapState>>) -> BootstrapState {
    *bootstrap.read().await
}

/// A concrete bind recorded immediately before the OS bind call. Tests use
/// this seam instead of relying on host interfaces or bind failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BindAttempt {
    address: SocketAddr,
    class: InterfaceClass,
}

trait BindAttemptObserver: Send {
    fn before_bind(&mut self, attempt: BindAttempt);
}

struct NoopBindAttemptObserver;

impl BindAttemptObserver for NoopBindAttemptObserver {
    fn before_bind(&mut self, _attempt: BindAttempt) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerReconciliationAction {
    Shutdown { ip: IpAddr, class: InterfaceClass },
    Bind(BindAttempt),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ListenerReconciliationPlan {
    actions: Vec<ListenerReconciliationAction>,
}

/// Plan all stale removals before any new bind. This ordering is important
/// when configuration is tampered with or a local LAN route begins to overlap
/// the Product A allocation: the old Mesh listener must be withdrawn before a
/// later reconcile can consider any replacement target.
#[must_use]
fn plan_listener_reconciliation(
    current: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
    desired: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
    port: u16,
) -> ListenerReconciliationPlan {
    let current: BTreeMap<IpAddr, InterfaceClass> = current.into_iter().collect();
    let desired: BTreeMap<IpAddr, InterfaceClass> = desired.into_iter().collect();
    let mut actions = Vec::new();

    for (ip, class) in &current {
        if desired.get(ip) != Some(class) {
            actions.push(ListenerReconciliationAction::Shutdown {
                ip: *ip,
                class: *class,
            });
        }
    }
    for (ip, class) in &desired {
        if current.get(ip) != Some(class) {
            actions.push(ListenerReconciliationAction::Bind(BindAttempt {
                address: SocketAddr::new(*ip, port),
                class: *class,
            }));
        }
    }

    ListenerReconciliationPlan { actions }
}

async fn apply_listener_reconciliation_plan(
    router: &Router,
    bound: &BoundSet,
    plan: &ListenerReconciliationPlan,
    source: &'static str,
    observer: &mut dyn BindAttemptObserver,
) {
    for action in &plan.actions {
        match action {
            ListenerReconciliationAction::Shutdown { ip, .. } => {
                shutdown_bound_target(bound, *ip, "interface_or_policy_removed").await;
            }
            ListenerReconciliationAction::Bind(attempt) => {
                observer.before_bind(*attempt);
                let _ = bind_allowed_target(
                    router,
                    attempt.address.port(),
                    bound,
                    attempt.address.ip(),
                    attempt.class,
                    source,
                )
                .await;
            }
        }
    }
}

async fn sync_interface_targets(
    router: &Router,
    port: u16,
    bootstrap: &Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
    source: &'static str,
    pairing_window: PairingWindow,
) -> Vec<(IpAddr, InterfaceClass)> {
    let state = bootstrap_state(bootstrap).await;
    let context = HouseholdListenerContext::from_system();
    let live = HouseholdExposurePolicy::allowed_targets_with(
        state,
        enumerate_bind_targets_with_context(&context),
        pairing_window,
    );
    let plan = plan_listener_reconciliation(bound.snapshot_targets().await, live, port);
    let mut observer = NoopBindAttemptObserver;
    apply_listener_reconciliation_plan(router, bound, &plan, source, &mut observer).await;

    bound.snapshot_targets().await
}

/// The narrowing half of reconciliation: shut down every bound target the
/// current state and window position no longer allow.
///
/// This is the reconciler that WITHDRAWS a listener, so its behaviour is
/// pinned in both window positions. It never binds, which is why an expired
/// window can be handled here alone while an opened one needs
/// [`sync_interface_targets`].
async fn sync_exposure_policy_with(
    bootstrap: &Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
    pairing_window: PairingWindow,
) {
    let state = bootstrap_state(bootstrap).await;
    let disallowed: Vec<IpAddr> = bound
        .snapshot_targets()
        .await
        .into_iter()
        .filter_map(|(ip, class)| {
            (!HouseholdExposurePolicy::allows_with(state, class, pairing_window)).then_some(ip)
        })
        .collect();
    for ip in disallowed {
        shutdown_bound_target(bound, ip, "bootstrap_state_policy").await;
    }
}

/// Spawn one `axum::serve` per bind target. Returns the set of addresses
/// that actually bound, so the Bonjour publisher can advertise only what's
/// reachable. Servers run in background tasks owned by tokio.
/// Proof that the caller is process startup, not a request handler.
///
/// A pair-machine reexec must never reopen the household router, "not even
/// transitively". That was previously argued by reading the reexec path and
/// seeing no router call, and then by a test that swept source text for call
/// sites. Both are weaker than they look: the first says nothing about a path
/// added later, and the second was defeated in review by a second caller in an
/// already-listed file, by a one-line `#[cfg(test)]` item, and by an import
/// alias. A brace-counting text classifier is not a control.
///
/// So the restriction is a type instead. This struct has a private field, no
/// `Clone`, no `Copy`, no `Default`, and no public constructor, so it cannot be
/// built outside this module. [`ProcessStartupToken::claim`] is the only way to
/// obtain one and succeeds exactly once per process. A handler cannot fabricate
/// it and cannot claim it after `main` has, so a handler-reachable call to
/// [`spawn_household_listeners`] does not compile — no sweep required.
///
/// Scope, so nobody reads more into this than it proves: this governs *starting*
/// listeners. It does not claim bootstrap state has no effect on exposure. It
/// does, by design — [`refresh_loop`] polls the bootstrap state on a timer and
/// re-filters bind targets through [`HouseholdExposurePolicy`], so a reexec that
/// commits `Ready` changes what an already-running listener exposes within one
/// poll interval. That belongs to the exposure-policy arms, which are pinned by
/// their own decision guard.
pub struct ProcessStartupToken(());

static STARTUP_TOKEN_CLAIMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl ProcessStartupToken {
    /// Claim the process-wide startup token.
    ///
    /// Returns `None` if it has already been claimed, so a second claim from
    /// anywhere — including a handler that reached this function at runtime —
    /// cannot manufacture startup authority.
    pub fn claim() -> Option<Self> {
        STARTUP_TOKEN_CLAIMED
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .ok()
            .map(|_| Self(()))
    }
}

pub async fn spawn_household_listeners(
    _startup: &ProcessStartupToken,
    router: Router,
    port: u16,
    bootstrap: Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
    pairing_window: PairingWindow,
) -> Vec<(IpAddr, InterfaceClass)> {
    sync_interface_targets(&router, port, &bootstrap, bound, "startup", pairing_window).await
}

/// One reconciliation pass against the live pair-device window.
///
/// Widening and narrowing are deliberately asymmetric, because they are not
/// the same risk. Narrowing runs on EVERY call, unconditionally: an expired
/// or consumed window must lose its LAN listener even if this pass cannot
/// tell that anything changed. Widening runs only on an observed
/// `Closed -> Open` edge, because re-enumerating the host's interfaces is the
/// expensive half and there is nothing new to bind while the window has not
/// moved.
///
/// Returns the position it observed, so the caller can carry it to the next
/// pass and to the 60 s interface refresh.
// Eight arguments, and deliberately eight: four are the listener being
// reconciled (router, port, bootstrap, bound), two are the facts situation 2 is
// the OR of, one is the position carried from the last pass and one names the
// caller in the log. Folding them into a context struct would read better and
// would hide which of them the source-level guard below actually checks.
#[allow(clippy::too_many_arguments)]
async fn reconcile_pairing_window(
    router: &Router,
    port: u16,
    bootstrap: &Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
    previous: PairingWindow,
    window: &PairDeviceWindow,
    visibility: &LocalNetworkVisibility,
    source: &'static str,
) -> PairingWindow {
    let observed = PairingWindow::observe(window, visibility).await;
    if observed != previous {
        info!(
            stage = "household_listener.pairing_window",
            pairing_window = observed.as_str(),
            source,
        );
    }
    // Not an edge. `previous` starts at the loop's own initial reading, so a
    // process that came up while a window was already open would compare Open
    // to Open, skip the widening, and never bind the LAN address the window
    // exists to expose — the engine restarting mid-window is exactly when
    // someone is standing there with a phone. Widen whenever the window is
    // open and the LAN is not bound yet; the enumeration is the expensive
    // half, so `already_bound_lan` keeps the steady state free.
    let already_bound_lan = bound
        .snapshot_targets()
        .await
        .iter()
        .any(|(_, class)| *class == InterfaceClass::Lan);
    if observed.is_open() && !already_bound_lan {
        let live = sync_interface_targets(
            router,
            port,
            bootstrap,
            bound,
            "add_iphone_window_open",
            observed,
        )
        .await;
        info!(
            stage = "household_listener.pairing_window_bound",
            target_count = live.len(),
        );
    }
    sync_exposure_policy_with(bootstrap, bound, observed).await;
    observed
}

/// Periodic refresh task — every 60 s re-enumerates the local interfaces
/// and binds any newly discovered LAN/Tailscale address (e.g. a Tailscale
/// interface coming up after boot, Wi-Fi reconnect). Removed addresses are
/// dropped from the bound set so the Bonjour publisher stops advertising
/// them on the next state event.
///
/// It is also the single place that reacts to the "Add iPhone" window moving,
/// by paths that cover each other:
/// - the pair-device window's broadcast subscription and the local-network
///   visibility broadcast subscription, so either way of opening binds the LAN
///   addresses at once rather than after a tick; and
/// - the 500 ms policy tick, which re-reads BOTH live facts, so a dropped or
///   never-sent event -- a lagged subscriber, or a process that started with
///   the window already open -- still reaches the right exposure. It is also
///   the only thing that withdraws an expired visibility grant, which by
///   design emits no event.
///
/// Worst case either way is one 500 ms tick, and the typical open is the
/// broadcast, i.e. the bind itself.
pub async fn refresh_loop(
    router: Router,
    port: u16,
    bootstrap: Arc<RwLock<BootstrapState>>,
    bound: BoundSet,
    pair_device_window: Arc<PairDeviceWindow>,
    visibility: Arc<LocalNetworkVisibility>,
) {
    let mut refresh = tokio::time::interval(INTERFACE_REFRESH_INTERVAL);
    refresh.tick().await; // skip the immediate first tick
    let mut policy_sync = tokio::time::interval(POLICY_SYNC_INTERVAL);
    policy_sync.tick().await; // skip the immediate first tick
    let mut window_events = pair_device_window.subscribe();
    let mut visibility_events = visibility.subscribe();
    // Whatever the window says right now, not an assumption that it is shut:
    // `theyos install` can persist a live token that this process adopted at
    // startup.
    let mut observed = PairingWindow::observe(&pair_device_window, &visibility).await;
    // The loop holds an `Arc` to the window, so the broadcast sender outlives
    // it and `RecvError::Closed` is unreachable in production. Guard the arm
    // anyway: a closed `broadcast::Receiver` returns immediately forever, and
    // a select arm that always completes is a busy loop, not a lost feature.
    let mut window_events_live = true;
    let mut visibility_events_live = true;
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                // Re-read rather than trust `observed`: this arm ENUMERATES
                // and binds, so it must not widen on a stale position.
                observed = PairingWindow::observe(&pair_device_window, &visibility).await;
                let live = sync_interface_targets(
                    &router, port, &bootstrap, &bound, "refresh", observed,
                ).await;
                info!(
                    stage = "household_listener.refresh",
                    target_count = live.len(),
                    pairing_window = observed.as_str(),
                );
            }
            _ = policy_sync.tick() => {
                observed = reconcile_pairing_window(
                    &router, port, &bootstrap, &bound, observed,
                    &pair_device_window, &visibility, "tick",
                ).await;
            }
            event = window_events.recv(), if window_events_live => {
                match event {
                    // The payload is ignored on purpose: `Open`/`Closed` is a
                    // notification that something moved, and the position that
                    // decides exposure is the one read back under the window's
                    // own lock, expiry included.
                    Ok(PairDeviceWindowState::Open { .. } | PairDeviceWindowState::Closed) => {}
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(
                            stage = "household_listener.pairing_window_lagged",
                            skipped,
                            "pair-device window updates were dropped; reconciling from the live window"
                        );
                    }
                    Err(RecvError::Closed) => {
                        window_events_live = false;
                        warn!(
                            stage = "household_listener.pairing_window_channel_closed",
                            "falling back to the 500 ms tick for pair-device window changes"
                        );
                        continue;
                    }
                }
                observed = reconcile_pairing_window(
                    &router, port, &bootstrap, &bound, observed,
                    &pair_device_window, &visibility, "window_event",
                ).await;
            }
            event = visibility_events.recv(), if visibility_events_live => {
                match event {
                    // Same rule as the pair-device arm: the payload is a
                    // notification that something moved, and the position that
                    // decides exposure is read back under the visibility's own
                    // lock, deadline included.
                    Ok(LocalNetworkVisibilityState::Open | LocalNetworkVisibilityState::Closed) => {}
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(
                            stage = "household_listener.local_network_visibility_lagged",
                            skipped,
                            "local-network visibility updates were dropped; reconciling from the live fact"
                        );
                    }
                    Err(RecvError::Closed) => {
                        visibility_events_live = false;
                        warn!(
                            stage = "household_listener.local_network_visibility_channel_closed",
                            "falling back to the 500 ms tick for Add-iPhone sheet changes"
                        );
                        continue;
                    }
                }
                observed = reconcile_pairing_window(
                    &router, port, &bootstrap, &bound, observed,
                    &pair_device_window, &visibility, "visibility_event",
                ).await;
            }
        }
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            // fe80::/10 link-local
            v6.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

/// Post-trust peer gate shared by routes that admit a direct remote peer.
///
/// Mesh is opt-in and fail-closed: a valid Product A configuration still needs
/// a verified local Mesh-interface fact before a remote 10.44/16 peer can pass.
/// The production path additionally reads the same live bootstrap state used
/// for listener reconciliation and applies [`HouseholdExposurePolicy`] to the
/// remote peer's class before any handler effect. Callers must still apply
/// their endpoint-specific owner/PoP authorization after this transport check.
#[must_use]
pub(crate) async fn is_post_trust_household_peer_allowed(ip: IpAddr) -> bool {
    let context = HouseholdListenerContext::from_system();
    let exposure_state = match crate::household_bootstrap::global_bootstrap_state() {
        Some(bootstrap) => *bootstrap.read().await,
        // The household router is only served after bootstrap installs this
        // handle. Treat an isolated/unbootstrapped router as onboarding so a
        // Mesh peer fails closed rather than receiving a synthetic Ready state.
        None => BootstrapState::Uninitialized,
    };
    is_post_trust_household_peer_allowed_with_context(ip, exposure_state, &context)
}

/// Apply the shared Ready-state source policy before invoking any route effect.
///
/// The handler routes use [`post_trust_household_peer_gate`], while this
/// injected form lets tests exercise the same 403 decision against a typed
/// configuration and interface snapshot without relying on host interfaces.
pub(crate) fn run_post_trust_household_peer_gate<T>(
    peer: Option<SocketAddr>,
    peer_allowed: impl FnOnce(IpAddr) -> bool,
    on_allowed: impl FnOnce() -> T,
) -> Result<T, StatusCode> {
    match peer {
        Some(peer) if peer_allowed(peer.ip()) => Ok(on_allowed()),
        Some(_) | None => Err(StatusCode::FORBIDDEN),
    }
}

/// Production adapter for the shared Ready-state source gate.
///
/// A Mesh peer may pass only if the daemon's live bootstrap state is `Ready`
/// and the same typed Mesh decision permits the listener bind. An absent
/// bootstrap state is treated as onboarding, which fails Mesh closed.
pub(crate) async fn post_trust_household_peer_gate(
    peer: Option<SocketAddr>,
) -> Result<(), StatusCode> {
    let peer_allowed = match peer {
        Some(peer) => is_post_trust_household_peer_allowed(peer.ip()).await,
        None => false,
    };
    run_post_trust_household_peer_gate(peer, |_| peer_allowed, || ())
}

fn is_post_trust_household_peer_allowed_with_context(
    ip: IpAddr,
    exposure_state: BootstrapState,
    context: &HouseholdListenerContext,
) -> bool {
    let class = if ip.is_loopback() {
        Some(InterfaceClass::Loopback)
    } else if crate::tailnet_address::is_tailnet_ip(ip) {
        Some(InterfaceClass::Tailscale)
    } else if context.mesh.allows_remote_mesh_peer(ip) {
        Some(InterfaceClass::Mesh)
    } else {
        None
    };

    let Some(class) = class else {
        return false;
    };

    HouseholdExposurePolicy::allows_terminal_attach_peer(exposure_state, class)
}

fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            // ULA fc00::/7. Tailscale's ULA prefix is filtered first.
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::http::StatusCode;

    use crate::household_attach_token::{HouseholdAttachScope, HouseholdAttachTokenStore};

    use super::*;

    fn fact(
        interface_name: &str,
        ip: &str,
        prefix_len: u8,
        ownership: LocalAddressOwnership,
    ) -> LocalAddressFact {
        LocalAddressFact {
            interface_name: interface_name.to_owned(),
            ip: ip.parse().expect("test IP"),
            prefix_len,
            ownership,
        }
    }

    fn inventory(addresses: Vec<LocalAddressFact>) -> LocalInterfaceInventory {
        LocalInterfaceInventory { addresses }
    }

    fn context(raw: Option<&str>, addresses: Vec<LocalAddressFact>) -> HouseholdListenerContext {
        HouseholdListenerContext::from_input(MeshExposureInput::raw(raw), inventory(addresses))
    }

    fn verified_mesh_fact() -> LocalAddressFact {
        fact(
            "verified-mesh0",
            "10.44.1.5",
            16,
            LocalAddressOwnership::VerifiedMesh,
        )
    }

    /// Ready-state bind targets with the pairing window pinned CLOSED.
    ///
    /// Every caller below is a mesh-exposure test asserting that a LAN fact
    /// never reaches a Ready bind -- `absent_mesh_configuration_is_inert_and_
    /// keeps_lan_out_of_ready`, `inactive_verified_mesh_fact_never_falls_back_
    /// to_lan_or_bonjour`, and the reconciliation-plan cases. That claim is
    /// about a Ready household nobody is adding a phone to, which is the
    /// closed column, so the position is supplied rather than observed: these
    /// tests are synchronous and have no window to read. Ready-with-the-
    /// window-open is pinned separately by
    /// `lan_is_the_only_class_the_pairing_window_moves` and by the Bonjour
    /// half of `bonjour_omits_mesh_even_when_the_listener_allows_it`.
    fn ready_targets(context: &HouseholdListenerContext) -> Vec<(IpAddr, InterfaceClass)> {
        HouseholdExposurePolicy::allowed_targets_with(
            BootstrapState::Ready,
            enumerate_bind_targets_with_context(context),
            PairingWindow::Closed,
        )
    }

    #[derive(Default)]
    struct RecordingBindFactory {
        attempts: Vec<BindAttempt>,
    }

    impl BindAttemptObserver for RecordingBindFactory {
        fn before_bind(&mut self, attempt: BindAttempt) {
            self.attempts.push(attempt);
        }
    }

    fn apply_plan_with_successful_test_factory(
        current: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
        plan: &ListenerReconciliationPlan,
    ) -> (Vec<(IpAddr, InterfaceClass)>, Vec<BindAttempt>) {
        let mut snapshot: BTreeMap<IpAddr, InterfaceClass> = current.into_iter().collect();
        let mut factory = RecordingBindFactory::default();
        for action in &plan.actions {
            match action {
                ListenerReconciliationAction::Shutdown { ip, .. } => {
                    snapshot.remove(ip);
                }
                ListenerReconciliationAction::Bind(attempt) => {
                    factory.before_bind(*attempt);
                    snapshot.insert(attempt.address.ip(), attempt.class);
                }
            }
        }
        (snapshot.into_iter().collect(), factory.attempts)
    }

    fn mesh_bind_attempts(attempts: &[BindAttempt]) -> Vec<BindAttempt> {
        attempts
            .iter()
            .copied()
            .filter(|attempt| attempt.class == InterfaceClass::Mesh)
            .collect()
    }

    fn bind_attempts_for_targets(
        targets: &[(IpAddr, InterfaceClass)],
        port: u16,
    ) -> Vec<BindAttempt> {
        targets
            .iter()
            .map(|(ip, class)| BindAttempt {
                address: SocketAddr::new(*ip, port),
                class: *class,
            })
            .collect()
    }

    fn assert_lan_request_is_403_before_effect(context: &HouseholdListenerContext) {
        let lan: SocketAddr = "192.168.50.10:41001".parse().expect("LAN peer");
        let attach_tokens = HouseholdAttachTokenStore::new();
        let pending_before = attach_tokens.pending_count();
        let mut handler_effect_count = 0;
        let status = match run_post_trust_household_peer_gate(
            Some(lan),
            |ip| {
                is_post_trust_household_peer_allowed_with_context(
                    ip,
                    BootstrapState::Ready,
                    context,
                )
            },
            || {
                handler_effect_count += 1;
                attach_tokens.mint(HouseholdAttachScope {
                    household_id: "hh-test".to_owned(),
                    container: "picoclaw-test".to_owned(),
                    session_id: "workspace-test".to_owned(),
                    actor_person_id: "person-test".to_owned(),
                })
            },
        ) {
            Ok(_) => StatusCode::OK,
            Err(status) => status,
        };

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(handler_effect_count, 0);
        assert_eq!(attach_tokens.pending_count(), pending_before);
    }

    fn assert_no_mesh_bind_and_lan_rejection(context: &HouseholdListenerContext) {
        let desired = ready_targets(context);
        let expected_attempts = bind_attempts_for_targets(&desired, 8091);
        let plan = plan_listener_reconciliation(Vec::new(), desired.clone(), 8091);
        let (snapshot, attempts) = apply_plan_with_successful_test_factory(Vec::new(), &plan);
        assert_eq!(snapshot, desired);
        assert_eq!(attempts, expected_attempts);
        assert!(mesh_bind_attempts(&attempts).is_empty());
        assert!(
            snapshot
                .iter()
                .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
        assert_lan_request_is_403_before_effect(context);
    }

    #[test]
    fn absent_mesh_configuration_is_inert_and_keeps_lan_out_of_ready() {
        let context = context(None, vec![verified_mesh_fact()]);

        assert_eq!(context.mesh.config, MeshExposureConfig::Disabled);
        assert_no_mesh_bind_and_lan_rejection(&context);
    }

    #[test]
    fn inactive_verified_mesh_fact_never_falls_back_to_lan_or_bonjour() {
        let mesh_ip: IpAddr = "10.44.1.5".parse().unwrap();
        let cases = [
            (None, MeshExposureConfig::Disabled),
            (
                Some("10.44.1.7/16"),
                MeshExposureConfig::Rejected(MeshExposureError::NonCanonicalNetwork),
            ),
        ];

        for (raw, expected_config) in cases {
            let context = context(raw, vec![verified_mesh_fact()]);
            let targets = enumerate_bind_targets_with_context(&context);
            let onboarding = HouseholdExposurePolicy::allowed_targets_with(
                BootstrapState::Uninitialized,
                targets.clone(),
                PairingWindow::Closed,
            );
            let bonjour = HouseholdExposurePolicy::bonjour_targets_with(
                BootstrapState::Uninitialized,
                targets.clone(),
                PairingWindow::Closed,
            );

            assert_eq!(context.mesh.config, expected_config);
            assert!(targets.iter().all(|(ip, _)| *ip != mesh_ip));
            assert!(onboarding.iter().all(|(ip, _)| *ip != mesh_ip));
            assert!(bonjour.iter().all(|(ip, _)| *ip != mesh_ip));
            assert_no_mesh_bind_and_lan_rejection(&context);
        }
    }

    #[test]
    fn configured_allocation_without_verified_ownership_is_quarantined_from_onboarding_and_bonjour()
    {
        let mesh_ip: IpAddr = "10.44.1.5".parse().unwrap();
        let context = context(
            Some("10.44.0.0/16"),
            vec![fact("en0", "10.44.1.5", 16, LocalAddressOwnership::Lan)],
        );
        let targets = enumerate_bind_targets_with_context(&context);
        let onboarding = HouseholdExposurePolicy::allowed_targets_with(
            BootstrapState::Uninitialized,
            targets.clone(),
            PairingWindow::Closed,
        );
        let bonjour = HouseholdExposurePolicy::bonjour_targets_with(
            BootstrapState::Uninitialized,
            targets.clone(),
            PairingWindow::Closed,
        );

        assert_eq!(
            context.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::LocalOverlap)
        );
        assert!(targets.iter().all(|(ip, _)| *ip != mesh_ip));
        assert!(onboarding.iter().all(|(ip, _)| *ip != mesh_ip));
        assert!(bonjour.iter().all(|(ip, _)| *ip != mesh_ip));
        assert_no_mesh_bind_and_lan_rejection(&context);
    }

    #[test]
    fn rejected_mesh_inputs_have_stable_errors_zero_mesh_binds_and_lan_403() {
        let cases = [
            ("", MeshExposureError::Empty),
            (" ", MeshExposureError::Whitespace),
            ("not-a-cidr", MeshExposureError::Syntax),
            ("10.44.0.0/33", MeshExposureError::InvalidPrefix),
            ("10.44.1.7/16", MeshExposureError::NonCanonicalNetwork),
            ("10.44.0.0/17", MeshExposureError::UntrustedAllocation),
            ("10.45.0.0/16", MeshExposureError::UntrustedAllocation),
            ("0.0.0.0/0", MeshExposureError::UniversalRange),
            ("::/0", MeshExposureError::UnsupportedAddressFamily),
            ("10.0.0.0/8", MeshExposureError::BroadPrivateRange),
            ("172.16.0.0/12", MeshExposureError::BroadPrivateRange),
            ("192.168.0.0/16", MeshExposureError::BroadPrivateRange),
            ("100.64.0.0/10", MeshExposureError::TailnetRange),
            (
                "fd7a:115c:a1e0::/48",
                MeshExposureError::UnsupportedAddressFamily,
            ),
            ("127.0.0.0/8", MeshExposureError::LoopbackRange),
            ("::1/128", MeshExposureError::UnsupportedAddressFamily),
            ("169.254.0.0/16", MeshExposureError::LinkLocalRange),
            ("fe80::/10", MeshExposureError::UnsupportedAddressFamily),
        ];

        for (raw, expected_error) in cases {
            let context = context(Some(raw), vec![verified_mesh_fact()]);
            assert_eq!(
                context.mesh.config,
                MeshExposureConfig::Rejected(expected_error)
            );
            assert_eq!(context.mesh.config.error(), Some(expected_error));
            assert_eq!(
                context.mesh.config.error().map(MeshExposureError::as_str),
                Some(expected_error.as_str())
            );
            assert_no_mesh_bind_and_lan_rejection(&context);
        }
    }

    #[test]
    fn valid_configuration_is_exact_product_a_allocation_not_a_general_cidr() {
        let config = MeshExposureConfig::from_input(MeshExposureInput::raw(Some("10.44.0.0/16")));

        assert_eq!(
            config,
            MeshExposureConfig::Enabled(TrustedMeshSubnet::product_a())
        );
        let subnet = config.trusted_subnet().expect("trusted subnet");
        assert_eq!(subnet.network, "10.44.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(subnet.prefix_len, 16);
    }

    #[test]
    fn local_lan_overlap_rejects_the_entire_mesh_exposure_before_bind() {
        let context = context(
            Some("10.44.0.0/16"),
            vec![
                verified_mesh_fact(),
                fact("en0", "10.44.1.9", 24, LocalAddressOwnership::Lan),
            ],
        );

        assert_eq!(
            context.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::LocalOverlap)
        );
        assert_no_mesh_bind_and_lan_rejection(&context);
    }

    #[test]
    fn valid_config_without_a_verified_mesh_interface_makes_zero_mesh_attempts() {
        let context = context(
            Some("10.44.0.0/16"),
            vec![fact(
                "mesh0",
                "192.168.50.2",
                24,
                LocalAddressOwnership::Lan,
            )],
        );

        assert_eq!(
            context.mesh.config,
            MeshExposureConfig::Enabled(TrustedMeshSubnet::product_a())
        );
        assert!(!context.mesh.is_active());
        assert_no_mesh_bind_and_lan_rejection(&context);
    }

    #[test]
    fn verified_mesh_inventory_produces_one_concrete_bind_and_no_bonjour_advertisement() {
        let context = context(
            Some("10.44.0.0/16"),
            vec![
                verified_mesh_fact(),
                fact(
                    "tailscale0",
                    "100.64.0.10",
                    32,
                    LocalAddressOwnership::Tailnet,
                ),
                fact("en0", "192.168.50.2", 24, LocalAddressOwnership::Lan),
            ],
        );
        let live = ready_targets(&context);
        let plan = plan_listener_reconciliation(Vec::new(), live.clone(), 8091);
        let (snapshot, attempts) = apply_plan_with_successful_test_factory(Vec::new(), &plan);
        let mesh_attempts = mesh_bind_attempts(&attempts);

        assert_eq!(
            context.mesh.config,
            MeshExposureConfig::Enabled(TrustedMeshSubnet::product_a())
        );
        assert_eq!(attempts, bind_attempts_for_targets(&live, 8091));
        assert_eq!(mesh_attempts.len(), 1);
        assert_eq!(mesh_attempts[0].address, "10.44.1.5:8091".parse().unwrap());
        assert!(!mesh_attempts[0].address.ip().is_unspecified());
        assert!(snapshot.contains(&("10.44.1.5".parse().unwrap(), InterfaceClass::Mesh)));
        assert!(snapshot.contains(&(IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback)));
        assert!(snapshot.contains(&("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale)));
        assert!(
            !snapshot
                .iter()
                .any(|(_, class)| *class == InterfaceClass::Lan)
        );
        assert_lan_request_is_403_before_effect(&context);
        assert!(
            HouseholdExposurePolicy::bonjour_targets_with(
                BootstrapState::Ready,
                live,
                PairingWindow::Closed
            )
            .iter()
            .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
    }

    #[test]
    fn interface_name_or_private_address_never_promotes_mesh_ownership() {
        let context = context(
            Some("10.44.0.0/16"),
            vec![fact(
                "verified-mesh0",
                "10.44.1.5",
                16,
                LocalAddressOwnership::Lan,
            )],
        );
        let unrelated = fact("mesh0", "192.168.50.2", 24, LocalAddressOwnership::Lan);

        assert_eq!(
            context.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::LocalOverlap)
        );
        assert_eq!(
            classify_local_address(&unrelated, &context.mesh),
            Some(InterfaceClass::Lan)
        );
        assert_no_mesh_bind_and_lan_rejection(&context);
    }

    #[test]
    fn post_trust_peer_gate_requires_the_same_active_mesh_decision_as_binding() {
        let inactive = context(None, vec![verified_mesh_fact()]);
        let active = context(Some("10.44.0.0/16"), vec![verified_mesh_fact()]);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let tailnet: IpAddr = "100.64.0.2".parse().unwrap();
        let mesh: IpAddr = "10.44.99.2".parse().unwrap();
        let lan: IpAddr = "192.168.50.10".parse().unwrap();

        assert!(is_post_trust_household_peer_allowed_with_context(
            loopback,
            BootstrapState::Ready,
            &inactive
        ));
        assert!(is_post_trust_household_peer_allowed_with_context(
            tailnet,
            BootstrapState::Ready,
            &inactive
        ));
        assert!(!is_post_trust_household_peer_allowed_with_context(
            mesh,
            BootstrapState::Ready,
            &inactive
        ));
        assert!(is_post_trust_household_peer_allowed_with_context(
            mesh,
            BootstrapState::Ready,
            &active
        ));
        assert!(!is_post_trust_household_peer_allowed_with_context(
            lan,
            BootstrapState::Ready,
            &active
        ));
    }

    #[test]
    fn terminal_attach_mesh_peer_requires_ready_before_any_effect() {
        let context = context(Some("10.44.0.0/16"), vec![verified_mesh_fact()]);
        let mesh_peer: SocketAddr = "10.44.99.2:41001".parse().expect("Mesh peer");

        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Recovering,
        ] {
            let attach_tokens = HouseholdAttachTokenStore::new();
            let minted = attach_tokens.mint(HouseholdAttachScope {
                household_id: "hh-test".to_owned(),
                container: "picoclaw-test".to_owned(),
                session_id: "workspace-test".to_owned(),
                actor_person_id: "person-test".to_owned(),
            });
            let pending_before = attach_tokens.pending_count();
            let mut effect_count = 0;

            let status = match run_post_trust_household_peer_gate(
                Some(mesh_peer),
                |ip| is_post_trust_household_peer_allowed_with_context(ip, state, &context),
                || {
                    effect_count += 1;
                    attach_tokens.consume(&minted.token)
                },
            ) {
                Ok(_) => StatusCode::OK,
                Err(status) => status,
            };

            assert_eq!(status, StatusCode::FORBIDDEN, "state={state:?}");
            assert_eq!(effect_count, 0, "state={state:?}");
            assert_eq!(
                attach_tokens.pending_count(),
                pending_before,
                "state={state:?}"
            );
            assert!(
                attach_tokens.consume(&minted.token).is_some(),
                "state={state:?}: rejected Mesh peer must not consume attach token"
            );
        }

        let mut effect_count = 0;
        let status = match run_post_trust_household_peer_gate(
            Some(mesh_peer),
            |ip| {
                is_post_trust_household_peer_allowed_with_context(
                    ip,
                    BootstrapState::Ready,
                    &context,
                )
            },
            || {
                effect_count += 1;
            },
        ) {
            Ok(_) => StatusCode::OK,
            Err(status) => status,
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(effect_count, 1);
    }

    #[test]
    fn refresh_with_disappearing_mesh_address_withdraws_the_existing_mesh_listener() {
        let active = context(Some("10.44.0.0/16"), vec![verified_mesh_fact()]);
        let disappeared = context(Some("10.44.0.0/16"), Vec::new());
        let current = vec![("10.44.1.5".parse().unwrap(), InterfaceClass::Mesh)];
        let plan = plan_listener_reconciliation(current.clone(), ready_targets(&disappeared), 8091);

        assert!(matches!(
            plan.actions.first(),
            Some(ListenerReconciliationAction::Shutdown {
                ip,
                class: InterfaceClass::Mesh,
            }) if *ip == "10.44.1.5".parse::<IpAddr>().unwrap()
        ));
        let (snapshot, attempts) = apply_plan_with_successful_test_factory(current, &plan);
        assert!(
            snapshot
                .iter()
                .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
        assert!(mesh_bind_attempts(&attempts).is_empty());
        assert!(active.mesh.is_active());
        assert_lan_request_is_403_before_effect(&disappeared);
    }

    #[test]
    fn overlap_refresh_shuts_down_mesh_before_any_new_bind() {
        let conflict = context(
            Some("10.44.0.0/16"),
            vec![
                verified_mesh_fact(),
                fact("en0", "10.44.1.9", 24, LocalAddressOwnership::Lan),
            ],
        );
        let current = vec![("10.44.1.5".parse().unwrap(), InterfaceClass::Mesh)];
        let plan = plan_listener_reconciliation(current.clone(), ready_targets(&conflict), 8091);
        let first_bind = plan
            .actions
            .iter()
            .position(|action| matches!(action, ListenerReconciliationAction::Bind(_)));
        let mesh_shutdown = plan.actions.iter().position(|action| {
            matches!(
                action,
                ListenerReconciliationAction::Shutdown {
                    ip,
                    class: InterfaceClass::Mesh,
                } if *ip == "10.44.1.5".parse::<IpAddr>().unwrap()
            )
        });

        assert_eq!(
            conflict.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::LocalOverlap)
        );
        assert!(mesh_shutdown.is_some());
        if let Some(first_bind) = first_bind {
            assert!(mesh_shutdown.expect("mesh shutdown") < first_bind);
        }
        let (snapshot, attempts) = apply_plan_with_successful_test_factory(current, &plan);
        assert!(
            snapshot
                .iter()
                .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
        assert!(mesh_bind_attempts(&attempts).is_empty());
        assert_lan_request_is_403_before_effect(&conflict);
    }

    #[test]
    fn invalid_to_valid_refresh_attempts_mesh_only_after_validation_and_verified_ownership() {
        let invalid = context(Some("10.44.1.7/16"), vec![verified_mesh_fact()]);
        let valid = context(Some("10.44.0.0/16"), vec![verified_mesh_fact()]);
        let invalid_targets = ready_targets(&invalid);
        let valid_targets = ready_targets(&valid);
        let invalid_plan = plan_listener_reconciliation(Vec::new(), invalid_targets.clone(), 8091);
        let valid_plan = plan_listener_reconciliation(Vec::new(), valid_targets.clone(), 8091);
        let (invalid_snapshot, invalid_attempts) =
            apply_plan_with_successful_test_factory(Vec::new(), &invalid_plan);
        let (valid_snapshot, valid_attempts) =
            apply_plan_with_successful_test_factory(Vec::new(), &valid_plan);

        assert_eq!(
            invalid.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::NonCanonicalNetwork)
        );
        assert_eq!(invalid_snapshot, invalid_targets);
        assert_eq!(
            invalid_attempts,
            bind_attempts_for_targets(&invalid_snapshot, 8091)
        );
        assert!(mesh_bind_attempts(&invalid_attempts).is_empty());
        assert!(
            invalid_snapshot
                .iter()
                .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
        assert_eq!(valid_snapshot, valid_targets);
        assert_eq!(
            valid_attempts,
            bind_attempts_for_targets(&valid_snapshot, 8091)
        );
        assert_eq!(
            mesh_bind_attempts(&valid_attempts),
            vec![BindAttempt {
                address: "10.44.1.5:8091".parse().unwrap(),
                class: InterfaceClass::Mesh,
            }]
        );
        assert_lan_request_is_403_before_effect(&invalid);
        assert_lan_request_is_403_before_effect(&valid);
    }

    #[test]
    fn tampered_config_refresh_removes_mesh_and_leaves_no_stale_target() {
        let tampered = context(Some("10.0.0.0/8"), vec![verified_mesh_fact()]);
        let current = vec![("10.44.1.5".parse().unwrap(), InterfaceClass::Mesh)];
        let plan = plan_listener_reconciliation(current.clone(), ready_targets(&tampered), 8091);
        let (snapshot, attempts) = apply_plan_with_successful_test_factory(current, &plan);

        assert_eq!(
            tampered.mesh.config,
            MeshExposureConfig::Rejected(MeshExposureError::BroadPrivateRange)
        );
        assert!(
            snapshot
                .iter()
                .all(|(_, class)| *class != InterfaceClass::Mesh)
        );
        assert!(mesh_bind_attempts(&attempts).is_empty());
        assert_lan_request_is_403_before_effect(&tampered);
    }

    #[test]
    fn classify_lan_v4() {
        let context = context(None, Vec::new());
        let fact = fact("en0", "192.168.1.5", 24, LocalAddressOwnership::Lan);
        assert_eq!(
            classify_local_address(&fact, &context.mesh),
            Some(InterfaceClass::Lan)
        );
    }

    #[test]
    fn classify_public_v4_is_not_bound() {
        let context = context(None, Vec::new());
        let fact = fact("en0", "203.0.113.10", 24, LocalAddressOwnership::Other);
        assert_eq!(classify_local_address(&fact, &context.mesh), None);
    }

    #[test]
    fn classify_link_local_skipped() {
        let ip: IpAddr = "169.254.1.5".parse().unwrap();
        assert!(is_link_local(&ip));
    }

    #[tokio::test]
    async fn enumerate_includes_loopback() {
        let targets = enumerate_bind_targets();
        assert!(
            targets
                .iter()
                .any(|(ip, c)| { ip.is_loopback() && *c == InterfaceClass::Loopback })
        );
    }

    #[tokio::test]
    async fn bind_concrete_rejects_wildcard_addresses() {
        for addr in ["0.0.0.0:0", "[::]:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let err = bind_concrete(addr)
                .await
                .expect_err("wildcard bind must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("refusing to listen on wildcard 0.0.0.0/::"),
                "unexpected wildcard reject error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn bound_set_preserves_interface_class() {
        let bound = BoundSet::default();
        let ip: IpAddr = "100.64.1.2".parse().unwrap();

        let (shutdown, _rx) = oneshot::channel();
        bound.insert(ip, InterfaceClass::Tailscale, shutdown).await;

        assert_eq!(bound.snapshot().await, vec![ip]);
        assert_eq!(
            bound.snapshot_targets().await,
            vec![(ip, InterfaceClass::Tailscale)]
        );
    }

    /// Situation 1 -- INSTALL -- does not depend on situation 2.
    ///
    /// A household that has not been set up yet is on the Wi-Fi because it is
    /// being installed, not because a window is open, so both positions must
    /// answer the same thing here. If a future arm ever routes the onboarding
    /// states through the window, first-launch setup would silently stop
    /// working on a LAN-only network.
    #[test]
    fn the_install_states_keep_lan_in_both_window_positions() {
        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
        ] {
            for window in [PairingWindow::Closed, PairingWindow::Open] {
                assert!(
                    HouseholdExposurePolicy::allows_with(state, InterfaceClass::Lan, window),
                    "{state:?} must expose LAN at pairing_window={window:?}"
                );
            }
        }
    }

    /// One Ready host with one address of every class, so the two window
    /// positions can be compared on identical input.
    fn one_target_per_class() -> Vec<(IpAddr, InterfaceClass)> {
        vec![
            (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
            ("192.0.2.10".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
        ]
    }

    #[test]
    fn exposure_policy_ready_excludes_lan_and_keeps_loopback_tailnet_mesh() {
        // Window CLOSED -- the shipped set, and what a Ready household
        // exposes at every moment nobody is adding a phone to it.
        let allowed = HouseholdExposurePolicy::allowed_targets_with(
            BootstrapState::Ready,
            one_target_per_class(),
            PairingWindow::Closed,
        );
        assert_eq!(
            allowed,
            vec![
                (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
                ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
                ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
            ]
        );
    }

    #[test]
    fn exposure_policy_ready_binds_lan_while_the_pairing_window_is_open() {
        let allowed = HouseholdExposurePolicy::allowed_targets_with(
            BootstrapState::Ready,
            one_target_per_class(),
            PairingWindow::Open,
        );
        assert_eq!(
            allowed,
            one_target_per_class(),
            "an open pairing window must add the LAN address to the bind set \
             and change nothing else about it"
        );
    }

    #[test]
    fn lan_is_the_only_class_the_pairing_window_moves() {
        // Every state x every class, both positions. Anything that differs
        // other than post-onboarding LAN is the window reaching further than
        // the rule allows.
        let states = [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::PairMachineInstallRestartRequired,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ];
        let classes = [
            InterfaceClass::Loopback,
            InterfaceClass::Lan,
            InterfaceClass::Tailscale,
            InterfaceClass::Mesh,
        ];
        for state in states {
            for class in classes {
                let closed =
                    HouseholdExposurePolicy::allows_with(state, class, PairingWindow::Closed);
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
                        "{state:?}/Lan must be denied while the pairing window is closed"
                    );
                    assert!(
                        open,
                        "{state:?}/Lan must be admitted while a pair-device window is open"
                    );
                } else {
                    assert_eq!(
                        closed, open,
                        "{state:?}/{class:?} moved with the pairing window; the window may \
                         only move post-onboarding LAN"
                    );
                }
            }
        }
    }

    /// A caller with no window to consult gets the narrow set.
    ///
    /// `PairingWindow` has no parse, no environment read and no fallible
    /// construction, so the only way to widen a Ready household is to hold a
    /// window and observe it open. `Default` is what a forgotten call site
    /// lands on, and it must be the column that shipped.
    #[test]
    fn the_default_window_position_is_closed() {
        assert_eq!(PairingWindow::default(), PairingWindow::Closed);
        assert!(!PairingWindow::default().is_open());
        for class in [
            InterfaceClass::Loopback,
            InterfaceClass::Lan,
            InterfaceClass::Tailscale,
            InterfaceClass::Mesh,
        ] {
            assert_eq!(
                HouseholdExposurePolicy::allows_with(
                    BootstrapState::Ready,
                    class,
                    PairingWindow::default()
                ),
                class != InterfaceClass::Lan,
                "a Ready household with no window must expose loopback + tailnet + mesh only"
            );
        }
    }

    /// A window that has run out of TTL stops granting LAN, with no restart
    /// and without waiting for anything to notify anyone.
    ///
    /// The mechanism under test is [`PairingWindow::observe`]: it reads the
    /// window under its own lock, and `PairToken::is_expired` is checked
    /// there, so an expired token reports `Closed` even though the broadcast
    /// that announces expiry comes from a task this test never spawns. That
    /// is what makes the 500 ms tick a sufficient backstop for a token this
    /// process adopted rather than minted.
    #[tokio::test]
    async fn an_expired_pairing_window_stops_granting_lan() {
        let window = PairDeviceWindow::new();
        let shut = LocalNetworkVisibility::new();
        assert_eq!(
            PairingWindow::observe(&window, &shut).await,
            PairingWindow::Closed,
            "a fresh window is shut"
        );

        window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("mint a live pairing window");
        let open = PairingWindow::observe(&window, &shut).await;
        assert_eq!(open, PairingWindow::Open);
        assert!(
            HouseholdExposurePolicy::allows_with(BootstrapState::Ready, InterfaceClass::Lan, open),
            "an open window is what puts a Ready household on the Wi-Fi"
        );

        // A zero TTL expires at the instant it is minted: `PairToken::mint`
        // sets `expires_at = now + ttl` and `is_expired` is `now >= expires_at`.
        window
            .mint_token(Duration::from_secs(0), None)
            .await
            .expect("mint an already-expired pairing window");
        let expired = PairingWindow::observe(&window, &shut).await;
        assert_eq!(
            expired,
            PairingWindow::Closed,
            "an expired token must not read as an open window"
        );
        assert!(
            !HouseholdExposurePolicy::allows_with(
                BootstrapState::Ready,
                InterfaceClass::Lan,
                expired
            ),
            "LAN must be withdrawn the moment the window stops being open"
        );
    }

    /// The half this branch adds: a Ready household with NO pair-device token
    /// reaches situation 2 because the Mac said it is showing an "Add iPhone"
    /// sheet.
    ///
    /// This is the measured gap as a test. The Mac mints its own offer
    /// (`MacPairingAdvertisement`), so the engine's `PairDeviceWindow` stays
    /// shut for the whole ceremony; before the visibility fact existed,
    /// `observe` answered `Closed` here and a Ready engine bound no LAN
    /// address at all.
    #[tokio::test]
    async fn the_add_iphone_sheet_opens_situation_two_with_no_token_minted() {
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();

        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Closed,
            "nothing is open yet"
        );

        visibility.open(Duration::from_secs(300)).await;
        let open = PairingWindow::observe(&window, &visibility).await;
        assert_eq!(open, PairingWindow::Open);
        assert!(
            window.current_token().await.is_none(),
            "the visibility fact must reach situation 2 without a token existing"
        );
        assert_eq!(
            HouseholdExposurePolicy::allowed_targets_with(
                BootstrapState::Ready,
                one_target_per_class(),
                open,
            ),
            one_target_per_class(),
            "opening the sheet must put the LAN address in a Ready bind set"
        );

        // Closing is explicit, and it withdraws.
        visibility.close().await;
        let closed = PairingWindow::observe(&window, &visibility).await;
        assert_eq!(closed, PairingWindow::Closed);
        assert!(
            !HouseholdExposurePolicy::allows_with(
                BootstrapState::Ready,
                InterfaceClass::Lan,
                closed
            ),
            "the sheet closing must withdraw LAN, not wait out a TTL"
        );
    }

    /// An expired sheet declaration withdraws LAN with no task having run.
    ///
    /// `LocalNetworkVisibility` deliberately spawns no TTL cleanup, so this is
    /// the whole of its expiry story: the deadline is compared on every read,
    /// and the reconciler's 500 ms tick is what turns that into a withdrawn
    /// listener.
    #[tokio::test]
    async fn an_expired_add_iphone_sheet_stops_granting_lan() {
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();
        // Zero TTL: the deadline is `now`, and `is_open` is `now < deadline`.
        visibility.open(Duration::ZERO).await;

        let expired = PairingWindow::observe(&window, &visibility).await;
        assert_eq!(expired, PairingWindow::Closed);
        assert!(
            !HouseholdExposurePolicy::allows_with(
                BootstrapState::Ready,
                InterfaceClass::Lan,
                expired
            ),
            "an expired sheet declaration must not keep a Ready household on the Wi-Fi"
        );
    }

    /// Either fact alone reaches situation 2, and BOTH have to be shut before
    /// LAN is withdrawn.
    ///
    /// The failure this pins is the tempting simplification: a reconciler that
    /// withdrew on "the token closed" would cut the LAN out from under an
    /// owner whose sheet is still open, and vice versa.
    #[tokio::test]
    async fn either_fact_opens_situation_two_and_both_must_shut_to_close_it() {
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();

        window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("mint");
        visibility.open(Duration::from_secs(300)).await;
        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Open
        );

        // Token gone, sheet still up.
        window.close().await.expect("close the token window");
        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Open,
            "the sheet is still open; LAN must not be withdrawn under it"
        );

        // Sheet gone too.
        visibility.close().await;
        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Closed
        );
    }

    /// The install states do not depend on either fact.
    ///
    /// Situation 1 grants LAN on its own, so opening or closing the sheet must
    /// not change what a household being installed exposes -- in particular,
    /// the new route must never be able to NARROW an install.
    #[tokio::test]
    async fn the_install_states_are_unaffected_by_the_add_iphone_sheet() {
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();

        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
        ] {
            let shut = PairingWindow::observe(&window, &visibility).await;
            visibility.open(Duration::from_secs(300)).await;
            let open = PairingWindow::observe(&window, &visibility).await;
            visibility.close().await;
            assert_eq!(shut, PairingWindow::Closed);
            assert_eq!(open, PairingWindow::Open);

            for class in [
                InterfaceClass::Loopback,
                InterfaceClass::Lan,
                InterfaceClass::Tailscale,
                InterfaceClass::Mesh,
            ] {
                assert_eq!(
                    HouseholdExposurePolicy::allows_with(state, class, shut),
                    HouseholdExposurePolicy::allows_with(state, class, open),
                    "{state:?}/{class:?} must not move with the Add iPhone sheet"
                );
            }
        }

        // And the interrupted install, which is the arm that must never widen:
        // it ignores the window in both positions.
        for class in [
            InterfaceClass::Loopback,
            InterfaceClass::Lan,
            InterfaceClass::Tailscale,
            InterfaceClass::Mesh,
        ] {
            assert_eq!(
                HouseholdExposurePolicy::allows_with(
                    BootstrapState::PairMachineInstallRestartRequired,
                    class,
                    PairingWindow::Open,
                ),
                matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale),
                "an interrupted install must expose loopback + tailnet whatever the sheet says"
            );
        }
    }

    /// Opening twice does not stack: one close still shuts it.
    #[tokio::test]
    async fn opening_the_sheet_twice_does_not_stack() {
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();

        visibility.open(Duration::from_secs(300)).await;
        visibility.open(Duration::from_secs(300)).await;
        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Open
        );

        visibility.close().await;
        assert_eq!(
            PairingWindow::observe(&window, &visibility).await,
            PairingWindow::Closed,
            "two opens and one close must leave the home invisible, or the LAN \
             stays bound after the person is done"
        );
    }

    /// Terminal attach stays denied on LAN in every state, and the pairing
    /// window cannot reach that decision.
    ///
    /// Binding the port so a phone can be added is a different decision from
    /// letting a LAN peer drive somebody's terminal, and only the first one
    /// was asked for. `allows_terminal_attach_peer` takes no window argument,
    /// so the window's inability to move it is a fact of the signature —
    /// an earlier version of this test looped over both positions calling a
    /// function that ignores them, which reads as evidence and is not. What
    /// IS evidence lives below: the controls prove LAN is alive exactly where
    /// the rule says, so the denials above are about attach and not about a
    /// dead class.
    #[test]
    fn terminal_attach_is_denied_on_lan_in_every_state() {
        let states = [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::PairMachineInstallRestartRequired,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ];
        for state in states {
            assert!(
                !HouseholdExposurePolicy::allows_terminal_attach_peer(state, InterfaceClass::Lan),
                "{state:?} must not accept a LAN terminal attach"
            );
        }
        // Controls, so the assertions above are about attach and not about LAN
        // being dead everywhere: the install states bind LAN regardless, and
        // the post-onboarding states bind it while the window is open.
        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
        ] {
            assert!(HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Lan,
                PairingWindow::Closed
            ));
        }
        for state in [
            BootstrapState::Ready,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Recovering,
        ] {
            assert!(HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Lan,
                PairingWindow::Open
            ));
        }
    }

    #[test]
    fn mesh_uses_the_same_post_trust_exposure_gate_as_tailscale() {
        for state in [
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ] {
            for window in [PairingWindow::Closed, PairingWindow::Open] {
                assert_eq!(
                    HouseholdExposurePolicy::allows_with(state, InterfaceClass::Mesh, window),
                    HouseholdExposurePolicy::allows_with(state, InterfaceClass::Tailscale, window)
                );
                assert!(HouseholdExposurePolicy::allows_with(
                    state,
                    InterfaceClass::Mesh,
                    window
                ));
            }
        }
        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
        ] {
            for window in [PairingWindow::Closed, PairingWindow::Open] {
                assert!(!HouseholdExposurePolicy::allows_with(
                    state,
                    InterfaceClass::Mesh,
                    window
                ));
            }
        }
    }

    #[test]
    fn bonjour_omits_mesh_even_when_the_listener_allows_it() {
        let ready_targets = vec![
            (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
            ("192.168.1.2".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
        ];

        assert_eq!(
            HouseholdExposurePolicy::bonjour_targets_with(
                BootstrapState::Ready,
                ready_targets.clone(),
                PairingWindow::Closed
            ),
            vec![("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale)]
        );

        // Opening the switch adds the LAN address to the Ready beacon -- that
        // is the point, the phone has to find the Mac by mDNS -- and STILL
        // withholds Mesh, whose /32 must never leave through a LAN multicast.
        assert_eq!(
            HouseholdExposurePolicy::bonjour_targets_with(
                BootstrapState::Ready,
                ready_targets,
                PairingWindow::Open
            ),
            vec![
                ("192.168.1.2".parse().unwrap(), InterfaceClass::Lan),
                ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ]
        );

        let onboarding_targets = vec![
            ("192.168.1.2".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
        ];
        assert_eq!(
            HouseholdExposurePolicy::bonjour_targets_with(
                BootstrapState::Uninitialized,
                onboarding_targets,
                PairingWindow::Closed
            ),
            vec![
                ("192.168.1.2".parse().unwrap(), InterfaceClass::Lan),
                ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ]
        );
    }

    #[test]
    fn mesh_and_tailscale_bind_through_the_same_router_path() {
        let source = include_str!("household_listener.rs");
        let bind_start = source
            .find("async fn bind_allowed_target")
            .expect("bind_allowed_target not found");
        let bind_end = source[bind_start..]
            .find("\nasync fn shutdown_bound_target")
            .map_or(source.len(), |offset| bind_start + offset);
        let bind_body = &source[bind_start..bind_end];

        assert!(
            bind_body.contains("spawn_listener_task(router.clone(), listener, addr, shutdown_rx)"),
            "every allowed interface class must receive the caller's shared router"
        );
        assert!(
            !bind_body.contains("match class"),
            "interface class must not select an alternate unauthenticated router"
        );
    }

    #[test]
    fn exposure_policy_transitional_states_exclude_lan() {
        for state in [
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Recovering,
        ] {
            assert!(!HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Lan,
                PairingWindow::Closed
            ));
            assert!(HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Loopback,
                PairingWindow::Closed
            ));
            assert!(HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Tailscale,
                PairingWindow::Closed
            ));
            assert!(HouseholdExposurePolicy::allows_with(
                state,
                InterfaceClass::Mesh,
                PairingWindow::Closed
            ));
        }
    }

    /// The 500 ms reconciler withdraws a Ready LAN listener while the pairing
    /// window is closed, and keeps it while the window is open.
    ///
    /// Both positions, because this is the loop that decides whether an
    /// already-bound LAN socket survives. It is also the whole of the
    /// expiry story: `PairingWindow::observe` reports `Closed` for an expired
    /// token, and what happens next is exactly the closed case below.
    #[tokio::test]
    async fn exposure_policy_sync_withdraws_ready_lan_listener_only_while_the_window_is_closed() {
        let lan_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let tailnet_ip: IpAddr = "100.64.0.10".parse().unwrap();

        // Closed -- nobody is adding a phone, or the window expired: LAN
        // loses its listener, Tailnet keeps its own, and the LAN task is told
        // to stop rather than merely dropped from the bookkeeping.
        {
            let bound = BoundSet::default();
            let (lan_shutdown, lan_rx) = oneshot::channel();
            let (tailnet_shutdown, _tailnet_rx) = oneshot::channel();
            bound
                .insert(lan_ip, InterfaceClass::Lan, lan_shutdown)
                .await;
            bound
                .insert(tailnet_ip, InterfaceClass::Tailscale, tailnet_shutdown)
                .await;

            let bootstrap = Arc::new(RwLock::new(BootstrapState::Ready));
            sync_exposure_policy_with(&bootstrap, &bound, PairingWindow::Closed).await;

            assert_eq!(
                bound.snapshot_targets().await,
                vec![(tailnet_ip, InterfaceClass::Tailscale)]
            );
            tokio::time::timeout(Duration::from_secs(1), lan_rx)
                .await
                .expect("LAN listener shutdown signal should be sent")
                .expect("LAN listener shutdown sender should not be dropped before send");
        }

        // Open -- somebody tapped Add iPhone: the reconciler must leave the
        // LAN listener alone, or the window would be undone within 500 ms of
        // the bind that honoured it.
        {
            let bound = BoundSet::default();
            let (lan_shutdown, mut lan_rx) = oneshot::channel();
            let (tailnet_shutdown, _tailnet_rx) = oneshot::channel();
            bound
                .insert(lan_ip, InterfaceClass::Lan, lan_shutdown)
                .await;
            bound
                .insert(tailnet_ip, InterfaceClass::Tailscale, tailnet_shutdown)
                .await;

            let bootstrap = Arc::new(RwLock::new(BootstrapState::Ready));
            sync_exposure_policy_with(&bootstrap, &bound, PairingWindow::Open).await;

            // Sorted: `BoundSet` is a `HashMap`, so iteration order is not a
            // property this test is allowed to assert.
            let mut surviving = bound.snapshot_targets().await;
            surviving.sort_by_key(|(ip, _)| *ip);
            assert_eq!(
                surviving,
                vec![
                    (tailnet_ip, InterfaceClass::Tailscale),
                    (lan_ip, InterfaceClass::Lan),
                ]
            );
            assert!(
                matches!(lan_rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "an open pairing window must not send the LAN listener a shutdown"
            );
        }
    }

    /// The reconciler that owns an already-bound socket, driven by the real
    /// visibility object rather than by a hand-written `PairingWindow`.
    ///
    /// This is the "closing withdraws it" claim at the level where it is a
    /// listener and not a boolean: the LAN task is told to stop, and the
    /// Tailnet one is not.
    #[tokio::test]
    async fn closing_the_add_iphone_sheet_withdraws_the_bound_lan_listener() {
        let lan_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let tailnet_ip: IpAddr = "100.64.0.10".parse().unwrap();
        let window = PairDeviceWindow::new();
        let visibility = LocalNetworkVisibility::new();

        let bound = BoundSet::default();
        let (lan_shutdown, lan_rx) = oneshot::channel();
        let (tailnet_shutdown, _tailnet_rx) = oneshot::channel();
        bound
            .insert(lan_ip, InterfaceClass::Lan, lan_shutdown)
            .await;
        bound
            .insert(tailnet_ip, InterfaceClass::Tailscale, tailnet_shutdown)
            .await;
        let bootstrap = Arc::new(RwLock::new(BootstrapState::Ready));

        // Sheet open: the reconciler must leave the LAN listener alone.
        visibility.open(Duration::from_secs(300)).await;
        let open = PairingWindow::observe(&window, &visibility).await;
        sync_exposure_policy_with(&bootstrap, &bound, open).await;
        let mut surviving = bound.snapshot_targets().await;
        surviving.sort_by_key(|(ip, _)| *ip);
        assert_eq!(
            surviving,
            vec![
                (tailnet_ip, InterfaceClass::Tailscale),
                (lan_ip, InterfaceClass::Lan),
            ]
        );

        // Sheet closed: the LAN task is told to stop, the Tailnet one is not.
        visibility.close().await;
        let closed = PairingWindow::observe(&window, &visibility).await;
        sync_exposure_policy_with(&bootstrap, &bound, closed).await;
        assert_eq!(
            bound.snapshot_targets().await,
            vec![(tailnet_ip, InterfaceClass::Tailscale)]
        );
        tokio::time::timeout(Duration::from_secs(1), lan_rx)
            .await
            .expect("LAN listener shutdown signal should be sent")
            .expect("LAN listener shutdown sender should not be dropped before send");
    }

    #[test]
    fn listener_entry_points_route_enumeration_through_policy() {
        let source = include_str!("household_listener.rs");
        let sync_start = source
            .find("async fn sync_interface_targets")
            .expect("sync_interface_targets not found");
        let sync_end = source[sync_start..]
            .find("\nasync fn sync_exposure_policy")
            .map_or(source.len(), |offset| sync_start + offset);
        let sync_body = &source[sync_start..sync_end];
        assert!(
            sync_body.contains("HouseholdExposurePolicy::allowed_targets"),
            "sync_interface_targets must filter enumerated bind targets through HouseholdExposurePolicy"
        );

        let spawn_start = source
            .find("pub async fn spawn_household_listeners")
            .expect("spawn_household_listeners not found");
        let spawn_end = source[spawn_start..]
            .find("\n/// Periodic refresh task")
            .map_or(source.len(), |offset| spawn_start + offset);
        let spawn_body = &source[spawn_start..spawn_end];
        assert!(
            spawn_body.contains("sync_interface_targets"),
            "spawn_household_listeners must route initial binds through the policy-aware sync helper"
        );
    }

    /// The listener reacts to BOTH facts by BOTH paths, not by one.
    ///
    /// A real end-to-end test here would need a bound socket and a wall-clock
    /// wait, so this is source-level -- but it is source-level about the
    /// things that make the delay bound true, and each is load-bearing on its
    /// own: drop either subscription and that way of tapping "Add iPhone"
    /// waits up to 500 ms; drop the re-read on the tick and a token whose TTL
    /// task lives in another process -- or a visibility grant, which has no TTL
    /// task at all -- never withdraws its LAN listener.
    #[test]
    fn the_refresh_loop_reacts_to_the_pairing_window_by_event_and_by_tick() {
        let source = include_str!("household_listener.rs");
        let start = source
            .find("pub async fn refresh_loop")
            .expect("refresh_loop not found");
        let end = source[start..]
            .find("\nfn is_link_local")
            .map_or(source.len(), |offset| start + offset);
        let body = &source[start..end];

        assert!(
            body.contains("pair_device_window.subscribe()"),
            "refresh_loop must subscribe to the pair-device window, or opening it \
             waits for the next 500 ms tick"
        );
        assert!(
            body.contains("visibility.subscribe()"),
            "refresh_loop must subscribe to the Add-iPhone sheet declaration too, \
             or the Mac-minted-offer half of situation 2 waits for a tick"
        );
        assert!(
            body.contains("event = window_events.recv(), if window_events_live"),
            "the window subscription must be a select arm, and must be disarmed \
             once closed rather than spinning"
        );
        assert!(
            body.contains("event = visibility_events.recv(), if visibility_events_live"),
            "the visibility subscription must be a select arm, and must be disarmed \
             once closed rather than spinning"
        );
        assert!(
            body.contains("_ = policy_sync.tick() => {")
                && body.contains("reconcile_pairing_window("),
            "the 500 ms tick must reconcile against the live window, or an expiry \
             that emits no event never withdraws the LAN listener"
        );
        assert!(
            body.matches("PairingWindow::observe(&pair_device_window, &visibility)")
                .count()
                >= 2,
            "the loop must re-read BOTH facts rather than trust a cached position: \
             once at startup, and again on the enumerating 60 s refresh"
        );

        let reconcile = {
            let start = source
                .find("async fn reconcile_pairing_window")
                .expect("reconcile_pairing_window not found");
            let end = source[start..]
                .find("\n/// Periodic refresh task")
                .map_or(source.len(), |offset| start + offset);
            &source[start..end]
        };
        assert!(
            reconcile.contains("sync_exposure_policy_with(bootstrap, bound, observed).await;"),
            "narrowing must run on every pass, not only on an observed edge: a \
             window that expired must lose its listener even if this pass cannot \
             tell that anything changed"
        );
        assert!(
            reconcile.contains("PairingWindow::observe(window, visibility).await"),
            "the reconciler must read both facts under their own locks; reading \
             only the token half is the bug this branch fixes"
        );
    }

    /// The half of a source file that is not the test module.
    ///
    /// Anchored on `#[cfg(test)]` immediately followed by `mod tests`, never on
    /// the first `#[cfg(test)]` alone: files with cfg-gated items scattered
    /// through production have many of the latter, and cutting at the first one
    /// discards the code the caller means to measure. `mesh_intent_nonce_ledger
    /// .rs` has seven at column zero, the first on line 55, with the definition
    /// on 588 -- the naive cut keeps 54 lines and finds nothing.
    fn production_half(text: &str) -> &str {
        text.split_once("\n#[cfg(test)]\nmod tests")
            .map_or(text, |(production, _)| production)
    }

    /// Exercises [`production_half`] against input that exhibits the failure.
    ///
    /// `household_listener.rs` cannot: it has exactly one `#[cfg(test)]` at
    /// column zero and that one *is* the module, so both partitions are the
    /// same cut and mutating the anchor cannot turn the guard below red. The
    /// guard's control would therefore be armed and never exercised, which is a
    /// green with no red behind it.
    ///
    /// The fixture is synthetic rather than a real file on purpose. Pointing it
    /// at `mesh_intent_nonce_ledger.rs` would make this test depend on that
    /// file keeping its scattered `#[cfg(test)]` attributes: tidy them and the
    /// input stops exhibiting the property, and the test goes green without
    /// anyone learning why. That is the `include_str!` self-reference one level
    /// up -- a fixture measuring another file's present instead of the property
    /// it means to demonstrate.
    #[test]
    fn production_half_cuts_at_the_module_not_the_first_attribute() {
        let fixture = "\
use std::fs;

#[cfg(test)]
fn helper_used_only_by_tests() {}

pub(crate) fn open(path: &str) {}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
";
        let naive = fixture
            .split_once("\n#[cfg(test)]")
            .map_or(fixture, |(production, _)| production);
        assert!(
            !naive.contains("pub(crate) fn open"),
            "the naive cut must lose the definition -- if it does not, this \
             fixture no longer exhibits the failure and proves nothing"
        );

        let correct = production_half(fixture);
        assert!(
            correct.contains("pub(crate) fn open"),
            "the module-anchored cut must keep the definition"
        );
        assert!(
            !correct.contains("fn t()"),
            "the module-anchored cut must still exclude the test module"
        );
    }

    /// The token closes *construction* by type; this closes *propagation*.
    ///
    /// `ProcessStartupToken(())` cannot be built outside this module, and
    /// `claim` hands out at most one per process. Neither fact stops the
    /// resulting `&ProcessStartupToken` from being stored -- parking it in a
    /// struct field reachable from `AppState` compiles, and a handler holding
    /// that state could call `spawn_household_listeners` a second time. That
    /// call is not idempotent: it reconciles through
    /// `sync_interface_targets(.., "startup")`, which opens bind targets and
    /// not only closes them.
    ///
    /// Nothing in the type system keeps the token on the stack. Today it is
    /// there because no field holds it -- a fact about the current tree, not an
    /// invariant, until something checks it. So enumerate every occurrence in
    /// the crate and pin the set: any new one, including a struct field, has to
    /// be looked at rather than merely compiled.
    #[test]
    fn the_startup_token_is_never_stored_only_passed() {
        // Scan the whole workspace, not just this crate. `ProcessStartupToken`
        // is `pub` and `server-rs` is a `[lib]`, so a dependent could park it
        // in a struct field where a crate-local scan would never look --
        // `t1-iptunnel-dev-runner-rs` and `e2e-rs` both declare a dependency
        // edge today. Scanning one crate in a workspace of thirty-one made the
        // assertion message ("a struct field holding it would let a handler
        // start the listeners again") broader than the evidence behind it.
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate dir has a workspace parent")
            .to_path_buf();
        let mut found: Vec<String> = Vec::new();
        let mut scanned_crates: Vec<String> = Vec::new();
        let mut stack: Vec<std::path::PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&workspace).expect("read workspace dir") {
            let member = entry.expect("workspace entry").path();
            if !member.is_dir() || member.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            let member_src = member.join("src");
            if member_src.is_dir() {
                scanned_crates.push(
                    member
                        .file_name()
                        .expect("member dir name")
                        .to_string_lossy()
                        .into_owned(),
                );
                stack.push(member_src);
            }
        }
        scanned_crates.sort();
        // Non-vacuity by set, not by cardinality. `>= 25` in a workspace of
        // thirty-one tolerates six members dropping out of the scan in
        // silence, and a scan that stops seeing members is precisely the
        // failure this guard exists to prevent -- the weak form fails only in
        // the extreme case. Read the declared list from the manifest and
        // require every member to have been reached: that fails on a shrunken
        // scan AND on a new member the walk cannot reach, and adding a member
        // needs no re-pinning here.
        let manifest =
            std::fs::read_to_string(workspace.join("Cargo.toml")).expect("read workspace manifest");
        let declared: Vec<String> = manifest
            .split_once("members = [")
            .expect("workspace manifest declares members")
            .1
            .split_once(']')
            .expect("members list terminates")
            .0
            .lines()
            .filter_map(|l| l.trim().trim_end_matches(',').strip_prefix('"'))
            .filter_map(|l| l.strip_suffix('"'))
            .map(str::to_owned)
            .collect();
        // Control on the parser, not on the workspace: if this parse silently
        // yielded few or no members the loop below would pass vacuously, so
        // require the crate that defines the token to be among what was
        // parsed. A parse that breaks fails here rather than downstream.
        assert!(
            declared.iter().any(|m| m == "server-rs"),
            "manifest parse did not yield the defining crate -- the parser shrank, not the scan: {declared:?}"
        );
        for member in &declared {
            assert!(
                scanned_crates.contains(member),
                "declared workspace member was never scanned: {member} (scanned: {scanned_crates:?})"
            );
        }
        // The walk is deliberately WIDER than `members`. The `exclude`d roots
        // depend on `server-rs` by path and compile, so they can park the
        // token in a field even though `--workspace` never builds them.
        // `read_dir` covers them; iterating `members` would not. Asserted so
        // that narrowing this walk to the declared list -- which reads like
        // tidying -- fails instead of quietly shedding the coverage.
        for excluded in ["mesh-session-core-rs", "mesh-session-control-model-rs"] {
            assert!(
                scanned_crates.iter().any(|c| c == excluded),
                "excluded root {excluded} must still be scanned: it compiles against \
                 server-rs and can hold the token"
            );
        }
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read source file");
                // Scan production only. This guard names the token in its own
                // expected set, so an unbounded scan matches those literals and
                // the assertion compares the guard against itself -- the same
                // `include_str!` self-reference that made the post-ACK guard
                // pass against an empty handler.
                //
                let text = production_half(&text);
                for line in text.lines() {
                    if !line.contains("ProcessStartupToken") {
                        continue;
                    }
                    let trimmed = line.trim();
                    if trimmed.starts_with("///") || trimmed.starts_with("//") {
                        continue;
                    }
                    let name = path
                        .strip_prefix(&workspace)
                        .expect("path under the workspace")
                        .to_string_lossy()
                        .into_owned();
                    found.push(format!("{name}: {trimmed}"));
                }
            }
        }
        found.sort();

        // Control on the partition itself (@khai): a guard whose production
        // half does not contain the definition it measures is broken whatever
        // number it returns. In `mesh_intent_nonce_ledger.rs` both partitions
        // happen to yield zero -- the wrong cut by discarding the definition,
        // the right cut because there genuinely is no production call -- so the
        // count alone cannot tell a working instrument from a broken one.
        assert!(
            found
                .iter()
                .any(|line| line.contains("pub struct ProcessStartupToken(())")),
            "the production half must contain the definition being measured; \
             if it does not, the partition cut in the wrong place and every \
             count below is measuring the wrong text"
        );

        let expected = [
            "server-rs/src/household_bootstrap.rs: startup: &household_listener::ProcessStartupToken,",
            "server-rs/src/household_listener.rs: _startup: &ProcessStartupToken,",
            "server-rs/src/household_listener.rs: impl ProcessStartupToken {",
            "server-rs/src/household_listener.rs: pub struct ProcessStartupToken(());",
            "server-rs/src/main.rs: let startup_token = server_rs::household_listener::ProcessStartupToken::claim()",
        ];

        assert_eq!(
            found, expected,
            "the startup token's occurrence set changed. It may be DEFINED, \
             IMPLEMENTED, taken by reference as a function parameter, and \
             claimed exactly once in main -- nothing else. A struct field \
             holding it would let a handler start the listeners again, and \
             `spawn_household_listeners` opens bind targets on every call."
        );
    }
}
