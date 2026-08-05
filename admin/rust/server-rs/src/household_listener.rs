//! Household-endpoint listener.
//!
//! Binds a fresh axum router to concrete loopback / LAN / Tailnet / verified
//! Mesh addresses,
//! then narrows the live set by [`HouseholdExposurePolicy`]:
//! - onboarding (`uninitialized`, `ready_for_naming`) allows loopback + LAN +
//!   Tailnet so first-launch setup can work on the local network;
//! - post-onboarding (`named_awaiting_pair`, `ready`, `recovering`) allows only
//!   loopback + Tailnet + verified Mesh so the Ready control plane is not
//!   exposed over LAN HTTP.
//!
//! Refuses wildcard `0.0.0.0` / `::` per FR-008. Refreshes the active address
//! set every 60 s and reconciles state-policy changes every 500 ms.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, http::StatusCode};
use household_rs::bootstrap_state::BootstrapState;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{info, warn};

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

/// Pure transport exposure policy for household listener and Bonjour surfaces.
///
/// This is intentionally independent from interface names and socket binding:
/// callers provide already-classified targets, and the policy only decides which
/// classes are allowed for the current bootstrap state.
pub struct HouseholdExposurePolicy;

impl HouseholdExposurePolicy {
    #[must_use]
    pub fn allows(state: BootstrapState, class: InterfaceClass) -> bool {
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
            BootstrapState::PairMachineInstallRestartRequired => {
                matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
            }
            BootstrapState::NamedAwaitingPair
            | BootstrapState::Ready
            | BootstrapState::Recovering => {
                matches!(
                    class,
                    InterfaceClass::Loopback | InterfaceClass::Tailscale | InterfaceClass::Mesh
                )
            }
        }
    }

    /// Direct remote terminal attachment is an effectful household operation,
    /// so a Mesh peer is stricter than a listener bind: it is admitted only
    /// after the household is fully `Ready`. Loopback and Tailnet retain the
    /// existing exposure policy for their class.
    #[must_use]
    pub fn allows_terminal_attach_peer(state: BootstrapState, class: InterfaceClass) -> bool {
        match class {
            InterfaceClass::Mesh => state == BootstrapState::Ready && Self::allows(state, class),
            InterfaceClass::Loopback | InterfaceClass::Tailscale => Self::allows(state, class),
            InterfaceClass::Lan => false,
        }
    }

    #[must_use]
    pub fn allowed_targets(
        state: BootstrapState,
        targets: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
    ) -> Vec<(IpAddr, InterfaceClass)> {
        targets
            .into_iter()
            .filter(|(_, class)| Self::allows(state, *class))
            .collect()
    }

    /// Targets that may be advertised through Bonjour after the listener
    /// policy has allowed them. Mesh addresses remain direct-connect only.
    #[must_use]
    pub fn bonjour_targets(
        state: BootstrapState,
        targets: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
    ) -> Vec<(IpAddr, InterfaceClass)> {
        Self::allowed_targets(state, targets)
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
) -> Vec<(IpAddr, InterfaceClass)> {
    let state = bootstrap_state(bootstrap).await;
    let context = HouseholdListenerContext::from_system();
    let live = HouseholdExposurePolicy::allowed_targets(
        state,
        enumerate_bind_targets_with_context(&context),
    );
    let plan = plan_listener_reconciliation(bound.snapshot_targets().await, live, port);
    let mut observer = NoopBindAttemptObserver;
    apply_listener_reconciliation_plan(router, bound, &plan, source, &mut observer).await;

    bound.snapshot_targets().await
}

async fn sync_exposure_policy(bootstrap: &Arc<RwLock<BootstrapState>>, bound: &BoundSet) {
    let state = bootstrap_state(bootstrap).await;
    let disallowed: Vec<IpAddr> = bound
        .snapshot_targets()
        .await
        .into_iter()
        .filter_map(|(ip, class)| (!HouseholdExposurePolicy::allows(state, class)).then_some(ip))
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
) -> Vec<(IpAddr, InterfaceClass)> {
    sync_interface_targets(&router, port, &bootstrap, bound, "startup").await
}

/// Periodic refresh task — every 60 s re-enumerates the local interfaces
/// and binds any newly discovered LAN/Tailscale address (e.g. a Tailscale
/// interface coming up after boot, Wi-Fi reconnect). Removed addresses are
/// dropped from the bound set so the Bonjour publisher stops advertising
/// them on the next state event.
pub async fn refresh_loop(
    router: Router,
    port: u16,
    bootstrap: Arc<RwLock<BootstrapState>>,
    bound: BoundSet,
) {
    let mut refresh = tokio::time::interval(INTERFACE_REFRESH_INTERVAL);
    refresh.tick().await; // skip the immediate first tick
    let mut policy_sync = tokio::time::interval(POLICY_SYNC_INTERVAL);
    policy_sync.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                let live = sync_interface_targets(&router, port, &bootstrap, &bound, "refresh").await;
                info!(
                    stage = "household_listener.refresh",
                    target_count = live.len(),
                );
            }
            _ = policy_sync.tick() => {
                sync_exposure_policy(&bootstrap, &bound).await;
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

    fn ready_targets(context: &HouseholdListenerContext) -> Vec<(IpAddr, InterfaceClass)> {
        HouseholdExposurePolicy::allowed_targets(
            BootstrapState::Ready,
            enumerate_bind_targets_with_context(context),
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
            let onboarding = HouseholdExposurePolicy::allowed_targets(
                BootstrapState::Uninitialized,
                targets.clone(),
            );
            let bonjour = HouseholdExposurePolicy::bonjour_targets(
                BootstrapState::Uninitialized,
                targets.clone(),
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
        let onboarding = HouseholdExposurePolicy::allowed_targets(
            BootstrapState::Uninitialized,
            targets.clone(),
        );
        let bonjour = HouseholdExposurePolicy::bonjour_targets(
            BootstrapState::Uninitialized,
            targets.clone(),
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
            HouseholdExposurePolicy::bonjour_targets(BootstrapState::Ready, live)
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

    #[test]
    fn exposure_policy_onboarding_keeps_lan() {
        assert!(HouseholdExposurePolicy::allows(
            BootstrapState::Uninitialized,
            InterfaceClass::Lan
        ));
        assert!(HouseholdExposurePolicy::allows(
            BootstrapState::ReadyForNaming,
            InterfaceClass::Lan
        ));
    }

    #[test]
    fn exposure_policy_ready_excludes_lan_and_keeps_loopback_tailnet_mesh() {
        let targets = vec![
            (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
            ("192.0.2.10".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
        ];

        let allowed = HouseholdExposurePolicy::allowed_targets(BootstrapState::Ready, targets);
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
    fn mesh_uses_the_same_post_trust_exposure_gate_as_tailscale() {
        for state in [
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ] {
            assert_eq!(
                HouseholdExposurePolicy::allows(state, InterfaceClass::Mesh),
                HouseholdExposurePolicy::allows(state, InterfaceClass::Tailscale)
            );
            assert!(HouseholdExposurePolicy::allows(state, InterfaceClass::Mesh));
        }
        for state in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
        ] {
            assert!(!HouseholdExposurePolicy::allows(
                state,
                InterfaceClass::Mesh
            ));
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
            HouseholdExposurePolicy::bonjour_targets(BootstrapState::Ready, ready_targets),
            vec![("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale)]
        );

        let onboarding_targets = vec![
            ("192.168.1.2".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
        ];
        assert_eq!(
            HouseholdExposurePolicy::bonjour_targets(
                BootstrapState::Uninitialized,
                onboarding_targets
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
            assert!(!HouseholdExposurePolicy::allows(state, InterfaceClass::Lan));
            assert!(HouseholdExposurePolicy::allows(
                state,
                InterfaceClass::Loopback
            ));
            assert!(HouseholdExposurePolicy::allows(
                state,
                InterfaceClass::Tailscale
            ));
            assert!(HouseholdExposurePolicy::allows(state, InterfaceClass::Mesh));
        }
    }

    #[tokio::test]
    async fn exposure_policy_sync_shutdowns_disallowed_lan_listener() {
        let bound = BoundSet::default();
        let lan_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let tailnet_ip: IpAddr = "100.64.0.10".parse().unwrap();
        let (lan_shutdown, lan_rx) = oneshot::channel();
        let (tailnet_shutdown, _tailnet_rx) = oneshot::channel();
        bound
            .insert(lan_ip, InterfaceClass::Lan, lan_shutdown)
            .await;
        bound
            .insert(tailnet_ip, InterfaceClass::Tailscale, tailnet_shutdown)
            .await;

        let bootstrap = Arc::new(RwLock::new(BootstrapState::Ready));
        sync_exposure_policy(&bootstrap, &bound).await;

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
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found: Vec<String> = Vec::new();
        let mut stack = vec![src.clone()];
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
                let text = text
                    .split_once("\n#[cfg(test)]")
                    .map_or(text.as_str(), |(p, _)| p);
                for line in text.lines() {
                    if !line.contains("ProcessStartupToken") {
                        continue;
                    }
                    let trimmed = line.trim();
                    if trimmed.starts_with("///") || trimmed.starts_with("//") {
                        continue;
                    }
                    let name = path
                        .strip_prefix(&src)
                        .expect("path under src")
                        .to_string_lossy()
                        .into_owned();
                    found.push(format!("{name}: {trimmed}"));
                }
            }
        }
        found.sort();

        let expected = [
            "household_bootstrap.rs: startup: &household_listener::ProcessStartupToken,",
            "household_listener.rs: _startup: &ProcessStartupToken,",
            "household_listener.rs: impl ProcessStartupToken {",
            "household_listener.rs: pub struct ProcessStartupToken(());",
            "main.rs: let startup_token = server_rs::household_listener::ProcessStartupToken::claim()",
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
