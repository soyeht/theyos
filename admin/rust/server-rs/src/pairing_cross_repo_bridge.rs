//! Test-only HTTP host for the Swift/Rust pairing contract gate.
//! Uses temporary software identities and ephemeral loopback ports. It never
//! starts the engine, reconciles host interfaces, or accesses installed state.

use super::{BoundSet, InterfaceClass};
use crate::{
    handlers_bootstrap::{BootstrapHandlerState, bootstrap_router},
    handlers_device_pairing as devices,
    handlers_owner_events::OwnerEventsRouterState,
    handlers_pair_device::{self, PairDeviceState},
    household_state::HouseholdState,
    local_network_visibility::{LocalNetworkVisibility, local_network_visibility_router},
    pairing_addresses::{self, PairingAddressesState, PairingInstallation},
};
use axum::Router;
use household_rs::{
    BootstrapOpts, HouseholdAuthState, KeyBackingPolicy,
    bootstrap_state::BootstrapState,
    household_lifecycle::HouseholdLifecycleLock,
    keys::{IdentityKey, P256Keypair},
    owner_events::{OwnerEventLog, OwnerEventsBroadcaster},
    pair_device::PairDeviceWindow,
    pair_machine::PairMachineWindow,
    person_cert::{PersonCert, SignOwnerOptions},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::RwLock};

fn verify_swift_phone(
    _: &str,
    token: &[u8; 32],
    installation: &PairingInstallation,
) -> Result<crate::setup_invitation::VerifiedInvitation, String> {
    let dir =
        std::env::var_os("SOYEHT_PAIRING_CONTRACT_DIR").ok_or("missing_contract_directory")?;
    let bytes = std::fs::read(PathBuf::from(dir).join("phone-verify.cbor"))
        .map_err(|_| "missing_swift_producer")?;
    // Replace transport only. This is the exact production callback consumer.
    crate::setup_invitation::decode_verified_invitation(&bytes, token, installation, None)
}

struct Fixture {
    bootstrap: BootstrapHandlerState,
    bound: BoundSet,
    visibility: Arc<LocalNetworkVisibility>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = BootstrapHandlerState::new(
            Arc::new(RwLock::new(BootstrapState::Uninitialized)),
            HouseholdState::empty(),
            dir.path().to_path_buf(),
            Arc::new(PairDeviceWindow::new()),
            Arc::new(PairMachineWindow::new_in_memory()),
            8091,
        )
        .with_pair_code_rate_limiter(Arc::new(
            crate::ratelimit::Limiter::new(":memory:", 1000).unwrap(),
        ));
        bootstrap.installation = PairingInstallation::new("release".into(), 8091);
        bootstrap.invitation_verifier = verify_swift_phone;
        let bound = BoundSet::default();
        // Controlled interface observations for wire/policy tests. Actual bind
        // lifetime and failed-bind behavior are tested in household_listener.
        for (ip, class) in [
            ("100.64.0.10", InterfaceClass::Tailscale),
            ("192.168.1.20", InterfaceClass::Lan),
        ] {
            let (shutdown, _receiver) = tokio::sync::oneshot::channel();
            bound.insert(ip.parse().unwrap(), class, shutdown).await;
        }
        Self {
            bootstrap,
            bound,
            visibility: Arc::new(LocalNetworkVisibility::new()),
            _dir: dir,
        }
    }

    fn bootstrap_router(&self) -> Router {
        bootstrap_router(self.bootstrap.clone())
            .merge(local_network_visibility_router(Arc::clone(
                &self.visibility,
            )))
            .merge(pairing_addresses::router(PairingAddressesState::new(
                self.bound.clone(),
                Arc::clone(&self.bootstrap.bootstrap),
                self.bootstrap.household.clone(),
                Arc::clone(&self.bootstrap.pair_device_window),
                Arc::clone(&self.visibility),
                self.bootstrap.installation.clone(),
            )))
            .merge(handlers_pair_device::pair_device_router(PairDeviceState {
                window: Arc::clone(&self.bootstrap.pair_device_window),
                household: self.bootstrap.household.clone(),
                state_dir: self.bootstrap.state_dir.clone(),
            }))
    }

    async fn established(&self, output: &Path) -> Router {
        let identity = Arc::new(
            household_rs::bootstrap_or_load(
                &self.bootstrap.state_dir,
                BootstrapOpts {
                    household_name: "Contract Home".into(),
                    hostname_label: Some("contract-mac".into()),
                },
                KeyBackingPolicy::ForceSoftware,
            )
            .unwrap(),
        );
        // A public test scalar shared with the Swift contract producer. It is
        // never written to installed storage or used outside this test host.
        let owner = P256Keypair::from_secret_scalar(&[1; 32]).unwrap();
        let certificate = PersonCert::sign_owner(
            identity.hh_priv.as_deref().unwrap(),
            SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: owner.public(),
                display_name: "Contract Owner".into(),
                issued_at: crate::time_util::unix_now_secs_checked("contract").unwrap(),
            },
        )
        .unwrap();
        std::fs::write(
            output.join("owner-cert.cbor"),
            household_rs::cbor::to_canonical_vec(&certificate).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("household-public-key.bin"),
            identity.record.hh_pub.as_bytes(),
        )
        .unwrap();
        std::fs::write(
            output.join("household-id.txt"),
            identity.record.hh_id.as_str(),
        )
        .unwrap();
        self.bootstrap
            .household
            .set_loaded(Arc::clone(&identity))
            .await;
        self.bootstrap
            .household
            .set_owner_auth(Arc::new(HouseholdAuthState::new(
                &identity.record,
                certificate,
            )))
            .await;
        *self.bootstrap.bootstrap.write().await = BootstrapState::Ready;
        self.visibility.open(Duration::from_secs(300)).await;
        let broadcaster = OwnerEventsBroadcaster::new();
        let lifecycle = HouseholdLifecycleLock::open_verified(&self.bootstrap.state_dir).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let events = OwnerEventLog::open_with_broadcaster_under_lifecycle(
            &guard,
            self.bootstrap.state_dir.clone(),
            identity.record.hh_id.as_str(),
            broadcaster.clone(),
        )
        .unwrap();
        drop(guard);
        let sign_router = crate::handlers_sign_machine_cert::sign_machine_cert_router(
            crate::handlers_sign_machine_cert::SignMachineCertRouterState {
                household: self.bootstrap.household.clone(),
                event_log: Arc::clone(&events),
                state_dir: self.bootstrap.state_dir.clone(),
            },
        );
        let state = OwnerEventsRouterState::new(
            self.bootstrap.household.clone(),
            Arc::clone(&self.bootstrap.pair_machine_window),
            events,
            broadcaster,
            self.bootstrap.state_dir.clone(),
            KeyBackingPolicy::ForceSoftware,
        );
        self.bootstrap_router()
            .merge(sign_router)
            .merge(devices::device_pairing_router(state))
    }
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    assert!(![8091, 8101, 8892].contains(&address.port()));
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Run explicitly through scripts/pairing-contract-gate.py with both checkouts"]
async fn serve_cross_repo_contract() {
    let output = PathBuf::from(
        std::env::var_os("SOYEHT_PAIRING_CONTRACT_DIR").expect("contract directory required"),
    );
    let swift = PathBuf::from(
        std::env::var_os("SOYEHT_PAIRING_SWIFT_ROOT").expect("Swift checkout required"),
    );
    assert!(
        swift
            .join("docs/contracts/pairing/v1/route-catalog.json")
            .is_file()
    );
    core_rs::env::set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let founder = Fixture::fresh().await;
    let ready = Fixture::fresh().await;
    let joiner = Fixture::fresh().await;
    let reissue = Fixture::fresh().await;
    let identity = household_rs::bootstrap_or_load(
        &reissue.bootstrap.state_dir,
        BootstrapOpts {
            household_name: "Contract Reissue".into(),
            hostname_label: Some("contract-reissue".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    reissue
        .bootstrap
        .household
        .set_loaded(Arc::new(identity))
        .await;
    *reissue.bootstrap.bootstrap.write().await = BootstrapState::NamedAwaitingPair;
    let (founder_url, founder_task) = serve(founder.bootstrap_router()).await;
    let (ready_url, ready_task) = serve(ready.established(&output).await).await;
    let (joiner_url, joiner_task) = serve(joiner.bootstrap_router()).await;
    let (reissue_url, reissue_task) = serve(reissue.bootstrap_router()).await;
    std::fs::write(output.join("bridge.json"), serde_json::to_vec(&serde_json::json!({
        "founder": founder_url, "ready": ready_url, "joiner": joiner_url, "reissue": reissue_url,
    })).unwrap()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while !output.join("stop").exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Swift consumer did not finish before deadline"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for task in [founder_task, ready_task, joiner_task, reissue_task] {
        task.abort();
    }
}
