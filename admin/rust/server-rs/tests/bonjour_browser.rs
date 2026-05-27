//! Simulated-mDNS coverage for the Phase 3 founder-side Bonjour browser.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::Platform;
use household_rs::owner_events::{OwnerEventLog, OwnerEventPayload, OwnerEventsBroadcaster};
use household_rs::pair_machine::{
    JoinTransport, PairMachineState, PairMachineWindow, PrepareCandidateOpts, prepare_candidate,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use server_rs::bonjour_browser::{JoinerAnnouncement, spawn_bonjour_browser_with_source};
use server_rs::handlers_pair_machine::{
    PairMachineRouterState, PreHouseholdRouterState, pre_household_router,
};
use server_rs::household_state::HouseholdState;
use tempfile::{TempDir, tempdir};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bootstrap(state_dir: &std::path::Path) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-founder".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap()
}

fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> HouseholdAuthState {
    let person = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
    )
    .unwrap();
    HouseholdAuthState::new(&identity.record, cert)
}

struct FounderHarness {
    _td: TempDir,
    state: PairMachineRouterState,
    window: Arc<PairMachineWindow>,
    event_log: Arc<OwnerEventLog>,
    _identity: Arc<household_rs::LoadedIdentity>,
}

fn founder_harness() -> FounderHarness {
    let td = tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let owner_auth = Arc::new(owner_auth_for(&identity));
    let household = HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(td.path().to_path_buf(), broadcaster.clone()).unwrap();
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let state = PairMachineRouterState {
        window: Arc::clone(&window),
        household,
        event_log: Arc::clone(&event_log),
        event_broadcaster: broadcaster,
        state_dir: td.path().to_path_buf(),
    };
    FounderHarness {
        _td: td,
        state,
        window,
        event_log,
        _identity: identity,
    }
}

struct CandidateHarness {
    _td: TempDir,
    prepared: household_rs::pair_machine::PreparedCandidate,
    addr: String,
}

async fn candidate_harness(hostname: &str) -> CandidateHarness {
    let td = tempdir().unwrap();
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host_port = listener.local_addr().unwrap().to_string();
    let addr = format!("http://{host_port}");
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Lan,
            addr: host_port,
            hostname: hostname.to_string(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();
    let router: Router = pre_household_router(PreHouseholdRouterState {
        window,
        state_dir: td.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
    });
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    CandidateHarness {
        _td: td,
        prepared,
        addr,
    }
}

fn announcement(
    _founder: &FounderHarness,
    candidate: &CandidateHarness,
    m_pub_b32: Option<String>,
) -> JoinerAnnouncement {
    // Per protocol §13 the joiner does NOT publish hh_id.
    JoinerAnnouncement {
        hh_id: None,
        addr: candidate.addr.clone(),
        pair_nonce: household_rs::ids::base32_lower_nopad_encode(
            &candidate.prepared.join_request.nonce.as_ref()[..8],
        ),
        m_pub_b32,
    }
}

async fn wait_for_window_state(window: &PairMachineWindow, expected: PairMachineState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if window.snapshot().await.state == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for window state {expected:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn published_joiner_with_correct_household_is_fetched_and_staged() {
    let founder = founder_harness();
    let candidate = candidate_harness("studio-joiner").await;
    let (tx, rx) = mpsc::channel(4);
    let browser = spawn_bonjour_browser_with_source(founder.state.clone(), rx);

    tx.send(announcement(
        &founder,
        &candidate,
        Some(household_rs::ids::m_pub_short(
            &candidate.prepared.m_pub_sec1,
        )),
    ))
    .await
    .unwrap();

    wait_for_window_state(&founder.window, PairMachineState::AwaitingOwner).await;
    let snap = founder.window.snapshot().await;
    assert_eq!(
        snap.cached_join_request.unwrap().as_ref(),
        candidate.prepared.join_request_cbor
    );
    assert_eq!(founder.event_log.read_since(0).unwrap().len(), 1);
    browser.abort();
}

#[tokio::test]
async fn published_joiner_with_wrong_household_is_ignored() {
    let founder = founder_harness();
    let candidate = candidate_harness("studio-joiner").await;
    let (tx, rx) = mpsc::channel(4);
    let browser = spawn_bonjour_browser_with_source(founder.state.clone(), rx);
    let mut wrong = announcement(
        &founder,
        &candidate,
        Some(household_rs::ids::m_pub_short(
            &candidate.prepared.m_pub_sec1,
        )),
    );
    wrong.hh_id = Some("hh_wronghousehold".to_string());

    tx.send(wrong).await.unwrap();

    let staged = tokio::time::timeout(
        Duration::from_millis(250),
        wait_for_window_state(&founder.window, PairMachineState::AwaitingOwner),
    )
    .await;
    assert!(staged.is_err());
    assert_eq!(
        founder.window.snapshot().await.state,
        PairMachineState::Idle
    );
    assert!(founder.event_log.read_since(0).unwrap().is_empty());
    browser.abort();
}

#[tokio::test]
async fn spoofed_txt_surfaces_fetched_join_request_fingerprint() {
    let founder = founder_harness();
    let attacker = candidate_harness("attacker-host").await;
    let unrelated = P256Keypair::generate().public().as_bytes().to_owned();
    let (tx, rx) = mpsc::channel(4);
    let browser = spawn_bonjour_browser_with_source(founder.state.clone(), rx);

    tx.send(announcement(
        &founder,
        &attacker,
        Some(household_rs::ids::m_pub_short(&unrelated)),
    ))
    .await
    .unwrap();

    wait_for_window_state(&founder.window, PairMachineState::AwaitingOwner).await;
    let events = founder.event_log.read_since(0).unwrap();
    assert_eq!(events.len(), 1);
    let OwnerEventPayload::JoinRequest(payload) = &events[0].payload else {
        panic!("expected join-request owner event");
    };
    assert_eq!(payload.fingerprint, attacker.prepared.fingerprint);
    browser.abort();
}
