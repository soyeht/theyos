use std::time::Duration;

use household_rs::pair_device::{PairDeviceWindow, PairDeviceWindowState};

#[tokio::test]
async fn pair_device_window_state_mirrors_bonjour_txt_contract() {
    let window = PairDeviceWindow::new();
    let mut rx = window.subscribe();
    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let state = rx.recv().await.unwrap();
    match state {
        PairDeviceWindowState::Open { short_nonce } => {
            assert_eq!(short_nonce, token.nonce.as_short_b64());
        }
        PairDeviceWindowState::Closed => panic!("window opened but emitted closed"),
    }

    window.consume_token(&token.nonce).await.unwrap();
    assert!(matches!(
        rx.recv().await.unwrap(),
        PairDeviceWindowState::Closed
    ));
}
