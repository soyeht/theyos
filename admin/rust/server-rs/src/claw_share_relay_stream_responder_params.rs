//! Assembly of validated inputs for the future Product A `relay_stream` responder.
//!
//! This module does not bind sockets, spawn tasks, inspect offers, advertise
//! `relay_stream`, or wire bootstrap/iOS. It combines parsed responder config,
//! the Noise static key store, and the caller-supplied admission factory into a
//! single typed bundle.
//!
//! The admission factory is the Claw-side authorization anchor. It owns the
//! trust-context runtime and hands out a `RelayStreamIssuerTrust` only per
//! accepted connection while the trust context is healthy. This prevents the
//! future pool from caching a raw trust seam across admissions.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use keystore_rs::KeystoreBackend;

use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
use crate::claw_share_relay_stream_noise::RelayStreamNoiseStaticKeypair;
use crate::claw_share_relay_stream_noise_keystore::{
    RelayStreamNoiseKeyStore, RelayStreamNoiseKeyStoreError,
};
use crate::claw_share_relay_stream_responder_config::RelayStreamResponderConfig;

pub struct RelayStreamResponderParams {
    pub bind_addr: SocketAddr,
    pub auth_deadline: Duration,
    pub idle_timeout: Duration,
    /// Long-lived admission factory. A per-connection `RelayStreamIssuerTrust`
    /// seam is minted via `admission.admit(now)` at accept time, never cached
    /// here, so the health/stop-serving gate is re-applied per connection.
    pub admission: RelayStreamAdmission,
    pub noise_keypair: RelayStreamNoiseStaticKeypair,
}

impl fmt::Debug for RelayStreamResponderParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamResponderParams")
            .field("bind_addr", &self.bind_addr)
            .field("auth_deadline", &self.auth_deadline)
            .field("idle_timeout", &self.idle_timeout)
            .field("admission", &self.admission)
            .field("noise_keypair", &"RelayStreamNoiseStaticKeypair(redacted)")
            .finish()
    }
}

/// Assemble responder params from config, the Noise key store, and a required
/// admission factory.
///
/// The admission factory (which owns the trust runtime) is the long-lived
/// Claw-side authorization holder and is provided by the caller; this function
/// performs no live household/mesh wiring itself (that is C4's responsibility
/// when it builds the runtime/admission).
pub async fn assemble_relay_stream_responder_params(
    config: &RelayStreamResponderConfig,
    keystore_backend: &dyn KeystoreBackend,
    admission: RelayStreamAdmission,
) -> Result<RelayStreamResponderParams, RelayStreamResponderParamsError> {
    if !config.enabled {
        return Err(RelayStreamResponderParamsError::Disabled);
    }

    let noise_keypair =
        RelayStreamNoiseKeyStore::new(keystore_backend).get_or_create(&config.key_id)?;

    Ok(RelayStreamResponderParams {
        bind_addr: config.bind_addr,
        auth_deadline: config.auth_deadline,
        idle_timeout: config.idle_timeout,
        admission,
        noise_keypair,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamResponderParamsError {
    #[error("relay stream responder is disabled")]
    Disabled,

    #[error("relay stream responder keystore failed: {0}")]
    KeyStore(#[from] RelayStreamNoiseKeyStoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use keystore_rs::{FileKeystore, KeystoreBackend};

    use crate::claw_share_relay_stream_noise_keystore::{
        DEFAULT_RELAY_STREAM_NOISE_KEY_ID, RelayStreamNoiseKeyStore,
    };
    use crate::claw_share_relay_stream_responder_config::RelayStreamResponderConfig;
    use crate::claw_share_relay_stream_test_support::relay_stream_admission;

    fn config() -> RelayStreamResponderConfig {
        RelayStreamResponderConfig::new(
            "127.0.0.1:49152",
            Some(DEFAULT_RELAY_STREAM_NOISE_KEY_ID),
            Duration::from_secs(7),
            Duration::from_secs(77),
        )
        .unwrap()
    }

    fn disabled_config() -> RelayStreamResponderConfig {
        RelayStreamResponderConfig {
            enabled: false,
            ..config()
        }
    }

    fn backend(dir: &tempfile::TempDir) -> FileKeystore {
        FileKeystore::new(dir.path(), "com.soyeht.theyos.test")
    }

    fn key_account() -> String {
        RelayStreamNoiseKeyStore::account_for_key_id(DEFAULT_RELAY_STREAM_NOISE_KEY_ID).unwrap()
    }

    #[tokio::test]
    async fn relay_stream_responder_params_disabled_does_not_create_key() {
        let key_dir = tempfile::tempdir().unwrap();
        let backend = backend(&key_dir);

        let error = assemble_relay_stream_responder_params(
            &disabled_config(),
            &backend,
            relay_stream_admission().await,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, RelayStreamResponderParamsError::Disabled));
        assert!(!backend.path_for(&key_account()).exists());
    }

    #[tokio::test]
    async fn relay_stream_responder_params_preserves_inputs_and_reuses_key() {
        let key_dir = tempfile::tempdir().unwrap();
        let backend = backend(&key_dir);
        let cfg = config();

        let first =
            assemble_relay_stream_responder_params(&cfg, &backend, relay_stream_admission().await)
                .await
                .unwrap();
        let second =
            assemble_relay_stream_responder_params(&cfg, &backend, relay_stream_admission().await)
                .await
                .unwrap();

        assert_eq!(first.bind_addr, cfg.bind_addr);
        assert_eq!(first.auth_deadline, cfg.auth_deadline);
        assert_eq!(first.idle_timeout, cfg.idle_timeout);
        assert_eq!(
            first.noise_keypair.public_key(),
            second.noise_keypair.public_key()
        );
    }

    #[tokio::test]
    async fn relay_stream_responder_params_invalid_keystore_blob_is_key_store_error() {
        let key_dir = tempfile::tempdir().unwrap();
        let backend = backend(&key_dir);
        backend.set(&key_account(), b"not-cbor").unwrap();

        let error = assemble_relay_stream_responder_params(
            &config(),
            &backend,
            relay_stream_admission().await,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamResponderParamsError::KeyStore(_)
        ));
    }

    #[tokio::test]
    async fn relay_stream_responder_params_debug_redacts_secret_material() {
        let key_dir = tempfile::tempdir().unwrap();
        let backend = backend(&key_dir);
        let params = assemble_relay_stream_responder_params(
            &config(),
            &backend,
            relay_stream_admission().await,
        )
        .await
        .unwrap();

        let debug = format!("{params:?}");
        let key_debug = format!("{:?}", params.noise_keypair);
        assert!(debug.contains("redacted"));
        assert!(key_debug.contains("redacted"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("token"));
        assert!(!debug.contains("secret"));

        let error_debug = format!("{:?}", RelayStreamResponderParamsError::Disabled);
        assert!(!error_debug.contains("private"));
        assert!(!error_debug.contains("token"));
        assert!(!error_debug.contains("secret"));
    }
}
