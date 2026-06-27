//! Owner passkey/WebAuthn relying-party core.
//!
//! This is intentionally backend-only S1 scaffolding: it owns RP configuration,
//! server-side challenge state, replay/TTL semantics, and sign-count policy. UI,
//! Protocol-v2 envelopes, `IdP` federation, and persistence wiring are separate
//! slices. The `WebAuthn` ceremonies themselves are delegated to `webauthn-rs`;
//! we do not hand-roll COSE, client-data, or assertion verification.

use std::collections::HashMap;
use std::time::Duration;

use rand::RngCore;
use thiserror::Error;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::owner_approval_v2::{OwnerApprovalContextV2, OwnerOperation};

const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerWebauthnConfig {
    rp_id: String,
    rp_origin: Url,
    rp_name: String,
    challenge_ttl: Duration,
}

impl OwnerWebauthnConfig {
    /// Construct RP config for one tenant-owned domain.
    ///
    /// `rp_id` must be the tenant/domain-controlled relying-party ID. It must
    /// not be a shared Soyeht domain.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerWebauthnError::InvalidRpConfig`] if `webauthn-rs`
    /// rejects the RP ID / origin pair.
    pub fn new(
        rp_id: impl Into<String>,
        rp_origin: Url,
        rp_name: impl Into<String>,
    ) -> Result<Self, OwnerWebauthnError> {
        let config = Self {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: rp_name.into(),
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
        };
        config.build_webauthn()?;
        Ok(config)
    }

    #[must_use]
    pub fn with_challenge_ttl(mut self, challenge_ttl: Duration) -> Self {
        self.challenge_ttl = challenge_ttl;
        self
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    #[must_use]
    pub fn rp_origin(&self) -> &Url {
        &self.rp_origin
    }

    #[must_use]
    pub fn challenge_ttl(&self) -> Duration {
        self.challenge_ttl
    }

    fn build_webauthn(&self) -> Result<Webauthn, OwnerWebauthnError> {
        let mut builder = WebauthnBuilder::new(&self.rp_id, &self.rp_origin)
            .map_err(OwnerWebauthnError::InvalidRpConfig)?;
        builder = builder.rp_name(&self.rp_name);
        builder.build().map_err(OwnerWebauthnError::InvalidRpConfig)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnerWebauthnChallengeId(String);

impl OwnerWebauthnChallengeId {
    /// Generate a non-secret handle for server-side challenge state.
    ///
    /// This ID is not the `WebAuthn` challenge itself; it is a lookup key into
    /// the server-side store. The opaque `WebAuthn` state remains server-side.
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0_u8; 16];
        rng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Parse the lookup handle returned by the server at ceremony start.
    ///
    /// The handle is intentionally narrow: 16 random bytes encoded as 32
    /// lowercase hex characters. This keeps it as an opaque server-side lookup
    /// key, not an owner-controlled policy input.
    pub fn parse(value: impl Into<String>) -> Result<Self, OwnerWebauthnError> {
        let value = value.into();
        let valid = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(OwnerWebauthnError::InvalidChallengeId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnCredential {
    passkey: Passkey,
    last_sign_count: u32,
    revoked: bool,
}

impl OwnerWebauthnCredential {
    #[must_use]
    pub fn new(passkey: Passkey) -> Self {
        Self {
            passkey,
            last_sign_count: 0,
            revoked: false,
        }
    }

    #[must_use]
    pub fn credential_id_bytes(&self) -> &[u8] {
        self.passkey.cred_id().as_slice()
    }

    #[must_use]
    pub fn passkey(&self) -> &Passkey {
        &self.passkey
    }

    #[must_use]
    pub fn last_sign_count(&self) -> u32 {
        self.last_sign_count
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn apply_authentication_result(
        &mut self,
        result: &AuthenticationResult,
    ) -> Result<(), OwnerWebauthnError> {
        let counter = result.counter();
        // The counter update is local to the credential instance used for this
        // ceremony. The authority log does not persist sign-count advances yet,
        // so clone detection is best-effort until a future persist+anchor slice.
        validate_next_sign_count(self.last_sign_count, counter)?;
        if counter > self.last_sign_count {
            self.last_sign_count = counter;
        }
        self.passkey
            .update_credential(result)
            .ok_or(OwnerWebauthnError::CredentialMismatch)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct OwnerWebauthnCredentialStore {
    credentials: Vec<OwnerWebauthnCredential>,
}

impl OwnerWebauthnCredentialStore {
    #[must_use]
    pub fn credentials(&self) -> &[OwnerWebauthnCredential] {
        &self.credentials
    }

    #[must_use]
    pub fn active_credentials(&self) -> Vec<&OwnerWebauthnCredential> {
        self.credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .collect()
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .count()
    }

    pub fn add(&mut self, credential: OwnerWebauthnCredential) -> Result<(), OwnerWebauthnError> {
        if self
            .credentials
            .iter()
            .any(|existing| existing.credential_id_bytes() == credential.credential_id_bytes())
        {
            return Err(OwnerWebauthnError::DuplicateCredential);
        }
        self.credentials.push(credential);
        Ok(())
    }

    pub fn revoke_by_credential_id(
        &mut self,
        credential_id: &[u8],
    ) -> Result<(), OwnerWebauthnError> {
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.credential_id_bytes() == credential_id)
            .ok_or(OwnerWebauthnError::CredentialNotFound)?;
        credential.revoke();
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnError {
    #[error("invalid WebAuthn RP configuration: {0}")]
    InvalidRpConfig(WebauthnError),
    #[error("WebAuthn ceremony failed: {0}")]
    Ceremony(WebauthnError),
    #[error("challenge not found")]
    ChallengeNotFound,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("challenge kind mismatch")]
    ChallengeKindMismatch,
    #[error("challenge id is invalid")]
    InvalidChallengeId,
    #[error("no active credentials")]
    NoActiveCredentials,
    #[error("credential is already registered")]
    DuplicateCredential,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("credential is revoked")]
    CredentialRevoked,
    #[error("authentication credential did not match stored credential")]
    CredentialMismatch,
    #[error("challenge is not bound to owner approval context")]
    ChallengeContextMissing,
    #[error("challenge is bound to owner approval context")]
    ChallengeContextUnexpected,
    #[error("owner approval context does not match challenge state")]
    ChallengeContextMismatch,
    #[error("owner approval context failed validation: {0}")]
    ChallengeContext(String),
    #[error("signature counter regressed: previous={previous}, next={next}")]
    SignCountRegression { previous: u32, next: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerWebauthnContextBinding {
    operation: OwnerOperation,
    canonical_context: Vec<u8>,
    expected_context_digest: [u8; 32],
}

impl OwnerWebauthnContextBinding {
    pub fn from_context(context: &OwnerApprovalContextV2) -> Result<Self, OwnerWebauthnError> {
        let canonical_context = context
            .to_canonical_bytes()
            .map_err(|e| OwnerWebauthnError::ChallengeContext(e.to_string()))?;
        let expected_context_digest = context
            .challenge_digest()
            .map_err(|e| OwnerWebauthnError::ChallengeContext(e.to_string()))?;
        Ok(Self {
            operation: context.op,
            canonical_context,
            expected_context_digest,
        })
    }

    #[must_use]
    pub fn operation(&self) -> OwnerOperation {
        self.operation
    }

    #[must_use]
    pub fn canonical_context(&self) -> &[u8] {
        &self.canonical_context
    }

    #[must_use]
    pub fn expected_context_digest(&self) -> [u8; 32] {
        self.expected_context_digest
    }

    fn require_context(
        &self,
        submitted_context: &OwnerApprovalContextV2,
    ) -> Result<(), OwnerWebauthnError> {
        let submitted = submitted_context
            .to_canonical_bytes()
            .map_err(|e| OwnerWebauthnError::ChallengeContext(e.to_string()))?;
        if submitted != self.canonical_context {
            return Err(OwnerWebauthnError::ChallengeContextMismatch);
        }
        let submitted_digest = submitted_context
            .challenge_digest()
            .map_err(|e| OwnerWebauthnError::ChallengeContext(e.to_string()))?;
        if submitted_digest != self.expected_context_digest {
            return Err(OwnerWebauthnError::ChallengeContextMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ChallengeState {
    Registration(PasskeyRegistration),
    Authentication(StoredAuthenticationChallenge),
}

#[derive(Debug)]
struct StoredAuthenticationChallenge {
    state: PasskeyAuthentication,
    context_binding: Option<OwnerWebauthnContextBinding>,
}

#[derive(Debug)]
struct StoredChallenge {
    expires_at_unix: u64,
    state: ChallengeState,
}

#[derive(Debug, Default)]
pub struct OwnerWebauthnChallengeStore {
    challenges: HashMap<OwnerWebauthnChallengeId, StoredChallenge>,
}

impl OwnerWebauthnChallengeStore {
    #[must_use]
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }

    fn insert_registration(
        &mut self,
        challenge_id: OwnerWebauthnChallengeId,
        state: PasskeyRegistration,
        expires_at_unix: u64,
    ) {
        self.challenges.insert(
            challenge_id,
            StoredChallenge {
                expires_at_unix,
                state: ChallengeState::Registration(state),
            },
        );
    }

    fn insert_authentication(
        &mut self,
        challenge_id: OwnerWebauthnChallengeId,
        state: PasskeyAuthentication,
        context_binding: Option<OwnerWebauthnContextBinding>,
        expires_at_unix: u64,
    ) {
        self.challenges.insert(
            challenge_id,
            StoredChallenge {
                expires_at_unix,
                state: ChallengeState::Authentication(StoredAuthenticationChallenge {
                    state,
                    context_binding,
                }),
            },
        );
    }

    fn take_registration(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<PasskeyRegistration, OwnerWebauthnError> {
        let stored = self
            .challenges
            .remove(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        if now_unix > stored.expires_at_unix {
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        match stored.state {
            ChallengeState::Registration(state) => Ok(state),
            ChallengeState::Authentication(_) => Err(OwnerWebauthnError::ChallengeKindMismatch),
        }
    }

    #[cfg(test)]
    fn take_authentication(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<StoredAuthenticationChallenge, OwnerWebauthnError> {
        let stored = self
            .challenges
            .remove(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        if now_unix > stored.expires_at_unix {
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        match stored.state {
            ChallengeState::Authentication(state) => Ok(state),
            ChallengeState::Registration(_) => Err(OwnerWebauthnError::ChallengeKindMismatch),
        }
    }

    fn authentication(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<&StoredAuthenticationChallenge, OwnerWebauthnError> {
        let expires_at_unix = self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?
            .expires_at_unix;
        if now_unix > expires_at_unix {
            self.challenges.remove(challenge_id);
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        match &self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?
            .state
        {
            ChallengeState::Authentication(state) => Ok(state),
            ChallengeState::Registration(_) => Err(OwnerWebauthnError::ChallengeKindMismatch),
        }
    }

    fn consume_authentication(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
    ) -> Result<StoredAuthenticationChallenge, OwnerWebauthnError> {
        let stored = self
            .challenges
            .remove(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        match stored.state {
            ChallengeState::Authentication(state) => Ok(state),
            ChallengeState::Registration(_) => Err(OwnerWebauthnError::ChallengeKindMismatch),
        }
    }
}

#[derive(Debug)]
pub struct OwnerWebauthnRp {
    webauthn: Webauthn,
    config: OwnerWebauthnConfig,
    challenges: OwnerWebauthnChallengeStore,
}

impl OwnerWebauthnRp {
    /// Build a tenant-scoped owner-auth relying party.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerWebauthnError::InvalidRpConfig`] if `webauthn-rs`
    /// rejects the RP ID / origin pair.
    pub fn new(config: OwnerWebauthnConfig) -> Result<Self, OwnerWebauthnError> {
        let webauthn = config.build_webauthn()?;
        Ok(Self {
            webauthn,
            config,
            challenges: OwnerWebauthnChallengeStore::default(),
        })
    }

    #[must_use]
    pub fn config(&self) -> &OwnerWebauthnConfig {
        &self.config
    }

    #[must_use]
    pub fn challenge_store_len(&self) -> usize {
        self.challenges.len()
    }

    pub fn start_registration(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        owner_user_id: Uuid,
        owner_name: &str,
        owner_display_name: &str,
        existing_credentials: &[OwnerWebauthnCredential],
    ) -> Result<(OwnerWebauthnChallengeId, CreationChallengeResponse), OwnerWebauthnError> {
        let exclude_credentials = existing_credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .map(|credential| credential.passkey().cred_id().clone())
            .collect::<Vec<_>>();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                owner_user_id,
                owner_name,
                owner_display_name,
                Some(exclude_credentials),
            )
            .map_err(OwnerWebauthnError::Ceremony)?;
        let id = OwnerWebauthnChallengeId::random(rng);
        self.challenges.insert_registration(
            id.clone(),
            state,
            now_unix + self.config.challenge_ttl().as_secs(),
        );
        Ok((id, challenge))
    }

    pub fn finish_registration(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<OwnerWebauthnCredential, OwnerWebauthnError> {
        let state = self.challenges.take_registration(challenge_id, now_unix)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(OwnerWebauthnError::Ceremony)?;
        Ok(OwnerWebauthnCredential::new(passkey))
    }

    pub fn start_assertion(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        credentials: &[OwnerWebauthnCredential],
    ) -> Result<(OwnerWebauthnChallengeId, RequestChallengeResponse), OwnerWebauthnError> {
        self.start_assertion_with_binding(rng, now_unix, credentials, None)
    }

    pub fn start_owner_approval_assertion(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        credentials: &[OwnerWebauthnCredential],
        expected_context: &OwnerApprovalContextV2,
    ) -> Result<(OwnerWebauthnChallengeId, RequestChallengeResponse), OwnerWebauthnError> {
        let context_binding = OwnerWebauthnContextBinding::from_context(expected_context)?;
        self.start_assertion_with_binding(rng, now_unix, credentials, Some(context_binding))
    }

    fn start_assertion_with_binding(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        credentials: &[OwnerWebauthnCredential],
        context_binding: Option<OwnerWebauthnContextBinding>,
    ) -> Result<(OwnerWebauthnChallengeId, RequestChallengeResponse), OwnerWebauthnError> {
        let active_credentials = credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .map(|credential| credential.passkey().clone())
            .collect::<Vec<_>>();
        if active_credentials.is_empty() {
            return Err(OwnerWebauthnError::NoActiveCredentials);
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&active_credentials)
            .map_err(OwnerWebauthnError::Ceremony)?;
        let id = OwnerWebauthnChallengeId::random(rng);
        self.challenges.insert_authentication(
            id.clone(),
            state,
            context_binding,
            now_unix + self.config.challenge_ttl().as_secs(),
        );
        Ok((id, challenge))
    }

    pub fn finish_assertion(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        assertion: &PublicKeyCredential,
        credential: &mut OwnerWebauthnCredential,
    ) -> Result<(), OwnerWebauthnError> {
        if credential.is_revoked() {
            return Err(OwnerWebauthnError::CredentialRevoked);
        }
        let result = {
            let stored_challenge = self.challenges.authentication(challenge_id, now_unix)?;
            if stored_challenge.context_binding.is_some() {
                return Err(OwnerWebauthnError::ChallengeContextUnexpected);
            }
            self.webauthn
                .finish_passkey_authentication(assertion, &stored_challenge.state)
                .map_err(OwnerWebauthnError::Ceremony)?
        };
        let stored_challenge = self.challenges.consume_authentication(challenge_id)?;
        debug_assert!(stored_challenge.context_binding.is_none());
        credential.apply_authentication_result(&result)
    }

    pub fn finish_owner_approval_assertion(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        assertion: &PublicKeyCredential,
        credential: &mut OwnerWebauthnCredential,
        submitted_context: &OwnerApprovalContextV2,
    ) -> Result<(), OwnerWebauthnError> {
        if credential.is_revoked() {
            return Err(OwnerWebauthnError::CredentialRevoked);
        }
        let result = {
            let stored_challenge = self.challenges.authentication(challenge_id, now_unix)?;
            self.webauthn
                .finish_passkey_authentication(assertion, &stored_challenge.state)
                .map_err(OwnerWebauthnError::Ceremony)?
        };
        let stored_challenge = self.challenges.consume_authentication(challenge_id)?;
        let context_binding = stored_challenge
            .context_binding
            .ok_or(OwnerWebauthnError::ChallengeContextMissing)?;
        context_binding.require_context(submitted_context)?;
        credential.apply_authentication_result(&result)
    }
}

pub fn validate_next_sign_count(previous: u32, next: u32) -> Result<(), OwnerWebauthnError> {
    // Synced platform passkeys commonly report zero forever. Treat zero as an
    // unknown counter baseline, not as durable clone-detection evidence.
    if previous > 0 && next <= previous {
        return Err(OwnerWebauthnError::SignCountRegression { previous, next });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::ids::{HouseholdId, MachineId};
    use crate::machine_cert::PersonId;
    use crate::owner_approval_v2::{OwnerApprovalContextV2, PairMachineApprovalContextInput};
    use crate::pair_machine::{JoinTransport, join_request_hash};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use serde_json::json;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::Url;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn config() -> OwnerWebauthnConfig {
        OwnerWebauthnConfig::new(
            "alpha.example.test",
            Url::parse("https://alpha.example.test").unwrap(),
            "Soyeht Alpha",
        )
        .unwrap()
        .with_challenge_ttl(Duration::from_secs(60))
    }

    fn rp() -> OwnerWebauthnRp {
        OwnerWebauthnRp::new(config()).unwrap()
    }

    fn synthetic_passkey(id: &[u8]) -> Passkey {
        let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
        serde_json::from_value(json!({
            "cred": {
                "cred_id": encoded_id,
                "cred": {
                    "type_": "ES256",
                    "key": {
                        "EC_EC2": {
                            "curve": "SECP256R1",
                            "x": data_encoding::BASE64URL_NOPAD.encode(&[1_u8; 32]),
                            "y": data_encoding::BASE64URL_NOPAD.encode(&[2_u8; 32])
                        }
                    }
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": true,
                "backup_state": true,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {
                    "data": "None",
                    "metadata": "None"
                },
                "attestation_format": "none"
            }
        }))
        .unwrap()
    }

    fn synthetic_credential(id: &[u8]) -> OwnerWebauthnCredential {
        OwnerWebauthnCredential::new(synthetic_passkey(id))
    }

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn machine_id() -> MachineId {
        MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
    }

    fn owner_person_id() -> PersonId {
        PersonId("p_owner-alpha".to_string())
    }

    fn owner_approval_context(join_request_bytes: &[u8]) -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id: household_id(),
            owner_p_id: owner_person_id(),
            cursor: 7,
            m_id: machine_id(),
            addr: "192.0.2.10:8091".to_string(),
            transport: JoinTransport::Lan,
            ttl_unix: NOW + 60,
            nonce: [0x11; 32],
            join_request_hash: join_request_hash(join_request_bytes),
            capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
            issued_at: NOW,
            expires_at: NOW + 60,
            replay_nonce: [0x22; 32],
        })
    }

    fn register_with_softpasskey(
        rp: &mut OwnerWebauthnRp,
        rng: &mut StdRng,
    ) -> (OwnerWebauthnCredential, WebauthnAuthenticator<SoftPasskey>) {
        let (challenge_id, challenge) = rp
            .start_registration(rng, NOW, Uuid::new_v4(), "owner-alpha", "Owner Alpha", &[])
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = authenticator
            .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();
        let credential = rp
            .finish_registration(NOW, &challenge_id, &response)
            .unwrap();
        (credential, authenticator)
    }

    #[test]
    fn tenant_rp_id_and_origin_are_validated_by_webauthn_rs() {
        let ok = OwnerWebauthnConfig::new(
            "alpha.example.test",
            Url::parse("https://alpha.example.test").unwrap(),
            "Soyeht Alpha",
        );
        assert!(ok.is_ok());

        let bad = OwnerWebauthnConfig::new(
            "alpha.example.test",
            Url::parse("https://beta.example.test").unwrap(),
            "Soyeht Alpha",
        );
        assert!(matches!(bad, Err(OwnerWebauthnError::InvalidRpConfig(_))));
    }

    #[test]
    fn registration_state_is_server_side_single_use() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(42);
        let (challenge_id, _challenge) = rp
            .start_registration(
                &mut rng,
                NOW,
                Uuid::new_v4(),
                "owner-alpha",
                "Owner Alpha",
                &[],
            )
            .unwrap();
        assert_eq!(rp.challenge_store_len(), 1);

        let first = rp.challenges.take_registration(&challenge_id, NOW);
        assert!(first.is_ok());
        assert_eq!(rp.challenge_store_len(), 0);

        let replay = rp.challenges.take_registration(&challenge_id, NOW);
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn expired_registration_challenge_is_removed_and_rejected() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(43);
        let (challenge_id, _challenge) = rp
            .start_registration(
                &mut rng,
                NOW,
                Uuid::new_v4(),
                "owner-alpha",
                "Owner Alpha",
                &[],
            )
            .unwrap();

        let expired = rp.challenges.take_registration(&challenge_id, NOW + 61);
        assert!(matches!(expired, Err(OwnerWebauthnError::ChallengeExpired)));
        let replay = rp.challenges.take_registration(&challenge_id, NOW);
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn challenge_kind_mismatch_consumes_state() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(44);
        let (challenge_id, _challenge) = rp
            .start_registration(
                &mut rng,
                NOW,
                Uuid::new_v4(),
                "owner-alpha",
                "Owner Alpha",
                &[],
            )
            .unwrap();

        let wrong_kind = rp.challenges.take_authentication(&challenge_id, NOW);
        assert!(matches!(
            wrong_kind,
            Err(OwnerWebauthnError::ChallengeKindMismatch)
        ));
        assert!(rp.challenges.is_empty());
    }

    #[test]
    fn assertion_requires_at_least_one_active_credential() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(45);
        let err = rp.start_assertion(&mut rng, NOW, &[]).unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::NoActiveCredentials));
    }

    #[test]
    fn credential_store_tracks_active_and_revoked_credentials() {
        let mut store = OwnerWebauthnCredentialStore::default();
        store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
        store.add(synthetic_credential(b"owner-passkey-2")).unwrap();

        assert_eq!(store.credentials().len(), 2);
        assert_eq!(store.active_count(), 2);

        store.revoke_by_credential_id(b"owner-passkey-1").unwrap();
        assert_eq!(store.credentials().len(), 2);
        assert_eq!(store.active_count(), 1);
        assert_eq!(
            store.active_credentials()[0].credential_id_bytes(),
            b"owner-passkey-2"
        );
    }

    #[test]
    fn credential_store_rejects_duplicate_credential_ids() {
        let mut store = OwnerWebauthnCredentialStore::default();
        store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
        let err = store
            .add(synthetic_credential(b"owner-passkey-1"))
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::DuplicateCredential));
    }

    #[test]
    fn credential_store_rejects_unknown_revocation() {
        let mut store = OwnerWebauthnCredentialStore::default();
        let err = store
            .revoke_by_credential_id(b"missing-passkey")
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::CredentialNotFound));
    }

    #[test]
    fn assertion_uses_only_active_credentials() {
        let mut store = OwnerWebauthnCredentialStore::default();
        store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
        store.add(synthetic_credential(b"owner-passkey-2")).unwrap();
        store.revoke_by_credential_id(b"owner-passkey-1").unwrap();

        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(46);
        let (challenge_id, _challenge) = rp
            .start_assertion(&mut rng, NOW, store.credentials())
            .unwrap();

        assert_eq!(rp.challenge_store_len(), 1);
        assert!(
            rp.challenges
                .take_authentication(&challenge_id, NOW)
                .is_ok()
        );
    }

    #[test]
    fn assertion_rejects_all_revoked_credentials() {
        let mut store = OwnerWebauthnCredentialStore::default();
        store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
        store.revoke_by_credential_id(b"owner-passkey-1").unwrap();

        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(47);
        let err = rp
            .start_assertion(&mut rng, NOW, store.credentials())
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::NoActiveCredentials));
        assert_eq!(rp.challenge_store_len(), 0);
    }

    #[test]
    fn softpasskey_register_and_assertion_round_trip() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(48);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);

        let (challenge_id, challenge) = rp
            .start_assertion(&mut rng, NOW + 1, &[credential.clone()])
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential)
            .unwrap();
        assert_eq!(rp.challenge_store_len(), 0);

        let replay = rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential);
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn owner_approval_assertion_requires_bound_context_bytes() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(50);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
        let expected_context = owner_approval_context(b"join request A");

        let (challenge_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 1,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        rp.finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        )
        .unwrap();
        assert_eq!(rp.challenge_store_len(), 0);

        let replay = rp.finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        );
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn owner_approval_assertion_rejects_context_a_challenge_with_context_b_body() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(51);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
        let expected_context = owner_approval_context(b"join request A");
        let submitted_context = owner_approval_context(b"join request B");

        let (challenge_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 1,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        let err = rp
            .finish_owner_approval_assertion(
                NOW + 1,
                &challenge_id,
                &assertion,
                &mut credential,
                &submitted_context,
            )
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::ChallengeContextMismatch));
        assert_eq!(rp.challenge_store_len(), 0);

        let replay = rp.finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        );
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn owner_approval_assertion_rejects_expired_and_consumed_context_challenges() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(52);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
        let expected_context = owner_approval_context(b"join request A");

        let (expired_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 1,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();
        let expired = rp.finish_owner_approval_assertion(
            NOW + 62,
            &expired_id,
            &assertion,
            &mut credential,
            &expected_context,
        );
        assert!(matches!(expired, Err(OwnerWebauthnError::ChallengeExpired)));

        let (challenge_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 2,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();
        rp.finish_owner_approval_assertion(
            NOW + 2,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        )
        .unwrap();
        let consumed = rp.finish_owner_approval_assertion(
            NOW + 2,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        );
        assert!(matches!(
            consumed,
            Err(OwnerWebauthnError::ChallengeNotFound)
        ));
    }

    #[test]
    fn owner_approval_finish_rejects_and_consumes_legacy_unbound_challenge() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(53);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
        let expected_context = owner_approval_context(b"join request A");

        let (challenge_id, challenge) = rp
            .start_assertion(&mut rng, NOW + 1, &[credential.clone()])
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        let err = rp
            .finish_owner_approval_assertion(
                NOW + 1,
                &challenge_id,
                &assertion,
                &mut credential,
                &expected_context,
            )
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::ChallengeContextMissing));

        let replay = rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential);
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
        assert_eq!(rp.challenge_store_len(), 0);
    }

    #[test]
    fn legacy_assertion_finish_rejects_context_bound_challenge() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(54);
        let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
        let expected_context = owner_approval_context(b"join request A");

        let (challenge_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 1,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        let err = rp
            .finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerWebauthnError::ChallengeContextUnexpected
        ));
    }

    #[test]
    fn finish_paths_reject_authentication_result_for_wrong_credential() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(55);
        let (mut signing_credential, mut signing_authenticator) =
            register_with_softpasskey(&mut rp, &mut rng);
        let (mut other_credential, _) = register_with_softpasskey(&mut rp, &mut rng);

        let (legacy_id, legacy_challenge) = rp
            .start_assertion(&mut rng, NOW + 1, &[signing_credential.clone()])
            .unwrap();
        let legacy_assertion = signing_authenticator
            .do_authentication(
                Url::parse("https://alpha.example.test").unwrap(),
                legacy_challenge,
            )
            .unwrap();
        let err = rp
            .finish_assertion(
                NOW + 1,
                &legacy_id,
                &legacy_assertion,
                &mut other_credential,
            )
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::CredentialMismatch));
        assert_eq!(rp.challenge_store_len(), 0);

        let expected_context = owner_approval_context(b"join request A");
        let (approval_id, approval_challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 2,
                &[signing_credential.clone()],
                &expected_context,
            )
            .unwrap();
        let approval_assertion = signing_authenticator
            .do_authentication(
                Url::parse("https://alpha.example.test").unwrap(),
                approval_challenge,
            )
            .unwrap();
        let err = rp
            .finish_owner_approval_assertion(
                NOW + 2,
                &approval_id,
                &approval_assertion,
                &mut other_credential,
                &expected_context,
            )
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::CredentialMismatch));
        assert_eq!(rp.challenge_store_len(), 0);

        let replay = rp.finish_owner_approval_assertion(
            NOW + 2,
            &approval_id,
            &approval_assertion,
            &mut signing_credential,
            &expected_context,
        );
        assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    }

    #[test]
    fn softpasskey_assertion_rejects_origin_mismatch() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(56);
        let (credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);

        let (_challenge_id, challenge) = rp
            .start_assertion(&mut rng, NOW + 1, &[credential])
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://beta.example.test").unwrap(), challenge);

        assert!(assertion.is_err());
    }

    #[test]
    fn sign_count_policy_treats_zero_as_synced_passkey_unknown_baseline() {
        assert!(validate_next_sign_count(0, 0).is_ok());
        assert!(validate_next_sign_count(0, 1).is_ok());
        assert!(validate_next_sign_count(0, 10).is_ok());
        assert!(validate_next_sign_count(1, 2).is_ok());
    }

    #[test]
    fn sign_count_rejects_regression_after_counter_is_established() {
        assert!(matches!(
            validate_next_sign_count(10, 10),
            Err(OwnerWebauthnError::SignCountRegression {
                previous: 10,
                next: 10
            })
        ));
        assert!(matches!(
            validate_next_sign_count(10, 9),
            Err(OwnerWebauthnError::SignCountRegression {
                previous: 10,
                next: 9
            })
        ));
        assert!(matches!(
            validate_next_sign_count(10, 0),
            Err(OwnerWebauthnError::SignCountRegression {
                previous: 10,
                next: 0
            })
        ));
    }
}
