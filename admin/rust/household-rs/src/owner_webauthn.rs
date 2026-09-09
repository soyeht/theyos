//! Owner passkey/WebAuthn relying-party core.
//!
//! This is intentionally backend-only S1 scaffolding: it owns RP configuration,
//! server-side challenge state, replay/TTL semantics, and sign-count policy. UI,
//! Protocol-v2 envelopes, `IdP` federation, and persistence wiring are separate
//! slices. The `WebAuthn` ceremonies themselves are delegated to `webauthn-rs`;
//! we do not hand-roll COSE, client-data, or assertion verification.

pub mod anchor;
pub mod authority;
pub mod recovery;
pub mod recovery_anchor;
pub mod recovery_consume;

use std::collections::HashMap;
use std::time::Duration;

use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use webauthn_rs::DEFAULT_AUTHENTICATOR_TIMEOUT;
use webauthn_rs::prelude::{
    AuthenticationResult, AuthenticatorAttachment, CreationChallengeResponse, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{AttestationFormat, Credential, RegistrationState};

use crate::owner_approval_v2::{OwnerApprovalContextV2, OwnerOperation};

const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const REGISTRATION_BINDING_DOMAIN: &[u8] = b"soyeht-owner-webauthn-registration-binding-v1\0";

mod macos_local_attested_registration {
    use webauthn_rs::prelude::{
        AttestationCaList, AttestationFormat, AuthenticatorAttachment, CreationChallengeResponse,
        CredentialID, Passkey, RegisterPublicKeyCredential,
    };
    use webauthn_rs_core::WebauthnCore;
    use webauthn_rs_core::proto::{
        AttestationConveyancePreference, CredProtect, Credential, CredentialProtectionPolicy,
        ParsedAttestationData, PublicKeyCredentialHints, RegistrationState,
        RequestRegistrationExtensions, UserVerificationPolicy,
    };

    use super::{
        OwnerWebauthnError, OwnerWebauthnLocalAttestationEvidence, OwnerWebauthnRegistrationStart,
        VerifiedLocalAppleAttestedCredential,
    };

    pub(super) const APPLE_WEBAUTHN_ROOT_POLICY_VERSION: &str = "apple-webauthn-root-ca-2020-03-18";
    pub(super) const APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT: &str = "09:15:DD:5C:07:A2:8D:B5:49:D1:F6:77:BB:5A:75:D4:BF:BE:95:61:A7:73:42:43:27:76:2E:9E:02:F9:BB:29";
    /// Public Apple `WebAuthn` root CA from Apple's certificate authority listing.
    ///
    /// Provenance:
    /// - <https://www.apple.com/certificateauthority/private/>
    /// - <https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem>
    /// - Same PEM is carried by `webauthn-rs-device-catalog 0.5.0-20230418`.
    ///
    /// This must remain a single Apple-only root policy. Do not replace it with
    /// a default CA list, a platform trust store, or a broad device catalog.
    /// Active local enrollment remains blocked until finish stores the
    /// resulting evidence with the authority commit in a later slice.
    const APPLE_WEBAUTHN_ROOT_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----";

    /// Build the macOS-local Apple Anonymous attested start challenge.
    ///
    /// This intentionally uses `webauthn-rs-core`: the safe `webauthn-rs`
    /// attested-passkey helper does not expose Apple Anonymous as an accepted
    /// attestation format. This function only shapes and stages the challenge.
    /// The proof helper below verifies Apple root and credential flags, but the
    /// HTTP local finish route remains inert and evidence storage/commit remain
    /// outside this slice.
    pub(super) fn start(
        webauthn_core: &WebauthnCore,
        input: &OwnerWebauthnRegistrationStart<'_>,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), OwnerWebauthnError> {
        let extensions = Some(RequestRegistrationExtensions {
            cred_protect: Some(CredProtect {
                credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
                enforce_credential_protection_policy: Some(true),
            }),
            uvm: Some(true),
            cred_props: Some(true),
            min_pin_length: Some(true),
            hmac_create_secret: Some(true),
        });
        let builder = webauthn_core
            .new_challenge_register_builder(
                input.owner_user_id.as_bytes(),
                input.owner_name,
                input.owner_display_name,
            )
            .map_err(OwnerWebauthnError::Ceremony)?
            .attestation(AttestationConveyancePreference::Direct)
            .require_resident_key(true)
            .authenticator_attachment(Some(AuthenticatorAttachment::Platform))
            .user_verification_policy(UserVerificationPolicy::Required)
            .reject_synchronised_authenticators(true)
            .exclude_credentials(Some(exclude_credentials))
            .hints(Some(vec![PublicKeyCredentialHints::ClientDevice]))
            .attestation_formats(Some(vec![AttestationFormat::AppleAnonymous]))
            .extensions(extensions);
        webauthn_core
            .generate_challenge_register(builder)
            .map_err(OwnerWebauthnError::Ceremony)
    }

    pub(super) fn apple_webauthn_root_ca_list() -> Result<AttestationCaList, OwnerWebauthnError> {
        AttestationCaList::try_from(APPLE_WEBAUTHN_ROOT_CA_PEM)
            .map_err(|err| OwnerWebauthnError::LocalAttestationPolicy(err.to_string()))
    }

    pub(super) fn finish(
        webauthn_core: &WebauthnCore,
        credential: &RegisterPublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<VerifiedLocalAppleAttestedCredential, OwnerWebauthnError> {
        let apple_ca_list = apple_webauthn_root_ca_list()?;
        let credential = webauthn_core
            .register_credential(credential, state, Some(&apple_ca_list))
            .map_err(OwnerWebauthnError::Ceremony)?;
        verified_local_apple_attested_credential_from_core(credential)
    }

    pub(super) fn verified_local_apple_attested_credential_from_core(
        credential: Credential,
    ) -> Result<VerifiedLocalAppleAttestedCredential, OwnerWebauthnError> {
        if credential.attestation_format != AttestationFormat::AppleAnonymous {
            return Err(OwnerWebauthnError::LocalAttestationPolicy(
                "local attestation format is not Apple Anonymous".into(),
            ));
        }
        if !matches!(
            &credential.attestation.data,
            ParsedAttestationData::AnonCa(_)
        ) {
            return Err(OwnerWebauthnError::LocalAttestationPolicy(
                "local attestation data is not anonymous CA verified".into(),
            ));
        }
        if !credential.user_verified {
            return Err(OwnerWebauthnError::LocalAttestationPolicy(
                "local attestation is not user verified".into(),
            ));
        }
        if credential.backup_eligible {
            return Err(OwnerWebauthnError::LocalAttestationPolicy(
                "local attestation is backup eligible".into(),
            ));
        }
        if credential.backup_state {
            return Err(OwnerWebauthnError::LocalAttestationPolicy(
                "local attestation is backed up".into(),
            ));
        }
        let evidence = OwnerWebauthnLocalAttestationEvidence {
            attestation_format: credential.attestation_format.clone(),
            user_verified: credential.user_verified,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            root_policy_version: APPLE_WEBAUTHN_ROOT_POLICY_VERSION,
            root_ca_sha256_fingerprint: APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT,
        };
        Ok(VerifiedLocalAppleAttestedCredential {
            credential,
            evidence,
        })
    }

    pub(super) fn local_attested_passkey_from_verified_credential(
        verified: VerifiedLocalAppleAttestedCredential,
    ) -> (Passkey, OwnerWebauthnLocalAttestationEvidence) {
        let passkey: Passkey = verified.credential.into();
        (passkey, verified.evidence)
    }
}

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

    fn build_webauthn_core(&self) -> WebauthnCore {
        WebauthnCore::new_unsafe_experts_only(
            &self.rp_name,
            &self.rp_id,
            vec![self.rp_origin.clone()],
            DEFAULT_AUTHENTICATOR_TIMEOUT,
            Some(false),
            Some(false),
        )
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerWebauthnLocalAttestationEvidence {
    attestation_format: AttestationFormat,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    root_policy_version: &'static str,
    root_ca_sha256_fingerprint: &'static str,
}

impl OwnerWebauthnLocalAttestationEvidence {
    #[must_use]
    pub fn attestation_format(&self) -> &AttestationFormat {
        &self.attestation_format
    }

    #[must_use]
    pub fn user_verified(&self) -> bool {
        self.user_verified
    }

    #[must_use]
    pub fn backup_eligible(&self) -> bool {
        self.backup_eligible
    }

    #[must_use]
    pub fn backup_state(&self) -> bool {
        self.backup_state
    }

    #[must_use]
    pub fn root_policy_version(&self) -> &'static str {
        self.root_policy_version
    }

    #[must_use]
    pub fn root_ca_sha256_fingerprint(&self) -> &'static str {
        self.root_ca_sha256_fingerprint
    }
}

#[derive(Debug)]
pub struct VerifiedLocalAppleAttestedCredential {
    credential: Credential,
    evidence: OwnerWebauthnLocalAttestationEvidence,
}

impl VerifiedLocalAppleAttestedCredential {
    #[must_use]
    pub fn credential_id_bytes(&self) -> &[u8] {
        self.credential.cred_id.as_slice()
    }

    #[must_use]
    pub fn evidence(&self) -> &OwnerWebauthnLocalAttestationEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn into_owner_webauthn_credential(
        self,
    ) -> (
        OwnerWebauthnCredential,
        OwnerWebauthnLocalAttestationEvidence,
    ) {
        let (passkey, evidence) =
            macos_local_attested_registration::local_attested_passkey_from_verified_credential(
                self,
            );
        (OwnerWebauthnCredential::new(passkey), evidence)
    }
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
    #[error("registration binding failed validation: {0}")]
    RegistrationBinding(String),
    #[error("local Apple attestation policy failed: {0}")]
    LocalAttestationPolicy(String),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerWebauthnRegistrationBinding {
    purpose: String,
    canonical_binding: Vec<u8>,
    binding_digest: [u8; 32],
}

impl OwnerWebauthnRegistrationBinding {
    pub fn from_canonical_binding(
        purpose: impl Into<String>,
        canonical_binding: impl Into<Vec<u8>>,
    ) -> Result<Self, OwnerWebauthnError> {
        let purpose = purpose.into();
        if purpose.is_empty() {
            return Err(OwnerWebauthnError::RegistrationBinding(
                "purpose is empty".into(),
            ));
        }
        let canonical_binding = canonical_binding.into();
        if canonical_binding.is_empty() {
            return Err(OwnerWebauthnError::RegistrationBinding(
                "canonical binding is empty".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(REGISTRATION_BINDING_DOMAIN);
        hasher.update(purpose.as_bytes());
        hasher.update([0_u8]);
        hasher.update(&canonical_binding);
        Ok(Self {
            purpose,
            canonical_binding,
            binding_digest: hasher.finalize().into(),
        })
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn canonical_binding(&self) -> &[u8] {
        &self.canonical_binding
    }

    #[must_use]
    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    fn require_binding(&self, submitted_binding: &Self) -> Result<(), OwnerWebauthnError> {
        if self != submitted_binding {
            return Err(OwnerWebauthnError::ChallengeContextMismatch);
        }
        Ok(())
    }
}

pub struct OwnerWebauthnRegistrationStart<'a> {
    pub owner_user_id: Uuid,
    pub owner_name: &'a str,
    pub owner_display_name: &'a str,
    pub existing_credentials: &'a [OwnerWebauthnCredential],
    pub binding: Option<OwnerWebauthnRegistrationBinding>,
}

#[derive(Debug)]
enum ChallengeState {
    Registration(StoredRegistrationChallenge),
    #[allow(dead_code)]
    LocalAttestedRegistration(StoredLocalAttestedRegistrationChallenge),
    Authentication(StoredAuthenticationChallenge),
}

#[derive(Debug)]
struct StoredRegistrationChallenge {
    state: PasskeyRegistration,
    binding: Option<OwnerWebauthnRegistrationBinding>,
}

#[derive(Debug)]
struct StoredLocalAttestedRegistrationChallenge {
    state: RegistrationState,
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
        binding: Option<OwnerWebauthnRegistrationBinding>,
        expires_at_unix: u64,
    ) {
        self.challenges.insert(
            challenge_id,
            StoredChallenge {
                expires_at_unix,
                state: ChallengeState::Registration(StoredRegistrationChallenge { state, binding }),
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

    fn insert_local_attested_registration(
        &mut self,
        challenge_id: OwnerWebauthnChallengeId,
        state: RegistrationState,
        expires_at_unix: u64,
    ) {
        self.challenges.insert(
            challenge_id,
            StoredChallenge {
                expires_at_unix,
                state: ChallengeState::LocalAttestedRegistration(
                    StoredLocalAttestedRegistrationChallenge { state },
                ),
            },
        );
    }

    fn local_attested_registration(
        &self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<&StoredLocalAttestedRegistrationChallenge, OwnerWebauthnError> {
        let stored = self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        if now_unix > stored.expires_at_unix {
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        match &stored.state {
            ChallengeState::LocalAttestedRegistration(state) => Ok(state),
            ChallengeState::Registration(_) | ChallengeState::Authentication(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
        }
    }

    fn take_local_attested_registration(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<StoredLocalAttestedRegistrationChallenge, OwnerWebauthnError> {
        let expires_at_unix = self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?
            .expires_at_unix;
        if now_unix > expires_at_unix {
            self.challenges.remove(challenge_id);
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        let stored = self
            .challenges
            .remove(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        match stored.state {
            ChallengeState::LocalAttestedRegistration(state) => Ok(state),
            ChallengeState::Registration(_) | ChallengeState::Authentication(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
        }
    }

    fn registration(
        &self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<&StoredRegistrationChallenge, OwnerWebauthnError> {
        let stored = self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        if now_unix > stored.expires_at_unix {
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        match &stored.state {
            ChallengeState::Registration(state) => Ok(state),
            ChallengeState::LocalAttestedRegistration(_) | ChallengeState::Authentication(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
        }
    }

    fn take_registration(
        &mut self,
        challenge_id: &OwnerWebauthnChallengeId,
        now_unix: u64,
    ) -> Result<StoredRegistrationChallenge, OwnerWebauthnError> {
        let expires_at_unix = self
            .challenges
            .get(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?
            .expires_at_unix;
        if now_unix > expires_at_unix {
            self.challenges.remove(challenge_id);
            return Err(OwnerWebauthnError::ChallengeExpired);
        }
        let stored = self
            .challenges
            .remove(challenge_id)
            .ok_or(OwnerWebauthnError::ChallengeNotFound)?;
        match stored.state {
            ChallengeState::Registration(state) => Ok(state),
            ChallengeState::LocalAttestedRegistration(_) | ChallengeState::Authentication(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
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
            ChallengeState::Registration(_) | ChallengeState::LocalAttestedRegistration(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
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
            ChallengeState::Registration(_) | ChallengeState::LocalAttestedRegistration(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
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
            ChallengeState::Registration(_) | ChallengeState::LocalAttestedRegistration(_) => {
                Err(OwnerWebauthnError::ChallengeKindMismatch)
            }
        }
    }
}

#[derive(Debug)]
pub struct OwnerWebauthnRp {
    webauthn: Webauthn,
    webauthn_core: WebauthnCore,
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
        let webauthn_core = config.build_webauthn_core();
        Ok(Self {
            webauthn,
            webauthn_core,
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
        self.start_registration_from(
            rng,
            now_unix,
            OwnerWebauthnRegistrationStart {
                owner_user_id,
                owner_name,
                owner_display_name,
                existing_credentials,
                binding: None,
            },
        )
    }

    /// Start a platform-hinted registration ceremony for the macOS local engine.
    ///
    /// This changes only the client options. `authenticatorAttachment=platform`
    /// is a UX hint, not a server-side proof, so local finish remains blocked
    /// until a separate attestation slice can verify platform+UV before commit.
    pub fn start_platform_registration(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        owner_user_id: Uuid,
        owner_name: &str,
        owner_display_name: &str,
        existing_credentials: &[OwnerWebauthnCredential],
    ) -> Result<(OwnerWebauthnChallengeId, CreationChallengeResponse), OwnerWebauthnError> {
        self.start_platform_registration_from(
            rng,
            now_unix,
            OwnerWebauthnRegistrationStart {
                owner_user_id,
                owner_name,
                owner_display_name,
                existing_credentials,
                binding: None,
            },
        )
    }

    pub fn start_registration_from(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        input: OwnerWebauthnRegistrationStart<'_>,
    ) -> Result<(OwnerWebauthnChallengeId, CreationChallengeResponse), OwnerWebauthnError> {
        let exclude_credentials = input
            .existing_credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .map(|credential| credential.passkey().cred_id().clone())
            .collect::<Vec<_>>();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                input.owner_user_id,
                input.owner_name,
                input.owner_display_name,
                Some(exclude_credentials),
            )
            .map_err(OwnerWebauthnError::Ceremony)?;
        let id = OwnerWebauthnChallengeId::random(rng);
        self.challenges.insert_registration(
            id.clone(),
            state,
            input.binding,
            now_unix + self.config.challenge_ttl().as_secs(),
        );
        Ok((id, challenge))
    }

    pub fn start_platform_registration_from(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        input: OwnerWebauthnRegistrationStart<'_>,
    ) -> Result<(OwnerWebauthnChallengeId, CreationChallengeResponse), OwnerWebauthnError> {
        let exclude_credentials = input
            .existing_credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .map(|credential| credential.passkey().cred_id().clone())
            .collect::<Vec<_>>();
        let (mut challenge, state) = self
            .webauthn
            .start_passkey_registration(
                input.owner_user_id,
                input.owner_name,
                input.owner_display_name,
                Some(exclude_credentials),
            )
            .map_err(OwnerWebauthnError::Ceremony)?;
        if let Some(selection) = challenge.public_key.authenticator_selection.as_mut() {
            selection.authenticator_attachment = Some(AuthenticatorAttachment::Platform);
            selection.require_resident_key = true;
        }
        let id = OwnerWebauthnChallengeId::random(rng);
        self.challenges.insert_registration(
            id.clone(),
            state,
            input.binding,
            now_unix + self.config.challenge_ttl().as_secs(),
        );
        Ok((id, challenge))
    }

    /// Start the macOS local attested first-registration ceremony.
    ///
    /// This is the A-now foundation for the Apple Anonymous policy path. It
    /// uses the webauthn-rs core builder because the safe attested-passkey
    /// helper does not expose Apple Anonymous as an accepted attestation
    /// format. The resulting state is stored under a distinct challenge kind,
    /// so the existing Passkey finish path cannot consume it by accident.
    pub fn start_macos_local_attested_registration_from(
        &mut self,
        rng: &mut impl RngCore,
        now_unix: u64,
        input: &OwnerWebauthnRegistrationStart<'_>,
    ) -> Result<(OwnerWebauthnChallengeId, CreationChallengeResponse), OwnerWebauthnError> {
        let exclude_credentials = input
            .existing_credentials
            .iter()
            .filter(|credential| !credential.is_revoked())
            .map(|credential| credential.passkey().cred_id().clone())
            .collect::<Vec<_>>();
        let (challenge, state) = macos_local_attested_registration::start(
            &self.webauthn_core,
            input,
            exclude_credentials,
        )?;
        let id = OwnerWebauthnChallengeId::random(rng);
        self.challenges.insert_local_attested_registration(
            id.clone(),
            state,
            now_unix + self.config.challenge_ttl().as_secs(),
        );
        Ok((id, challenge))
    }

    pub fn finish_macos_local_attested_registration(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<VerifiedLocalAppleAttestedCredential, OwnerWebauthnError> {
        self.challenges
            .local_attested_registration(challenge_id, now_unix)?;
        let state = self
            .challenges
            .take_local_attested_registration(challenge_id, now_unix)?
            .state;
        macos_local_attested_registration::finish(&self.webauthn_core, credential, &state)
    }

    pub fn finish_registration(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<OwnerWebauthnCredential, OwnerWebauthnError> {
        let stored = self.challenges.registration(challenge_id, now_unix)?;
        if stored.binding.is_some() {
            return Err(OwnerWebauthnError::ChallengeContextUnexpected);
        }
        let state = self
            .challenges
            .take_registration(challenge_id, now_unix)?
            .state;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(OwnerWebauthnError::Ceremony)?;
        Ok(OwnerWebauthnCredential::new(passkey))
    }

    pub fn require_registration_challenge_binding(
        &self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        submitted_binding: &OwnerWebauthnRegistrationBinding,
    ) -> Result<(), OwnerWebauthnError> {
        let stored = self.challenges.registration(challenge_id, now_unix)?;
        let expected = stored
            .binding
            .as_ref()
            .ok_or(OwnerWebauthnError::ChallengeContextMissing)?;
        expected.require_binding(submitted_binding)
    }

    pub fn finish_registration_with_binding(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        credential: &RegisterPublicKeyCredential,
        submitted_binding: &OwnerWebauthnRegistrationBinding,
    ) -> Result<OwnerWebauthnCredential, OwnerWebauthnError> {
        self.require_registration_challenge_binding(now_unix, challenge_id, submitted_binding)?;
        let state = self
            .challenges
            .take_registration(challenge_id, now_unix)?
            .state;
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

    pub fn require_owner_approval_challenge_context(
        &mut self,
        now_unix: u64,
        challenge_id: &OwnerWebauthnChallengeId,
        submitted_context: &OwnerApprovalContextV2,
    ) -> Result<(), OwnerWebauthnError> {
        let stored_challenge = self.challenges.authentication(challenge_id, now_unix)?;
        let context_binding = stored_challenge
            .context_binding
            .as_ref()
            .ok_or(OwnerWebauthnError::ChallengeContextMissing)?;
        context_binding.require_context(submitted_context)
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
mod tests;
