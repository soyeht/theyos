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
mod tests {
    use std::time::Duration;

    use crate::ids::{HouseholdId, MachineId};
    use crate::machine_cert::PersonId;
    use crate::owner_approval_v2::{OwnerApprovalContextV2, PairMachineApprovalContextInput};
    use crate::pair_machine::{JoinTransport, join_request_hash};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use serde::Deserialize;
    use serde_json::json;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{AttestationFormat, AuthenticatorAttachment, Url};
    use webauthn_rs_core::proto::{AttestationConveyancePreference, UserVerificationPolicy};

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

    fn spectral_apple_fixture_rp() -> OwnerWebauthnRp {
        let config = OwnerWebauthnConfig::new(
            "spectral.local",
            Url::parse("https://spectral.local:8443").unwrap(),
            "Soyeht Spectral",
        )
        .unwrap()
        .with_challenge_ttl(Duration::from_secs(60));
        OwnerWebauthnRp::new(config).unwrap()
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

    fn synthetic_core_credential(
        id: &[u8],
        attestation_format: &str,
        attestation_data: serde_json::Value,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
    ) -> Credential {
        let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
        serde_json::from_value(json!({
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
            "user_verified": user_verified,
            "backup_eligible": backup_eligible,
            "backup_state": backup_state,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {
                "data": attestation_data,
                "metadata": "None"
            },
            "attestation_format": attestation_format
        }))
        .unwrap()
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

    fn registration_binding(bytes: &[u8]) -> OwnerWebauthnRegistrationBinding {
        OwnerWebauthnRegistrationBinding::from_canonical_binding(
            "owner-webauthn-recovery-consume",
            bytes,
        )
        .unwrap()
    }

    fn apple_anonymous_registration_response() -> RegisterPublicKeyCredential {
        serde_json::from_value(json!({
            "id": "u_tliFf-aXRLg9XIz-SuQ0XBlbE",
            "rawId": "u_tliFf-aXRLg9XIz-SuQ0XBlbE",
            "response": {
                "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXZFUv6nMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMjA4MDIyNzE1WhcNMjAxMjExMDIyNzE1WjCBkTFJMEcGA1UEAwxAOWFhOTBjN2M5MzZhNGUxYmI4Njg5NjVmMTQ3YTQzOTlmMTQwY2Y0MDliNDM0ZjkwNTliMmQ0ZjVhM2NmYzA5MjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATU-GOH9U5e9ecWPuItKNcE-7y0fRbshaHqTvtpC3eUkGn5x6eYrV6TOQL6FQUzdK7ZJ6AjDPl47TSUq4aKzRqto1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIKjioMU9kg_qZHwWHSISq1v9elHxtmnw0YKwsz1Ut06-MAoGCCqGSM49BAMCA2gAMGUCMA7yhkkMMAJnuIS7hHzMP5SoTuHjofCTu1rYQZ9aamb5OJzJ1rYPrbun83_qiikyPgIxAMYPCraOZ1QHEgDngtYaQDoRdkIOxvQ60wJh7KN0fEmmRUVwa-RTaFvNFMv6fh2-KlkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmNoUsfKpHi3fFS3-SiJ9vGALAUcpOl78tKnz0RXnirZbRQAAAAAAAAAAAAAAAAAAAAAAAAAAABS7-2WIV_5pdEuD1cjP5K5DRcGVsaUBAgMmIAEhWCDU-GOH9U5e9ecWPuItKNcE-7y0fRbshaHqTvtpC3eUkCJYIGn5x6eYrV6TOQL6FQUzdK7ZJ6AjDPl47TSUq4aKzRqt",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSlRiazd5ZWtJS09aUXd3ZEdXN05lRElmeHJZSzBQdnVZeHN1ZS0tRzlOSSIsIm9yaWdpbiI6Imh0dHBzOi8vc3BlY3RyYWwubG9jYWw6ODQ0MyJ9"
            },
            "type": "public-key"
        }))
        .unwrap()
    }

    fn patch_local_attested_challenge(
        rp: &mut OwnerWebauthnRp,
        challenge_id: &OwnerWebauthnChallengeId,
        challenge: &str,
    ) {
        let stored = rp
            .challenges
            .challenges
            .get_mut(challenge_id)
            .expect("local attested challenge exists");
        let ChallengeState::LocalAttestedRegistration(local) = &mut stored.state else {
            panic!("challenge is local attested");
        };
        let mut state = serde_json::to_value(&local.state).unwrap();
        state["challenge"] = json!(challenge);
        local.state = serde_json::from_value(state).unwrap();
    }

    fn patch_local_attested_challenge_for_apple_fixture(
        rp: &mut OwnerWebauthnRp,
        challenge_id: &OwnerWebauthnChallengeId,
    ) {
        const APPLE_ANONYMOUS_CHALLENGE: &str = "JTbk7yekIKOZQwwdGW7NeDIfxrYK0PvuYxsue--G9NI";
        patch_local_attested_challenge(rp, challenge_id, APPLE_ANONYMOUS_CHALLENGE);
    }

    #[derive(Debug, Deserialize)]
    struct ManualLocalAppleAttestationFixture {
        rp_id: String,
        origin: String,
        credential: RegisterPublicKeyCredential,
    }

    fn client_data_json(credential: &RegisterPublicKeyCredential) -> serde_json::Value {
        serde_json::from_slice(credential.response.client_data_json.as_slice()).unwrap()
    }

    fn client_data_string<'a>(client_data: &'a serde_json::Value, key: &str) -> &'a str {
        client_data
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("clientDataJSON {key} is a string"))
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
    fn bound_registration_mismatch_does_not_consume_challenge() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(4301);
        let expected = registration_binding(b"canonical-recovery-consume-context");
        let mismatch = registration_binding(b"tampered-recovery-consume-context");
        let (challenge_id, challenge) = rp
            .start_registration_from(
                &mut rng,
                NOW,
                OwnerWebauthnRegistrationStart {
                    owner_user_id: Uuid::new_v4(),
                    owner_name: "owner-alpha",
                    owner_display_name: "Owner Alpha",
                    existing_credentials: &[],
                    binding: Some(expected.clone()),
                },
            )
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = authenticator
            .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        let err = rp
            .finish_registration_with_binding(NOW, &challenge_id, &response, &mismatch)
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::ChallengeContextMismatch));
        assert_eq!(rp.challenge_store_len(), 1);

        let credential = rp
            .finish_registration_with_binding(NOW, &challenge_id, &response, &expected)
            .unwrap();
        assert_eq!(credential.credential_id_bytes(), response.raw_id.as_slice());
        assert_eq!(rp.challenge_store_len(), 0);
    }

    #[test]
    fn unbound_finish_rejects_bound_registration_without_consuming() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(4302);
        let expected = registration_binding(b"canonical-recovery-consume-context");
        let (challenge_id, challenge) = rp
            .start_registration_from(
                &mut rng,
                NOW,
                OwnerWebauthnRegistrationStart {
                    owner_user_id: Uuid::new_v4(),
                    owner_name: "owner-alpha",
                    owner_display_name: "Owner Alpha",
                    existing_credentials: &[],
                    binding: Some(expected.clone()),
                },
            )
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = authenticator
            .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();

        let err = rp
            .finish_registration(NOW, &challenge_id, &response)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerWebauthnError::ChallengeContextUnexpected
        ));
        assert_eq!(rp.challenge_store_len(), 1);

        rp.finish_registration_with_binding(NOW, &challenge_id, &response, &expected)
            .unwrap();
        assert_eq!(rp.challenge_store_len(), 0);
    }

    #[test]
    fn macos_local_attested_registration_requests_apple_anonymous_and_separates_state() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(4303);
        let (challenge_id, challenge) = rp
            .start_macos_local_attested_registration_from(
                &mut rng,
                NOW,
                &OwnerWebauthnRegistrationStart {
                    owner_user_id: Uuid::new_v4(),
                    owner_name: "owner-alpha",
                    owner_display_name: "Owner Alpha",
                    existing_credentials: &[],
                    binding: None,
                },
            )
            .unwrap();

        assert!(matches!(
            challenge.public_key.attestation.as_ref(),
            Some(AttestationConveyancePreference::Direct)
        ));
        assert_eq!(
            challenge
                .public_key
                .attestation_formats
                .as_ref()
                .map(Vec::as_slice),
            Some([AttestationFormat::AppleAnonymous].as_slice())
        );
        let selection = challenge
            .public_key
            .authenticator_selection
            .as_ref()
            .expect("local attested start requests authenticator selection");
        assert_eq!(
            selection.authenticator_attachment,
            Some(AuthenticatorAttachment::Platform)
        );
        assert_eq!(
            selection.user_verification,
            UserVerificationPolicy::Required
        );
        assert!(selection.require_resident_key);
        assert!(matches!(
            rp.challenges.registration(&challenge_id, NOW),
            Err(OwnerWebauthnError::ChallengeKindMismatch)
        ));
        assert_eq!(rp.challenge_store_len(), 1);
    }

    #[test]
    fn local_apple_root_policy_is_single_pinned_root() {
        let ca_list = macos_local_attested_registration::apple_webauthn_root_ca_list().unwrap();
        assert_eq!(ca_list.len(), 1);
        assert_eq!(
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION,
            "apple-webauthn-root-ca-2020-03-18"
        );
        assert_eq!(
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT,
            "09:15:DD:5C:07:A2:8D:B5:49:D1:F6:77:BB:5A:75:D4:BF:BE:95:61:A7:73:42:43:27:76:2E:9E:02:F9:BB:29"
        );
    }

    #[test]
    fn macos_local_attested_registration_rejects_expired_apple_anonymous_fixture() {
        let mut rp = spectral_apple_fixture_rp();
        let mut rng = StdRng::seed_from_u64(4304);
        let (challenge_id, _challenge) = rp
            .start_macos_local_attested_registration_from(
                &mut rng,
                NOW,
                &OwnerWebauthnRegistrationStart {
                    owner_user_id: Uuid::new_v4(),
                    owner_name: "owner-alpha",
                    owner_display_name: "Owner Alpha",
                    existing_credentials: &[],
                    binding: None,
                },
            )
            .unwrap();
        patch_local_attested_challenge_for_apple_fixture(&mut rp, &challenge_id);
        let response = apple_anonymous_registration_response();

        let err = rp
            .finish_macos_local_attested_registration(NOW, &challenge_id, &response)
            .unwrap_err();

        assert!(matches!(err, OwnerWebauthnError::Ceremony(_)));
        assert_eq!(rp.challenge_store_len(), 0);
    }

    #[test]
    #[ignore = "manual hardware evidence; requires SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE"]
    fn macos_local_attested_registration_manual_hardware_fixture_verifies_current_apple_chain() {
        let fixture_path = std::env::var("SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE").expect(
            "set SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE to an untracked local fixture path",
        );
        let fixture_bytes =
            std::fs::read(&fixture_path).expect("read local Apple attestation fixture");
        let fixture: ManualLocalAppleAttestationFixture =
            serde_json::from_slice(&fixture_bytes).expect("parse local Apple attestation fixture");
        let origin =
            Url::parse(&fixture.origin).unwrap_or_else(|_| panic!("fixture origin is a URL"));
        let client_data = client_data_json(&fixture.credential);
        assert_eq!(client_data_string(&client_data, "type"), "webauthn.create");
        let challenge = client_data_string(&client_data, "challenge").to_string();
        if client_data_string(&client_data, "origin") != fixture.origin {
            panic!("clientDataJSON origin must match fixture origin");
        }

        let config =
            OwnerWebauthnConfig::new(fixture.rp_id, origin, "Soyeht Local Attestation Evidence")
                .unwrap_or_else(|_| panic!("fixture RP/origin pair is valid"))
                .with_challenge_ttl(Duration::from_secs(60));
        let mut rp = OwnerWebauthnRp::new(config).unwrap();
        let mut rng = StdRng::seed_from_u64(4308);
        let (challenge_id, _challenge) = rp
            .start_macos_local_attested_registration_from(
                &mut rng,
                NOW,
                &OwnerWebauthnRegistrationStart {
                    owner_user_id: Uuid::new_v4(),
                    owner_name: "owner-alpha",
                    owner_display_name: "Owner Alpha",
                    existing_credentials: &[],
                    binding: None,
                },
            )
            .unwrap();
        patch_local_attested_challenge(&mut rp, &challenge_id, &challenge);

        let verified = rp
            .finish_macos_local_attested_registration(NOW, &challenge_id, &fixture.credential)
            .expect("fresh hardware Apple Anonymous fixture verifies at current time");
        let evidence = verified.evidence();
        assert_eq!(
            evidence.attestation_format(),
            &AttestationFormat::AppleAnonymous
        );
        assert!(evidence.user_verified());
        assert!(!evidence.backup_eligible());
        assert!(!evidence.backup_state());
        assert_eq!(
            evidence.root_policy_version(),
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION
        );
        assert_eq!(
            evidence.root_ca_sha256_fingerprint(),
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT
        );
        assert_eq!(rp.challenge_store_len(), 0);

        eprintln!(
            "local_apple_attestation_manual_evidence verified=true format={:?} uv={} be={} bs={} root_policy={} root_fingerprint={}",
            evidence.attestation_format(),
            evidence.user_verified(),
            evidence.backup_eligible(),
            evidence.backup_state(),
            evidence.root_policy_version(),
            evidence.root_ca_sha256_fingerprint(),
        );
    }

    #[test]
    fn local_apple_attestation_policy_requires_apple_uv_and_device_bound_flags() {
        let accepted = synthetic_core_credential(
            b"apple-local-credential",
            "apple",
            json!({ "AnonCa": [] }),
            true,
            false,
            false,
        );
        let verified =
            macos_local_attested_registration::verified_local_apple_attested_credential_from_core(
                accepted,
            )
            .unwrap();
        assert_eq!(verified.credential_id_bytes(), b"apple-local-credential");
        assert_eq!(
            verified.evidence().root_policy_version(),
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION
        );
        let (owner_credential, evidence) = verified.into_owner_webauthn_credential();
        assert_eq!(
            owner_credential.credential_id_bytes(),
            b"apple-local-credential"
        );
        assert_eq!(
            evidence.root_ca_sha256_fingerprint(),
            macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT
        );

        let cases = [
            synthetic_core_credential(
                b"wrong-format",
                "packed",
                json!({ "AnonCa": [] }),
                true,
                false,
                false,
            ),
            synthetic_core_credential(
                b"wrong-attestation-data",
                "apple",
                json!("None"),
                true,
                false,
                false,
            ),
            synthetic_core_credential(
                b"uv-false",
                "apple",
                json!({ "AnonCa": [] }),
                false,
                false,
                false,
            ),
            synthetic_core_credential(
                b"backup-eligible",
                "apple",
                json!({ "AnonCa": [] }),
                true,
                true,
                false,
            ),
            synthetic_core_credential(
                b"backup-state",
                "apple",
                json!({ "AnonCa": [] }),
                true,
                false,
                true,
            ),
        ];
        for credential in cases {
            let err =
                macos_local_attested_registration::verified_local_apple_attested_credential_from_core(
                    credential,
                )
                .unwrap_err();
            assert!(matches!(err, OwnerWebauthnError::LocalAttestationPolicy(_)));
        }
    }

    #[test]
    fn local_attested_finish_rejects_normal_registration_challenge_without_consuming() {
        let mut rp = rp();
        let mut rng = StdRng::seed_from_u64(4306);
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
        let response = apple_anonymous_registration_response();

        let err = rp
            .finish_macos_local_attested_registration(NOW, &challenge_id, &response)
            .unwrap_err();

        assert!(matches!(err, OwnerWebauthnError::ChallengeKindMismatch));
        assert!(rp.challenges.registration(&challenge_id, NOW).is_ok());
        assert_eq!(rp.challenge_store_len(), 1);
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
