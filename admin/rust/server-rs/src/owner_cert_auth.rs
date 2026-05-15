//! T079 — Owner cert chain verifier for `POST /bootstrap/teardown`.
//!
//! Phase 2 owner cert chain: `D_pub` (device pubkey from `signed_by`) must
//! match the `p_pub` in the persisted `HouseholdAuthState.owner_person_cert`.
//! The cert itself is validated against the household's `hh_pub`.
//!
//! In future phases, multiple device certs will be supported; for now the
//! household has exactly one owner device.

use household_rs::HouseholdAuthState;
use household_rs::keys::P256PublicKey;

#[derive(Debug)]
pub enum OwnerCertError {
    /// `signed_by` does not match any known owner device pubkey.
    UnknownSigner,
    /// Owner cert failed Phase 2 chain validation (invalid signature, expired, etc.).
    CertInvalid(String),
}

impl std::fmt::Display for OwnerCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSigner => write!(f, "signed_by not in owner device cert set"),
            Self::CertInvalid(e) => write!(f, "cert invalid: {e}"),
        }
    }
}

/// Verify that `signed_by_sec1` (33-byte SEC1-compressed P-256 pubkey) is a
/// known owner device key AND that the corresponding cert chain is valid up to
/// `hh_pub`.
///
/// Returns `Ok(())` iff both checks pass. Any failure returns a generic
/// `OwnerCertError` — callers should map this to a 401 without revealing
/// which step failed (prevents probing).
pub fn verify_owner_cert(
    auth: &HouseholdAuthState,
    signed_by_sec1: &[u8; 33],
    hh_pub: &P256PublicKey,
    now_unix: u64,
) -> Result<(), OwnerCertError> {
    let cert = &auth.owner_person_cert;

    // Phase 2: single owner device. Check the device pubkey matches.
    if cert.p_pub.as_bytes() != signed_by_sec1 {
        return Err(OwnerCertError::UnknownSigner);
    }

    // Validate cert chain: cert.signature verified against hh_pub, TTL, etc.
    let record_hh_id = &auth.hh_id;
    cert.verify(record_hh_id, hh_pub, now_unix)
        .map_err(|e| OwnerCertError::CertInvalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::HouseholdAuthState;
    use household_rs::IdentityKey;
    use household_rs::household_record::HouseholdRecord;
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::keys::P256Keypair;
    use household_rs::person_cert::{PersonCert, SignOwnerOptions};

    fn make_hh_key() -> P256Keypair {
        P256Keypair::generate()
    }

    fn make_owner_key() -> P256Keypair {
        P256Keypair::generate()
    }

    fn make_record(hh_pub: &P256PublicKey) -> HouseholdRecord {
        let hh_id = derive_household_id(hh_pub);
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id,
            hh_pub: hh_pub.clone(),
            name: "Test Home".to_string(),
            shamir_n: 1,
            shamir_k: 1,
            members: vec![derive_machine_id(hh_pub)],
            created_at: 1000,
        }
    }

    fn make_auth(hh_key: &P256Keypair, owner_pub: &P256PublicKey) -> HouseholdAuthState {
        let hh_pub = hh_key.public();
        let record = make_record(&hh_pub);
        let cert = PersonCert::sign_owner(
            hh_key,
            SignOwnerOptions {
                hh_id: record.hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".to_string(),
                issued_at: 1000,
            },
        )
        .expect("sign_owner");
        HouseholdAuthState::new(&record, cert)
    }

    #[test]
    fn valid_owner_cert_passes() {
        let hh_key = make_hh_key();
        let owner_key = make_owner_key();
        let auth = make_auth(&hh_key, &owner_key.public());
        let result =
            verify_owner_cert(&auth, owner_key.public().as_bytes(), &hh_key.public(), 1001);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn wrong_signer_returns_unknown() {
        let hh_key = make_hh_key();
        let owner_key = make_owner_key();
        let attacker_key = make_owner_key();
        let auth = make_auth(&hh_key, &owner_key.public());
        let result = verify_owner_cert(
            &auth,
            attacker_key.public().as_bytes(),
            &hh_key.public(),
            1001,
        );
        assert!(matches!(result, Err(OwnerCertError::UnknownSigner)));
    }
}
