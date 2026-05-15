//! End-to-end chain verification: [`HouseholdRecord`] ↔ [`MachineCert`] ↔ signature.
//!
//! [`HouseholdRecord`]: crate::HouseholdRecord
//! [`MachineCert`]: crate::MachineCert
//!
//! Used by US2 acceptance and by `bootstrap_or_load`'s "load existing" path.

use crate::error::HouseholdError;
use crate::household_record::HouseholdRecord;
use crate::machine_cert::{MachineCert, SubjectId};

/// Verify that a freshly-loaded `(HouseholdRecord, MachineCert)` pair is
/// internally consistent and signed by the household root.
pub fn verify_loaded_chain(
    record: &HouseholdRecord,
    cert: &MachineCert,
) -> Result<(), HouseholdError> {
    record.validate()?;
    if cert.hh_id != record.hh_id {
        return Err(HouseholdError::InvalidCert(format!(
            "machine cert hh_id {} != household record hh_id {}",
            cert.hh_id, record.hh_id
        )));
    }
    match &cert.issued_by {
        SubjectId::Household(h) if h == &record.hh_id => {}
        other => {
            return Err(HouseholdError::InvalidCert(format!(
                "cert.issued_by must be Household({}); got {}",
                record.hh_id,
                other.as_str(),
            )));
        }
    }
    if !cert.caveats.is_empty() {
        // Caveat semantics are reserved for the macaroon/biscuit-style
        // delegation work in a later phase (US4/US5/US7/US10/US11). Until
        // those land, the validator MUST refuse any non-empty caveat list
        // — otherwise an unevaluated caveat would silently grant the
        // capability it was meant to constrain. Phase-agnostic message
        // intentionally avoids hardcoding which phase introduces support.
        return Err(HouseholdError::InvalidCert(
            "cert.caveats not yet supported (reserved for delegation work in a later phase)".into(),
        ));
    }
    // Self-cert's m_id must appear in the household's members list.
    // In Phase 1 the list has exactly one entry (the founder); in Phase 3
    // it has two entries (founder + admitted machine). Validating
    // membership instead of strict equality lets `verify_loaded_chain`
    // succeed on either side of the join ceremony.
    if !record.members.iter().any(|m| m == &cert.m_id) {
        return Err(HouseholdError::InvalidRecord(format!(
            "self machine id {} not present in household members[]",
            cert.m_id,
        )));
    }
    cert.verify(&record.hh_pub)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{derive_household_id, derive_machine_id};
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::machine_cert::{Platform, SignOptions};

    fn build_pair() -> (P256Keypair, HouseholdRecord, MachineCert) {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        let m_id = derive_machine_id(&m.public());
        let record = HouseholdRecord {
            version: 1,
            hh_id: hh_id.clone(),
            hh_pub: hh.public(),
            name: "Sample Home".into(),
            created_at: 1_714_972_800,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![m_id],
        };
        let cert = MachineCert::sign(
            &hh,
            &m.public(),
            &SignOptions {
                hh_id,
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .unwrap();
        (hh, record, cert)
    }

    #[test]
    fn happy_path() {
        let (_hh, record, cert) = build_pair();
        verify_loaded_chain(&record, &cert).unwrap();
    }

    #[test]
    fn record_hh_id_tamper_fails() {
        let (_hh, mut record, cert) = build_pair();
        record.hh_id = derive_household_id(&P256Keypair::generate().public());
        verify_loaded_chain(&record, &cert).unwrap_err();
    }

    #[test]
    fn cert_hh_id_tamper_fails() {
        let (_hh, record, mut cert) = build_pair();
        cert.hh_id = derive_household_id(&P256Keypair::generate().public());
        verify_loaded_chain(&record, &cert).unwrap_err();
    }

    #[test]
    fn cert_signature_tamper_fails() {
        let (_hh, record, mut cert) = build_pair();
        cert.signature.0[5] ^= 0x55;
        verify_loaded_chain(&record, &cert).unwrap_err();
    }

    #[test]
    fn members_must_match_machine_cert() {
        let (_hh, mut record, cert) = build_pair();
        record.members = vec![derive_machine_id(&P256Keypair::generate().public())];
        verify_loaded_chain(&record, &cert).unwrap_err();
    }
}
