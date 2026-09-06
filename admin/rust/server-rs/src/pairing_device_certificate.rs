//! Validation of the existing household pairing certificate wire format.
//!
//! This format includes `hh_id` and explicit inherited caveats, as produced by
//! the Swift pairing client. It is distinct from the R0a device-admission
//! certificate; accepting a pairing response does not grant R0a admission.

use household_rs::{
    PersonCert,
    caveats::Caveat,
    cbor,
    device_cert::derive_device_id,
    keys::{P256PublicKey, P256Signature, verify_signature},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingDeviceCertificate {
    v: u8,
    #[serde(rename = "type")]
    cert_type: String,
    hh_id: String,
    p_id: String,
    d_id: String,
    d_pub: P256PublicKey,
    device_name: String,
    platform: String,
    added_at: u64,
    issued_by: String,
    caveats: Vec<Caveat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<P256Signature>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::{
        keys::{IdentityKey, P256Keypair},
        person_cert::SignOwnerOptions,
    };
    const NOW: u64 = 1_700_000_000;

    fn fixture() -> (PersonCert, P256Keypair, PairingDeviceCertificate) {
        let root = P256Keypair::generate();
        let owner = P256Keypair::generate();
        let device = P256Keypair::generate().public();
        let person = PersonCert::sign_owner(
            &root,
            SignOwnerOptions {
                hh_id: household_rs::ids::derive_household_id(&root.public()),
                p_pub: owner.public(),
                display_name: "Test Owner".into(),
                issued_at: NOW,
            },
        )
        .unwrap();
        let cert = PairingDeviceCertificate {
            v: 1,
            cert_type: "device".into(),
            hh_id: person.hh_id.to_string(),
            p_id: person.p_id.0.clone(),
            d_id: derive_device_id(&device).0,
            d_pub: device,
            device_name: "Test iPhone".into(),
            platform: "ios".into(),
            added_at: NOW,
            issued_by: person.p_id.0.clone(),
            caveats: person.caveats.clone(),
            signature: None,
        };
        (person, owner, cert)
    }

    fn signed(mut cert: PairingDeviceCertificate, signer: &P256Keypair) -> Vec<u8> {
        cert.signature = Some(
            signer
                .sign(&cbor::to_canonical_vec(&cert).unwrap())
                .unwrap(),
        );
        cbor::to_canonical_vec(&cert).unwrap()
    }

    #[test]
    fn verifies_the_current_pairing_format() {
        let (person, key, cert) = fixture();
        let bytes = signed(cert, &key);
        let verified =
            VerifiedPairingDeviceCertificate::verify(bytes.clone(), &person, NOW).unwrap();
        assert_eq!(verified.bytes, bytes);
        assert_eq!(verified.device_name, "Test iPhone");
    }

    #[test]
    fn rejects_another_signer_and_a_truncated_certificate() {
        let (person, _, cert) = fixture();
        let bytes = signed(cert, &P256Keypair::generate());
        assert!(VerifiedPairingDeviceCertificate::verify(bytes.clone(), &person, NOW).is_err());
        assert!(
            VerifiedPairingDeviceCertificate::verify(
                bytes[..bytes.len() - 1].to_vec(),
                &person,
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_cross_house_cross_person_and_invented_device_id_even_when_signed() {
        for field in ["house", "person", "device", "issuer", "grant", "future"] {
            let (person, key, mut cert) = fixture();
            match field {
                "house" => cert.hh_id = "hh_other".into(),
                "person" => cert.p_id = "p_other".into(),
                "device" => cert.d_id = "d_other".into(),
                "issuer" => cert.issued_by = "p_other".into(),
                "grant" => {
                    cert.caveats.pop();
                }
                "future" => cert.added_at += 60,
                _ => unreachable!(),
            }
            assert!(
                VerifiedPairingDeviceCertificate::verify(signed(cert, &key), &person, NOW).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_missing_signature() {
        let (person, key, cert) = fixture();
        let unsigned = cbor::to_canonical_vec(&cert).unwrap();
        assert!(VerifiedPairingDeviceCertificate::verify(unsigned, &person, NOW).is_err());
        let mut bytes = signed(cert, &key);
        bytes.push(0);
        assert!(VerifiedPairingDeviceCertificate::verify(bytes, &person, NOW).is_err());
    }
}

pub(crate) struct VerifiedPairingDeviceCertificate {
    pub(crate) bytes: Vec<u8>,
    pub(crate) device_public_key: Vec<u8>,
    pub(crate) device_name: String,
    pub(crate) platform: String,
}

impl VerifiedPairingDeviceCertificate {
    pub(crate) fn verify(bytes: Vec<u8>, owner: &PersonCert, now: u64) -> Result<Self, ()> {
        let mut cert: PairingDeviceCertificate =
            cbor::from_canonical_slice_strict(&bytes).map_err(|_| ())?;
        let key = P256PublicKey::from_bytes(cert.d_pub.as_bytes()).map_err(|_| ())?;
        if cert.v != 1
            || cert.cert_type != "device"
            || cert.hh_id != owner.hh_id.to_string()
            || cert.p_id != owner.p_id.0
            || cert.issued_by != owner.p_id.0
            || cert.d_id != derive_device_id(&key).0
            || cert.added_at > now.saturating_add(30)
            || cert.caveats != owner.caveats
            || cert.device_name.trim().is_empty()
            || cert.device_name.len() > 64
            || cert.device_name.chars().any(char::is_control)
            || !matches!(cert.platform.as_str(), "ios" | "ipados")
        {
            return Err(());
        }
        let signature = cert.signature.take().ok_or(())?;
        let signing_bytes = cbor::to_canonical_vec(&cert).map_err(|_| ())?;
        verify_signature(&owner.p_pub, &signing_bytes, &signature).map_err(|_| ())?;
        Ok(Self {
            bytes,
            device_public_key: key.as_bytes().to_vec(),
            device_name: cert.device_name,
            platform: cert.platform,
        })
    }

    #[cfg(test)]
    pub(crate) fn store_fixture(bytes: Vec<u8>, device_public_key: Vec<u8>) -> Self {
        Self {
            bytes,
            device_public_key,
            device_name: "alpha".into(),
            platform: "ios".into(),
        }
    }
}
