//! Household machine-issuer trust boundary.
//!
//! Answers one question, with no I/O and no ambient state: *is this P256 public
//! key an active, household-authorized machine issuer?* This is the trust
//! anchor the Product A `relay_stream` path needs so it can verify an
//! owner-signed offer against the engine's real signing key
//! (`identity.m_priv`) instead of the raw household root `hh_pub`. The root
//! scalar is split by Shamir and is not a live signer, so offers are signed by
//! a member machine and must be authorized through that machine's
//! [`MachineCert`].
//!
//! Authority is anchored entirely in the [`HouseholdRecord`]:
//!   * a [`MachineCert`] that the household root signed for `signer_pub`, and
//!   * that machine's `m_id` listed in `record.members`.
//!
//! Revocation is an OVERLAY, not a separate store. The household mesh log's
//! [`ProjectedState::directory_devices`] is consulted only to REMOVE trust: a
//! `Removed` directory entry for `signer_pub` fails closed. Absence is NOT a
//! rejection — no production flow emits `DirectoryDeviceAdded` for issuing
//! machines today, so membership + cert remain the source of truth for
//! "active" and the directory acts purely as a kill switch. Owner-key CRL
//! beyond this device overlay is still unimplemented; a designated revocation
//! home is a release gate for the `relay_stream` path, decided elsewhere.

use crate::error::HouseholdError;
use crate::household_mesh_log::{DirectoryDeviceStatus, ProjectedState};
use crate::household_record::HouseholdRecord;
use crate::keys::P256PublicKey;
use crate::machine_cert::MachineCert;

/// Why a candidate signing key is not an authorized machine issuer.
///
/// Reasons are stable and carry no secret material (no private keys, no
/// rendezvous tokens). [`Self::CertInvalid`] forwards the underlying
/// [`HouseholdError`], which only describes certificate *shape* and public
/// identifiers; callers at a blind-relay boundary should still collapse every
/// variant to one opaque reason before it leaves the trusted process.
#[derive(Debug, thiserror::Error)]
pub enum MachineIssuerError {
    /// The certificate's subject key (`m_pub`) is not `signer_pub`; the cert
    /// does not speak for the key being judged.
    #[error("machine issuer cert subject did not match signer key")]
    SignerMismatch,
    /// The certificate did not verify against the household root.
    #[error("machine issuer cert did not verify against household root: {0}")]
    CertInvalid(#[source] HouseholdError),
    /// The certificate is authentic but its machine is not a current member.
    #[error("machine issuer is not a household member")]
    NonMember,
    /// The issuing device was removed from the household directory overlay.
    #[error("machine issuer device was removed from the household directory")]
    DeviceRemoved,
}

/// Returns `Ok(())` iff `signer_pub` is an active, household-authorized machine
/// issuer for `record`.
///
/// Checks, fail-closed, in order:
/// 1. **Root/degenerate** (only when `allow_root_signer`): `signer_pub ==
///    record.hh_pub` is accepted directly. The household root is the ultimate
///    trust anchor, so an offer signed by it needs no cert chain. This is the
///    single-machine / Device shape; in the steady-state regime the engine signs
///    with `identity.m_priv`, not the root, so this branch is not the live path.
///    Callers verifying credential-less **Group/Public** offers pass
///    `allow_root_signer = false`: those audiences require the full machine-cert
///    chain + revocation overlay, never the bare root fallback.
/// 2. **Subject binding**: `cert.m_pub == signer_pub`, else [`SignerMismatch`].
///    A valid cert for a *different* member must not authorize this key.
/// 3. **Authenticity**: `cert.verify(&record.hh_pub)`, else [`CertInvalid`].
/// 4. **Membership**: `cert.m_id ∈ record.members`, else [`NonMember`].
/// 5. **Revocation overlay**: if `projection` records `signer_pub` as
///    `Removed`, fail with [`DeviceRemoved`]. Absent / `Active` / no projection
///    is NOT a rejection (see module docs).
///
/// `projection` is optional: callers without a projected mesh log pass `None`
/// and rely on membership + cert alone.
pub fn is_machine_issuer_active(
    record: &HouseholdRecord,
    cert: &MachineCert,
    projection: Option<&ProjectedState>,
    signer_pub: &P256PublicKey,
    allow_root_signer: bool,
) -> Result<(), MachineIssuerError> {
    // 1. Root/degenerate: signed directly by the household root key. The root
    //    is the trust anchor itself, so the cert chain is not consulted here.
    if allow_root_signer && *signer_pub == record.hh_pub {
        return Ok(());
    }
    // 2. The cert must speak for exactly this signer key (cheap structural
    //    bind before the crypto check; a valid cert for another member must
    //    not be swapped in to authorize a foreign key).
    if cert.m_pub != *signer_pub {
        return Err(MachineIssuerError::SignerMismatch);
    }
    // 3. The cert must be authentic under the household root (signature +
    //    shape + m_id-derives-from-m_pub, all enforced by `MachineCert::verify`).
    cert.verify(&record.hh_pub)
        .map_err(MachineIssuerError::CertInvalid)?;
    // 4. The certified machine must be a current household member.
    if !record.members.contains(&cert.m_id) {
        return Err(MachineIssuerError::NonMember);
    }
    // 5. Revocation overlay: a `Removed` directory entry is a kill switch.
    //    Absent or `Active` entries (and a `None` projection) do not reject —
    //    membership + cert are the source of truth for "active".
    if let Some(projection) = projection {
        let key = signer_pub.as_bytes().to_vec();
        if matches!(
            projection.directory_devices.get(&key),
            Some(device) if device.status == DirectoryDeviceStatus::Removed
        ) {
            return Err(MachineIssuerError::DeviceRemoved);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::household_mesh_log::{LogEntry, MeshEvent, ProjectedDirectoryDevice};
    use crate::ids::{MachineId, derive_household_id, derive_machine_id};
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::machine_cert::{Platform, SignOptions};

    fn member_cert(hh: &P256Keypair, m: &P256Keypair) -> MachineCert {
        MachineCert::sign(
            hh,
            &m.public(),
            &SignOptions {
                hh_id: derive_household_id(&hh.public()),
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .unwrap()
    }

    fn record_with(hh: &P256Keypair, members: Vec<MachineId>) -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh.public()),
            hh_pub: hh.public(),
            name: "home".into(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members,
            is_follower: false,
        }
    }

    fn signed_event(owner: &P256Keypair, ts: u64, event: MeshEvent) -> LogEntry {
        LogEntry::sign(ts, owner.public(), event, owner as &dyn IdentityKey).unwrap()
    }

    #[test]
    fn accepts_member_machine_cert_without_projection() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);

        is_machine_issuer_active(&record, &cert, None, &m.public(), true).unwrap();
    }

    #[test]
    fn accepts_root_signer_without_consulting_cert() {
        // signer_pub == hh_pub short-circuits: the cert is for `m` and `m` is
        // NOT a member, which would fail on the normal path — root acceptance
        // must bypass both the subject/cert checks and the membership check.
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let stranger = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&stranger.public())]);

        is_machine_issuer_active(&record, &cert, None, &hh.public(), true).unwrap();
    }

    #[test]
    fn rejects_root_signer_when_disabled() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);

        let err = is_machine_issuer_active(&record, &cert, None, &hh.public(), false).unwrap_err();

        assert!(matches!(err, MachineIssuerError::SignerMismatch));
    }

    #[test]
    fn accepts_member_cert_even_when_root_signer_disabled() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);

        is_machine_issuer_active(&record, &cert, None, &m.public(), false).unwrap();
    }

    #[test]
    fn rejects_signer_not_matching_cert_subject() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let attacker = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);

        let err =
            is_machine_issuer_active(&record, &cert, None, &attacker.public(), true).unwrap_err();

        assert!(matches!(err, MachineIssuerError::SignerMismatch));
    }

    #[test]
    fn rejects_cert_signed_by_foreign_root() {
        let hh = P256Keypair::generate();
        let foreign_hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        // Cert is well-formed but signed by a different household root.
        let cert = member_cert(&foreign_hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);

        let err = is_machine_issuer_active(&record, &cert, None, &m.public(), true).unwrap_err();

        assert!(matches!(err, MachineIssuerError::CertInvalid(_)));
    }

    #[test]
    fn rejects_non_member_cert() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let other = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        // Valid, household-signed cert for `m`, but `m` is not in members.
        let record = record_with(&hh, vec![derive_machine_id(&other.public())]);

        let err = is_machine_issuer_active(&record, &cert, None, &m.public(), true).unwrap_err();

        assert!(matches!(err, MachineIssuerError::NonMember));
    }

    #[test]
    fn accepts_active_directory_device() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);
        // An Active directory entry for the signer must NOT block.
        let projection = ProjectedState::project(&[signed_event(
            &hh,
            1_000,
            MeshEvent::DirectoryDeviceAdded {
                device_pub: m.public(),
                label: "studio-mac".to_string(),
            },
        )]);

        is_machine_issuer_active(&record, &cert, Some(&projection), &m.public(), true).unwrap();
    }

    #[test]
    fn accepts_when_signer_absent_from_directory() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let stranger = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);
        // A projection that removed some OTHER device must not block `m`;
        // absence from the directory is not a rejection.
        let projection = ProjectedState::project(&[signed_event(
            &hh,
            1_000,
            MeshEvent::DirectoryDeviceRemoved {
                device_pub: stranger.public(),
            },
        )]);

        is_machine_issuer_active(&record, &cert, Some(&projection), &m.public(), true).unwrap();
    }

    #[test]
    fn rejects_directory_removed_device() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);
        let mut projection = ProjectedState::default();
        projection.directory_devices.insert(
            m.public().as_bytes().to_vec(),
            ProjectedDirectoryDevice {
                label: "studio-mac".to_string(),
                status: DirectoryDeviceStatus::Removed,
            },
        );

        let err = is_machine_issuer_active(&record, &cert, Some(&projection), &m.public(), true)
            .unwrap_err();

        assert!(matches!(err, MachineIssuerError::DeviceRemoved));
    }

    #[test]
    fn rejects_after_added_then_removed_projection() {
        // Exercise the real projection: Added (Active) then Removed must fold
        // to Removed and reject, even though `m` is a valid, certified member.
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_cert(&hh, &m);
        let record = record_with(&hh, vec![derive_machine_id(&m.public())]);
        let projection = ProjectedState::project(&[
            signed_event(
                &hh,
                1_000,
                MeshEvent::DirectoryDeviceAdded {
                    device_pub: m.public(),
                    label: "studio-mac".to_string(),
                },
            ),
            signed_event(
                &hh,
                2_000,
                MeshEvent::DirectoryDeviceRemoved {
                    device_pub: m.public(),
                },
            ),
        ]);

        let err = is_machine_issuer_active(&record, &cert, Some(&projection), &m.public(), true)
            .unwrap_err();

        assert!(matches!(err, MachineIssuerError::DeviceRemoved));
    }
}
