mod phase3_support;

use std::path::{Path, PathBuf};

use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::pair_machine::{household_root_sole_path, shamir_self_shard_path};
use household_rs::shard_at_rest::{EncryptedShard, decrypt_self};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[tokio::test]
async fn test_no_plaintext_hh_priv_after_commit() {
    let ceremony = phase3_support::run_remote_ceremony().await;
    phase3_support::assert_successful_remote_ceremony(&ceremony);

    let original_hh_priv = Zeroizing::new(
        *ceremony
            .founder
            .identity
            .hh_priv
            .as_ref()
            .and_then(|k| k.as_software_secret())
            .expect("pre-Shamir founder fixture has software HH_priv"),
    );

    assert!(!household_root_sole_path(ceremony.founder.dir.path()).exists());
    assert!(!household_root_sole_path(ceremony.candidate.dir.path()).exists());

    assert_only_encrypted_self_shard(ceremony.founder.dir.path());
    assert_only_encrypted_self_shard(ceremony.candidate.dir.path());

    assert_wrong_key_fails_shard_decrypt(
        ceremony.founder.dir.path(),
        &ceremony.founder.identity.cert.m_id.to_string(),
    );
    assert_wrong_key_fails_shard_decrypt(
        ceremony.candidate.dir.path(),
        &ceremony.candidate.prepared.m_id.to_string(),
    );

    assert_correct_key_decrypts_non_root_shard(
        ceremony.founder.dir.path(),
        &ceremony.founder.identity.cert.m_id.to_string(),
        ceremony.founder.identity.m_priv.as_ref(),
        &original_hh_priv,
    );
    assert_correct_key_decrypts_non_root_shard(
        ceremony.candidate.dir.path(),
        &ceremony.candidate.prepared.m_id.to_string(),
        ceremony.candidate.prepared.m_priv.as_ref(),
        &original_hh_priv,
    );

    assert_no_file_contains_secret_window(ceremony.founder.dir.path(), &original_hh_priv);
    assert_no_file_contains_secret_window(ceremony.candidate.dir.path(), &original_hh_priv);
}

fn assert_only_encrypted_self_shard(state_dir: &Path) {
    let files = files_with_shard_in_name(state_dir);
    let expected = shamir_self_shard_path(state_dir);
    assert_eq!(
        files,
        vec![expected],
        "unexpected shard-named files under {}",
        state_dir.display()
    );
}

fn assert_wrong_key_fails_shard_decrypt(state_dir: &Path, m_id: &str) {
    let shard_path = shamir_self_shard_path(state_dir);
    let shard: EncryptedShard = household_rs::storage::read_optional_cbor(&shard_path)
        .expect("read encrypted shard")
        .expect("encrypted shard exists");
    let wrong_key = P256Keypair::generate();
    let wrong_priv = wrong_key
        .as_software_secret()
        .expect("generated test key exposes software scalar");
    let wrong_pub = wrong_key.public();

    let err = decrypt_self(&shard, wrong_priv, &wrong_pub, m_id);
    assert!(
        err.is_err(),
        "encrypted shard at {} decrypted with a wrong machine key",
        shard_path.display()
    );
}

fn assert_correct_key_decrypts_non_root_shard(
    state_dir: &Path,
    m_id: &str,
    key: &dyn IdentityKey,
    original_hh_priv: &[u8; 32],
) {
    let shard_path = shamir_self_shard_path(state_dir);
    let shard: EncryptedShard = household_rs::storage::read_optional_cbor(&shard_path)
        .expect("read encrypted shard")
        .expect("encrypted shard exists");
    let correct_priv = key
        .as_software_secret()
        .expect("test machine key exposes software scalar");
    let correct_pub = key.public();

    let plaintext = decrypt_self(&shard, correct_priv, &correct_pub, m_id)
        .expect("correct machine key decrypts shard");
    let plaintext_bytes: &[u8; 32] = &plaintext;
    assert!(
        !bool::from(
            plaintext_bytes
                .as_slice()
                .ct_eq(original_hh_priv.as_slice())
        ),
        "decrypted Shamir share at {} unexpectedly equals plaintext HH_priv",
        shard_path.display()
    );
}

fn assert_no_file_contains_secret_window(state_dir: &Path, secret: &[u8; 32]) {
    for path in all_files_under(state_dir) {
        let bytes = std::fs::read(&path).expect("read state file");
        assert!(
            !contains_secret_window(&bytes, secret),
            "plaintext HH_priv scalar found in {}",
            path.display()
        );
    }
}

fn contains_secret_window(bytes: &[u8], secret: &[u8; 32]) -> bool {
    bytes
        .windows(secret.len())
        .any(|window| bool::from(window.ct_eq(secret.as_slice())))
}

fn files_with_shard_in_name(state_dir: &Path) -> Vec<PathBuf> {
    let mut files = all_files_under(state_dir)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("shard"))
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn all_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files(root, &mut out);
    out.sort();
    out
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let entries = std::fs::read_dir(path).expect("read state dir");
    for entry in entries {
        let entry = entry.expect("state dir entry");
        collect_files(&entry.path(), out);
    }
}
