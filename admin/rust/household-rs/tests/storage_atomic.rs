use std::io::{Error, ErrorKind};

use household_rs::StorageError;
use household_rs::storage::{atomic_write_cbor_with_tmp_write_error, household_record_path};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TinyRecord {
    value: String,
}

#[test]
fn enospc_during_tmp_write_leaves_no_partial_state() {
    let temp = tempdir().unwrap();
    let path = household_record_path(temp.path());
    let tmp_path = {
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        std::path::PathBuf::from(tmp_name)
    };

    let error = atomic_write_cbor_with_tmp_write_error(
        &path,
        &TinyRecord {
            value: "not persisted".into(),
        },
        Error::new(ErrorKind::StorageFull, "No space left on device"),
    )
    .unwrap_err();

    match error {
        StorageError::OutOfSpace { path: failed, hint } => {
            assert_eq!(failed, tmp_path);
            assert_eq!(hint, "Free disk space and retry `theyos install`.");
        }
        other => panic!("expected OutOfSpace, got {other:?}"),
    }

    assert!(!tmp_path.exists(), "orphan tmp file remained");
    assert!(!path.exists(), "final household_record.cbor was created");
}
