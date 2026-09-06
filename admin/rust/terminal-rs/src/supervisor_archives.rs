//! Retention for completed PTY instances. Live writers and attached readers
//! are protected by the broker registry; this never expires a live session.
//! With the broker's 64 ownership slots and default 32 MiB physical log cap,
//! protected output plus this 256 MiB archive budget totals 2.25 GiB, apart
//! from metadata and one transient append per log. Foreign layouts preserved
//! as unmanaged are outside that budget; this is not a filesystem quota.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) const MAX_ARCHIVED_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_ARCHIVED_INSTANCES: usize = 64;

pub(crate) fn prune(
    root: &Path,
    protected: &HashSet<PathBuf>,
    max_bytes: u64,
    max_instances: usize,
) -> io::Result<()> {
    let mut archives = Vec::new();
    let mut total = 0_u64;
    for conversation in fs::read_dir(root)? {
        let conversation = conversation?;
        if !conversation.file_type()?.is_dir() {
            continue;
        }
        'instances: for instance in fs::read_dir(conversation.path())? {
            let instance = instance?;
            if !instance.file_type()?.is_dir()
                || instance
                    .file_name()
                    .to_str()
                    .is_none_or(|id| uuid::Uuid::parse_str(id).is_err())
                || protected.contains(&instance.path())
            {
                continue;
            }
            // Registry protection is supplemented by the actual writer lock:
            // a finishing reader can still own the log after its entry retires.
            match fs::symlink_metadata(instance.path().join(".writer.lock")) {
                Ok(metadata) if !metadata.is_file() => {
                    tracing::warn!(reason = "unexpected_lock_type", "ptyd.archive.unmanaged");
                    continue;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(instance.path().join(".writer.lock"))?;
            match fs2::FileExt::try_lock_exclusive(&lock) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
            let mut bytes = 0_u64;
            for file in fs::read_dir(instance.path())? {
                let file = file?;
                if !file.file_type()?.is_file() {
                    // Unknown layouts are not ours to delete or a transient
                    // disk failure. Preserve this instance and collect others.
                    // Its bytes are outside the managed archive budget; the
                    // diagnostic must not imply a quota on foreign content.
                    tracing::warn!(reason = "unexpected_entry_type", "ptyd.archive.unmanaged");
                    continue 'instances;
                }
                bytes = bytes
                    .checked_add(file.metadata()?.len())
                    .ok_or_else(|| io::Error::other("PTY archive size overflow"))?;
            }
            total = total
                .checked_add(bytes)
                .ok_or_else(|| io::Error::other("PTY archive size overflow"))?;
            let age = instance
                .metadata()?
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH);
            archives.push((age, instance.path(), bytes, lock));
        }
        // Completed conversations must not accumulate empty directories after
        // their last instance expires. Never follow a directory symlink.
        if fs::read_dir(conversation.path())?.next().is_none() {
            fs::remove_dir(conversation.path())?;
        }
    }
    archives.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    let mut count = archives.len();
    for (_, path, bytes, _lock) in archives {
        if total <= max_bytes && count <= max_instances {
            break;
        }
        fs::remove_dir_all(&path)?;
        total -= bytes;
        count -= 1;
        if let Some(parent) = path.parent() {
            if fs::read_dir(parent)?.next().is_none() {
                fs::remove_dir(parent)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segmented_log::{LogLimits, ReplayRead, SegmentedLog};

    #[test]
    fn unexpected_layout_is_preserved_without_blocking_other_archive_collection() {
        let root = tempfile::tempdir().unwrap();
        let foreign = root
            .path()
            .join("conversation")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(foreign.join("unknown-layout")).unwrap();
        fs::write(
            foreign.join("unknown-layout").join("preserve"),
            b"foreign data",
        )
        .unwrap();
        let unusual_lock = root
            .path()
            .join("conversation")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(unusual_lock.join(".writer.lock")).unwrap();
        let known = root
            .path()
            .join("conversation")
            .join(uuid::Uuid::new_v4().to_string());
        let log = SegmentedLog::open(&known, LogLimits::default()).unwrap();
        log.append(b"eligible archive").unwrap();
        drop(log);
        prune(root.path(), &HashSet::new(), 0, 0).unwrap();
        assert!(!known.exists());
        assert_eq!(
            fs::read(foreign.join("unknown-layout").join("preserve")).unwrap(),
            b"foreign data"
        );
        assert!(unusual_lock.join(".writer.lock").is_dir());
    }

    #[test]
    fn physical_archive_budget_preserves_protected_output_and_cleans_empty_conversations() {
        let root = tempfile::tempdir().unwrap();
        let live_path = root
            .path()
            .join("live")
            .join(uuid::Uuid::new_v4().to_string());
        let live = SegmentedLog::open(&live_path, LogLimits::default()).unwrap();
        live.append(b"still owned").unwrap();
        for index in 0..12 {
            let path = root
                .path()
                .join(format!("closed-{index}"))
                .join(uuid::Uuid::new_v4().to_string());
            let log = SegmentedLog::open(&path, LogLimits::default()).unwrap();
            log.append(&[0x61; 1024]).unwrap();
        }
        prune(root.path(), &HashSet::from([live_path]), 2200, 2).unwrap();
        let mut archived_bytes = 0;
        let mut instances = 0;
        for conversation in fs::read_dir(root.path()).unwrap() {
            let conversation = conversation.unwrap();
            if conversation.file_name() == "live" {
                continue;
            }
            let children: Vec<_> = fs::read_dir(conversation.path()).unwrap().collect();
            assert!(!children.is_empty());
            for child in children {
                instances += 1;
                for file in fs::read_dir(child.unwrap().path()).unwrap() {
                    archived_bytes += file.unwrap().metadata().unwrap().len();
                }
            }
        }
        assert!(instances <= 2 && archived_bytes <= 2200);
        let ReplayRead::Data(chunk) = live.read(0, 100).unwrap() else {
            panic!("live history lost")
        };
        assert_eq!(chunk.bytes, b"still owned");
        live.append(b" after GC").unwrap();
        // A finishing owner not listed in the registry still holds the actual
        // writer lock. A zero archive budget must not delete that output.
        prune(root.path(), &HashSet::new(), 0, 0).unwrap();
        let ReplayRead::Data(chunk) = live.read(0, 100).unwrap() else {
            panic!("writer lock protection lost")
        };
        assert_eq!(chunk.bytes, b"still owned after GC");
    }
}
