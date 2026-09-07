//! Bounded, broker-issued execution tickets. Absence always revokes CREATE;
//! collecting a consumed ticket can therefore never authorize its replay.
//! Methods require exclusive access, supplied by the broker's registry lock.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Ticket {
    version: u8,
    conversation_id: String,
    consumed: bool,
}

pub(crate) struct IntentStore {
    root: PathBuf,
    limit: usize,
    count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitStep {
    SyncRecord,
    Rename,
    SyncDirectory,
    Complete,
}

impl IntentStore {
    pub(crate) fn open(root: &Path, limit: usize) -> Result<Self, &'static str> {
        if limit == 0 {
            return Err("intent_limit");
        }
        let mut count = 0;
        for entry in fs::read_dir(root).map_err(|_| "storage_unavailable")? {
            let entry = entry.map_err(|_| "storage_unavailable")?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            {
                count += 1;
            }
            if entry.file_name().to_str().is_some_and(|name| {
                name.strip_suffix(".next")
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
            }) {
                fs::remove_file(entry.path()).map_err(|_| "storage_unavailable")?;
            }
        }
        Ok(Self {
            root: root.into(),
            limit,
            count,
        })
    }

    /// Emission has no execution effect and accepts no caller-selected ID.
    /// Losing its response can waste a ticket, but cannot duplicate a command.
    pub(crate) fn issue(
        &mut self,
        conversation: &str,
        protected: &HashSet<String>,
    ) -> Result<String, &'static str> {
        if self.count >= self.limit {
            let mut files = Vec::new();
            for entry in fs::read_dir(&self.root).map_err(|_| "storage_unavailable")? {
                let entry = entry.map_err(|_| "storage_unavailable")?;
                let name = entry
                    .file_name()
                    .to_str()
                    .ok_or("storage_unavailable")?
                    .to_owned();
                if Uuid::parse_str(&name).is_err() {
                    continue;
                }
                let modified = entry
                    .metadata()
                    .map_err(|_| "storage_unavailable")?
                    .modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                files.push((modified, name, entry.path()));
            }
            // Age only selects which authorization to revoke; no timestamp
            // can make an absent ticket valid, even after clock corrections.
            files.sort();
            let mut remaining = files.len();
            let target = self.limit.saturating_sub((self.limit / 8).max(1));
            for (_, name, path) in &files {
                if remaining <= target {
                    break;
                }
                if protected.contains(name) {
                    continue;
                }
                fs::remove_file(path).map_err(|_| "storage_unavailable")?;
                remaining -= 1;
                self.count = remaining;
            }
            self.count = remaining;
            // Expiration is an authorization change too. Do not acknowledge
            // collection while a lost directory update could restore issued.
            self.sync_directory()?;
            if remaining >= self.limit {
                return Err("intent_limit");
            }
        }
        let ticket = Ticket {
            version: 1,
            conversation_id: conversation.into(),
            consumed: false,
        };
        let data = serde_json::to_vec(&ticket).map_err(|_| "storage_unavailable")?;
        loop {
            let id = Uuid::new_v4().to_string();
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.root.join(&id))
            {
                Ok(mut file) => {
                    // Count even an incomplete issuance: it remains fail-closed
                    // on disk and must still consume the storage budget.
                    self.count += 1;
                    file.write_all(&data).map_err(|_| "storage_unavailable")?;
                    return Ok(id);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("storage_unavailable"),
            }
        }
    }

    fn read(&self, conversation: &str, id: &str) -> Result<Ticket, &'static str> {
        if Uuid::parse_str(id).is_err() {
            return Err("intent_expired");
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.root.join(id))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    "intent_expired"
                } else {
                    "storage_unavailable"
                }
            })?;
        let mut data = Vec::new();
        file.take(1025)
            .read_to_end(&mut data)
            .map_err(|_| "storage_unavailable")?;
        // Legacy F1 reservations contain only a digest. They can be collected,
        // but never interpreted as newly issued execution authority.
        let ticket: Ticket = serde_json::from_slice(&data).map_err(|_| "intent_consumed")?;
        if ticket.version != 1 {
            return Err("intent_consumed");
        }
        if ticket.conversation_id != conversation {
            return Err("intent_mismatch");
        }
        Ok(ticket)
    }

    pub(crate) fn require_issued(&self, conversation: &str, id: &str) -> Result<(), &'static str> {
        if self.read(conversation, id)?.consumed {
            Err("intent_consumed")
        } else {
            Ok(())
        }
    }

    /// Confirm record data and the replacement directory entry before spawn.
    /// Any persistence error refuses execution, including errors after rename.
    /// `sync_all` requests the platform's storage barrier (`F_FULLFSYNC` on Apple);
    /// this relies on the filesystem/device honoring that barrier, not on an
    /// assertion that software can prove survival of every physical failure.
    pub(crate) fn consume(&mut self, conversation: &str, id: &str) -> Result<(), &'static str> {
        let mut ticket = self.read(conversation, id)?;
        if ticket.consumed {
            return Err("intent_consumed");
        }
        ticket.consumed = true;
        self.commit_consumed(id, &ticket, |_| Ok(()))
    }

    fn sync_directory(&self) -> Result<(), &'static str> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "storage_unavailable")
    }

    // The checkpoint seam injects errors at persistence boundaries in tests;
    // it never substitutes an in-memory barrier for an actual filesystem sync.
    fn commit_consumed(
        &self,
        id: &str,
        ticket: &Ticket,
        mut checkpoint: impl FnMut(CommitStep) -> std::io::Result<()>,
    ) -> Result<(), &'static str> {
        let next = self.root.join(format!("{id}.next"));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&next)
                .map_err(|_| "storage_unavailable")?;
            file.write_all(&serde_json::to_vec(&ticket).map_err(|_| "storage_unavailable")?)
                .map_err(|_| "storage_unavailable")?;
            checkpoint(CommitStep::SyncRecord).map_err(|_| "storage_unavailable")?;
            file.sync_all().map_err(|_| "storage_unavailable")?;
            checkpoint(CommitStep::Rename).map_err(|_| "storage_unavailable")?;
            fs::rename(&next, self.root.join(id)).map_err(|_| "storage_unavailable")?;
            checkpoint(CommitStep::SyncDirectory).map_err(|_| "storage_unavailable")?;
            self.sync_directory()?;
            checkpoint(CommitStep::Complete).map_err(|_| "storage_unavailable")
        })();
        if result.is_err() {
            let _ = fs::remove_file(next);
        }
        result
    }

    /// Missing, corrupt and legacy records cannot authorize CREATE and are
    /// idempotent success. Real read failures and ownership mismatches are not.
    /// Keep a synchronized consumed record until GC: merely unlinking issued
    /// could resurrect its execution authority after a lost directory update.
    pub(crate) fn cancel(&mut self, conversation: &str, id: &str) -> Result<(), &'static str> {
        let mut ticket = match self.read(conversation, id) {
            Err("intent_expired" | "intent_consumed") => return Ok(()),
            Err(error) => return Err(error),
            Ok(ticket) => ticket,
        };
        ticket.consumed = true;
        self.commit_consumed(id, &ticket, |_| Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_failures_never_acknowledge_consumption() {
        let steps = [
            CommitStep::SyncRecord,
            CommitStep::Rename,
            CommitStep::SyncDirectory,
            CommitStep::Complete,
        ];
        for failed_step in steps {
            let root = tempfile::tempdir().unwrap();
            let mut store = IntentStore::open(root.path(), 8).unwrap();
            let id = store.issue("pane", &HashSet::new()).unwrap();
            let ticket = Ticket {
                version: 1,
                conversation_id: "pane".into(),
                consumed: true,
            };
            let mut visited = Vec::new();
            let result = store.commit_consumed(&id, &ticket, |step| {
                visited.push(step);
                if step == failed_step {
                    Err(std::io::Error::other("injected persistence failure"))
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err("storage_unavailable"));
            let position = steps.iter().position(|step| *step == failed_step).unwrap();
            assert_eq!(visited, steps[..=position]);
            assert!(!root.path().join(format!("{id}.next")).exists());
            let reopened = IntentStore::open(root.path(), 8).unwrap();
            // Failure before rename leaves issued, but the caller received no
            // permission to spawn. Failure after rename must refuse any retry.
            assert_eq!(
                reopened.require_issued("pane", &id),
                if position < 2 {
                    Ok(())
                } else {
                    Err("intent_consumed")
                }
            );
        }
        let root = tempfile::tempdir().unwrap();
        let mut store = IntentStore::open(root.path(), 8).unwrap();
        let id = store.issue("pane", &HashSet::new()).unwrap();
        let ticket = Ticket {
            version: 1,
            conversation_id: "pane".into(),
            consumed: true,
        };
        let mut visited = Vec::new();
        store
            .commit_consumed(&id, &ticket, |step| {
                visited.push(step);
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, steps);
        assert_eq!(
            IntentStore::open(root.path(), 8)
                .unwrap()
                .require_issued("pane", &id),
            Err("intent_consumed")
        );
    }

    #[test]
    fn cancellation_is_idempotent_without_hiding_storage_or_owner_failures() {
        let root = tempfile::tempdir().unwrap();
        let mut store = IntentStore::open(root.path(), 8).unwrap();
        let id = store.issue("pane", &HashSet::new()).unwrap();
        assert_eq!(store.cancel("other", &id), Err("intent_mismatch"));
        assert_eq!(store.require_issued("pane", &id), Ok(()));
        store.cancel("pane", &id).unwrap();
        store.cancel("pane", &id).unwrap();
        assert_eq!(
            IntentStore::open(root.path(), 8)
                .unwrap()
                .require_issued("pane", &id),
            Err("intent_consumed")
        );
        for data in [
            b"truncated".as_slice(),
            b"legacy-digest",
            b"{\"version\":2,\"conversation_id\":\"pane\",\"consumed\":false}",
        ] {
            fs::write(root.path().join(&id), data).unwrap();
            assert_eq!(store.cancel("pane", &id), Ok(()));
            assert_eq!(store.require_issued("pane", &id), Err("intent_consumed"));
        }
        fs::remove_file(root.path().join(&id)).unwrap();
        fs::create_dir(root.path().join(&id)).unwrap();
        assert_eq!(store.cancel("pane", &id), Err("storage_unavailable"));
        fs::remove_dir(root.path().join(&id)).unwrap();
        assert_eq!(store.cancel("pane", &id), Ok(()));
    }

    #[test]
    fn collection_revokes_authority_without_clock_or_lifetime_exhaustion() {
        let root = tempfile::tempdir().unwrap();
        let mut store = IntentStore::open(root.path(), 32).unwrap();
        let live = store.issue("live", &HashSet::new()).unwrap();
        store.consume("live", &live).unwrap();
        let protected = HashSet::from([live.clone()]);
        let old = store.issue("pane", &protected).unwrap();
        store.consume("pane", &old).unwrap();
        for _ in 0..5000 {
            store.issue("pane", &protected).unwrap();
        }
        assert!(fs::read_dir(root.path()).unwrap().count() <= 32);
        assert!(root.path().join(&live).exists());
        assert_eq!(store.consume("pane", &old), Err("intent_expired"));
        assert_eq!(store.cancel("pane", &old), Ok(()));
        let mut reopened = IntentStore::open(root.path(), 32).unwrap();
        assert_eq!(reopened.consume("pane", &old), Err("intent_expired"));
        assert_eq!(reopened.consume("live", &live), Err("intent_consumed"));
        assert!(reopened.issue("new", &protected).is_ok());
    }

    #[test]
    fn consumption_recovery_never_grants_authority_from_a_partial_record() {
        let root = tempfile::tempdir().unwrap();
        let mut store = IntentStore::open(root.path(), 8).unwrap();
        let id = store.issue("pane", &HashSet::new()).unwrap();
        assert_eq!(store.consume("different-pane", &id), Err("intent_mismatch"));
        fs::write(
            root.path().join(format!("{id}.next")),
            b"partial transition",
        )
        .unwrap();
        let mut reopened = IntentStore::open(root.path(), 8).unwrap();
        reopened.consume("pane", &id).unwrap();
        let mut reopened = IntentStore::open(root.path(), 8).unwrap();
        assert_eq!(reopened.consume("pane", &id), Err("intent_consumed"));
        reopened.cancel("pane", &id).unwrap();
        reopened.cancel("pane", &id).unwrap();
        assert_eq!(reopened.consume("pane", &id), Err("intent_consumed"));
    }
}
