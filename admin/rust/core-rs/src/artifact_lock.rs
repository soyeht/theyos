//! Global filesystem lock for artifact operations.
//!
//! Prevents concurrent artifact operations (snapshot-create, artifacts sync,
//! claw install) from racing with each other.  Uses `flock(2)` for
//! cross-process advisory locking.
//!
//! Lock file location: `<lock_dir>/artifacts.lock`
//! (typically `~/firecracker/locks/artifacts.lock`).

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// RAII guard for the global artifact lock.
///
/// Acquiring the lock creates `<lock_dir>/artifacts.lock` and holds an
/// exclusive `flock(2)` on it.  Dropping the guard releases the lock.
///
/// # Example
///
/// ```no_run
/// use core_rs::artifact_lock::ArtifactLock;
/// use std::path::Path;
///
/// let lock = ArtifactLock::acquire(Path::new("/home/user/firecracker/locks"))?;
/// // ... do artifact work ...
/// drop(lock); // or let it go out of scope
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct ArtifactLock {
    _file: File,
    path: PathBuf,
}

impl ArtifactLock {
    /// Acquire the global artifact lock (blocking).
    ///
    /// Creates `<lock_dir>/artifacts.lock` if it doesn't exist.
    /// Blocks until the lock is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock directory cannot be created or the lock
    /// file cannot be opened/locked.
    pub fn acquire(lock_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(lock_dir)?;
        let path = lock_dir.join("artifacts.lock");
        let file = File::create(&path)?;

        // SAFETY: flock is safe to call on a valid fd.
        #[allow(unsafe_code)]
        {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self { _file: file, path })
    }

    /// Try to acquire the lock without blocking.
    ///
    /// Returns `Ok(Some(lock))` if acquired, `Ok(None)` if already held by
    /// another process, or `Err` on I/O failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock directory cannot be created or the lock
    /// file cannot be opened.
    pub fn try_acquire(lock_dir: &Path) -> io::Result<Option<Self>> {
        fs::create_dir_all(lock_dir)?;
        let path = lock_dir.join("artifacts.lock");
        let file = File::create(&path)?;

        #[allow(unsafe_code)]
        {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(err);
            }
        }

        Ok(Some(Self { _file: file, path }))
    }

    /// Check if the artifact lock is currently held by any process.
    ///
    /// Non-blocking: returns immediately.
    #[must_use]
    pub fn is_held(lock_dir: &Path) -> bool {
        let path = lock_dir.join("artifacts.lock");
        let Ok(file) = File::open(&path) else {
            return false; // file doesn't exist => not held
        };

        #[allow(unsafe_code)]
        {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if ret == 0 {
                // We acquired it => it was NOT held. Release immediately.
                unsafe { libc::flock(fd, libc::LOCK_UN) };
                false
            } else {
                // EWOULDBLOCK => someone else holds it
                true
            }
        }
    }

    /// The path to the lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// flock is automatically released when the File is dropped.
// No explicit Drop needed — the OS releases the advisory lock on fd close.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_drop() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let lock = ArtifactLock::acquire(&lock_dir).unwrap();
        assert!(lock.path().exists());
        assert!(ArtifactLock::is_held(&lock_dir));

        drop(lock);
        // After drop, lock should be released.
        assert!(!ArtifactLock::is_held(&lock_dir));
    }

    #[test]
    fn try_acquire_succeeds_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let lock = ArtifactLock::try_acquire(&lock_dir).unwrap();
        assert!(lock.is_some());
    }

    #[test]
    fn try_acquire_returns_none_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let _lock = ArtifactLock::acquire(&lock_dir).unwrap();
        let second = ArtifactLock::try_acquire(&lock_dir).unwrap();
        assert!(second.is_none(), "should return None when lock is held");
    }

    #[test]
    fn is_held_false_when_no_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!ArtifactLock::is_held(dir.path()));
    }

    #[test]
    fn is_held_false_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let lock = ArtifactLock::acquire(&lock_dir).unwrap();
        drop(lock);
        assert!(!ArtifactLock::is_held(&lock_dir));
    }

    #[test]
    fn lock_dir_is_created_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("deeply").join("nested").join("locks");

        assert!(!lock_dir.exists());
        let lock = ArtifactLock::acquire(&lock_dir).unwrap();
        assert!(lock_dir.exists());
        drop(lock);
    }

    #[test]
    fn lock_path_is_correct() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");
        let lock = ArtifactLock::acquire(&lock_dir).unwrap();
        assert_eq!(lock.path(), lock_dir.join("artifacts.lock"));
    }
}
