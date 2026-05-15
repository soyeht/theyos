//! SSH port selection helpers.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::VmError;

// ── Port lock directory ─────────────────────────────────────────────────────

fn port_locks_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(".port-locks")
}

fn port_lock_path(state_dir: &Path, port: u16) -> PathBuf {
    port_locks_dir(state_dir).join(format!("{port}.lock"))
}

/// A port reservation that releases the lock file on drop.
///
/// Holds an exclusive claim on `port` until dropped or `release()` is called.
/// The lock file is created atomically via `O_CREAT | O_EXCL`. If the process
/// crashes, the lock file is left behind but is detected as stale on the next
/// `pick_ssh_port` call (the lock file is deleted if its owning instance.env
/// no longer lists the port).
pub struct PortReservation {
    pub port: u16,
    lock_path: PathBuf,
    released: bool,
}

impl PortReservation {
    /// Explicitly release the lock (also called automatically on drop).
    pub fn release(&mut self) {
        if !self.released {
            let _ = fs::remove_file(&self.lock_path);
            self.released = true;
        }
    }
}

impl Drop for PortReservation {
    fn drop(&mut self) {
        self.release();
    }
}

/// Pick an available SSH port in the range 22000–23999 and atomically reserve it.
///
/// Returns both the port number and a `PortReservation` guard. The caller
/// **must keep the reservation alive** until either:
///   - The `instance.env` has been written with `SSH_PORT=<port>` (at which
///     point the port is visible to future `pick_ssh_port` callers via the
///     scan), OR
///   - The create flow fails (the `Drop` impl removes the lock file).
///
/// This eliminates the TOCTOU race between the old probe-then-use pattern.
/// # Errors
///
/// Returns an error if no port is available in the range or the lock directory
/// cannot be created.
#[allow(clippy::result_large_err)]
pub fn pick_ssh_port(state_dir: &Path) -> Result<(u16, PortReservation), VmError> {
    use std::fs::OpenOptions;

    let locks_dir = port_locks_dir(state_dir);
    fs::create_dir_all(&locks_dir).map_err(|e| {
        VmError::Io(format!(
            "create port-locks dir {}: {e}",
            locks_dir.display()
        ))
    })?;

    // Collect ports already claimed by existing instances (written to instance.env)
    // as a fast-path skip before attempting atomic lock creation.
    let used_ports = collect_used_ssh_ports(state_dir);

    // Also sweep stale lock files that have no matching instance.env entry
    // (left behind by crashed processes).
    sweep_stale_port_locks(state_dir, &locks_dir, &used_ports);

    for port in 22000u16..=23999 {
        if used_ports.contains(&port) {
            continue;
        }

        // OS-level check: skip ports already bound by any process (e.g. pool
        // slirp4netns instances from other claw types running concurrently).
        // This prevents `slirp_add_hostfwd` from failing with EADDRINUSE when
        // a warm-pool VM from a different claw type is holding the same port.
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_err() {
            continue;
        }

        let lock_path = port_lock_path(state_dir, port);

        // Atomically create the lock file. O_CREAT | O_EXCL ensures only one
        // caller succeeds even across concurrent processes.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_file) => {
                // We own the lock. The file descriptor is dropped here but the
                // file remains; the PortReservation guard will remove it.
                return Ok((
                    port,
                    PortReservation {
                        port,
                        lock_path,
                        released: false,
                    },
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another concurrent create already claimed this port.
            }
            Err(e) => {
                return Err(VmError::Io(format!(
                    "create port lock {}: {e}",
                    lock_path.display()
                )));
            }
        }
    }

    Err(VmError::NoFreeSshPort)
}

/// Remove stale lock files that have no matching instance.env entry.
///
/// A lock file is stale if:
///   - Its port number does not appear in any instance.env, AND
///   - The lock file is older than 60 seconds (giving in-flight creates time
///     to write their instance.env before we clean them up).
fn sweep_stale_port_locks(
    _state_dir: &Path,
    locks_dir: &Path,
    used_ports: &std::collections::HashSet<u16>,
) {
    let Ok(entries) = fs::read_dir(locks_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(port) = stem.parse::<u16>() else {
            continue;
        };
        if used_ports.contains(&port) {
            // Port is legitimately in use — leave the lock alone.
            continue;
        }
        // Only remove if the lock file is old enough to not be an in-flight create.
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age > Duration::from_secs(60) {
            tracing::info!(
                "[vmrunner-cid] removing stale port lock: {}",
                path.display()
            );
            let _ = fs::remove_file(&path);
        }
    }
}

/// Collect SSH ports already assigned to existing instances by scanning `instance.env` files.
pub(crate) fn collect_used_ssh_ports(state_dir: &Path) -> std::collections::HashSet<u16> {
    let mut ports = std::collections::HashSet::new();
    if !state_dir.is_dir() {
        return ports;
    }
    if let Ok(entries) = fs::read_dir(state_dir) {
        for entry in entries.flatten() {
            let env_path = entry.path().join("instance.env");
            if let Ok(content) = fs::read_to_string(&env_path) {
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("SSH_PORT=") {
                        if let Ok(p) = val.trim().parse::<u16>() {
                            ports.insert(p);
                        }
                    }
                }
            }
        }
    }
    ports
}
