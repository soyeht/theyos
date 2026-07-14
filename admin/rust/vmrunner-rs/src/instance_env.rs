//! `instance_env.rs` — parse/write `instance.env` state files for Firecracker VMs.
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]
//!
//! Stores instance state in `$FIRECRACKER_STATE_DIR/<container>/instance.env`
//! as shell variable assignments (KEY=VALUE, one per line, no quoting).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::VmError;

pub(crate) const HOSTFWD_UNCERTAIN_MARKER: &str = ".hostfwd-uncertain";

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn persist_hostfwd_uncertain_marker(
    instance_dir: &Path,
    reason: &str,
) -> Result<(), VmError> {
    let marker = instance_dir.join(HOSTFWD_UNCERTAIN_MARKER);
    let mut file = fs::File::create(&marker).map_err(|e| {
        VmError::Io(format!(
            "write hostfwd quarantine marker {}: {e}",
            marker.display()
        ))
    })?;
    file.write_all(format!("{reason}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_parent_dir(&marker))
        .map_err(|e| {
            VmError::Io(format!(
                "persist hostfwd quarantine marker {}: {e}",
                marker.display()
            ))
        })
}

/// All persistent state for a single Firecracker VM instance.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceEnv {
    /// Full container name (e.g. `picoclaw-myinst`)
    pub(crate) container: String,
    /// Customer/instance slug (e.g. `myinst`)
    pub(crate) customer: String,
    /// Claw type (e.g. `picoclaw`, `zeroclaw`)
    pub(crate) claw_type: String,
    /// Host-side port the claw agent listens on
    pub(crate) host_port: u16,
    /// Host-side SSH forward port from the configured guest-net range.
    pub(crate) ssh_port: u16,
    /// PID of the `unshare`/firecracker process group leader (None if stopped)
    pub(crate) firecracker_pid: Option<u32>,
    /// PID of slirp4netns (None if stopped)
    pub(crate) slirp_pid: Option<u32>,

    // ── Derived paths (not persisted, computed from instance_dir) ──────────
    /// Root directory for this instance (e.g. `<state_dir>/<container>/`)
    pub(crate) instance_dir: PathBuf,
    /// Path to the per-instance rootfs copy
    pub(crate) rootfs_path: PathBuf,
    /// Firecracker API Unix socket path
    pub(crate) firecracker_sock: PathBuf,
    /// slirp4netns API socket path
    pub(crate) slirp_api_sock: PathBuf,
    /// Path to the serial console log
    pub(crate) serial_log: PathBuf,
    /// Path to the slirp log
    pub(crate) slirp_log: PathBuf,
    /// Optional customer data directory (may be empty)
    pub(crate) customer_dir: String,
}

impl InstanceEnv {
    /// The Firecracker PID (if running).
    #[must_use]
    pub fn firecracker_pid(&self) -> Option<u32> {
        self.firecracker_pid
    }

    /// The slirp4netns PID (if running).
    #[must_use]
    pub fn slirp_pid(&self) -> Option<u32> {
        self.slirp_pid
    }

    /// The host-side SSH forward port.
    #[must_use]
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /// Load an `instance.env` from `<instance_dir>/instance.env`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or required keys are missing.
    pub fn load(instance_dir: &Path) -> Result<Self, VmError> {
        if instance_dir.join(HOSTFWD_UNCERTAIN_MARKER).exists() {
            return Err(VmError::HostfwdUncertain(format!(
                "instance {} is quarantined after an unverified hostfwd teardown",
                instance_dir.display()
            )));
        }

        Self::load_unchecked(instance_dir)
    }

    /// Load an instance even when its persistent quarantine marker is set.
    ///
    /// This is restricted to cleanup paths that must be able to stop/delete a
    /// quarantined instance. Normal lifecycle operations must use `load()` so
    /// an uncertain VM cannot be reused accidentally.
    pub(crate) fn load_unchecked(instance_dir: &Path) -> Result<Self, VmError> {
        let env_path = instance_dir.join("instance.env");
        let content = fs::read_to_string(&env_path).map_err(|e| {
            VmError::InstanceNotFound(format!("cannot read {}: {e}", env_path.display()))
        })?;

        let mut map: HashMap<String, String> = HashMap::new();
        for (line_number, raw_line) in content.lines().enumerate() {
            let line_number = line_number + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let eq = line.find('=').ok_or_else(|| {
                VmError::InvalidEnvFile(format!(
                    "malformed instance.env line {line_number}: expected KEY=VALUE"
                ))
            })?;
            let key = line[..eq].trim();
            if key.is_empty() {
                return Err(VmError::InvalidEnvFile(format!(
                    "malformed instance.env line {line_number}: empty key"
                )));
            }
            let val = line[eq + 1..].to_string();
            if map.insert(key.to_string(), val).is_some() {
                return Err(VmError::InvalidEnvFile(format!(
                    "duplicate instance.env key {key} on line {line_number}"
                )));
            }
        }

        let get = |k: &str| -> Result<String, VmError> {
            map.get(k)
                .cloned()
                .ok_or_else(|| VmError::InvalidEnvFile(format!("missing key: {k}")))
        };

        let parse_u16 = |k: &str| -> Result<u16, VmError> {
            get(k)?
                .parse::<u16>()
                .map_err(|e| VmError::InvalidEnvFile(format!("bad {k}: {e}")))
        };

        let parse_opt_pid = |k: &str| -> Result<Option<u32>, VmError> {
            let Some(value) = map.get(k) else {
                return Ok(None);
            };
            if value.is_empty() {
                return Ok(None);
            }
            value
                .parse::<u32>()
                .map(Some)
                .map_err(|e| VmError::InvalidEnvFile(format!("bad {k} PID {value:?}: {e}")))
        };

        let container = get("CONTAINER_NAME")?;
        let customer = get("CUSTOMER_NAME")?;
        let claw_type = get("CLAW_TYPE")?;
        let host_port = parse_u16("PORT")?;
        let ssh_port = parse_u16("SSH_PORT")?;
        let firecracker_pid = parse_opt_pid("FIRECRACKER_PID")?;
        let slirp_pid = parse_opt_pid("SLIRP_PID")?;
        let customer_dir = map.get("CUSTOMER_DIR").cloned().unwrap_or_default();

        // Derive paths from instance_dir
        let rootfs_path = instance_dir.join("rootfs.ext4");
        let firecracker_sock = instance_dir.join("firecracker.sock");
        let slirp_api_sock = instance_dir.join("slirp-api.sock");
        let serial_log = instance_dir.join("serial.log");
        let slirp_log = instance_dir.join("slirp.log");

        Ok(InstanceEnv {
            container,
            customer,
            claw_type,
            host_port,
            ssh_port,
            firecracker_pid,
            slirp_pid,
            instance_dir: instance_dir.to_path_buf(),
            rootfs_path,
            firecracker_sock,
            slirp_api_sock,
            serial_log,
            slirp_log,
            customer_dir,
        })
    }

    /// Persist a quarantine marker that prevents normal lifecycle reuse.
    pub(crate) fn mark_hostfwd_uncertain(&self, reason: &str) -> Result<(), VmError> {
        persist_hostfwd_uncertain_marker(&self.instance_dir, reason)
    }

    /// Remove a quarantine marker after all tracked processes have stopped.
    pub(crate) fn clear_hostfwd_uncertain(&self) -> Result<(), VmError> {
        let marker = self.instance_dir.join(HOSTFWD_UNCERTAIN_MARKER);
        match fs::remove_file(&marker) {
            Ok(()) => match sync_parent_dir(&marker) {
                Ok(()) => Ok(()),
                Err(error) => {
                    // The unlink happened, but without a durable parent-dir
                    // sync it is unsafe to claim that reuse is unquarantined.
                    // Recreate the marker before returning the error so a
                    // crash cannot turn an uncertain state into a reusable one.
                    let restore = persist_hostfwd_uncertain_marker(
                        &self.instance_dir,
                        "quarantine marker removal was not durably confirmed",
                    )
                    .err();
                    let restore_detail = restore
                        .map(|restore_error| format!("; marker restore failed: {restore_error}"))
                        .unwrap_or_default();
                    Err(VmError::Io(format!(
                        "persist removal of hostfwd quarantine marker {}: {error}{restore_detail}",
                        marker.display()
                    )))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VmError::Io(format!(
                "remove hostfwd quarantine marker {}: {e}",
                marker.display()
            ))),
        }
    }

    /// Save the current state to `<instance_dir>/instance.env`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the file cannot
    /// be written.
    pub fn save(&self) -> Result<(), VmError> {
        fs::create_dir_all(&self.instance_dir).map_err(|e| {
            VmError::Io(format!(
                "create instance dir {}: {e}",
                self.instance_dir.display()
            ))
        })?;

        let env_path = self.instance_dir.join("instance.env");

        let fc_pid = self
            .firecracker_pid
            .map(|p| p.to_string())
            .unwrap_or_default();
        let slirp_pid = self.slirp_pid.map(|p| p.to_string()).unwrap_or_default();

        let content = format!(
            "CONTAINER_NAME={container}\n\
             CUSTOMER_NAME={customer}\n\
             CLAW_TYPE={claw_type}\n\
             PORT={host_port}\n\
             SSH_PORT={ssh_port}\n\
             ROOTFS_PATH={rootfs_path}\n\
             API_SOCK={api_sock}\n\
             SLIRP_API_SOCK={slirp_api_sock}\n\
             SERIAL_LOG={serial_log}\n\
             SLIRP_LOG={slirp_log}\n\
             CUSTOMER_DIR={customer_dir}\n\
             CODE_DIR=\n\
             CONFIG_PATH=\n\
             WORKSPACE_PATH=\n\
             FIRECRACKER_PID={fc_pid}\n\
             SLIRP_PID={slirp_pid}\n",
            container = self.container,
            customer = self.customer,
            claw_type = self.claw_type,
            host_port = self.host_port,
            ssh_port = self.ssh_port,
            rootfs_path = self.rootfs_path.display(),
            api_sock = self.firecracker_sock.display(),
            slirp_api_sock = self.slirp_api_sock.display(),
            serial_log = self.serial_log.display(),
            slirp_log = self.slirp_log.display(),
            customer_dir = self.customer_dir,
            fc_pid = fc_pid,
            slirp_pid = slirp_pid,
        );

        let temp_path = self.instance_dir.join(".instance.env.tmp");
        let write_result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, &env_path)?;
            sync_parent_dir(&env_path)
        })();

        if let Err(e) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(VmError::Io(format!(
                "atomically persist instance.env {}: {e}",
                env_path.display()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_env(dir: &Path, content: &str) {
        fs::write(dir.join("instance.env"), content).unwrap();
    }

    #[test]
    fn roundtrip_full_env() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        let content = format!(
            "CONTAINER_NAME=picoclaw-myinst\n\
             CUSTOMER_NAME=myinst\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22001\n\
             ROOTFS_PATH={dir}/rootfs.ext4\n\
             API_SOCK={dir}/firecracker.sock\n\
             SLIRP_API_SOCK={dir}/slirp-api.sock\n\
             SERIAL_LOG={dir}/serial.log\n\
             SLIRP_LOG={dir}/slirp.log\n\
             CUSTOMER_DIR=/data/myinst\n\
             CODE_DIR=\n\
             CONFIG_PATH=\n\
             WORKSPACE_PATH=\n\
             FIRECRACKER_PID=54321\n\
             SLIRP_PID=54322\n",
            dir = dir.display()
        );
        write_env(dir, &content);

        let env = InstanceEnv::load(dir).unwrap();
        assert_eq!(env.container, "picoclaw-myinst");
        assert_eq!(env.customer, "myinst");
        assert_eq!(env.claw_type, "picoclaw");
        assert_eq!(env.host_port, 35000);
        assert_eq!(env.ssh_port, 22001);
        assert_eq!(env.firecracker_pid, Some(54321));
        assert_eq!(env.slirp_pid, Some(54322));

        // Save then reload and compare key fields
        env.save().unwrap();
        let env2 = InstanceEnv::load(dir).unwrap();
        assert_eq!(env.container, env2.container);
        assert_eq!(env.host_port, env2.host_port);
        assert_eq!(env.ssh_port, env2.ssh_port);
        assert_eq!(env.firecracker_pid, env2.firecracker_pid);
        assert_eq!(env.slirp_pid, env2.slirp_pid);
    }

    #[test]
    fn save_preserves_previous_path_when_atomic_rename_fails() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let content = "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22002\n\
             FIRECRACKER_PID=\n\
             SLIRP_PID=\n";
        write_env(dir, content);
        let env = InstanceEnv::load(dir).unwrap();

        fs::remove_file(dir.join("instance.env")).unwrap();
        fs::create_dir(dir.join("instance.env")).unwrap();

        assert!(env.save().is_err(), "rename over a directory must fail");
        assert!(
            dir.join("instance.env").is_dir(),
            "the previous state path must not be replaced by a partial file"
        );
        assert!(
            !dir.join(".instance.env.tmp").exists(),
            "failed atomic saves must clean the temporary file"
        );
    }

    #[test]
    fn empty_pids_parse_as_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        let content = "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22002\n\
             ROOTFS_PATH=/tmp/rootfs.ext4\n\
             API_SOCK=/tmp/fc.sock\n\
             SLIRP_API_SOCK=/tmp/slirp.sock\n\
             SERIAL_LOG=/tmp/serial.log\n\
             SLIRP_LOG=/tmp/slirp.log\n\
             CUSTOMER_DIR=\n\
             CODE_DIR=\n\
             CONFIG_PATH=\n\
             WORKSPACE_PATH=\n\
             FIRECRACKER_PID=\n\
             SLIRP_PID=\n";
        write_env(dir, content);

        let env = InstanceEnv::load(dir).unwrap();
        assert_eq!(env.firecracker_pid, None);
        assert_eq!(env.slirp_pid, None);
    }

    #[test]
    fn malformed_pid_is_not_downgraded_to_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_env(
            dir,
            "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22002\n\
             FIRECRACKER_PID=not-a-pid\n\
             SLIRP_PID=\n",
        );

        let error = InstanceEnv::load_unchecked(dir).unwrap_err().to_string();
        assert!(
            error.contains("FIRECRACKER_PID") && error.contains("bad"),
            "invalid PID must fail closed: {error}"
        );
    }

    #[test]
    fn duplicate_pid_key_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_env(
            dir,
            "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22002\n\
             FIRECRACKER_PID=54321\n\
             FIRECRACKER_PID=54322\n\
             SLIRP_PID=\n",
        );

        let error = InstanceEnv::load_unchecked(dir).unwrap_err().to_string();
        assert!(
            error.contains("duplicate") && error.contains("FIRECRACKER_PID"),
            "duplicate PID must fail closed: {error}"
        );
    }

    #[test]
    fn missing_required_key_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_env(dir, "CONTAINER_NAME=only-this\n");

        let result = InstanceEnv::load(dir);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("CUSTOMER_NAME") || msg.contains("missing key"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn missing_file_returns_not_found_error() {
        let tmp = TempDir::new().unwrap();
        let result = InstanceEnv::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn quarantined_instance_cannot_be_loaded_for_reuse() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_env(
            dir,
            "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22001\n\
             FIRECRACKER_PID=\n\
             SLIRP_PID=\n",
        );
        fs::write(
            dir.join(HOSTFWD_UNCERTAIN_MARKER),
            "teardown not verified\n",
        )
        .unwrap();

        assert!(matches!(
            InstanceEnv::load(dir),
            Err(VmError::HostfwdUncertain(_))
        ));
        assert!(
            InstanceEnv::load_unchecked(dir).is_ok(),
            "cleanup-only loading must remain possible"
        );
    }
}
