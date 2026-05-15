//! Mock VZ (Virtualization Framework) backend for testing.
//!
//! Provides mock implementations of VZ types that can be used in unit tests
//! and contract tests without requiring actual macOS Virtualization Framework.

#![cfg(target_os = "macos")]
#![allow(dead_code)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unnecessary_wraps)]

use std::path::PathBuf;
use std::time::SystemTime;

use vmrunner_macos_rs::error::VZError;
use vmrunner_macos_rs::vz::VmState;

// ─── Mock VZVirtualMachine ───────────────────────────────────────────────────

/// Mock VM that tracks state transitions for testing.
pub struct MockVZVirtualMachine {
    state: VmState,
    start_result: Option<Result<(), VZError>>,
    stop_result: Option<Result<(), VZError>>,
}

impl Default for MockVZVirtualMachine {
    fn default() -> Self {
        Self {
            state: VmState::Stopped,
            start_result: None,
            stop_result: None,
        }
    }
}

impl MockVZVirtualMachine {
    /// Create a new mock VM with no expectations set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a mock VM that succeeds all operations.
    pub fn success() -> Self {
        Self {
            state: VmState::Running,
            start_result: Some(Ok(())),
            stop_result: Some(Ok(())),
        }
    }

    /// Create a mock VM that fails on start.
    pub fn start_failure() -> Self {
        Self {
            state: VmState::Stopped,
            start_result: Some(Err(VZError::StartFailed("Mock start failure".into()))),
            stop_result: None,
        }
    }

    /// Create a mock VM with a specific state.
    pub fn with_state(state: VmState) -> Self {
        Self {
            state,
            start_result: Some(Ok(())),
            stop_result: Some(Ok(())),
        }
    }

    /// Get current state.
    pub fn get_state(&self) -> VmState {
        self.state
    }

    /// Attempt to start.
    pub fn start(&mut self) -> Result<(), VZError> {
        match &self.start_result {
            Some(Ok(())) => {
                self.state = VmState::Running;
                Ok(())
            }
            Some(Err(_)) => Err(VZError::StartFailed("Mock start failure".into())),
            None => Err(VZError::StartFailed("No start behavior configured".into())),
        }
    }

    /// Attempt to stop.
    pub fn stop(&mut self) -> Result<(), VZError> {
        match &self.stop_result {
            Some(Ok(())) => {
                self.state = VmState::Stopped;
                Ok(())
            }
            Some(Err(_)) => Err(VZError::StopFailed("Mock stop failure".into())),
            None => Err(VZError::StopFailed("No stop behavior configured".into())),
        }
    }
}

// ─── Mock VZVirtualMachineConfiguration ───────────────────────────────────────

/// Mock configuration builder that always validates successfully.
#[derive(Debug, Clone)]
pub struct MockVZConfigBuilder {
    pub cpus: u32,
    pub memory_mb: u32,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub boot_args: String,
}

impl Default for MockVZConfigBuilder {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mb: 2048,
            kernel_path: PathBuf::from("/tmp/test-vmlinuz"),
            rootfs_path: PathBuf::from("/tmp/test-rootfs.img"),
            boot_args: "console=ttyS0".to_string(),
        }
    }
}

impl MockVZConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    pub fn memory_mb(mut self, memory_mb: u32) -> Self {
        self.memory_mb = memory_mb;
        self
    }

    pub fn kernel_path(mut self, path: PathBuf) -> Self {
        self.kernel_path = path;
        self
    }

    pub fn rootfs_path(mut self, path: PathBuf) -> Self {
        self.rootfs_path = path;
        self
    }

    pub fn boot_args(mut self, args: String) -> Self {
        self.boot_args = args;
        self
    }

    /// Always returns Ok for tests.
    pub fn build(self) -> Result<MockVZConfig, VZError> {
        Ok(MockVZConfig {
            cpus: self.cpus,
            memory_mb: self.memory_mb,
            kernel_path: self.kernel_path,
            rootfs_path: self.rootfs_path,
            boot_args: self.boot_args,
        })
    }
}

/// Mock VM configuration.
#[derive(Debug, Clone)]
pub struct MockVZConfig {
    pub cpus: u32,
    pub memory_mb: u32,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub boot_args: String,
}

// ─── Mock Snapshot ──────────────────────────────────────────────────────────

/// Mock snapshot metadata.
#[derive(Debug, Clone)]
pub struct MockSnapshot {
    pub id: String,
    pub claw_type: String,
    pub path: PathBuf,
    pub state: MockSnapshotState,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockSnapshotState {
    Ready,
    Warming,
    Expired,
}

impl MockSnapshot {
    pub fn new(id: String, claw_type: String) -> Self {
        Self {
            id,
            claw_type,
            path: PathBuf::from("/tmp/snapshots/test.snap"),
            state: MockSnapshotState::Ready,
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            size_bytes: 1024 * 1024 * 1024, // 1GB
        }
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

/// Create a mock VM configuration with test defaults.
pub fn mock_vm_config() -> MockVZConfig {
    MockVZConfigBuilder::new()
        .cpus(2)
        .memory_mb(2048)
        .kernel_path(PathBuf::from("/tmp/test-kernel"))
        .rootfs_path(PathBuf::from("/tmp/test-rootfs.img"))
        .build()
        .unwrap()
}

/// Create a mock snapshot for testing.
pub fn mock_snapshot(id: &str, claw_type: &str) -> MockSnapshot {
    MockSnapshot::new(id.to_string(), claw_type.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_vm_success() {
        let mut vm = MockVZVirtualMachine::success();
        vm.start().unwrap();
        assert_eq!(vm.get_state(), VmState::Running);
        vm.stop().unwrap();
        assert_eq!(vm.get_state(), VmState::Stopped);
    }

    #[test]
    fn test_mock_vm_start_failure() {
        let mut vm = MockVZVirtualMachine::start_failure();
        let result = vm.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_vm_with_state() {
        let vm = MockVZVirtualMachine::with_state(VmState::Stopped);
        assert_eq!(vm.get_state(), VmState::Stopped);
    }

    #[test]
    fn test_mock_config_builder() {
        let config = MockVZConfigBuilder::new()
            .cpus(4)
            .memory_mb(4096)
            .build()
            .unwrap();

        assert_eq!(config.cpus, 4);
        assert_eq!(config.memory_mb, 4096);
    }

    #[test]
    fn test_mock_snapshot() {
        let snapshot = mock_snapshot("test-snap", "picoclaw");
        assert_eq!(snapshot.id, "test-snap");
        assert_eq!(snapshot.claw_type, "picoclaw");
        assert_eq!(snapshot.state, MockSnapshotState::Ready);
    }

    #[test]
    fn test_mock_helpers() {
        let config = mock_vm_config();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 2048);
    }
}
