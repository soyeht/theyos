//! Common vmrunner warm-pool contract types.
//!
//! This crate intentionally owns only data contracts that have active callers.
//! Platform-specific VM lifecycle, networking, boot, and filesystem behavior
//! stays in the Linux and macOS vmrunner crates.

pub mod create;
pub mod guest_image;
pub mod network;
pub mod warm_pool;

pub use create::{
    DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_DISK_GB, DEFAULT_CREATE_RAM_MB,
    ResolvedVmCreateResourceSpec, VmCreatePhaseTiming, VmCreateResourceSpec, VmCreateTimingWire,
};
pub use guest_image::{
    MacOsBaseInstallRequest, MacOsPrepareRequest, MacOsProvisionAndSnapshotRequest,
};
pub use network::{
    HostPortRange, LINUX_SSH_HOST_PORT_RANGE, PUBLIC_APP_HOST_PORT_RANGE, PortForward, PortProtocol,
};
pub use warm_pool::{WarmPoolSlotState, WarmPoolSlotStatus, WarmPoolStatus, WarmPoolStatusWire};
