//! Member-scoped T1 `IpTunnel` backend for the per-Claw VPN live caller.
//!
//! This is the first relay-stream shaped caller that consumes the authenticated
//! Group audience context from the `IpTunnel` offer gate. It still does not
//! mount itself into bootstrap. Construction is intended to stay behind the T1
//! caller gate; `open_ip_tunnel` derives the VPN ACL key from the authenticated
//! `(member, device, claw)` tuple, builds the target-session runtime with
//! caller-supplied lazy inputs, and hands the resulting wiring to a
//! caller-supplied launcher.

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use hmac::{Hmac, Mac};
use household_rs::claw_share_data_tunnel::{DataTunnelError, MeshIpv4, TargetSession};
use household_rs::claw_vpn::{
    ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditEvent, ClawVpnDatapathSide,
    ClawVpnSessionRegistry,
};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelRouter, RelayStreamIpTunnelTarget,
};
use crate::claw_vpn_dev_config::{ClawVpnDevConfig, ClawVpnDevConfigError};
use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
use crate::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;
use crate::claw_vpn_relay_stream::ClawVpnRelayStream;
use crate::claw_vpn_t1_caller::{ClawVpnT1CallerStatus, assemble_claw_vpn_t1_caller};
use crate::claw_vpn_target_session_relay::ClawVpnPollableTargetSessionRelay;
use crate::claw_vpn_target_session_router::{
    ClawVpnPollableTargetSessionRouterWiring, ClawVpnTargetSessionRouterLaunchResult,
    ClawVpnTargetSessionRouterWiring,
};
use crate::claw_vpn_target_session_runtime::{
    ClawVpnTargetSessionRuntimeError, assemble_claw_vpn_pollable_target_session_runtime,
    assemble_claw_vpn_target_session_runtime,
};
use crate::claw_vpn_wiring::{
    ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringContext, ClawVpnRuntimeWiringInputs,
};
use crate::startup_wiring::PerClawVpnT1PreflightEvidence;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type ClawVpnT1RelayStreamWiringInputs<I> =
    ClawVpnRuntimeWiringInputs<I, ClawVpnRelayStream<StdUnixStream>>;
pub type ClawVpnT1RelayStreamBuildInputs<I> = Box<
    dyn Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnRelayStream<StdUnixStream>,
        ) -> io::Result<ClawVpnT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
>;
pub type ClawVpnT1RelayStreamLaunchRuntime<I> = Box<
    dyn Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
>;
pub type ClawVpnT1RelayStreamAuditSink =
    Box<dyn Fn(ClawVpnAuditEvent) -> Result<(), &'static str> + Send + Sync>;
pub const CLAW_VPN_T1_AUDIT_SINK_QUEUE_CAPACITY: usize = 128;
pub const CLAW_VPN_T1_AUDIT_LOG_ROTATE_BYTES: u64 = 1_048_576;
pub const CLAW_VPN_T1_AUDIT_LOG_RETAINED_FILES: usize = 4;
pub const CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES: usize = 32;
pub const CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME: &str = "claw-vpn-t1-audit";
pub const CLAW_VPN_T1_AUDIT_LOG_FILE_NAME: &str = "audit.jsonl";
pub type ClawVpnT1RelayStreamBoxedRouter<I> = ClawVpnT1RelayStreamIpTunnelRouter<
    I,
    ClawVpnT1RelayStreamBuildInputs<I>,
    ClawVpnT1RelayStreamLaunchRuntime<I>,
>;

type ClawVpnT1AuditExportHmac = Hmac<Sha256>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClawVpnT1AuditExportHmacKey {
    bytes: [u8; CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES],
}

impl fmt::Debug for ClawVpnT1AuditExportHmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnT1AuditExportHmacKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl ClawVpnT1AuditExportHmacKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    fn bytes(&self) -> &[u8; CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES] {
        &self.bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClawVpnT1AuditSinkError {
    #[error("claw vpn t1 audit sink parent directory unavailable")]
    CreateDir(#[source] io::Error),

    #[error("claw vpn t1 audit sink file unavailable")]
    OpenFile(#[source] io::Error),

    #[error("claw vpn t1 audit sink worker unavailable")]
    SpawnWorker(#[source] io::Error),
}

pub fn claw_vpn_t1_spooled_jsonl_audit_sink(
    path: impl Into<PathBuf>,
) -> Result<ClawVpnT1RelayStreamAuditSink, ClawVpnT1AuditSinkError> {
    claw_vpn_t1_spooled_jsonl_audit_sink_with_capacity(path, CLAW_VPN_T1_AUDIT_SINK_QUEUE_CAPACITY)
}

pub fn claw_vpn_t1_canonical_audit_log_path(root: impl AsRef<Path>) -> io::Result<PathBuf> {
    let root = root.as_ref();
    validate_claw_vpn_t1_canonical_audit_root(root)?;
    Ok(root
        .join(CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME)
        .join(CLAW_VPN_T1_AUDIT_LOG_FILE_NAME))
}

fn claw_vpn_t1_spooled_jsonl_audit_sink_with_capacity(
    path: impl Into<PathBuf>,
    capacity: usize,
) -> Result<ClawVpnT1RelayStreamAuditSink, ClawVpnT1AuditSinkError> {
    claw_vpn_t1_spooled_jsonl_audit_sink_with_capacity_and_rotation(
        path,
        capacity,
        CLAW_VPN_T1_AUDIT_LOG_ROTATE_BYTES,
        CLAW_VPN_T1_AUDIT_LOG_RETAINED_FILES,
    )
}

fn claw_vpn_t1_spooled_jsonl_audit_sink_with_capacity_and_rotation(
    path: impl Into<PathBuf>,
    capacity: usize,
    rotate_bytes: u64,
    retained_files: usize,
) -> Result<ClawVpnT1RelayStreamAuditSink, ClawVpnT1AuditSinkError> {
    if rotate_bytes == 0 {
        return Err(ClawVpnT1AuditSinkError::OpenFile(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit rotate bytes must be nonzero",
        )));
    }
    let path = path.into();
    let parent = path.parent().ok_or_else(|| {
        ClawVpnT1AuditSinkError::OpenFile(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit path must include a file name",
        ))
    })?;
    let parent_dir =
        ensure_claw_vpn_t1_audit_parent(parent).map_err(ClawVpnT1AuditSinkError::CreateDir)?;
    let file_name =
        claw_vpn_t1_audit_log_file_name(&path).map_err(ClawVpnT1AuditSinkError::OpenFile)?;
    let writer =
        ClawVpnT1RotatingAuditLog::open(parent_dir, file_name, rotate_bytes, retained_files)
            .map_err(ClawVpnT1AuditSinkError::OpenFile)?;
    let (sender, receiver) = sync_channel(capacity);
    let healthy = Arc::new(AtomicBool::new(true));
    let worker_healthy = Arc::clone(&healthy);

    spawn_claw_vpn_t1_audit_worker(writer, receiver, worker_healthy)
        .map(|_handle| ())
        .map_err(ClawVpnT1AuditSinkError::SpawnWorker)?;

    Ok(Box::new(move |event| {
        claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, event)
    }))
}

fn spawn_claw_vpn_t1_audit_worker<W>(
    mut writer: W,
    receiver: Receiver<ClawVpnAuditEvent>,
    worker_healthy: Arc<AtomicBool>,
) -> io::Result<thread::JoinHandle<()>>
where
    W: ClawVpnT1AuditLogWriter + Send + 'static,
{
    thread::Builder::new()
        .name("claw-vpn-t1-audit-jsonl".to_string())
        .spawn(move || {
            while let Ok(event) = receiver.recv() {
                if claw_vpn_t1_write_audit_event(&mut writer, &event).is_err() {
                    worker_healthy.store(false, Ordering::SeqCst);
                    break;
                }
            }
        })
}

fn validate_claw_vpn_t1_canonical_audit_root(root: &Path) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit root must be absolute",
        ));
    }
    for component in root.components() {
        match component {
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "claw vpn t1 audit root must be a unix path",
                ));
            }
            Component::RootDir => {}
            Component::CurDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "claw vpn t1 audit root must be canonical",
                ));
            }
            Component::Normal(component) => {
                claw_vpn_t1_path_component_cstring(component)?;
            }
        }
    }

    let metadata = std::fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit root must be a real directory",
        ));
    }
    let canonical = std::fs::canonicalize(root)?;
    if canonical != root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit root must be canonical",
        ));
    }
    if metadata.uid() != claw_vpn_t1_current_euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "claw vpn t1 audit root must be owned by current user",
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "claw vpn t1 audit root must be mode 0700",
        ));
    }
    Ok(())
}

fn ensure_claw_vpn_t1_audit_parent(parent: &Path) -> io::Result<File> {
    let mut current = open_claw_vpn_t1_start_dir(parent)?;
    for component in parent.components() {
        match component {
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "claw vpn t1 audit parent must be a unix path",
                ));
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "claw vpn t1 audit parent must not contain parent components",
                ));
            }
            Component::Normal(component) => {
                let component = claw_vpn_t1_path_component_cstring(component)?;
                let (next, created) =
                    open_or_create_claw_vpn_t1_audit_dir_at(current.as_raw_fd(), &component)?;
                if created {
                    set_claw_vpn_t1_audit_dir_mode(next.as_raw_fd(), 0o700)?;
                }
                current = next;
            }
        }
    }
    validate_claw_vpn_t1_audit_parent_fd(current.as_raw_fd())?;
    Ok(current)
}

fn claw_vpn_t1_audit_log_file_name(path: &Path) -> io::Result<CString> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit path must include a file name",
        )
    })?;
    claw_vpn_t1_path_component_cstring(file_name)
}

fn open_claw_vpn_t1_audit_log_file(
    parent_dir: &impl AsRawFd,
    file_name: &CString,
) -> io::Result<File> {
    let file = open_claw_vpn_t1_audit_file_at(parent_dir.as_raw_fd(), file_name)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

trait ClawVpnT1AuditParentDir: AsRawFd + Send {
    fn sync_audit_dir(&self) -> io::Result<()>;
}

impl ClawVpnT1AuditParentDir for File {
    fn sync_audit_dir(&self) -> io::Result<()> {
        self.sync_all()
    }
}

struct ClawVpnT1RotatingAuditLog<P = File>
where
    P: ClawVpnT1AuditParentDir,
{
    parent_dir: P,
    file_name: CString,
    file: File,
    current_len: u64,
    rotate_bytes: u64,
    retained_files: usize,
}

impl ClawVpnT1RotatingAuditLog<File> {
    fn open(
        parent_dir: File,
        file_name: CString,
        rotate_bytes: u64,
        retained_files: usize,
    ) -> io::Result<Self> {
        Self::open_with_parent(parent_dir, file_name, rotate_bytes, retained_files)
    }
}

impl<P> ClawVpnT1RotatingAuditLog<P>
where
    P: ClawVpnT1AuditParentDir,
{
    fn open_with_parent(
        parent_dir: P,
        file_name: CString,
        rotate_bytes: u64,
        retained_files: usize,
    ) -> io::Result<Self> {
        let file = open_claw_vpn_t1_audit_log_file(&parent_dir, &file_name)?;
        let current_len = file.metadata()?.len();
        Ok(Self {
            parent_dir,
            file_name,
            file,
            current_len,
            rotate_bytes,
            retained_files,
        })
    }

    fn rotate_before_write_if_needed(&mut self, next_len: u64) -> io::Result<()> {
        if self.current_len == 0 || self.current_len.saturating_add(next_len) <= self.rotate_bytes {
            return Ok(());
        }

        self.file.flush()?;
        self.file.sync_data()?;
        rotate_claw_vpn_t1_audit_log_files(
            self.parent_dir.as_raw_fd(),
            &self.file_name,
            self.retained_files,
        )?;
        self.file = open_claw_vpn_t1_audit_log_file(&self.parent_dir, &self.file_name)?;
        self.parent_dir.sync_audit_dir()?;
        self.current_len = 0;
        Ok(())
    }
}

impl<P> ClawVpnT1AuditLogWriter for ClawVpnT1RotatingAuditLog<P>
where
    P: ClawVpnT1AuditParentDir,
{
    fn write_audit_record(&mut self, record: &[u8]) -> io::Result<()> {
        let record_len = record.len() as u64;
        if record_len > self.rotate_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "claw vpn t1 audit record exceeds rotate bytes",
            ));
        }
        self.rotate_before_write_if_needed(record_len)?;
        self.file.write_all(record)?;
        self.current_len = self.current_len.saturating_add(record_len);
        self.file.flush()?;
        self.file.sync_data()
    }
}

fn open_claw_vpn_t1_start_dir(parent: &Path) -> io::Result<File> {
    let start = if parent.is_absolute() { "/" } else { "." };
    File::open(start)
}

fn open_or_create_claw_vpn_t1_audit_dir_at(
    parent_fd: RawFd,
    component: &CString,
) -> io::Result<(File, bool)> {
    match open_claw_vpn_t1_audit_dir_at(parent_fd, component) {
        Ok(file) => Ok((file, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            mkdir_claw_vpn_t1_audit_dir_at(parent_fd, component, 0o700)?;
            open_claw_vpn_t1_audit_dir_at(parent_fd, component).map(|file| (file, true))
        }
        Err(error) => Err(error),
    }
}

fn claw_vpn_t1_path_component_cstring(component: &OsStr) -> io::Result<CString> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit path component must be a plain name",
        ));
    }
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit path component must not contain nul",
        )
    })
}

#[allow(unsafe_code)]
fn open_claw_vpn_t1_audit_dir_at(parent_fd: RawFd, component: &CString) -> io::Result<File> {
    // SAFETY: component is a nul-terminated single path component. openat does
    // not retain the pointer after returning, and the returned fd is owned here.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by openat and is transferred into File ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(unsafe_code)]
fn mkdir_claw_vpn_t1_audit_dir_at(
    parent_fd: RawFd,
    component: &CString,
    mode: libc::mode_t,
) -> io::Result<()> {
    // SAFETY: component is a nul-terminated single path component; mkdirat does
    // not retain the pointer and only creates below parent_fd.
    let result = unsafe { libc::mkdirat(parent_fd, component.as_ptr(), mode) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_claw_vpn_t1_audit_dir_mode(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: fd is an open directory descriptor owned by File; fchmod does not
    // take ownership and only updates permissions on that descriptor.
    let result = unsafe { libc::fchmod(fd, mode) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn validate_claw_vpn_t1_audit_parent_fd(parent_fd: RawFd) -> io::Result<()> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to valid uninitialized storage for fstat to fill; fd
    // is borrowed and fstat does not take ownership.
    let result = unsafe { libc::fstat(parent_fd, stat.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success, so stat has been initialized.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 audit parent must be a real directory",
        ));
    }
    if stat.st_uid != claw_vpn_t1_current_euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "claw vpn t1 audit parent must be owned by current user",
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "claw vpn t1 audit parent must be mode 0700",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn open_claw_vpn_t1_audit_file_at(parent_fd: RawFd, file_name: &CString) -> io::Result<File> {
    // SAFETY: file_name is a nul-terminated single path component. openat does
    // not retain the pointer, and the returned fd is owned by the File below.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            file_name.as_ptr(),
            libc::O_CREAT | libc::O_APPEND | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by openat and is transferred into File ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(unsafe_code)]
fn claw_vpn_t1_current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and only returns the effective uid.
    unsafe { libc::geteuid() as u32 }
}

fn rotate_claw_vpn_t1_audit_log_files(
    parent_fd: RawFd,
    file_name: &CString,
    retained_files: usize,
) -> io::Result<()> {
    if retained_files == 0 {
        return unlink_claw_vpn_t1_audit_file_if_exists(parent_fd, file_name);
    }

    let oldest = claw_vpn_t1_rotated_audit_log_file_name(file_name, retained_files)?;
    unlink_claw_vpn_t1_audit_file_if_exists(parent_fd, &oldest)?;
    for index in (1..retained_files).rev() {
        let from = claw_vpn_t1_rotated_audit_log_file_name(file_name, index)?;
        let to = claw_vpn_t1_rotated_audit_log_file_name(file_name, index + 1)?;
        rename_claw_vpn_t1_audit_file_if_exists(parent_fd, &from, &to)?;
    }
    let first = claw_vpn_t1_rotated_audit_log_file_name(file_name, 1)?;
    rename_claw_vpn_t1_audit_file(parent_fd, file_name, &first)
}

fn claw_vpn_t1_rotated_audit_log_file_name(
    file_name: &CString,
    index: usize,
) -> io::Result<CString> {
    let mut bytes = file_name.as_bytes().to_vec();
    bytes.push(b'.');
    bytes.extend_from_slice(index.to_string().as_bytes());
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "claw vpn t1 rotated audit file name must not contain nul",
        )
    })
}

fn rename_claw_vpn_t1_audit_file_if_exists(
    parent_fd: RawFd,
    from: &CString,
    to: &CString,
) -> io::Result<()> {
    match rename_claw_vpn_t1_audit_file(parent_fd, from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[allow(unsafe_code)]
fn rename_claw_vpn_t1_audit_file(parent_fd: RawFd, from: &CString, to: &CString) -> io::Result<()> {
    // SAFETY: from and to are nul-terminated single file names under the same
    // validated parent fd. renameat does not retain either pointer.
    let result = unsafe { libc::renameat(parent_fd, from.as_ptr(), parent_fd, to.as_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_claw_vpn_t1_audit_file_if_exists(
    parent_fd: RawFd,
    file_name: &CString,
) -> io::Result<()> {
    match unlink_claw_vpn_t1_audit_file(parent_fd, file_name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[allow(unsafe_code)]
fn unlink_claw_vpn_t1_audit_file(parent_fd: RawFd, file_name: &CString) -> io::Result<()> {
    // SAFETY: file_name is a nul-terminated single file name under the
    // validated parent fd. unlinkat does not retain the pointer.
    let result = unsafe { libc::unlinkat(parent_fd, file_name.as_ptr(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn claw_vpn_t1_try_enqueue_audit_event(
    sender: &SyncSender<ClawVpnAuditEvent>,
    healthy: &AtomicBool,
    event: ClawVpnAuditEvent,
) -> Result<(), &'static str> {
    if !healthy.load(Ordering::SeqCst) {
        return Err("claw-vpn-t1-audit-sink-unavailable");
    }
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err("claw-vpn-t1-audit-sink-full"),
        Err(TrySendError::Disconnected(_)) => Err("claw-vpn-t1-audit-sink-unavailable"),
    }
}

trait ClawVpnT1AuditLogWriter {
    fn write_audit_record(&mut self, record: &[u8]) -> io::Result<()>;
}

impl ClawVpnT1AuditLogWriter for File {
    fn write_audit_record(&mut self, record: &[u8]) -> io::Result<()> {
        self.write_all(record)?;
        self.flush()?;
        self.sync_data()
    }
}

fn claw_vpn_t1_write_audit_event<W>(writer: &mut W, event: &ClawVpnAuditEvent) -> io::Result<()>
where
    W: ClawVpnT1AuditLogWriter,
{
    let line = claw_vpn_t1_redacted_audit_jsonl(event);
    writer.write_audit_record(line.as_bytes())
}

fn claw_vpn_t1_redacted_audit_jsonl(event: &ClawVpnAuditEvent) -> String {
    let subject = event.subject().map(|subject| {
        serde_json::json!({
            "member_id_hash": hex::encode(subject.member_id_hash()),
            "device_pub_hash": hex::encode(subject.device_pub_hash()),
            "claw_id_hash": hex::encode(subject.claw_id_hash()),
        })
    });
    let line = serde_json::json!({
        "schema": "claw_vpn_t1_audit_v1",
        "subject": subject,
        "action": format!("{:?}", event.action()),
        "reason": format!("{:?}", event.reason()),
        "session_id_present": event.session_id().is_some(),
        "byte_count": event.byte_count(),
        "closed_session_count": event.closed_session_count(),
    });
    format!("{line}\n")
}

#[must_use]
pub fn claw_vpn_t1_keyed_audit_export_jsonl(
    event: &ClawVpnAuditEvent,
    key: &ClawVpnT1AuditExportHmacKey,
) -> String {
    let subject = event.subject().map(|subject| {
        serde_json::json!({
            "derivation": "hmac-sha256-v1",
            "member_id_keyed_hash": hex::encode(claw_vpn_t1_audit_export_hmac(
                key,
                b"member_id_hash",
                subject.member_id_hash(),
            )),
            "device_pub_keyed_hash": hex::encode(claw_vpn_t1_audit_export_hmac(
                key,
                b"device_pub_hash",
                subject.device_pub_hash(),
            )),
            "claw_id_keyed_hash": hex::encode(claw_vpn_t1_audit_export_hmac(
                key,
                b"claw_id_hash",
                subject.claw_id_hash(),
            )),
        })
    });
    let line = serde_json::json!({
        "schema": "claw_vpn_t1_audit_export_v1",
        "subject": subject,
        "action": format!("{:?}", event.action()),
        "reason": format!("{:?}", event.reason()),
        "session_id_present": event.session_id().is_some(),
        "byte_count": event.byte_count(),
        "closed_session_count": event.closed_session_count(),
    });
    format!("{line}\n")
}

fn claw_vpn_t1_audit_export_hmac(
    key: &ClawVpnT1AuditExportHmacKey,
    label: &[u8],
    local_hash: [u8; 32],
) -> [u8; 32] {
    let mut mac = ClawVpnT1AuditExportHmac::new_from_slice(key.bytes())
        .expect("hmac-sha256 accepts fixed-size export keys");
    mac.update(b"claw-vpn-t1-audit-export-v1");
    mac.update(&[0]);
    mac.update(label);
    mac.update(&[0]);
    mac.update(&local_hash);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub struct ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime> {
    runtime_config: ClawVpnRuntimeWiringConfig,
    io_timeout: Duration,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnT1RelayStreamRouterParts")
            .field("runtime_config", &self.runtime_config)
            .field("io_timeout", &self.io_timeout)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime> ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime> {
    #[must_use]
    pub fn new(
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self {
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            _interface: PhantomData,
        }
    }
}

pub struct ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime> {
    config: ClawVpnDevConfig,
    runtime_config: ClawVpnRuntimeWiringConfig,
    io_timeout: Duration,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnT1RelayStreamIpTunnelRouter")
            .field("config", &self.config)
            .field("runtime_config", &self.runtime_config)
            .field("io_timeout", &self.io_timeout)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .field("admission", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime>
    ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    #[must_use]
    fn new(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self::with_admission(
            config,
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            Arc::new(Mutex::new(ClawVpnT1RelayStreamAdmission::default())),
        )
    }

    #[must_use]
    fn with_admission(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
        admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    ) -> Self {
        Self {
            config,
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            admission,
            _interface: PhantomData,
        }
    }
}

#[derive(Default)]
struct ClawVpnT1RelayStreamAdmission {
    active_by_key: HashMap<ClawVpnAclKey, usize>,
    active_by_claw: HashMap<String, usize>,
}

impl ClawVpnT1RelayStreamAdmission {
    fn reserve(
        &mut self,
        key: &ClawVpnAclKey,
        max_sessions_per_member_claw: usize,
        max_sessions_per_claw: usize,
    ) -> Result<(), &'static str> {
        if self.active_by_key.get(key).copied().unwrap_or(0) >= max_sessions_per_member_claw {
            return Err("claw-vpn-t1-session-member-claw-limit-reached");
        }
        if self.active_by_claw.get(key.claw_id()).copied().unwrap_or(0) >= max_sessions_per_claw {
            return Err("claw-vpn-t1-session-claw-limit-reached");
        }

        *self.active_by_key.entry(key.clone()).or_insert(0) += 1;
        *self
            .active_by_claw
            .entry(key.claw_id().to_string())
            .or_insert(0) += 1;
        Ok(())
    }

    fn release(&mut self, key: &ClawVpnAclKey) {
        decrement_count(&mut self.active_by_key, key);
        decrement_count(&mut self.active_by_claw, &key.claw_id().to_string());
    }
}

fn decrement_count<K>(counts: &mut HashMap<K, usize>, key: &K)
where
    K: Eq + std::hash::Hash,
{
    if let Some(count) = counts.get_mut(key) {
        if *count <= 1 {
            counts.remove(key);
        } else {
            *count -= 1;
        }
    }
}

struct ClawVpnT1RelayStreamAdmissionPermit {
    admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    key: ClawVpnAclKey,
}

impl Drop for ClawVpnT1RelayStreamAdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.release(&self.key);
        }
    }
}

struct ClawVpnT1RelayStreamPermitReader<R> {
    inner: R,
    _permit: Arc<ClawVpnT1RelayStreamAdmissionPermit>,
}

impl<R> AsyncRead for ClawVpnT1RelayStreamPermitReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct ClawVpnT1RelayStreamPermitWriter<W> {
    inner: W,
    _permit: Arc<ClawVpnT1RelayStreamAdmissionPermit>,
}

impl<W> AsyncWrite for ClawVpnT1RelayStreamPermitWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Build the guest's VPN interface parameters from the real pool allocation,
/// enforcing the ROUTE-SCOPE INVARIANT (contract with the iOS client): the ONLY
/// route the client installs is the pool CIDR `network(addr, prefix_len)` —
/// NEVER a default route (`0.0.0.0/0`, full exit-node capture). Fails CLOSED on
/// anything that would widen the route:
///
/// - `prefix_len` 0 (== `0.0.0.0/0`) or > 32;
/// - a device or peer address OUTSIDE the pool CIDR;
/// - a peer equal to the device, or a non-unicast address.
///
/// A real default route / exit-node is a separate authenticated policy decision,
/// never inferred here.
fn build_vpn_mesh_ipv4(
    network: Ipv4Addr,
    prefix_len: u8,
    device: Ipv4Addr,
    peer: Ipv4Addr,
) -> Result<MeshIpv4, &'static str> {
    if prefix_len == 0 || prefix_len > 32 {
        return Err("claw-vpn-t1-route-scope-prefix");
    }
    if device == peer || !is_unicast_host(device) || !is_unicast_host(peer) {
        return Err("claw-vpn-t1-route-scope-peer");
    }
    // Both hosts MUST live inside the SAME pool CIDR — that CIDR is the only
    // route the client installs.
    if !in_same_ipv4_network(network, prefix_len, device)
        || !in_same_ipv4_network(network, prefix_len, peer)
    {
        return Err("claw-vpn-t1-route-scope-cidr");
    }
    Ok(MeshIpv4 {
        addr: device.to_string(),
        prefix_len,
        peer: peer.to_string(),
    })
}

/// True iff `addr` is in `network/prefix_len`. `prefix_len` is 1..=32 here
/// (0 is rejected before this is reached, so the route is never `0.0.0.0/0`).
fn in_same_ipv4_network(network: Ipv4Addr, prefix_len: u8, addr: Ipv4Addr) -> bool {
    let shift = 32u32.saturating_sub(u32::from(prefix_len));
    let mask = if shift >= 32 { 0 } else { u32::MAX << shift };
    (u32::from(network) & mask) == (u32::from(addr) & mask)
}

/// A routable unicast host (not unspecified / loopback / broadcast / multicast).
fn is_unicast_host(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_loopback() && !addr.is_broadcast() && !addr.is_multicast()
}

fn attach_admission_permit(
    session: TargetSession,
    permit: ClawVpnT1RelayStreamAdmissionPermit,
) -> TargetSession {
    let TargetSession {
        reader,
        writer,
        resize,
        exit,
        vpn_mesh_ipv4,
    } = session;
    let permit = Arc::new(permit);
    let resize_permit = Arc::clone(&permit);
    let exit_permit = Arc::clone(&permit);
    TargetSession {
        reader: Box::new(ClawVpnT1RelayStreamPermitReader {
            inner: reader,
            _permit: Arc::clone(&permit),
        }),
        writer: Box::new(ClawVpnT1RelayStreamPermitWriter {
            inner: writer,
            _permit: Arc::clone(&permit),
        }),
        resize: Box::new(move |cols, rows| {
            let _permit = Arc::clone(&resize_permit);
            resize(cols, rows)
        }),
        exit: Box::pin(async move {
            let result = exit.await;
            drop(exit_permit);
            result
        }),
        vpn_mesh_ipv4,
    }
}

impl<I, BuildInputs, LaunchRuntime> RelayStreamIpTunnelRouter
    for ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
where
    I: ClawVpnPacketInterface + Send + 'static,
    BuildInputs: Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnRelayStream<StdUnixStream>,
        ) -> io::Result<ClawVpnT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
    LaunchRuntime: Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
{
    async fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        let key = ClawVpnAclKey::try_new(
            target.member_id().to_string(),
            target.member_device_pub().clone(),
            target.claw_id().to_string(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-acl-key-invalid"))?;
        let permit = {
            let mut admission = self
                .admission
                .lock()
                .map_err(|_| target_unavailable("claw-vpn-t1-admission-lock-poisoned"))?;
            admission
                .reserve(
                    &key,
                    self.config.max_sessions_per_member_claw(),
                    self.config.max_sessions_per_claw(),
                )
                .map_err(target_unavailable)?;
            ClawVpnT1RelayStreamAdmissionPermit {
                admission: Arc::clone(&self.admission),
                key: key.clone(),
            }
        };

        let mut acl = ClawVpnAcl::new();
        acl.grant(key.clone());
        let registry = ClawVpnSessionRegistry::with_limits(
            acl,
            self.config.ipv4_pool(),
            self.config.max_sessions_per_member_claw(),
            self.config.max_sessions_per_claw(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-session-registry-invalid"))?;
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Claw, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.map_err(|_| target_unavailable("claw-vpn-t1-session-open-failed"))?;
        let session_id = session.id();
        if let Err(reason) = (self.audit_sink)(open_event) {
            let (_closed, close_event) = core.close_with_audit(session_id);
            let _ = (self.audit_sink)(close_event);
            return Err(target_unavailable(reason));
        }
        // Real, pool-allocated VPN interface for the guest. Validate the route
        // scope NOW and fail CLOSED (closing the session) before assembling any
        // runtime: the client installs a route for exactly the pool CIDR, never
        // 0.0.0.0/0. It is delivered post-Open in a NetworkSettings frame (see the
        // data-tunnel serve loop). RATCHET: this is where a real routable address
        // is first minted for the client.
        let pool = self.config.ipv4_pool();
        let addrs = session.addrs();
        let vpn_mesh_ipv4 = match build_vpn_mesh_ipv4(
            pool.network(),
            pool.prefix_len(),
            addrs.device(),
            addrs.claw(),
        ) {
            Ok(mesh) => mesh,
            Err(reason) => {
                let (_closed, close_event) = core.close_with_audit(session_id);
                let _ = (self.audit_sink)(close_event);
                return Err(target_unavailable(reason));
            }
        };
        let session_core = core
            .into_session_core(session_id)
            .map_err(|_| target_unavailable("claw-vpn-t1-session-core-missing"))?;
        let config = &self.config;
        let build_inputs = &self.build_inputs;
        let runtime = assemble_claw_vpn_target_session_runtime(
            self.runtime_config,
            self.io_timeout,
            move || session_core,
            |context, relay| build_inputs(config, &target, context, relay),
        )
        .map_err(|error| map_runtime_error(&error))?;
        let Some(runtime) = runtime else {
            return Err(target_unavailable("claw-vpn-t1-runtime-disabled"));
        };
        let (target_session, wiring) = runtime.into_parts();
        (self.launch_runtime)(wiring)
            .map_err(|_| target_unavailable("claw-vpn-t1-runtime-launch-failed"))?;
        Ok(attach_admission_permit(target_session, permit).with_vpn_mesh_ipv4(vpn_mesh_ipv4))
    }
}

#[must_use = "inspect the T1 relay-stream router gate status before mounting IpTunnel"]
pub fn assemble_claw_vpn_t1_relay_stream_router<
    I,
    LoadConfig,
    LoadPreflight,
    BuildRouterParts,
    BuildInputs,
    LaunchRuntime,
>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_router_parts: BuildRouterParts,
) -> ClawVpnT1CallerStatus<ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildRouterParts:
        FnOnce(&ClawVpnDevConfig) -> ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>,
    BuildInputs: Send + Sync,
    LaunchRuntime: Send + Sync,
{
    assemble_claw_vpn_t1_caller(load_config, load_preflight, move |config| {
        let parts = build_router_parts(config);
        ClawVpnT1RelayStreamIpTunnelRouter::new(
            config.clone(),
            parts.runtime_config,
            parts.io_timeout,
            parts.build_inputs,
            parts.launch_runtime,
            parts.audit_sink,
        )
    })
}

// ---- Pollable (non-blocking) T1 relay-stream responder ----
//
// Parallel to the blocking router above: identical admission, session-open/audit,
// and gate, but it launches the readiness-driven pollable pump so the Claw
// responder no longer stalls on an idle direction. The blocking router stays for
// the inert prod mount; only the dev claw responder is switched to this variant.
// No `io_timeout` — the pollable relay side is `O_NONBLOCK` (`new_pollable`).

pub type ClawVpnPollableT1RelayStreamWiringInputs<I> =
    ClawVpnRuntimeWiringInputs<I, ClawVpnPollableTargetSessionRelay>;
pub type ClawVpnPollableT1RelayStreamBuildInputs<I> = Box<
    dyn Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnPollableTargetSessionRelay,
        ) -> io::Result<ClawVpnPollableT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
>;
pub type ClawVpnPollableT1RelayStreamLaunchRuntime<I> = Box<
    dyn Fn(ClawVpnPollableTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
>;
pub type ClawVpnPollableT1RelayStreamBoxedRouter<I> = ClawVpnPollableT1RelayStreamIpTunnelRouter<
    I,
    ClawVpnPollableT1RelayStreamBuildInputs<I>,
    ClawVpnPollableT1RelayStreamLaunchRuntime<I>,
>;

pub struct ClawVpnPollableT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime> {
    runtime_config: ClawVpnRuntimeWiringConfig,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnPollableT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableT1RelayStreamRouterParts")
            .field("runtime_config", &self.runtime_config)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime>
    ClawVpnPollableT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>
{
    #[must_use]
    pub fn new(
        runtime_config: ClawVpnRuntimeWiringConfig,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self {
            runtime_config,
            build_inputs,
            launch_runtime,
            audit_sink,
            _interface: PhantomData,
        }
    }
}

pub struct ClawVpnPollableT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime> {
    config: ClawVpnDevConfig,
    runtime_config: ClawVpnRuntimeWiringConfig,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnPollableT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableT1RelayStreamIpTunnelRouter")
            .field("config", &self.config)
            .field("runtime_config", &self.runtime_config)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .field("admission", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime>
    ClawVpnPollableT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    #[must_use]
    fn new(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self::with_admission(
            config,
            runtime_config,
            build_inputs,
            launch_runtime,
            audit_sink,
            Arc::new(Mutex::new(ClawVpnT1RelayStreamAdmission::default())),
        )
    }

    #[must_use]
    fn with_admission(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
        admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    ) -> Self {
        Self {
            config,
            runtime_config,
            build_inputs,
            launch_runtime,
            audit_sink,
            admission,
            _interface: PhantomData,
        }
    }
}

impl<I, BuildInputs, LaunchRuntime> RelayStreamIpTunnelRouter
    for ClawVpnPollableT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
where
    I: ClawVpnPollablePacketInterface + Send + 'static,
    BuildInputs: Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnPollableTargetSessionRelay,
        ) -> io::Result<ClawVpnPollableT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
    LaunchRuntime: Fn(ClawVpnPollableTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
{
    async fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        let key = ClawVpnAclKey::try_new(
            target.member_id().to_string(),
            target.member_device_pub().clone(),
            target.claw_id().to_string(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-acl-key-invalid"))?;
        let permit = {
            let mut admission = self
                .admission
                .lock()
                .map_err(|_| target_unavailable("claw-vpn-t1-admission-lock-poisoned"))?;
            admission
                .reserve(
                    &key,
                    self.config.max_sessions_per_member_claw(),
                    self.config.max_sessions_per_claw(),
                )
                .map_err(target_unavailable)?;
            ClawVpnT1RelayStreamAdmissionPermit {
                admission: Arc::clone(&self.admission),
                key: key.clone(),
            }
        };

        let mut acl = ClawVpnAcl::new();
        acl.grant(key.clone());
        let registry = ClawVpnSessionRegistry::with_limits(
            acl,
            self.config.ipv4_pool(),
            self.config.max_sessions_per_member_claw(),
            self.config.max_sessions_per_claw(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-session-registry-invalid"))?;
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Claw, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.map_err(|_| target_unavailable("claw-vpn-t1-session-open-failed"))?;
        let session_id = session.id();
        if let Err(reason) = (self.audit_sink)(open_event) {
            let (_closed, close_event) = core.close_with_audit(session_id);
            let _ = (self.audit_sink)(close_event);
            return Err(target_unavailable(reason));
        }
        // Real, pool-allocated VPN interface for the guest. Validate the route
        // scope NOW and fail CLOSED (closing the session) before assembling any
        // runtime: the client installs a route for exactly the pool CIDR, never
        // 0.0.0.0/0. It is delivered post-Open in a NetworkSettings frame (see the
        // data-tunnel serve loop). RATCHET: this is where a real routable address
        // is first minted for the client.
        let pool = self.config.ipv4_pool();
        let addrs = session.addrs();
        let vpn_mesh_ipv4 = match build_vpn_mesh_ipv4(
            pool.network(),
            pool.prefix_len(),
            addrs.device(),
            addrs.claw(),
        ) {
            Ok(mesh) => mesh,
            Err(reason) => {
                let (_closed, close_event) = core.close_with_audit(session_id);
                let _ = (self.audit_sink)(close_event);
                return Err(target_unavailable(reason));
            }
        };
        let session_core = core
            .into_session_core(session_id)
            .map_err(|_| target_unavailable("claw-vpn-t1-session-core-missing"))?;
        let config = &self.config;
        let build_inputs = &self.build_inputs;
        let runtime = assemble_claw_vpn_pollable_target_session_runtime(
            self.runtime_config,
            move || session_core,
            |context, relay| build_inputs(config, &target, context, relay),
        )
        .map_err(|error| map_runtime_error(&error))?;
        let Some(runtime) = runtime else {
            return Err(target_unavailable("claw-vpn-t1-runtime-disabled"));
        };
        let (target_session, wiring) = runtime.into_parts();
        (self.launch_runtime)(wiring)
            .map_err(|_| target_unavailable("claw-vpn-t1-runtime-launch-failed"))?;
        Ok(attach_admission_permit(target_session, permit).with_vpn_mesh_ipv4(vpn_mesh_ipv4))
    }
}

#[must_use = "inspect the T1 relay-stream router gate status before mounting IpTunnel"]
pub fn assemble_claw_vpn_pollable_t1_relay_stream_router<
    I,
    LoadConfig,
    LoadPreflight,
    BuildRouterParts,
    BuildInputs,
    LaunchRuntime,
>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_router_parts: BuildRouterParts,
) -> ClawVpnT1CallerStatus<ClawVpnPollableT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildRouterParts:
        FnOnce(
            &ClawVpnDevConfig,
        ) -> ClawVpnPollableT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>,
    BuildInputs: Send + Sync,
    LaunchRuntime: Send + Sync,
{
    assemble_claw_vpn_t1_caller(load_config, load_preflight, move |config| {
        let parts = build_router_parts(config);
        ClawVpnPollableT1RelayStreamIpTunnelRouter::new(
            config.clone(),
            parts.runtime_config,
            parts.build_inputs,
            parts.launch_runtime,
            parts.audit_sink,
        )
    })
}

fn map_runtime_error(error: &ClawVpnTargetSessionRuntimeError<io::Error>) -> DataTunnelError {
    match error {
        ClawVpnTargetSessionRuntimeError::Session(_) => {
            target_unavailable("claw-vpn-t1-session-core-failed")
        }
        ClawVpnTargetSessionRuntimeError::TargetSessionRelay(_) => {
            target_unavailable("claw-vpn-t1-target-session-relay-failed")
        }
        ClawVpnTargetSessionRuntimeError::Inputs(_) => {
            target_unavailable("claw-vpn-t1-runtime-inputs-failed")
        }
    }
}

fn target_unavailable(reason: &'static str) -> DataTunnelError {
    DataTunnelError::TargetUnavailable(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::claw_vpn_interface_route_plan::{
        ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
    };

    use household_rs::claw_vpn::{ClawVpnAuditAction, ClawVpnAuditReason, ClawVpnAuditSubject};
    use household_rs::keys::{IdentityKey, P256Keypair};

    // ── Route-scope invariant: the per-Claw VPN interface route is EXACTLY the
    //    pool CIDR, NEVER a default route (0.0.0.0/0). Cross-language contract
    //    with the iOS client — full exit-node capture is a separate authenticated
    //    policy decision, never inferred here. (household_listener.rs style.) ──

    #[test]
    fn build_vpn_mesh_ipv4_scopes_route_to_pool_cidr_never_default() {
        // A valid pool CIDR + two distinct in-prefix unicast hosts.
        let network = Ipv4Addr::new(11, 0, 0, 0);
        let mesh = build_vpn_mesh_ipv4(
            network,
            24,
            Ipv4Addr::new(11, 0, 0, 1),
            Ipv4Addr::new(11, 0, 0, 2),
        )
        .expect("a valid in-CIDR pair is accepted");

        assert_eq!(mesh.prefix_len, 24);
        assert_ne!(
            mesh.prefix_len, 0,
            "the included route must never be 0.0.0.0/0"
        );
        let addr: Ipv4Addr = mesh.addr.parse().unwrap();
        let peer: Ipv4Addr = mesh.peer.parse().unwrap();
        assert_ne!(addr, peer, "peer must be a distinct host");
        // The ONLY route the client installs is network(addr, prefix_len), and it
        // equals the pool CIDR — never wider.
        let mask = u32::MAX << (32 - u32::from(mesh.prefix_len));
        assert_eq!(
            u32::from(addr) & mask,
            u32::from(network),
            "the included route must equal the pool CIDR, nothing wider"
        );
    }

    #[test]
    fn build_vpn_mesh_ipv4_rejects_default_route_prefix() {
        let net = Ipv4Addr::new(11, 0, 0, 0);
        let (dev, peer) = (Ipv4Addr::new(11, 0, 0, 1), Ipv4Addr::new(11, 0, 0, 2));
        // prefix 0 == 0.0.0.0/0 == full exit-node capture. Rejected fail-closed.
        assert_eq!(
            build_vpn_mesh_ipv4(net, 0, dev, peer),
            Err("claw-vpn-t1-route-scope-prefix")
        );
        // >32 is not a valid IPv4 prefix.
        assert_eq!(
            build_vpn_mesh_ipv4(net, 33, dev, peer),
            Err("claw-vpn-t1-route-scope-prefix")
        );
    }

    #[test]
    fn build_vpn_mesh_ipv4_rejects_equal_or_non_unicast_peer() {
        let net = Ipv4Addr::new(11, 0, 0, 0);
        let dev = Ipv4Addr::new(11, 0, 0, 1);
        // device == peer.
        assert_eq!(
            build_vpn_mesh_ipv4(net, 24, dev, dev),
            Err("claw-vpn-t1-route-scope-peer")
        );
        // non-unicast peer (loopback / multicast / broadcast / unspecified).
        for bad in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert_eq!(
                build_vpn_mesh_ipv4(net, 24, dev, bad),
                Err("claw-vpn-t1-route-scope-peer")
            );
        }
    }

    #[test]
    fn build_vpn_mesh_ipv4_rejects_addresses_outside_the_pool_cidr() {
        let net = Ipv4Addr::new(11, 0, 0, 0);
        // peer outside the /24 CIDR (would widen / misroute).
        assert_eq!(
            build_vpn_mesh_ipv4(
                net,
                24,
                Ipv4Addr::new(11, 0, 0, 1),
                Ipv4Addr::new(11, 0, 5, 2)
            ),
            Err("claw-vpn-t1-route-scope-cidr")
        );
        // device outside the CIDR.
        assert_eq!(
            build_vpn_mesh_ipv4(
                net,
                24,
                Ipv4Addr::new(11, 0, 5, 1),
                Ipv4Addr::new(11, 0, 0, 2)
            ),
            Err("claw-vpn-t1-route-scope-cidr")
        );
    }

    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
    }

    impl FakeInterface {
        fn empty() -> Self {
            Self {
                reads: VecDeque::new(),
            }
        }
    }

    impl ClawVpnPacketInterface for FakeInterface {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet = self.reads.pop_front().unwrap_or_default();
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    fn live_config() -> ClawVpnDevConfig {
        config_with_session_limits("1", "1")
    }

    fn config_with_session_limits(
        max_sessions_per_member_claw: &str,
        max_sessions_per_claw: &str,
    ) -> ClawVpnDevConfig {
        ClawVpnDevConfig::from_values(
            Some("1"),
            None,
            Some("relay-stream://127.0.0.1:49152"),
            Some("198.18.0.0/24"),
            Some(max_sessions_per_member_claw),
            Some(max_sessions_per_claw),
        )
        .unwrap()
        .unwrap()
    }

    fn enabled_runtime_config() -> ClawVpnRuntimeWiringConfig {
        let defaults = ClawVpnRuntimeWiringConfig::default();
        ClawVpnRuntimeWiringConfig::new(
            true,
            defaults.runtime_step_budget(),
            defaults.driver_budget(),
        )
    }

    fn target_with_device(
        member_id: &str,
        member_device_pub: household_rs::keys::P256PublicKey,
        claw_id: &str,
    ) -> RelayStreamIpTunnelTarget {
        RelayStreamIpTunnelTarget::new_for_test(
            "group-alpha",
            member_id,
            member_device_pub,
            claw_id,
        )
    }

    fn target(member_id: &str, claw_id: &str) -> RelayStreamIpTunnelTarget {
        target_with_device(member_id, P256Keypair::generate().public(), claw_id)
    }

    fn inputs(
        interface: FakeInterface,
        relay: ClawVpnRelayStream<StdUnixStream>,
    ) -> ClawVpnT1RelayStreamWiringInputs<FakeInterface> {
        ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Linux,
            interface_name: ClawVpnInterfaceName::new("t1test0").unwrap(),
            route_tool_paths: ClawVpnInterfaceRouteToolPaths::try_new(
                "/sbin/ip",
                "/sbin/ifconfig",
                "/sbin/route",
            )
            .unwrap(),
            interface,
            relay,
        }
    }

    fn noop_audit_sink() -> ClawVpnT1RelayStreamAuditSink {
        Box::new(|_event| Ok(()))
    }

    fn recording_audit_sink(
        events: Arc<Mutex<Vec<ClawVpnAuditEvent>>>,
    ) -> ClawVpnT1RelayStreamAuditSink {
        Box::new(move |event| {
            events.lock().unwrap().push(event);
            Ok(())
        })
    }

    fn read_audit_file_until(path: &std::path::Path, needle: &str) -> String {
        for _ in 0..100 {
            if let Ok(body) = std::fs::read_to_string(path) {
                if body.contains(needle) {
                    return body;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::read_to_string(path).unwrap_or_default()
    }

    fn t1_open_audit_event_for_test() -> ClawVpnAuditEvent {
        t1_open_audit_event_for_member("member-alpha")
    }

    fn t1_open_audit_event_for_member(member_id: &str) -> ClawVpnAuditEvent {
        let key = ClawVpnAclKey::try_new(
            member_id.to_string(),
            P256Keypair::generate().public(),
            "claw-alpha".to_string(),
        )
        .unwrap();
        let mut acl = ClawVpnAcl::new();
        acl.grant(key.clone());
        let registry =
            ClawVpnSessionRegistry::with_limits(acl, live_config().ipv4_pool(), 1, 1).unwrap();
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Claw, registry);
        core.open_with_audit(&key).1
    }

    #[derive(Default)]
    struct FakeAuditWriterState {
        body: Vec<u8>,
        flush_count: usize,
        sync_count: usize,
    }

    struct FakeAuditWriter {
        state: Arc<Mutex<FakeAuditWriterState>>,
        fail_sync: bool,
    }

    impl ClawVpnT1AuditLogWriter for FakeAuditWriter {
        fn write_audit_record(&mut self, record: &[u8]) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.body.extend_from_slice(record);
            state.flush_count += 1;
            state.sync_count += 1;
            drop(state);
            if self.fail_sync {
                return Err(io::Error::other("sync failed"));
            }
            Ok(())
        }
    }

    struct TrackingAuditParentDir {
        file: File,
        sync_count: Arc<AtomicUsize>,
        fail_sync: bool,
    }

    impl AsRawFd for TrackingAuditParentDir {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    impl ClawVpnT1AuditParentDir for TrackingAuditParentDir {
        fn sync_audit_dir(&self) -> io::Result<()> {
            self.sync_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_sync {
                return Err(io::Error::other("parent dir sync failed"));
            }
            self.file.sync_all()
        }
    }

    #[tokio::test]
    async fn t1_spooled_audit_sink_writes_redacted_jsonl_without_raw_target_ids() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let dir = t1_audit_sink_test_tempdir();
        let audit_path = dir.path().join("audit").join("t1.jsonl");
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).unwrap(),
        );

        let _session = router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
            .unwrap();

        let body = read_audit_file_until(&audit_path, "SessionOpened");
        assert!(body.contains("\"schema\":\"claw_vpn_t1_audit_v1\""));
        assert!(body.contains("\"action\":\"SessionOpen\""));
        assert!(body.contains("\"reason\":\"SessionOpened\""));
        assert!(body.contains("\"session_id_present\":true"));
        assert!(body.contains("member_id_hash"));
        assert!(body.contains("device_pub_hash"));
        assert!(body.contains("claw_id_hash"));
        assert!(!body.contains("member-alpha"));
        assert!(!body.contains("claw-alpha"));
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn t1_audit_export_jsonl_uses_keyed_hashes_without_local_subject_hashes() {
        let event = t1_open_audit_event_for_member("member-export-alpha");
        let subject = event.subject().expect("open event has subject");
        let local_member_hash = hex::encode(subject.member_id_hash());
        let local_device_hash = hex::encode(subject.device_pub_hash());
        let local_claw_hash = hex::encode(subject.claw_id_hash());
        let key = ClawVpnT1AuditExportHmacKey::from_bytes([0xA5; 32]);
        let alternate_key = ClawVpnT1AuditExportHmacKey::from_bytes([0x5A; 32]);

        let body = claw_vpn_t1_keyed_audit_export_jsonl(&event, &key);
        let body_again = claw_vpn_t1_keyed_audit_export_jsonl(&event, &key);
        let alternate_body = claw_vpn_t1_keyed_audit_export_jsonl(&event, &alternate_key);

        assert_eq!(body, body_again);
        assert_ne!(body, alternate_body);
        assert!(body.contains("\"schema\":\"claw_vpn_t1_audit_export_v1\""));
        assert!(body.contains("\"derivation\":\"hmac-sha256-v1\""));
        assert!(body.contains("member_id_keyed_hash"));
        assert!(body.contains("device_pub_keyed_hash"));
        assert!(body.contains("claw_id_keyed_hash"));
        assert!(!body.contains("member_id_hash"));
        assert!(!body.contains("device_pub_hash"));
        assert!(!body.contains("claw_id_hash"));
        assert!(!body.contains(&local_member_hash));
        assert!(!body.contains(&local_device_hash));
        assert!(!body.contains(&local_claw_hash));
        assert!(!body.contains("member-export-alpha"));
        assert!(!body.contains("claw-alpha"));
        let key_debug = format!("{:?}", key);
        assert!(key_debug.contains("<redacted>"));
        assert!(!key_debug.contains("A5"));
        assert!(!key_debug.contains("a5"));
        assert!(!key_debug.contains("165"));
    }

    fn t1_canonical_owner_only_audit_root() -> (tempfile::TempDir, PathBuf) {
        let dir = t1_audit_sink_test_tempdir();
        let root = dir.path().join("canonical-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = root.canonicalize().unwrap();
        (dir, canonical)
    }

    #[test]
    fn t1_audit_log_path_uses_fixed_suffix_under_canonical_owner_root() {
        let (_dir, root) = t1_canonical_owner_only_audit_root();
        let audit_path = claw_vpn_t1_canonical_audit_log_path(&root).unwrap();

        assert_eq!(
            audit_path,
            root.join(CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME)
                .join(CLAW_VPN_T1_AUDIT_LOG_FILE_NAME)
        );

        let event = t1_open_audit_event_for_member("member-fixed-path");
        let line = claw_vpn_t1_redacted_audit_jsonl(&event);
        let sink = claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).unwrap();
        sink(event).unwrap();

        let body = read_audit_file_until(&audit_path, &line);
        assert!(body.contains(&line));
        assert_eq!(
            std::fs::metadata(audit_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn t1_audit_log_path_rejects_relative_root() {
        let error = claw_vpn_t1_canonical_audit_log_path("target").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn t1_audit_log_path_rejects_parent_dir_components() {
        let (_dir, root) = t1_canonical_owner_only_audit_root();
        let noncanonical = root.join("..").join(root.file_name().unwrap());
        let error = claw_vpn_t1_canonical_audit_log_path(&noncanonical).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn t1_audit_log_path_rejects_symlink_ancestor() {
        let dir = t1_audit_sink_test_tempdir();
        let base = dir.path().canonicalize().unwrap();
        let target_parent = base.join("target-parent");
        let real_root = target_parent.join("root");
        std::fs::create_dir(&target_parent).unwrap();
        std::fs::create_dir(&real_root).unwrap();
        std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link_parent = base.join("link-parent");
        std::os::unix::fs::symlink(&target_parent, &link_parent).unwrap();
        let root_via_link = link_parent.join("root");

        let error = claw_vpn_t1_canonical_audit_log_path(root_via_link).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn t1_audit_log_path_rejects_file_root() {
        let dir = t1_audit_sink_test_tempdir();
        let root_file = dir.path().join("root-file");
        std::fs::write(&root_file, b"not a directory").unwrap();
        let root_file = root_file.canonicalize().unwrap();

        let error = claw_vpn_t1_canonical_audit_log_path(root_file).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn t1_audit_log_path_rejects_shared_root_directory() {
        let (_dir, root) = t1_canonical_owner_only_audit_root();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = claw_vpn_t1_canonical_audit_log_path(root).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn t1_spooled_audit_sink_rotates_and_retains_bounded_files() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_path = dir.path().join("audit").join("audit.jsonl");
        let first = t1_open_audit_event_for_member("member-rotate-one");
        let second = t1_open_audit_event_for_member("member-rotate-two");
        let third = t1_open_audit_event_for_member("member-rotate-three");
        let first_line = claw_vpn_t1_redacted_audit_jsonl(&first);
        let second_line = claw_vpn_t1_redacted_audit_jsonl(&second);
        let third_line = claw_vpn_t1_redacted_audit_jsonl(&third);
        let rotate_bytes = first_line.len() as u64 + 1;
        let sink = claw_vpn_t1_spooled_jsonl_audit_sink_with_capacity_and_rotation(
            &audit_path,
            8,
            rotate_bytes,
            1,
        )
        .unwrap();

        sink(first).unwrap();
        sink(second).unwrap();
        sink(third).unwrap();

        let active = read_audit_file_until(&audit_path, &third_line);
        let rotated_path = audit_path.with_file_name("audit.jsonl.1");
        let rotated = read_audit_file_until(&rotated_path, &second_line);

        assert!(active.contains(&third_line));
        assert!(rotated.contains(&second_line));
        assert!(!audit_path.with_file_name("audit.jsonl.2").exists());
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&rotated_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_record_larger_than_rotate_cap() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_path = dir.path().join("audit").join("audit.jsonl");
        let parent_dir = ensure_claw_vpn_t1_audit_parent(audit_path.parent().unwrap()).unwrap();
        let file_name = claw_vpn_t1_audit_log_file_name(&audit_path).unwrap();
        let writer = ClawVpnT1RotatingAuditLog::open(parent_dir, file_name, 1, 1).unwrap();
        let (sender, receiver) = sync_channel(1);
        let healthy = Arc::new(AtomicBool::new(true));
        let handle =
            spawn_claw_vpn_t1_audit_worker(writer, receiver, Arc::clone(&healthy)).unwrap();
        let event = t1_open_audit_event_for_test();
        assert!(claw_vpn_t1_redacted_audit_jsonl(&event).len() > 1);

        claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, event).unwrap();
        handle.join().unwrap();

        assert!(!healthy.load(Ordering::SeqCst));
        assert_eq!(
            claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, t1_open_audit_event_for_test()),
            Err("claw-vpn-t1-audit-sink-unavailable")
        );
        assert_eq!(std::fs::read_to_string(&audit_path).unwrap(), "");
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_after_parent_dir_sync_failure() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_path = dir.path().join("audit").join("audit.jsonl");
        let parent_dir = ensure_claw_vpn_t1_audit_parent(audit_path.parent().unwrap()).unwrap();
        let sync_count = Arc::new(AtomicUsize::new(0));
        let first = t1_open_audit_event_for_member("member-parent-sync-one");
        let second = t1_open_audit_event_for_member("member-parent-sync-two");
        let first_line = claw_vpn_t1_redacted_audit_jsonl(&first);
        let second_line = claw_vpn_t1_redacted_audit_jsonl(&second);
        let rotate_bytes = first_line.len() as u64 + 1;
        let writer = ClawVpnT1RotatingAuditLog::open_with_parent(
            TrackingAuditParentDir {
                file: parent_dir,
                sync_count: Arc::clone(&sync_count),
                fail_sync: true,
            },
            claw_vpn_t1_audit_log_file_name(&audit_path).unwrap(),
            rotate_bytes,
            1,
        )
        .unwrap();
        let (sender, receiver) = sync_channel(4);
        let healthy = Arc::new(AtomicBool::new(true));
        let handle =
            spawn_claw_vpn_t1_audit_worker(writer, receiver, Arc::clone(&healthy)).unwrap();

        claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, first).unwrap();
        claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, second).unwrap();
        handle.join().unwrap();

        assert_eq!(sync_count.load(Ordering::SeqCst), 1);
        assert!(!healthy.load(Ordering::SeqCst));
        assert_eq!(
            claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, t1_open_audit_event_for_test()),
            Err("claw-vpn-t1-audit-sink-unavailable")
        );
        let rotated_path = audit_path.with_file_name("audit.jsonl.1");
        assert!(read_audit_file_until(&rotated_path, &first_line).contains(&first_line));
        let active = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(!active.contains(&second_line));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_after_sync_data_failure() {
        let (sender, receiver) = sync_channel(1);
        let healthy = Arc::new(AtomicBool::new(true));
        let state = Arc::new(Mutex::new(FakeAuditWriterState::default()));
        let handle = spawn_claw_vpn_t1_audit_worker(
            FakeAuditWriter {
                state: Arc::clone(&state),
                fail_sync: true,
            },
            receiver,
            Arc::clone(&healthy),
        )
        .unwrap();

        claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, t1_open_audit_event_for_test())
            .unwrap();
        handle.join().unwrap();

        assert!(!healthy.load(Ordering::SeqCst));
        {
            let state = state.lock().unwrap();
            let body = String::from_utf8_lossy(&state.body);
            assert!(body.contains("\"schema\":\"claw_vpn_t1_audit_v1\""));
            assert!(body.contains("\"reason\":\"SessionOpened\""));
            assert_eq!(state.flush_count, 1);
            assert_eq!(state.sync_count, 1);
        }
        assert_eq!(
            claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, t1_open_audit_event_for_test()),
            Err("claw-vpn-t1-audit-sink-unavailable")
        );
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_directory_as_log_file() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_path = audit_dir.join("audit.jsonl");
        std::fs::create_dir(&audit_path).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path) {
            Ok(_) => panic!("directory path must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::OpenFile(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_forces_owner_only_log_file_permissions() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_path = audit_dir.join("audit.jsonl");
        std::fs::write(&audit_path, "").unwrap();
        std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _sink = claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).unwrap();

        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn t1_spooled_audit_sink_creates_owner_only_parent_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_root = dir.path().join("audit");
        let audit_dir = audit_root.join("nested");
        let audit_path = audit_dir.join("audit.jsonl");

        let _sink = claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).unwrap();

        assert_eq!(
            std::fs::metadata(&audit_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&audit_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_symlink_parent_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let target_dir = dir.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_dir = dir.path().join("audit-link");
        std::os::unix::fs::symlink(&target_dir, &audit_dir).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(audit_dir.join("audit.jsonl")) {
            Ok(_) => panic!("symlink parent must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_symlink_intermediate_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let target_dir = dir.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_link = dir.path().join("audit-link");
        std::os::unix::fs::symlink(&target_dir, &audit_link).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(
            audit_link.join("nested").join("audit.jsonl"),
        ) {
            Ok(_) => panic!("symlink intermediate must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_parent_dir_components() {
        let dir = t1_audit_sink_test_tempdir();

        let error =
            match claw_vpn_t1_spooled_jsonl_audit_sink(dir.path().join("..").join("audit.jsonl")) {
                Ok(_) => panic!("parent-dir component must not create an audit sink"),
                Err(error) => error,
            };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_file_intermediate_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_file = dir.path().join("audit-file");
        std::fs::write(&audit_file, "").unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(
            audit_file.join("nested").join("audit.jsonl"),
        ) {
            Ok(_) => panic!("file intermediate must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_shared_parent_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(audit_dir.join("audit.jsonl")) {
            Ok(_) => panic!("shared parent must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_sticky_parent_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o1700)).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(audit_dir.join("audit.jsonl")) {
            Ok(_) => panic!("sticky parent must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_setgid_parent_directory() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o2700)).unwrap();
        let mode = std::fs::symlink_metadata(&audit_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        if mode & 0o2000 == 0 {
            eprintln!("skipping setgid rejection check because this platform cleared setgid");
            return;
        }
        assert_eq!(mode, 0o2700);

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(audit_dir.join("audit.jsonl")) {
            Ok(_) => panic!("setgid parent must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::CreateDir(_)));
    }

    #[test]
    fn t1_spooled_audit_sink_rejects_symlink_log_file() {
        let dir = t1_audit_sink_test_tempdir();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target_path = audit_dir.join("target.jsonl");
        let audit_path = audit_dir.join("audit.jsonl");
        std::fs::write(&target_path, "").unwrap();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target_path, &audit_path).unwrap();

        let error = match claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path) {
            Ok(_) => panic!("symlink path must not create an audit sink"),
            Err(error) => error,
        };

        assert!(matches!(error, ClawVpnT1AuditSinkError::OpenFile(_)));
        assert_eq!(
            std::fs::metadata(&target_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[tokio::test]
    async fn t1_spooled_audit_sink_rejects_disconnected_worker_at_event_time() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let captured_event = Arc::new(Mutex::new(None));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            {
                let captured_event = Arc::clone(&captured_event);
                Box::new(move |event: ClawVpnAuditEvent| {
                    *captured_event.lock().unwrap() = Some(event);
                    Err("claw-vpn-t1-audit-open-failed")
                })
            },
        );

        let error = match router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("audit sink failure must fail before returning a target session"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-audit-open-failed")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
        let event = captured_event
            .lock()
            .unwrap()
            .take()
            .expect("audit sink must receive the open event before rejecting");
        let (sender, receiver) = sync_channel(1);
        drop(receiver);
        let healthy = AtomicBool::new(true);

        assert_eq!(
            claw_vpn_t1_try_enqueue_audit_event(&sender, &healthy, event),
            Err("claw-vpn-t1-audit-sink-unavailable")
        );
    }

    fn t1_audit_sink_test_tempdir() -> tempfile::TempDir {
        let root = Path::new("target").join("t1-audit-sink-tests");
        std::fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .prefix("audit-")
            .tempdir_in(root)
            .unwrap()
    }

    #[tokio::test]
    async fn t1_relay_stream_router_builds_wiring_from_group_target_context() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let seen_target = Arc::new(Mutex::new(None));
        let audit_events = Arc::new(Mutex::new(Vec::new()));
        let member_device_pub = P256Keypair::generate().public();
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                let seen_target = Arc::clone(&seen_target);
                move |
                    _config: &ClawVpnDevConfig,
                    target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    *seen_target.lock().unwrap() = Some((
                        target.group_id().to_string(),
                        target.member_id().to_string(),
                        target.member_device_pub().clone(),
                        target.claw_id().to_string(),
                    ));
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            recording_audit_sink(Arc::clone(&audit_events)),
        );

        let _session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();

        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            seen_target.lock().unwrap().as_ref(),
            Some(&(
                "group-alpha".to_string(),
                "member-alpha".to_string(),
                member_device_pub.clone(),
                "claw-alpha".to_string()
            ))
        );
        let audit_events = audit_events.lock().unwrap();
        assert_eq!(audit_events.len(), 1);
        let audit_event = &audit_events[0];
        assert_eq!(audit_event.action(), ClawVpnAuditAction::SessionOpen);
        assert_eq!(audit_event.reason(), ClawVpnAuditReason::SessionOpened);
        assert_eq!(
            audit_event.subject(),
            Some(ClawVpnAuditSubject::from_acl_key(
                &ClawVpnAclKey::try_new(
                    "member-alpha".to_string(),
                    member_device_pub.clone(),
                    "claw-alpha".to_string()
                )
                .unwrap()
            ))
        );
        assert!(audit_event.session_id().is_some());
    }

    #[tokio::test]
    async fn t1_relay_stream_router_enforces_member_claw_limit_until_session_drops() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            config_with_session_limits("1", "2"),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );
        let member_device_pub = P256Keypair::generate().public();

        let first_session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();
        let error = match router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
        {
            Ok(_) => panic!("second session for the same member/claw must be limited"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-member-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);

        drop(first_session);
        let _second_session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub,
                "claw-alpha",
            ))
            .await
            .unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
        assert_eq!(launch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_enforces_claw_limit_across_members() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            config_with_session_limits("2", "1"),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );

        let _first_session = router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
            .unwrap();
        let error = match router
            .open_ip_tunnel(target("member-beta", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("second session for the same claw must be limited"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_shared_admission_crosses_router_instances() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let admission = Arc::new(Mutex::new(ClawVpnT1RelayStreamAdmission::default()));
        let router = |admission| {
            ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::with_admission(
                config_with_session_limits("1", "2"),
                enabled_runtime_config(),
                Duration::from_secs(1),
                {
                    let build_count = Arc::clone(&build_count);
                    move |
                        _config: &ClawVpnDevConfig,
                        _target: &RelayStreamIpTunnelTarget,
                        _context: ClawVpnRuntimeWiringContext,
                        relay: ClawVpnRelayStream<StdUnixStream>,
                    | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                        build_count.fetch_add(1, Ordering::SeqCst);
                        Ok(inputs(FakeInterface::empty(), relay))
                    }
                },
                {
                    let launch_count = Arc::clone(&launch_count);
                    move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                        launch_count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
                noop_audit_sink(),
                admission,
            )
        };
        let first_router = router(Arc::clone(&admission));
        let second_router = router(admission);
        let member_device_pub = P256Keypair::generate().public();

        let first_session = first_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();
        let error = match second_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
        {
            Ok(_) => panic!("shared admission must cross router instances"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-member-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);

        drop(first_session);
        let _second_session = second_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub,
                "claw-alpha",
            ))
            .await
            .unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
        assert_eq!(launch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_rejects_invalid_acl_context_before_inputs() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );

        let error = match router
            .open_ip_tunnel(target(" member-alpha", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("invalid ACL context must fail before returning a target session"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-acl-key-invalid")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_rejects_audit_failure_before_inputs() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let audit_count = Arc::new(AtomicUsize::new(0));
        let member_device_pub = P256Keypair::generate().public();
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            {
                let audit_count = Arc::clone(&audit_count);
                Box::new(move |event: ClawVpnAuditEvent| {
                    let index = audit_count.fetch_add(1, Ordering::SeqCst);
                    match index % 2 {
                        0 => {
                            assert_eq!(event.action(), ClawVpnAuditAction::SessionOpen);
                            assert_eq!(event.reason(), ClawVpnAuditReason::SessionOpened);
                            Err("claw-vpn-t1-audit-open-failed")
                        }
                        1 => {
                            assert_eq!(event.action(), ClawVpnAuditAction::SessionClose);
                            assert_eq!(event.reason(), ClawVpnAuditReason::SessionClosed);
                            Ok(())
                        }
                        _ => unreachable!(),
                    }
                })
            },
        );

        for _ in 0..2 {
            let error = match router
                .open_ip_tunnel(target_with_device(
                    "member-alpha",
                    member_device_pub.clone(),
                    "claw-alpha",
                ))
                .await
            {
                Ok(_) => panic!("audit sink failure must fail before returning a target session"),
                Err(error) => error,
            };

            assert!(
                matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-audit-open-failed")
            );
        }

        assert_eq!(audit_count.load(Ordering::SeqCst), 4);
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn t1_relay_stream_router_gate_returns_before_building_router_when_preflight_missing() {
        let parts_built = Arc::new(AtomicUsize::new(0));
        let status = assemble_claw_vpn_t1_relay_stream_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(live_config())),
            PerClawVpnT1PreflightEvidence::missing,
            {
                let parts_built = Arc::clone(&parts_built);
                move |_config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    ClawVpnT1RelayStreamRouterParts::new(
                        enabled_runtime_config(),
                        Duration::from_secs(1),
                        |_config: &ClawVpnDevConfig,
                         _target: &RelayStreamIpTunnelTarget,
                         _context: ClawVpnRuntimeWiringContext,
                         relay: ClawVpnRelayStream<StdUnixStream>|
                         -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                            Ok(inputs(FakeInterface::empty(), relay))
                        },
                        |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                            Ok::<(), crate::claw_vpn_target_session_router::ClawVpnTargetSessionRouterLaunchError>(
                                (),
                            )
                        },
                        noop_audit_sink(),
                    )
                }
            },
        );

        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::OwnerAuthorizationRequired { .. }
        ));
        assert_eq!(parts_built.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_present_preflight_writes_spooled_audit_log() {
        let parts_built = Arc::new(AtomicUsize::new(0));
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let (_dir, root) = t1_canonical_owner_only_audit_root();
        let audit_path = claw_vpn_t1_canonical_audit_log_path(&root).unwrap();
        let audit_sink = claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).unwrap();

        let status = assemble_claw_vpn_t1_relay_stream_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(live_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            {
                let parts_built = Arc::clone(&parts_built);
                let build_count = Arc::clone(&build_count);
                let launch_count = Arc::clone(&launch_count);
                move |_config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    ClawVpnT1RelayStreamRouterParts::new(
                        enabled_runtime_config(),
                        Duration::from_secs(1),
                        {
                            let build_count = Arc::clone(&build_count);
                            move |
                                _config: &ClawVpnDevConfig,
                                _target: &RelayStreamIpTunnelTarget,
                                _context: ClawVpnRuntimeWiringContext,
                                relay: ClawVpnRelayStream<StdUnixStream>,
                            | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                                build_count.fetch_add(1, Ordering::SeqCst);
                                Ok(inputs(FakeInterface::empty(), relay))
                            }
                        },
                        {
                            let launch_count = Arc::clone(&launch_count);
                            move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                                launch_count.fetch_add(1, Ordering::SeqCst);
                                Ok::<(), crate::claw_vpn_target_session_router::ClawVpnTargetSessionRouterLaunchError>(
                                    (),
                                )
                            }
                        },
                        audit_sink,
                    )
                }
            },
        );
        let (_mode, router) = status
            .into_ready()
            .expect("present Live preflight must build the T1 router");

        let _session = router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
            .unwrap();

        let body = read_audit_file_until(&audit_path, "SessionOpened");
        assert!(body.contains("\"schema\":\"claw_vpn_t1_audit_v1\""));
        assert!(body.contains("\"action\":\"SessionOpen\""));
        assert!(body.contains("\"reason\":\"SessionOpened\""));
        assert!(body.contains("\"session_id_present\":true"));
        assert!(body.contains("member_id_hash"));
        assert!(body.contains("device_pub_hash"));
        assert!(body.contains("claw_id_hash"));
        assert!(!body.contains("member-alpha"));
        assert!(!body.contains("claw-alpha"));
        assert_eq!(parts_built.load(Ordering::SeqCst), 1);
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::metadata(audit_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn t1_relay_stream_router_present_preflight_rejects_failed_audit_sink() {
        let parts_built = Arc::new(AtomicUsize::new(0));
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let audit_count = Arc::new(AtomicUsize::new(0));
        let status = assemble_claw_vpn_t1_relay_stream_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(live_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            {
                let parts_built = Arc::clone(&parts_built);
                let build_count = Arc::clone(&build_count);
                let launch_count = Arc::clone(&launch_count);
                let audit_count = Arc::clone(&audit_count);
                move |_config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    ClawVpnT1RelayStreamRouterParts::new(
                        enabled_runtime_config(),
                        Duration::from_secs(1),
                        {
                            let build_count = Arc::clone(&build_count);
                            move |
                                _config: &ClawVpnDevConfig,
                                _target: &RelayStreamIpTunnelTarget,
                                _context: ClawVpnRuntimeWiringContext,
                                relay: ClawVpnRelayStream<StdUnixStream>,
                            | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                                build_count.fetch_add(1, Ordering::SeqCst);
                                Ok(inputs(FakeInterface::empty(), relay))
                            }
                        },
                        {
                            let launch_count = Arc::clone(&launch_count);
                            move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                                launch_count.fetch_add(1, Ordering::SeqCst);
                                Ok::<(), crate::claw_vpn_target_session_router::ClawVpnTargetSessionRouterLaunchError>(
                                    (),
                                )
                            }
                        },
                        {
                            let audit_count = Arc::clone(&audit_count);
                            Box::new(move |event: ClawVpnAuditEvent| {
                                let index = audit_count.fetch_add(1, Ordering::SeqCst);
                                match index {
                                    0 => {
                                        assert_eq!(event.action(), ClawVpnAuditAction::SessionOpen);
                                        assert_eq!(
                                            event.reason(),
                                            ClawVpnAuditReason::SessionOpened
                                        );
                                        Err("claw-vpn-t1-audit-open-failed")
                                    }
                                    1 => {
                                        assert_eq!(
                                            event.action(),
                                            ClawVpnAuditAction::SessionClose
                                        );
                                        assert_eq!(
                                            event.reason(),
                                            ClawVpnAuditReason::SessionClosed
                                        );
                                        Ok(())
                                    }
                                    _ => unreachable!(),
                                }
                            })
                        },
                    )
                }
            },
        );
        let (_mode, router) = status
            .into_ready()
            .expect("present Live preflight must build the T1 router");

        let error = match router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("audit sink failure must reject the T1 target session"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-audit-open-failed")
        );
        assert_eq!(parts_built.load(Ordering::SeqCst), 1);
        assert_eq!(audit_count.load(Ordering::SeqCst), 2);
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }
}
