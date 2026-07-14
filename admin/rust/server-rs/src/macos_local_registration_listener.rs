//! UDS listener for macOS local owner-passkey enrollment routes.
//!
//! This module is transport-only. It mounts only the dedicated `/local/`
//! registration router and captures peer identity from the accepted Unix
//! socket. HTTP handlers remain responsible for fail-closed authorization.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::macos_local_caller_auth::MacosLocalPeer;

const SOCKET_NAME: &str = "owner-webauthn.sock";
const PROD_SOCKET_NAMESPACE: &str = "soyeht-local-reg-prod";
const DEV_SOCKET_NAMESPACE: &str = "soyeht-local-reg-dev";
const MACOS_SUN_PATH_LIMIT: usize = 104;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacosLocalPeerConnectInfo {
    pub peer: Option<MacosLocalPeer>,
}

impl MacosLocalPeerConnectInfo {
    #[must_use]
    pub fn from_peer(peer: MacosLocalPeer) -> Self {
        Self { peer: Some(peer) }
    }

    #[must_use]
    pub fn missing() -> Self {
        Self { peer: None }
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for MacosLocalPeerConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        match peer_from_unix_stream(stream.io()) {
            Ok(peer) => Self::from_peer(peer),
            Err(e) => {
                warn!(
                    stage = "macos_local_registration.peer_token_failed",
                    error = %e,
                    "macOS local registration request missing peer audit token"
                );
                Self::missing()
            }
        }
    }
}

#[must_use]
pub fn macos_local_registration_socket_path(state_dir: &Path) -> PathBuf {
    macos_local_registration_socket_path_from_roots(
        state_dir,
        macos_local_registration_runtime_roots(),
    )
}

fn macos_local_registration_socket_path_from_roots(
    state_dir: &Path,
    roots: Vec<PathBuf>,
) -> PathBuf {
    let namespace = macos_local_registration_socket_namespace(state_dir);
    roots
        .into_iter()
        .chain(std::iter::once(PathBuf::from("/tmp")))
        .map(|root| {
            root.join(format!("{namespace}-{}", current_euid()))
                .join(SOCKET_NAME)
        })
        .find(|path| socket_path_fits_macos(path))
        .expect("/tmp macOS local registration socket path must fit SUN_LEN")
}

pub fn spawn_macos_local_registration_listener(
    state_dir: &Path,
    router: Router,
) -> io::Result<PathBuf> {
    let socket_path = prepare_socket_path(state_dir)?;
    let listener = UnixListener::bind(&socket_path)?;
    tokio::spawn(async move {
        if let Err(e) =
            core_rs::phase0_axum_serve!(listener, router, connect_info = MacosLocalPeerConnectInfo)
                .await
        {
            warn!(
                stage = "macos_local_registration.serve_failed",
                error = %e,
            );
        }
    });
    info!(
        stage = "macos_local_registration.listener_started",
        "macOS local registration UDS listener started"
    );
    Ok(socket_path)
}

fn prepare_socket_path(state_dir: &Path) -> io::Result<PathBuf> {
    prepare_socket_path_at(macos_local_registration_socket_path(state_dir))
}

fn prepare_socket_path_at(socket_path: PathBuf) -> io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};

    let Some(parent) = socket_path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path has no parent",
        ));
    };

    match std::fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(parent)?;
        }
        Err(e) => return Err(e),
    }
    validate_socket_parent(parent)?;

    match std::fs::symlink_metadata(&socket_path) {
        Ok(meta) => {
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to replace socket symlink",
                ));
            }
            if !file_type.is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "socket path exists and is not a socket",
                ));
            }
            std::fs::remove_file(&socket_path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    Ok(socket_path)
}

fn validate_socket_parent(parent: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent_meta = std::fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket parent must be a real directory",
        ));
    }
    if parent_meta.uid() != current_euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket parent must be owned by current user",
        ));
    }
    let mode = parent_meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket parent must be mode 0700",
        ));
    }
    Ok(())
}

fn socket_path_fits_macos(path: &Path) -> bool {
    path.as_os_str().as_bytes().len() < MACOS_SUN_PATH_LIMIT
}

fn macos_local_registration_runtime_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = darwin_user_temp_dir() {
        roots.push(root);
    }
    if let Some(root) = std::env::var_os("TMPDIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        if !roots.iter().any(|existing| existing == &root) {
            roots.push(root);
        }
    }
    roots
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::CStr;

    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return None;
    }
    let mut buffer = vec![0 as libc::c_char; len];
    let written = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if written == 0 {
        return None;
    }
    let raw = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy();
    Some(PathBuf::from(raw.trim_end_matches('/')))
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    None
}

fn macos_local_registration_socket_namespace(state_dir: &Path) -> &'static str {
    let namespace = if state_dir
        .file_name()
        .is_some_and(|name| name == "household-state")
    {
        state_dir.parent().and_then(Path::file_name)
    } else {
        state_dir.file_name()
    };
    if namespace.is_some_and(|name| name == "SoyehtDev") {
        DEV_SOCKET_NAMESPACE
    } else {
        PROD_SOCKET_NAMESPACE
    }
}

#[allow(unsafe_code)]
fn current_euid() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn peer_from_unix_stream(stream: &UnixStream) -> io::Result<MacosLocalPeer> {
    use std::mem;
    use std::os::fd::AsRawFd;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuditToken {
        val: [libc::c_uint; 8],
    }

    let mut token = AuditToken { val: [0; 8] };
    let mut len = libc::socklen_t::try_from(mem::size_of::<AuditToken>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "peer audit token size exceeds socklen_t",
        )
    })?;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            std::ptr::addr_of_mut!(token).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<AuditToken>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer audit token length",
        ));
    }
    Ok(MacosLocalPeer::from_audit_token_words(token.val))
}

#[cfg(not(target_os = "macos"))]
fn peer_from_unix_stream(_stream: &UnixStream) -> io::Result<MacosLocalPeer> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "LOCAL_PEERTOKEN is only available on macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    #[test]
    fn socket_path_prefers_short_profile_scoped_runtime_dir() {
        let root = PathBuf::from("/tmp/slr-test");
        let prod = Path::new("/Users/example/Library/Application Support/Soyeht/household-state");
        let dev = Path::new("/Users/example/Library/Application Support/SoyehtDev/household-state");
        let prod_path = macos_local_registration_socket_path_from_roots(prod, vec![root.clone()]);
        let dev_path = macos_local_registration_socket_path_from_roots(dev, vec![root.clone()]);
        assert_ne!(prod_path, dev_path);
        assert!(
            prod_path.starts_with(root.join(format!("{PROD_SOCKET_NAMESPACE}-{}", current_euid())))
        );
        assert!(
            dev_path.starts_with(root.join(format!("{DEV_SOCKET_NAMESPACE}-{}", current_euid())))
        );
        assert!(prod_path.ends_with(SOCKET_NAME));
        assert!(dev_path.ends_with(SOCKET_NAME));
        assert!(
            socket_path_fits_macos(&dev_path),
            "socket path must stay under the conservative macOS SUN_LEN limit"
        );
    }

    #[test]
    fn socket_path_falls_back_when_runtime_root_is_too_long() {
        let long_root = PathBuf::from(format!("/tmp/{}", "x".repeat(MACOS_SUN_PATH_LIMIT)));
        let dev = Path::new("/Users/example/Library/Application Support/SoyehtDev/household-state");
        let dev_path = macos_local_registration_socket_path_from_roots(dev, vec![long_root]);
        assert!(dev_path.starts_with(format!("/tmp/{DEV_SOCKET_NAMESPACE}-{}", current_euid())));
        assert!(socket_path_fits_macos(&dev_path));
    }

    #[test]
    fn prepare_socket_path_makes_parent_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare_socket_path_at(
            dir.path()
                .join(format!("{DEV_SOCKET_NAMESPACE}-{}", current_euid()))
                .join(SOCKET_NAME),
        )
        .unwrap();
        assert!(path.starts_with(dir.path()));
        assert!(path.ends_with(SOCKET_NAME));
        let parent = path.parent().unwrap();
        let parent_meta = std::fs::metadata(parent).unwrap();
        let mode = parent_meta.permissions().mode() & 0o777;
        assert_eq!(parent_meta.uid(), current_euid());
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_socket_path_rejects_parent_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let parent = dir.path().join("runtime-link");
        std::os::unix::fs::symlink(&target, &parent).unwrap();
        let err = prepare_socket_path_at(parent.join(SOCKET_NAME)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn prepare_socket_path_rejects_parent_with_group_or_other_access() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("runtime");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_socket_path_at(parent.join(SOCKET_NAME)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn socket_path_rejects_non_socket_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime").join(SOCKET_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&path, b"not a socket").unwrap();
        let err = prepare_socket_path_at(path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn socket_path_rejects_symlink_at_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime").join(SOCKET_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"not a socket").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let err = prepare_socket_path_at(path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn socket_path_unlinks_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime").join(SOCKET_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        let prepared = prepare_socket_path_at(path.clone()).unwrap();
        assert_eq!(prepared, path);
        assert!(!path.exists());
    }
}
