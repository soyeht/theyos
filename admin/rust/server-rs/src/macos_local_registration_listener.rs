//! UDS listener for macOS local owner-passkey enrollment routes.
//!
//! This module is transport-only. It mounts only the dedicated `/local/`
//! registration router and captures peer identity from the accepted Unix
//! socket. HTTP handlers remain responsible for fail-closed authorization.

use std::io;
use std::path::{Path, PathBuf};

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::macos_local_caller_auth::MacosLocalPeer;

const SOCKET_DIR: &str = "runtime";
const SOCKET_NAME: &str = "owner-webauthn-registration.sock";

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
    state_dir.join(SOCKET_DIR).join(SOCKET_NAME)
}

pub fn spawn_macos_local_registration_listener(
    state_dir: &Path,
    router: Router,
) -> io::Result<PathBuf> {
    let socket_path = prepare_socket_path(state_dir)?;
    let listener = UnixListener::bind(&socket_path)?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<MacosLocalPeerConnectInfo>(),
        )
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
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let socket_path = macos_local_registration_socket_path(state_dir);
    let Some(parent) = socket_path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path has no parent",
        ));
    };

    std::fs::create_dir_all(parent)?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket parent must be a real directory",
        ));
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;

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
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    #[test]
    fn socket_path_is_profile_scoped_under_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare_socket_path(dir.path()).unwrap();
        assert!(path.starts_with(dir.path()));
        assert!(path.ends_with(SOCKET_NAME));
        let parent = path.parent().unwrap();
        let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn socket_path_rejects_non_socket_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = macos_local_registration_socket_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a socket").unwrap();
        let err = prepare_socket_path(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn socket_path_unlinks_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = macos_local_registration_socket_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        let prepared = prepare_socket_path(dir.path()).unwrap();
        assert_eq!(prepared, path);
        assert!(!path.exists());
    }
}
