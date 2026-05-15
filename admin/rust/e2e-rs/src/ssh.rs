use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, client};

use crate::error::E2eError;

/// Minimal handler that accepts any host key (we connect to local VMs only).
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connect, authenticate, and execute a single command. Returns stdout.
async fn ssh_exec_once(ssh_port: u16, key_path: &Path, command: &str) -> Result<String, E2eError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let mut handle = client::connect(config, ("127.0.0.1", ssh_port), SshHandler)
        .await
        .map_err(|e| E2eError::Ssh {
            port: ssh_port,
            reason: format!("SSH connect: {e}"),
        })?;

    let key = russh::keys::load_secret_key(key_path, None).map_err(|e| E2eError::Ssh {
        port: ssh_port,
        reason: format!("load SSH key {}: {e}", key_path.display()),
    })?;

    // Use SHA-512 for RSA keys — OpenSSH 9.x disabled legacy ssh-rsa (SHA-1)
    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha512));

    let auth_result = handle
        .authenticate_publickey("root", key_with_alg)
        .await
        .map_err(|e| E2eError::Ssh {
            port: ssh_port,
            reason: format!("auth: {e}"),
        })?;

    if !auth_result.success() {
        return Err(E2eError::Ssh {
            port: ssh_port,
            reason: "authentication failed".into(),
        });
    }

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| E2eError::Ssh {
            port: ssh_port,
            reason: format!("open channel: {e}"),
        })?;

    channel
        .exec(true, command)
        .await
        .map_err(|e| E2eError::Ssh {
            port: ssh_port,
            reason: format!("exec '{command}': {e}"),
        })?;

    let mut stdout = String::new();

    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::Data { ref data } = msg {
            stdout.push_str(&String::from_utf8_lossy(data));
        }
    }

    Ok(stdout)
}

/// Wait for SSH to become available, then execute a command.
///
/// Retries SSH connection up to `max_retries` times with 2s between attempts.
/// Once connected, executes `command` and returns stdout.
///
/// This is a blocking wrapper around the async implementation. It requires a
/// tokio runtime to be available (e.g. via `#[tokio::main]` on the binary
/// entry point). Uses `tokio::task::block_in_place` + `Handle::block_on` so
/// it can be called from synchronous code running on a tokio worker thread.
///
/// # Errors
///
/// Returns an error if SSH is not available after all retries, or the command
/// execution fails.
pub fn ssh_wait_and_exec(
    ssh_port: u16,
    key_path: &Path,
    command: &str,
    max_retries: u32,
) -> Result<String, E2eError> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(ssh_wait_and_exec_async(
            ssh_port,
            key_path,
            command,
            max_retries,
        ))
    })
}

/// Async implementation of `ssh_wait_and_exec`.
async fn ssh_wait_and_exec_async(
    ssh_port: u16,
    key_path: &Path,
    command: &str,
    max_retries: u32,
) -> Result<String, E2eError> {
    let mut last_err = String::new();

    for attempt in 1..=max_retries {
        match tokio::time::timeout(
            Duration::from_secs(30),
            ssh_exec_once(ssh_port, key_path, command),
        )
        .await
        {
            Ok(Ok(stdout)) => return Ok(stdout),
            Ok(Err(e)) => {
                last_err = format!("attempt {attempt}/{max_retries}: {e}");
            }
            Err(_elapsed) => {
                last_err = format!("attempt {attempt}/{max_retries}: timed out");
            }
        }

        if attempt < max_retries {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    Err(E2eError::Ssh {
        port: ssh_port,
        reason: format!("SSH not available after {max_retries} retries: {last_err}"),
    })
}

/// Run an SSH smoke test: connect, execute `echo SSH_OK`, verify output.
///
/// Uses the same retry loop as [`ssh_wait_and_exec`] so claims restored from
/// the warm pool get a short grace period for `sshd` to start accepting
/// connections.
///
/// # Errors
///
/// Returns an error if the SSH connection fails or the smoke test command
/// does not produce the expected output.
pub fn ssh_smoke_test(ssh_port: u16, key_path: &Path) -> Result<(), E2eError> {
    let stdout = ssh_wait_and_exec(ssh_port, key_path, "echo SSH_OK", 15)?;

    if stdout.contains("SSH_OK") {
        Ok(())
    } else {
        Err(E2eError::Ssh {
            port: ssh_port,
            reason: format!("expected 'SSH_OK' in output, got: {}", stdout.trim()),
        })
    }
}
