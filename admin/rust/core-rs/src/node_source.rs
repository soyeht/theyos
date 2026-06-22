//! `NodeSource` APT setup helpers.
//!
//! Install plans should not execute `NodeSource`'s remote setup scripts. Keep the
//! repository/keyring setup here so every Node.js install path uses one audited
//! command string.

/// Fast idempotency check for Node.js 22+ with npm on PATH.
pub const NODE_22_CHECK: &str = "node --version 2>/dev/null | grep -qE '^v(2[2-9]|[3-9][0-9])' \
     && command -v npm >/dev/null 2>&1";

/// Fast idempotency check for Node.js 22.12+ with npm on PATH.
pub const NODE_22_12_CHECK: &str = "node --version 2>/dev/null | grep -qE '^v(2[3-9]|[3-9][0-9]|22\\.(1[2-9]|[2-9][0-9]))' \
     && command -v npm >/dev/null 2>&1";

/// Reviewed SHA-256 digest for `NodeSource`'s repository signing key.
pub const NODESOURCE_REPO_KEY_SHA256: &str =
    "b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d";

/// Configure the `NodeSource` Node.js 22.x APT repository and install `nodejs`.
///
/// This mirrors the official setup script's keyring + `nodesource.sources`
/// shape without downloading and executing the setup script itself.
pub const INSTALL_NODE_22_COMMAND: &str = "export DEBIAN_FRONTEND=noninteractive && \
     apt-get update -qq && \
     apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl gnupg >/dev/null 2>&1 && \
     mkdir -p /usr/share/keyrings && \
     rm -f /usr/share/keyrings/nodesource.gpg /etc/apt/sources.list.d/nodesource.list /etc/apt/sources.list.d/nodesource.sources && \
     curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /tmp/nodesource-repo.gpg.key && \
     echo \"b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d  /tmp/nodesource-repo.gpg.key\" | sha256sum -c - && \
     gpg --dearmor -o /usr/share/keyrings/nodesource.gpg /tmp/nodesource-repo.gpg.key && \
     rm -f /tmp/nodesource-repo.gpg.key && \
     chmod 644 /usr/share/keyrings/nodesource.gpg && \
     ARCH=$(dpkg --print-architecture) && \
     case \"$ARCH\" in amd64|arm64) ;; *) echo \"Unsupported NodeSource architecture: $ARCH\" >&2; exit 1 ;; esac && \
     printf 'Package: nodejs\\nPin: origin deb.nodesource.com\\nPin-Priority: 600\\n' > /etc/apt/preferences.d/nodejs && \
     printf 'Types: deb\\nURIs: https://deb.nodesource.com/node_22.x\\nSuites: nodistro\\nComponents: main\\nArchitectures: %s\\nSigned-By: /usr/share/keyrings/nodesource.gpg\\n' \"$ARCH\" > /etc/apt/sources.list.d/nodesource.sources && \
     apt-get update -qq && \
     apt-get install -y --no-install-recommends nodejs && \
     node --version && npm --version";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodesource_install_command_does_not_execute_remote_setup_script() {
        assert!(!INSTALL_NODE_22_COMMAND.contains("setup_22.x"));
        assert!(!INSTALL_NODE_22_COMMAND.contains("| bash"));
        assert!(!INSTALL_NODE_22_COMMAND.contains("| sh "));
        assert!(!INSTALL_NODE_22_COMMAND.contains("| sh -"));
        assert!(!INSTALL_NODE_22_COMMAND.contains("bash /tmp/nodesource"));
    }

    #[test]
    fn nodesource_install_command_uses_signed_sources_file() {
        assert!(INSTALL_NODE_22_COMMAND.contains("nodesource-repo.gpg.key"));
        assert!(INSTALL_NODE_22_COMMAND.contains(NODESOURCE_REPO_KEY_SHA256));
        assert!(INSTALL_NODE_22_COMMAND.contains("sha256sum -c -"));
        assert!(INSTALL_NODE_22_COMMAND.contains("Signed-By: /usr/share/keyrings/nodesource.gpg"));
        assert!(INSTALL_NODE_22_COMMAND.contains("https://deb.nodesource.com/node_22.x"));
        assert!(INSTALL_NODE_22_COMMAND.contains("Suites: nodistro"));
    }
}
