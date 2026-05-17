//! Configuration for macOS VZ VMs.
//!
//! Includes both VM configuration (`VmConfigMacOS`) and user-facing config
//! loading from ~/.theyos/config.yaml.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{error::VZError, network::NetworkConfig};

/// VM-specific configuration for `VZVirtualMachine`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOSVmConfig {
    /// Number of vCPUs (1-4)
    #[serde(default = "default_cpus")]
    pub cpus: u32,

    /// Memory in MB (512-8192)
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,

    /// Path to kernel image
    pub kernel_path: PathBuf,

    /// Path to rootfs disk image
    pub rootfs_path: PathBuf,

    /// Kernel boot arguments
    #[serde(default = "default_boot_args")]
    pub boot_args: String,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Disk size in MB
    #[serde(default = "default_disk_size_mb")]
    pub disk_size_mb: u32,
}

const fn default_cpus() -> u32 {
    2
}

const fn default_memory_mb() -> u32 {
    2048
}

const fn default_disk_size_mb() -> u32 {
    2048
}

fn default_boot_args() -> String {
    "console=hvc0 panic=1".to_string()
}

impl Default for MacOSVmConfig {
    fn default() -> Self {
        Self {
            cpus: default_cpus(),
            memory_mb: default_memory_mb(),
            kernel_path: PathBuf::from("/usr/local/share/theyos/vms/vmlinuz-aarch64"),
            rootfs_path: PathBuf::from("/usr/local/share/theyos/vms/rootfs.img"),
            boot_args: default_boot_args(),
            network: NetworkConfig::default(),
            disk_size_mb: default_disk_size_mb(),
        }
    }
}

impl MacOSVmConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration values are out of range.
    pub fn validate(&self) -> Result<(), VZError> {
        if self.cpus < 1 || self.cpus > 4 {
            return Err(VZError::config_validation(
                &format!("CPU count must be between 1 and 4, got {}", self.cpus),
                r"vm_backend:
  macos:
    default_cpus: 2",
            ));
        }

        if self.memory_mb < 512 || self.memory_mb > 8192 {
            return Err(VZError::config_validation(
                &format!(
                    "Memory must be between 512 and 8192 MB, got {}",
                    self.memory_mb
                ),
                r"vm_backend:
  macos:
    default_memory_mb: 2048",
            ));
        }

        Ok(())
    }
}

/// User-facing configuration loaded from ~/.theyos/config.yaml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOSConfig {
    /// VM backend configuration
    pub vm_backend: VMBackendConfig,

    /// Warm pool configuration
    #[serde(default)]
    pub warm_pool: WarmPoolConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Custom claw type configurations
    #[serde(default)]
    pub claw_types: std::collections::HashMap<String, ClawTypeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMBackendConfig {
    /// Backend type ("vz" for macOS)
    pub backend: String,

    /// macOS-specific settings
    pub macos: Option<MacOSSpecific>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MacOSSpecific {
    /// Path to VM files
    #[serde(default = "default_vms_path")]
    pub vms_path: String,

    /// Path to snapshots
    #[serde(default = "default_snapshots_path")]
    pub snapshots_path: String,

    /// Default memory in MB
    #[serde(default = "default_memory_mb")]
    pub default_memory_mb: u32,

    /// Default CPU count
    #[serde(default = "default_cpus")]
    pub default_cpus: u32,
}

fn default_vms_path() -> String {
    "/usr/local/share/theyos/vms".to_string()
}

fn default_snapshots_path() -> String {
    // This will be expanded relative to HOME when loading
    "~/Library/Application Support/theyos/snapshots".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WarmPoolConfig {
    /// Whether warm pool is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of pre-warmed snapshots
    #[serde(default = "default_pool_size")]
    pub size: usize,

    /// Snapshot TTL in hours
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_pool_size() -> usize {
    2
}

const fn default_ttl_hours() -> u64 {
    24
}

/// Custom configuration for a specific claw type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClawTypeConfig {
    /// Override CPU count for this claw type
    pub cpus: Option<u32>,

    /// Override memory in MB for this claw type
    pub memory_mb: Option<u32>,

    /// Override disk size in MB for this claw type
    pub disk_size_mb: Option<u32>,

    /// Override boot arguments for this claw type
    pub boot_args: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json, text)
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl Default for MacOSConfig {
    fn default() -> Self {
        Self {
            vm_backend: VMBackendConfig {
                backend: "vz".to_string(),
                macos: Some(MacOSSpecific {
                    vms_path: default_vms_path(),
                    snapshots_path: default_snapshots_path(),
                    default_memory_mb: default_memory_mb(),
                    default_cpus: default_cpus(),
                }),
            },
            warm_pool: WarmPoolConfig {
                enabled: true,
                size: default_pool_size(),
                ttl_hours: default_ttl_hours(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
            },
            claw_types: std::collections::HashMap::new(),
        }
    }
}

impl MacOSConfig {
    /// Load configuration from ~/.theyos/config.yaml.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> Result<Self, VZError> {
        let home = std::env::var("HOME")
            .map_err(|_| VZError::InvalidConfig("HOME environment variable not set".into()))?;

        let config_path = PathBuf::from(home).join(".theyos/config.yaml");

        // If config doesn't exist, return defaults
        if !config_path.exists() {
            tracing::info!(
                "Config file not found at {}, using defaults",
                config_path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            VZError::InvalidConfig(format!(
                "Failed to read config file {}: {e}",
                config_path.display()
            ))
        })?;

        // Parse with better error messages
        let config: MacOSConfig = serde_yaml::from_str(&content).map_err(|e| {
            // Try to extract line/column from serde_yaml error
            let error_str = e.to_string();
            if let Some(line_loc) = extract_line_col(&error_str) {
                VZError::config_parse(&error_str, line_loc.0, line_loc.1)
            } else {
                VZError::ConfigParse(error_str)
            }
        })?;

        // Expand ~ in paths
        let config = config.expand_tilde();

        Ok(config)
    }

    /// Apply environment variable overrides to the loaded configuration.
    ///
    /// Environment variables take precedence over config file values:
    /// - `THEYOS_VM_CPUS`: Override CPU count (1-4)
    /// - `THEYOS_VM_MEMORY_MB`: Override memory in MB (512-8192)
    /// - `THEYOS_VM_VMS_PATH`: Override VM files path
    /// - `THEYOS_SNAPSHOTS_PATH`: Override snapshots path
    /// - `THEYOS_WARM_POOL_SIZE`: Override warm pool size
    /// - `THEYOS_WARM_POOL_TTL_HOURS`: Override snapshot TTL in hours
    #[must_use]
    pub fn with_env_override(mut self) -> Self {
        // Apply VM CPU override
        if let Ok(cpu_str) = std::env::var("THEYOS_VM_CPUS") {
            if let Ok(cpus) = cpu_str.parse::<u32>() {
                if let Some(ref mut macos) = self.vm_backend.macos {
                    macos.default_cpus = cpus;
                }
            }
        }

        // Apply VM memory override
        if let Ok(mem_str) = std::env::var("THEYOS_VM_MEMORY_MB") {
            if let Ok(memory_mb) = mem_str.parse::<u32>() {
                if let Some(ref mut macos) = self.vm_backend.macos {
                    macos.default_memory_mb = memory_mb;
                }
            }
        }

        // Apply VM path override
        if let Ok(vms_path) = std::env::var("THEYOS_VM_VMS_PATH") {
            if let Some(ref mut macos) = self.vm_backend.macos {
                macos.vms_path.clone_from(&vms_path);
            }
        }

        // Apply snapshots path override
        if let Ok(snapshots_path) = std::env::var("THEYOS_SNAPSHOTS_PATH") {
            if let Some(ref mut macos) = self.vm_backend.macos {
                macos.snapshots_path.clone_from(&snapshots_path);
            }
        }

        // Apply warm pool size override
        if let Ok(size_str) = std::env::var("THEYOS_WARM_POOL_SIZE") {
            if let Ok(size) = size_str.parse::<usize>() {
                self.warm_pool.size = size;
            }
        }

        // Apply warm pool TTL override
        if let Ok(ttl_str) = std::env::var("THEYOS_WARM_POOL_TTL_HOURS") {
            if let Ok(ttl_hours) = ttl_str.parse::<u64>() {
                self.warm_pool.ttl_hours = ttl_hours;
            }
        }

        self
    }

    /// Expand ~ in paths to the actual HOME directory.
    fn expand_tilde(mut self) -> Self {
        if let Ok(home) = std::env::var("HOME") {
            if let Some(macos_cfg) = &self.vm_backend.macos {
                let mut macos = macos_cfg.clone();
                if macos.snapshots_path.starts_with("~/") {
                    macos.snapshots_path = macos.snapshots_path.replacen('~', &home, 1);
                }
                self.vm_backend.macos = Some(macos);
            }
        }
        self
    }

    /// Get VM configuration from the loaded config.
    ///
    /// Supports custom claw type configuration via config.yaml:
    /// ```yaml
    /// claw_types:
    ///   picoclaw:
    ///     cpus: 2
    ///     memory_mb: 2048
    ///     disk_size_mb: 2048
    ///   zeroclaw:
    ///     cpus: 4
    ///     memory_mb: 4096
    ///     disk_size_mb: 4096
    /// ```
    pub fn vm_config(&self, claw_type: &str) -> MacOSVmConfig {
        let macos_cfg = self.vm_backend.macos.clone().unwrap_or_default();

        // Check for custom claw type configuration
        let custom_config = self.claw_types.get(claw_type).cloned().unwrap_or_default();

        MacOSVmConfig {
            cpus: custom_config.cpus.unwrap_or(macos_cfg.default_cpus),
            memory_mb: custom_config
                .memory_mb
                .unwrap_or(macos_cfg.default_memory_mb),
            kernel_path: PathBuf::from(format!("{}/vmlinuz-aarch64", macos_cfg.vms_path)),
            rootfs_path: PathBuf::from(format!("{}/{}-rootfs.img", macos_cfg.vms_path, claw_type)),
            boot_args: custom_config.boot_args.unwrap_or_else(default_boot_args),
            network: NetworkConfig::default(),
            disk_size_mb: custom_config.disk_size_mb.unwrap_or(2048),
        }
    }

    /// Get snapshots directory.
    #[must_use]
    pub fn snapshots_dir(&self) -> PathBuf {
        match std::env::var("THEYOS_SNAPSHOTS_DIR") {
            Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => {
                if let Some(ref macos_cfg) = self.vm_backend.macos {
                    PathBuf::from(&macos_cfg.snapshots_path)
                } else {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home).join("Library/Application Support/theyos/snapshots")
                }
            }
        }
    }

    /// Get VM state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        if let Some(ref macos_cfg) = self.vm_backend.macos {
            PathBuf::from(&macos_cfg.vms_path)
        } else {
            PathBuf::from("/usr/local/share/theyos/vms")
        }
    }
}

/// Try to extract line and column from `serde_yaml` error message.
fn extract_line_col(error_str: &str) -> Option<(usize, usize)> {
    // serde_yaml errors look like: "line 5, column 10" or "at line 5, column 10"
    let error_lower = error_str.to_lowercase();

    // Find "line X, column Y" pattern
    let line_key = if error_lower.contains("line ") {
        "line "
    } else {
        return None;
    };

    let line_start = error_lower.find(line_key)? + line_key.len();
    let comma_pos = error_str[line_start..].find(',')?;

    let line: usize = error_str[line_start..line_start + comma_pos]
        .trim()
        .parse()
        .ok()?;

    // Extract column: everything after "column " until the next non-digit or end of string
    let after_comma = &error_str[line_start + comma_pos + 1..];
    let col_key = "column ";
    let col_start = after_comma.to_lowercase().find(col_key)? + col_key.len();
    let col_str = &after_comma[col_start..];
    let col_end = col_str
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(col_str.len());
    let col: usize = col_str[..col_end].trim().parse().ok()?;

    Some((line, col))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_vm_config_default() {
        let config = MacOSVmConfig::default();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 2048);
        assert_eq!(config.disk_size_mb, 2048);
    }

    #[test]
    fn test_macos_vm_config_validate() {
        let mut config = MacOSVmConfig::default();

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid CPU count
        config.cpus = 0;
        assert!(config.validate().is_err());
        config.cpus = 5;
        assert!(config.validate().is_err());

        config.cpus = 2;
        config.memory_mb = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_macos_config_default() {
        let config = MacOSConfig::default();
        assert_eq!(config.vm_backend.backend, "vz");
        assert!(config.warm_pool.enabled);
        assert_eq!(config.warm_pool.size, 2);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_extract_line_col() {
        let error = "parsing error at line 5, column 10";
        let result = extract_line_col(error);
        assert_eq!(result, Some((5, 10)));

        let error = "line 42, column 3";
        let result = extract_line_col(error);
        assert_eq!(result, Some((42, 3)));

        let error = "some other error";
        let result = extract_line_col(error);
        assert_eq!(result, None);
    }

    #[test]
    fn test_port_protocol_default() {
        use crate::network::PortProtocol;
        assert_eq!(PortProtocol::default(), PortProtocol::TCP);
    }
}
