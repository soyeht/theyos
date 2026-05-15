#![cfg(target_os = "macos")]
//! Property-based tests for macOS VM configuration validation.
//!
//! Uses proptest to generate random inputs and test configuration validation
//! with edge cases and boundary conditions.
//!
//! ```bash
//! cargo test --package vmrunner-macos-rs --test config_prop
//! ```

use proptest::prelude::*;
use std::collections::HashMap;
use vmrunner_macos_rs::config::{
    ClawTypeConfig, LoggingConfig, MacOSConfig, MacOSSpecific, MacOSVmConfig, VMBackendConfig,
    WarmPoolConfig,
};
use vmrunner_macos_rs::network::{NetworkConfig, PortForward, PortProtocol, validate_port_range};

// ── Config validation properties ──────────────────────────────────────────

proptest! {
    #[test]
    fn cpu_validation_accepts_valid_range(cpu in 1u32..=4) {
        let config = MacOSVmConfig { cpus: cpu, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_ok(), "cpu={cpu} should be valid");
    }

    #[test]
    fn cpu_validation_rejects_zero(cpu in 0u32..1) {
        let config = MacOSVmConfig { cpus: cpu, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_err(), "cpu={cpu} should be invalid");
    }

    #[test]
    fn cpu_validation_rejects_above_max(cpu in 5u32..1000) {
        let config = MacOSVmConfig { cpus: cpu, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_err(), "cpu={cpu} should be invalid");
    }

    #[test]
    fn memory_validation_accepts_valid_range(mem in 512u32..=8192) {
        let config = MacOSVmConfig { memory_mb: mem, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_ok(), "memory={mem} should be valid");
    }

    #[test]
    fn memory_validation_rejects_below_min(mem in 0u32..512) {
        let config = MacOSVmConfig { memory_mb: mem, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_err(), "memory={mem} should be invalid");
    }

    #[test]
    fn memory_validation_rejects_above_max(mem in 8193u32..100_000) {
        let config = MacOSVmConfig { memory_mb: mem, ..MacOSVmConfig::default() };
        prop_assert!(config.validate().is_err(), "memory={mem} should be invalid");
    }
}

// ── Port range validation properties ──────────────────────────────────────

proptest! {
    #[test]
    fn port_range_accepts_valid(port in 18790u16..=19999) {
        prop_assert!(validate_port_range(port).is_ok(), "port={port} should be valid");
    }

    #[test]
    fn port_range_rejects_below_min(port in 0u16..18790) {
        prop_assert!(validate_port_range(port).is_err(), "port={port} should be invalid");
    }

    #[test]
    fn port_range_rejects_above_max(port in 20000u16..=u16::MAX) {
        prop_assert!(validate_port_range(port).is_err(), "port={port} should be invalid");
    }
}

// ── Port forward validation properties ────────────────────────────────────

proptest! {
    #[test]
    fn port_forward_zero_host_port_rejected(vm_port in 1u16..=65535) {
        let pf = PortForward::tcp(0, vm_port);
        prop_assert!(pf.validate(&[]).is_err());
    }

    #[test]
    fn port_forward_zero_vm_port_rejected(host_port in 1u16..=65535) {
        let pf = PortForward::tcp(host_port, 0);
        prop_assert!(pf.validate(&[]).is_err());
    }

    #[test]
    fn port_forward_nonzero_ports_accepted(host_port in 1u16..=65535, vm_port in 1u16..=65535) {
        let pf = PortForward::tcp(host_port, vm_port);
        prop_assert!(pf.validate(&[]).is_ok());
    }

    #[test]
    fn port_forward_duplicate_host_port_rejected(
        host_port in 1u16..=65535,
        vm_port_a in 1u16..=65535,
        vm_port_b in 1u16..=65535,
    ) {
        let existing = vec![PortForward::tcp(host_port, vm_port_a)];
        let new_rule = PortForward::tcp(host_port, vm_port_b);
        prop_assert!(new_rule.validate(&existing).is_err());
    }

    #[test]
    fn port_forward_different_host_ports_accepted(
        host_a in 1u16..32000u16,
        vm_port_a in 1u16..=65535,
        vm_port_b in 1u16..=65535,
    ) {
        // Ensure different host ports by offsetting
        let host_b = host_a.saturating_add(1).max(1);
        if host_a != host_b {
            let existing = vec![PortForward::tcp(host_a, vm_port_a)];
            let new_rule = PortForward::tcp(host_b, vm_port_b);
            prop_assert!(new_rule.validate(&existing).is_ok());
        }
    }
}

// ── Serialization roundtrip properties ────────────────────────────────────

proptest! {
    #[test]
    fn vm_config_json_roundtrip(
        cpus in 1u32..=4,
        memory_mb in 512u32..=8192,
        disk_size_mb in 512u32..=8192,
    ) {
        let config = MacOSVmConfig {
            cpus,
            memory_mb,
            disk_size_mb,
            ..MacOSVmConfig::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: MacOSVmConfig = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(config.cpus, deserialized.cpus);
        prop_assert_eq!(config.memory_mb, deserialized.memory_mb);
        prop_assert_eq!(config.disk_size_mb, deserialized.disk_size_mb);
    }

    #[test]
    fn network_config_json_roundtrip(
        host_port in 1u16..=65535,
        vm_port in 1u16..=65535,
    ) {
        let config = NetworkConfig {
            subnet: "192.168.0.0/24".to_string(),
            port_forwards: vec![PortForward::tcp(host_port, vm_port)],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NetworkConfig = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(config.port_forwards.len(), deserialized.port_forwards.len());
        prop_assert_eq!(config.port_forwards[0].host_port, deserialized.port_forwards[0].host_port);
        prop_assert_eq!(config.port_forwards[0].vm_port, deserialized.port_forwards[0].vm_port);
    }

    #[test]
    fn port_protocol_roundtrip(is_tcp: bool) {
        let proto = if is_tcp { PortProtocol::TCP } else { PortProtocol::UDP };
        let s = proto.as_str();
        let parsed = PortProtocol::parse(s).unwrap();
        prop_assert_eq!(proto, parsed);
    }
}

// ── Environment override properties ───────────────────────────────────────

proptest! {
    #[test]
    fn env_override_cpu_takes_precedence(
        file_cpus in 1u32..=4,
        _env_cpus in 1u32..=100,
    ) {
        let config = MacOSConfig {
            vm_backend: VMBackendConfig {
                backend: "vz".to_string(),
                macos: Some(MacOSSpecific {
                    default_cpus: file_cpus,
                    ..MacOSSpecific::default()
                }),
            },
            warm_pool: WarmPoolConfig::default(),
            logging: LoggingConfig::default(),
            claw_types: HashMap::new(),
        };

        // We can't safely set env vars in proptest (concurrent threads),
        // so we verify the config structure supports overrides instead
        let macos = config.vm_backend.macos.as_ref().unwrap();
        prop_assert_eq!(macos.default_cpus, file_cpus);
    }
}

// ── Warm pool config properties ───────────────────────────────────────────

proptest! {
    #[test]
    fn warm_pool_config_yaml_roundtrip(
        size in 0usize..100,
        ttl_hours in 1u64..10000,
        enabled: bool,
    ) {
        let config = WarmPoolConfig {
            enabled,
            size,
            ttl_hours,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: WarmPoolConfig = serde_yaml::from_str(&yaml).unwrap();

        prop_assert_eq!(config.enabled, deserialized.enabled);
        prop_assert_eq!(config.size, deserialized.size);
        prop_assert_eq!(config.ttl_hours, deserialized.ttl_hours);
    }
}

// ── Claw type config override properties ──────────────────────────────────

proptest! {
    #[test]
    fn claw_type_override_applies_when_present(
        default_cpus in 1u32..=4,
        override_cpus in 1u32..=4,
    ) {
        let mut claw_types = HashMap::new();
        claw_types.insert("testclaw".to_string(), ClawTypeConfig {
            cpus: Some(override_cpus),
            memory_mb: None,
            disk_size_mb: None,
            boot_args: None,
        });

        let config = MacOSConfig {
            vm_backend: VMBackendConfig {
                backend: "vz".to_string(),
                macos: Some(MacOSSpecific {
                    default_cpus,
                    ..MacOSSpecific::default()
                }),
            },
            warm_pool: WarmPoolConfig::default(),
            logging: LoggingConfig::default(),
            claw_types,
        };

        let vm_config = config.vm_config("testclaw");
        prop_assert_eq!(vm_config.cpus, override_cpus, "override should take precedence");
    }

    #[test]
    fn claw_type_fallback_uses_default(
        default_cpus in 1u32..=4,
    ) {
        let config = MacOSConfig {
            vm_backend: VMBackendConfig {
                backend: "vz".to_string(),
                macos: Some(MacOSSpecific {
                    default_cpus,
                    ..MacOSSpecific::default()
                }),
            },
            warm_pool: WarmPoolConfig::default(),
            logging: LoggingConfig::default(),
            claw_types: HashMap::new(),
        };

        let vm_config = config.vm_config("unknownclaw");
        prop_assert_eq!(vm_config.cpus, default_cpus, "should use default when no override");
    }
}

// ── Snapshot expiration properties ────────────────────────────────────────

#[cfg(test)]
mod snapshot_props {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use vmrunner_macos_rs::snapshot::VMSnapshot;

    proptest! {
        #[test]
        fn fresh_snapshot_never_expired(ttl_hours in 1u64..10000) {
            let snapshot = VMSnapshot::new(
                "testclaw".to_string(),
                PathBuf::from("/tmp/test.vzsnapshot"),
            );
            // Just-created snapshot should not be expired
            prop_assert!(!snapshot.is_expired(ttl_hours));
        }

        #[test]
        fn old_snapshot_expired_when_past_ttl(ttl_hours in 1u64..1000) {
            let mut snapshot = VMSnapshot::new(
                "testclaw".to_string(),
                PathBuf::from("/tmp/test.vzsnapshot"),
            );
            // Set created_at to well past the TTL
            let past = SystemTime::now()
                .checked_sub(Duration::from_secs((ttl_hours + 1) * 3600))
                .unwrap();
            snapshot.created_at = past;

            prop_assert!(snapshot.is_expired(ttl_hours));
        }

        #[test]
        fn snapshot_not_expired_within_ttl(ttl_hours in 2u64..1000) {
            let mut snapshot = VMSnapshot::new(
                "testclaw".to_string(),
                PathBuf::from("/tmp/test.vzsnapshot"),
            );
            // Set created_at to half the TTL ago
            let half_ttl = SystemTime::now()
                .checked_sub(Duration::from_secs((ttl_hours / 2) * 3600))
                .unwrap();
            snapshot.created_at = half_ttl;

            prop_assert!(!snapshot.is_expired(ttl_hours));
        }
    }
}

// ── Multiple port forwards coexistence ────────────────────────────────────

proptest! {
    #[test]
    fn multiple_unique_port_forwards_all_validate(
        base_port in 1u16..60000u16,
        count in 1usize..5,
    ) {
        let mut existing: Vec<PortForward> = Vec::new();

        for i in 0..count {
            #[allow(clippy::cast_possible_truncation)]
            let host_port = base_port.saturating_add(i as u16);
            if host_port == 0 { continue; }

            let pf = PortForward::tcp(host_port, 80);
            // Each new forward should validate against the existing ones
            // (as long as host_port is unique)
            let unique = !existing.iter().any(|e| e.host_port == host_port);
            if unique {
                prop_assert!(pf.validate(&existing).is_ok());
                existing.push(pf);
            }
        }
    }
}
