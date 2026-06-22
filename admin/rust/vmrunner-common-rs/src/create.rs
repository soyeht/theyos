//! Shared vmrunner Create resource contracts.

use serde::{Deserialize, Deserializer, Serialize};

/// Default CPU cores for instance Create requests.
pub const DEFAULT_CREATE_CPU_CORES: u32 = 2;

/// Default RAM in MiB for instance Create requests.
pub const DEFAULT_CREATE_RAM_MB: u32 = 2048;

/// Default disk size in GiB for instance Create requests.
pub const DEFAULT_CREATE_DISK_GB: u32 = 10;

/// Optional resource fields accepted by vmrunner Create IPC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCreateResourceSpec {
    #[serde(default, deserialize_with = "deserialize_optional_u32")]
    pub cpu_cores: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_optional_u32")]
    pub ram_mb: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_optional_u32")]
    pub disk_gb: Option<u32>,
}

impl VmCreateResourceSpec {
    #[must_use]
    pub const fn from_options(
        cpu_cores: Option<u32>,
        ram_mb: Option<u32>,
        disk_gb: Option<u32>,
    ) -> Self {
        Self {
            cpu_cores,
            ram_mb,
            disk_gb,
        }
    }

    #[must_use]
    pub const fn resolve(self) -> ResolvedVmCreateResourceSpec {
        self.resolve_with_cpu_ram(DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_RAM_MB)
    }

    #[must_use]
    pub const fn resolve_with_cpu_ram(
        self,
        default_cpu_cores: u32,
        default_ram_mb: u32,
    ) -> ResolvedVmCreateResourceSpec {
        ResolvedVmCreateResourceSpec {
            cpu_cores: match self.cpu_cores {
                Some(value) => value,
                None => default_cpu_cores,
            },
            ram_mb: match self.ram_mb {
                Some(value) => value,
                None => default_ram_mb,
            },
            disk_gb: match self.disk_gb {
                Some(value) => value,
                None => DEFAULT_CREATE_DISK_GB,
            },
        }
    }
}

/// Create resource fields after applying defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedVmCreateResourceSpec {
    pub cpu_cores: u32,
    pub ram_mb: u32,
    pub disk_gb: u32,
}

fn deserialize_optional_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalU32Visitor;

    impl<'de> serde::de::Visitor<'de> for OptionalU32Visitor {
        type Value = Option<u32>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a u32-compatible integer")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(u32::try_from(value).ok())
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(u32::try_from(value).ok())
        }

        fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            Ok(None)
        }

        fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(OptionalU32Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_current_create_defaults() {
        let resolved = VmCreateResourceSpec::default().resolve();

        assert_eq!(resolved.cpu_cores, 2);
        assert_eq!(resolved.ram_mb, 2048);
        assert_eq!(resolved.disk_gb, 10);
    }

    #[test]
    fn preserves_supplied_resource_fields() {
        let resolved = VmCreateResourceSpec::from_options(Some(4), Some(4096), Some(20)).resolve();

        assert_eq!(resolved.cpu_cores, 4);
        assert_eq!(resolved.ram_mb, 4096);
        assert_eq!(resolved.disk_gb, 20);
    }

    #[test]
    fn resolves_custom_cpu_ram_defaults_for_platform_install_paths() {
        let resolved = VmCreateResourceSpec::default().resolve_with_cpu_ram(4, 4096);

        assert_eq!(resolved.cpu_cores, 4);
        assert_eq!(resolved.ram_mb, 4096);
        assert_eq!(resolved.disk_gb, 10);
    }

    #[test]
    fn deserializes_create_resource_wire_fields() {
        let spec: VmCreateResourceSpec = serde_json::from_value(json!({
            "cpu_cores": 3,
            "ram_mb": 3072,
            "disk_gb": 15
        }))
        .unwrap();

        assert_eq!(
            spec,
            VmCreateResourceSpec::from_options(Some(3), Some(3072), Some(15))
        );
    }

    #[test]
    fn ignores_unrelated_create_fields() {
        let spec: VmCreateResourceSpec = serde_json::from_value(json!({
            "container": "picoclaw-alice",
            "cpu_cores": 3,
            "guest_os": "macos"
        }))
        .unwrap();

        assert_eq!(
            spec,
            VmCreateResourceSpec::from_options(Some(3), None, None)
        );
    }

    #[test]
    fn treats_invalid_resource_values_as_absent() {
        let spec: VmCreateResourceSpec = serde_json::from_value(json!({
            "cpu_cores": "4",
            "ram_mb": 9_999_999_999_u64,
            "disk_gb": null
        }))
        .unwrap();

        assert_eq!(spec, VmCreateResourceSpec::default());
    }
}
