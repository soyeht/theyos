//! Warm-pool status contracts and compatibility parsers.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

/// Canonical warm-pool slot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmPoolSlotState {
    #[default]
    Empty,
    Filling,
    Warm,
    Stale,
    Expired,
}

impl WarmPoolSlotState {
    #[must_use]
    pub fn from_wire_str(value: &str) -> Self {
        match value {
            "Ready" | "ready" | "warm" | "Warm" => Self::Warm,
            "Filling" | "filling" => Self::Filling,
            "Stale" | "stale" => Self::Stale,
            "Expired" | "expired" => Self::Expired,
            "Empty" | "empty" => Self::Empty,
            _ => Self::Empty,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Filling => "filling",
            Self::Warm => "warm",
            Self::Stale => "stale",
            Self::Expired => "expired",
        }
    }
}

impl<'de> Deserialize<'de> for WarmPoolSlotState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_wire_str(&value))
    }
}

/// Status for one warm-pool slot in the normalized slots-array form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmPoolSlotStatus {
    pub claw_type: String,
    #[serde(default)]
    pub state: WarmPoolSlotState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WarmPoolSlotStatusWire {
    #[serde(default)]
    claw_type: Option<String>,
    #[serde(default)]
    state: WarmPoolSlotState,
    #[serde(default)]
    snapshot_path: Option<String>,
}

/// Normalized warm-pool status response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct WarmPoolStatus {
    #[serde(default)]
    pub slots: Vec<WarmPoolSlotStatus>,
}

impl<'de> Deserialize<'de> for WarmPoolStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            #[serde(default)]
            slots: Vec<WarmPoolSlotStatusWire>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let slots = fields
            .slots
            .into_iter()
            .filter_map(|slot| {
                slot.claw_type.map(|claw_type| WarmPoolSlotStatus {
                    claw_type,
                    state: slot.state,
                    snapshot_path: slot.snapshot_path,
                })
            })
            .collect();
        Ok(Self { slots })
    }
}

/// Compatibility wrapper for current Linux and macOS warm-pool status shapes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum WarmPoolStatusWire {
    /// Linux-style shape: `{ "picoclaw": "warm", "zeroclaw": "filling" }`.
    Map(BTreeMap<String, WarmPoolSlotState>),
    /// macOS-style shape: `{ "slots": [{ "claw_type": "...", "state": "Ready" }] }`.
    Slots(WarmPoolStatus),
}

impl WarmPoolStatusWire {
    #[must_use]
    pub fn into_slot_states(self) -> BTreeMap<String, WarmPoolSlotState> {
        match self {
            Self::Slots(status) => status
                .slots
                .into_iter()
                .map(|slot| (slot.claw_type, slot.state))
                .collect(),
            Self::Map(map) => map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_current_linux_map_shape() {
        let wire: WarmPoolStatusWire = serde_json::from_value(json!({
            "picoclaw": "warm",
            "zeroclaw": "filling",
            "nanobot": "stale",
            "openclaw": "unknown-future-state"
        }))
        .unwrap();

        let slots = wire.into_slot_states();
        assert_eq!(slots["picoclaw"], WarmPoolSlotState::Warm);
        assert_eq!(slots["zeroclaw"], WarmPoolSlotState::Filling);
        assert_eq!(slots["nanobot"], WarmPoolSlotState::Stale);
        assert_eq!(slots["openclaw"], WarmPoolSlotState::Empty);
    }

    #[test]
    fn parses_current_macos_slots_shape() {
        let wire: WarmPoolStatusWire = serde_json::from_value(json!({
            "slots": [
                {
                    "claw_type": "picoclaw",
                    "state": "Ready",
                    "snapshot_path": "/tmp/picoclaw.vzsnapshot"
                },
                {
                    "claw_type": "zeroclaw",
                    "state": "Filling",
                    "snapshot_path": null
                },
                {
                    "claw_type": "nanobot",
                    "state": "Expired"
                }
            ],
            "filling": ["zeroclaw"]
        }))
        .unwrap();

        let slots = wire.into_slot_states();
        assert_eq!(slots["picoclaw"], WarmPoolSlotState::Warm);
        assert_eq!(slots["zeroclaw"], WarmPoolSlotState::Filling);
        assert_eq!(slots["nanobot"], WarmPoolSlotState::Expired);
    }

    #[test]
    fn skips_malformed_macos_slots_without_claw_type() {
        let wire: WarmPoolStatusWire = serde_json::from_value(json!({
            "slots": [
                {
                    "state": "Ready",
                    "snapshot_path": "/tmp/missing-claw-type.vzsnapshot"
                },
                {
                    "claw_type": "picoclaw",
                    "state": "Ready"
                }
            ]
        }))
        .unwrap();

        let slots = wire.into_slot_states();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots["picoclaw"], WarmPoolSlotState::Warm);
    }

    #[test]
    fn serializes_normalized_slots_shape() {
        let status = WarmPoolStatus {
            slots: vec![WarmPoolSlotStatus {
                claw_type: "picoclaw".to_string(),
                state: WarmPoolSlotState::Warm,
                snapshot_path: None,
            }],
        };

        assert_eq!(
            serde_json::to_value(status).unwrap(),
            json!({
                "slots": [
                    {
                        "claw_type": "picoclaw",
                        "state": "warm"
                    }
                ]
            })
        );
    }
}
