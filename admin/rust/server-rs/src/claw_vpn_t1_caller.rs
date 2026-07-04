//! Default-off T1 caller gate for the per-Claw VPN `IpTunnel` backend.
//!
//! This module is the narrow decision point between the startup preflight and a
//! caller-supplied target-session router. It does not open TUN/utun devices,
//! install routes, dial relays, run runtime wiring, spawn work, or mount the
//! router into `relay_stream`. It only returns a caller after the dev config is
//! present and the owner-auth, rollback, and hardware preflight booleans are
//! all present.

use std::fmt;
use std::sync::Arc;

use crate::claw_vpn_dev_config::{ClawVpnDevConfig, ClawVpnDevConfigError, ClawVpnDevMode};
use crate::claw_vpn_target_session_router::{
    ClawVpnTargetSessionRouter, ClawVpnTargetSessionRouterBuildResult,
    ClawVpnTargetSessionRouterLaunchResult, ClawVpnTargetSessionRouterWiring,
};
use crate::startup_wiring::PerClawVpnT1PreflightEvidence;

pub type ClawVpnT1TargetSessionRouterBuild<I> =
    Box<dyn Fn(&str) -> ClawVpnTargetSessionRouterBuildResult<I> + Send + Sync>;

pub type ClawVpnT1TargetSessionRouterLaunch<I> = Box<
    dyn Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
>;

pub type ClawVpnT1TargetSessionRouter<I> = ClawVpnTargetSessionRouter<
    I,
    ClawVpnT1TargetSessionRouterBuild<I>,
    ClawVpnT1TargetSessionRouterLaunch<I>,
>;

pub type ClawVpnT1TargetSessionRouterFactory<I> =
    Arc<dyn Fn() -> ClawVpnT1TargetSessionRouter<I> + Send + Sync>;

pub type ClawVpnT1TargetSessionRouterParts<I> = (
    ClawVpnT1TargetSessionRouterBuild<I>,
    ClawVpnT1TargetSessionRouterLaunch<I>,
);

#[derive(Debug, PartialEq, Eq)]
pub struct ClawVpnT1CallerReadySeal(());

impl ClawVpnT1CallerReadySeal {
    fn new() -> Self {
        Self(())
    }
}

#[must_use = "consume the ready payload through the reviewed T1 caller gate"]
pub struct ClawVpnT1Ready<C> {
    mode: ClawVpnDevMode,
    caller: C,
    _seal: ClawVpnT1CallerReadySeal,
}

impl<C> ClawVpnT1Ready<C> {
    fn new(mode: ClawVpnDevMode, caller: C) -> Self {
        Self {
            mode,
            caller,
            _seal: ClawVpnT1CallerReadySeal::new(),
        }
    }

    fn into_parts(self) -> (ClawVpnDevMode, C) {
        (self.mode, self.caller)
    }
}

#[must_use = "inspect the T1 caller gate status before using the caller"]
pub enum ClawVpnT1CallerStatus<C> {
    Disabled,
    OwnerAuthorizationRequired { mode: ClawVpnDevMode },
    RollbackRequired { mode: ClawVpnDevMode },
    HardwareEvidenceRequired { mode: ClawVpnDevMode },
    UnsupportedMode { mode: ClawVpnDevMode },
    Ready(ClawVpnT1Ready<C>),
    InvalidConfig,
}

impl<C> fmt::Debug for ClawVpnT1CallerStatus<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("ClawVpnT1CallerStatus::Disabled"),
            Self::OwnerAuthorizationRequired { mode } => f
                .debug_struct("ClawVpnT1CallerStatus::OwnerAuthorizationRequired")
                .field("mode", mode)
                .finish(),
            Self::RollbackRequired { mode } => f
                .debug_struct("ClawVpnT1CallerStatus::RollbackRequired")
                .field("mode", mode)
                .finish(),
            Self::HardwareEvidenceRequired { mode } => f
                .debug_struct("ClawVpnT1CallerStatus::HardwareEvidenceRequired")
                .field("mode", mode)
                .finish(),
            Self::UnsupportedMode { mode } => f
                .debug_struct("ClawVpnT1CallerStatus::UnsupportedMode")
                .field("mode", mode)
                .finish(),
            Self::Ready(ready) => f
                .debug_struct("ClawVpnT1CallerStatus::Ready")
                .field("mode", &ready.mode)
                .field("caller", &"<redacted>")
                .finish(),
            Self::InvalidConfig => f.write_str("ClawVpnT1CallerStatus::InvalidConfig"),
        }
    }
}

impl<C> ClawVpnT1CallerStatus<C> {
    #[must_use]
    pub fn mode(&self) -> Option<ClawVpnDevMode> {
        match self {
            Self::Disabled | Self::InvalidConfig => None,
            Self::OwnerAuthorizationRequired { mode }
            | Self::RollbackRequired { mode }
            | Self::HardwareEvidenceRequired { mode }
            | Self::UnsupportedMode { mode } => Some(*mode),
            Self::Ready(ready) => Some(ready.mode),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    #[must_use]
    pub fn into_ready(self) -> Option<(ClawVpnDevMode, C)> {
        match self {
            Self::Ready(ready) => Some(ready.into_parts()),
            _ => None,
        }
    }

    fn ready(mode: ClawVpnDevMode, caller: C) -> Self {
        Self::Ready(ClawVpnT1Ready::new(mode, caller))
    }
}

#[must_use = "inspect the T1 caller gate status before using the caller"]
pub fn assemble_claw_vpn_t1_caller<LoadConfig, LoadPreflight, BuildCaller, C>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_caller: BuildCaller,
) -> ClawVpnT1CallerStatus<C>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildCaller: FnOnce(&ClawVpnDevConfig) -> C,
{
    let config = match load_config() {
        Ok(Some(config)) => config,
        Ok(None) => return ClawVpnT1CallerStatus::Disabled,
        Err(_) => return ClawVpnT1CallerStatus::InvalidConfig,
    };
    let mode = config.mode();
    let preflight = load_preflight();
    if !preflight.has_owner_authorization() {
        return ClawVpnT1CallerStatus::OwnerAuthorizationRequired { mode };
    }
    if !preflight.has_rollback() {
        return ClawVpnT1CallerStatus::RollbackRequired { mode };
    }
    if !preflight.has_hardware_t1_t4() {
        return ClawVpnT1CallerStatus::HardwareEvidenceRequired { mode };
    }
    match mode {
        ClawVpnDevMode::Live => {}
        ClawVpnDevMode::Dial => {
            return ClawVpnT1CallerStatus::UnsupportedMode { mode };
        }
    }

    ClawVpnT1CallerStatus::ready(mode, build_caller(&config))
}

#[must_use = "inspect the T1 caller gate status before using the router"]
pub fn assemble_claw_vpn_t1_target_session_router<
    I,
    LoadConfig,
    LoadPreflight,
    BuildRouterParts,
    BuildRuntime,
    LaunchRuntime,
>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_router_parts: BuildRouterParts,
) -> ClawVpnT1CallerStatus<ClawVpnTargetSessionRouter<I, BuildRuntime, LaunchRuntime>>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildRouterParts: FnOnce(&ClawVpnDevConfig) -> (BuildRuntime, LaunchRuntime),
    BuildRuntime: Fn(&str) -> ClawVpnTargetSessionRouterBuildResult<I>,
    LaunchRuntime:
        Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult,
{
    assemble_claw_vpn_t1_caller(load_config, load_preflight, |config| {
        let (build_runtime, launch_runtime) = build_router_parts(config);
        ClawVpnTargetSessionRouter::new(build_runtime, launch_runtime)
    })
}

#[must_use = "inspect the T1 caller gate status before using the router factory"]
pub fn assemble_claw_vpn_t1_target_session_router_factory<
    I,
    LoadConfig,
    LoadPreflight,
    BuildRouterParts,
>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_router_parts: BuildRouterParts,
) -> ClawVpnT1CallerStatus<ClawVpnT1TargetSessionRouterFactory<I>>
where
    I: 'static,
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildRouterParts: FnOnce(&ClawVpnDevConfig) -> ClawVpnT1TargetSessionRouterParts<I>,
{
    assemble_claw_vpn_t1_caller(load_config, load_preflight, move |config| {
        let (build_runtime, launch_runtime) = build_router_parts(config);
        let build_runtime = Arc::new(build_runtime);
        let launch_runtime = Arc::new(launch_runtime);
        let factory: ClawVpnT1TargetSessionRouterFactory<I> = Arc::new(move || {
            let build_runtime = Arc::clone(&build_runtime);
            let launch_runtime = Arc::clone(&launch_runtime);
            let build_runtime: ClawVpnT1TargetSessionRouterBuild<I> = Box::new(move |target_id| {
                let build_runtime = Arc::clone(&build_runtime);
                build_runtime(target_id)
            });
            let launch_runtime: ClawVpnT1TargetSessionRouterLaunch<I> = Box::new(move |wiring| {
                let launch_runtime = Arc::clone(&launch_runtime);
                launch_runtime(wiring)
            });
            ClawVpnTargetSessionRouter::new(build_runtime, launch_runtime)
        });
        factory
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeInterface;

    fn live_config() -> ClawVpnDevConfig {
        ClawVpnDevConfig::from_values(
            Some("1"),
            None,
            Some("relay-stream://127.0.0.1:49152"),
            Some("198.18.0.0/24"),
            None,
            None,
        )
        .unwrap()
        .unwrap()
    }

    fn dial_config() -> ClawVpnDevConfig {
        ClawVpnDevConfig::from_values(
            None,
            Some("1"),
            Some("relay-stream://127.0.0.1:49152"),
            Some("198.18.0.0/24"),
            None,
            None,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn t1_caller_default_off_loads_no_preflight_and_builds_no_caller() {
        let preflight_loaded = Cell::new(false);
        let caller_built = Cell::new(false);

        let status = assemble_claw_vpn_t1_caller(
            || Ok(None),
            || {
                preflight_loaded.set(true);
                PerClawVpnT1PreflightEvidence::new(true, true, true)
            },
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );

        assert!(matches!(status, ClawVpnT1CallerStatus::Disabled));
        assert!(!preflight_loaded.get());
        assert!(!caller_built.get());
    }

    #[test]
    fn t1_caller_invalid_config_loads_no_preflight_and_builds_no_caller() {
        let preflight_loaded = Cell::new(false);
        let caller_built = Cell::new(false);

        let status = assemble_claw_vpn_t1_caller(
            || Err(ClawVpnDevConfigError::ConflictingModes),
            || {
                preflight_loaded.set(true);
                PerClawVpnT1PreflightEvidence::new(true, true, true)
            },
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );

        assert!(matches!(status, ClawVpnT1CallerStatus::InvalidConfig));
        assert!(!preflight_loaded.get());
        assert!(!caller_built.get());
    }

    #[test]
    fn t1_caller_blocks_in_preflight_order_before_building_caller() {
        let caller_built = Cell::new(false);
        let config = || Ok(Some(live_config()));

        let status = assemble_claw_vpn_t1_caller(
            config,
            || PerClawVpnT1PreflightEvidence::missing(),
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );
        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::OwnerAuthorizationRequired {
                mode: ClawVpnDevMode::Live
            }
        ));

        let status = assemble_claw_vpn_t1_caller(
            config,
            || PerClawVpnT1PreflightEvidence::new(true, false, true),
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );
        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::RollbackRequired {
                mode: ClawVpnDevMode::Live
            }
        ));

        let status = assemble_claw_vpn_t1_caller(
            config,
            || PerClawVpnT1PreflightEvidence::new(true, true, false),
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );
        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::HardwareEvidenceRequired {
                mode: ClawVpnDevMode::Live
            }
        ));
        assert!(!caller_built.get());
    }

    #[test]
    fn t1_caller_builds_caller_only_after_preflight_is_present() {
        let caller_built = Cell::new(false);

        let status = assemble_claw_vpn_t1_caller(
            || Ok(Some(live_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            |config| {
                caller_built.set(true);
                assert_eq!(config.mode(), ClawVpnDevMode::Live);
                "SECRET-CALLER"
            },
        );

        assert!(caller_built.get());
        assert!(status.is_ready());
        assert_eq!(status.mode(), Some(ClawVpnDevMode::Live));
        let debug = format!("{status:?}");
        assert!(debug.contains("ClawVpnT1CallerStatus::Ready"));
        assert!(!debug.contains("SECRET-CALLER"));

        let ready = status.into_ready();
        assert_eq!(ready, Some((ClawVpnDevMode::Live, "SECRET-CALLER")));
    }

    #[test]
    fn t1_caller_rejects_dial_mode_without_building_caller() {
        let caller_built = Cell::new(false);

        let status = assemble_claw_vpn_t1_caller(
            || Ok(Some(dial_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            |_config| {
                caller_built.set(true);
                "caller"
            },
        );

        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::UnsupportedMode {
                mode: ClawVpnDevMode::Dial
            }
        ));
        assert!(!caller_built.get());
    }

    #[test]
    fn t1_target_session_router_is_constructed_only_after_preflight_is_present() {
        let parts_built = Cell::new(false);
        let build_runtime_called = Cell::new(false);
        let launch_runtime_called = Cell::new(false);

        let status = assemble_claw_vpn_t1_target_session_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(live_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            |config| {
                parts_built.set(true);
                assert_eq!(config.mode(), ClawVpnDevMode::Live);
                (
                    |_target_id| {
                        build_runtime_called.set(true);
                        Ok(None)
                    },
                    |_wiring| {
                        launch_runtime_called.set(true);
                        Ok(())
                    },
                )
            },
        );

        assert!(status.is_ready());
        assert!(parts_built.get());
        assert!(!build_runtime_called.get());
        assert!(!launch_runtime_called.get());
    }

    #[test]
    fn t1_target_session_router_rejects_dial_mode_without_building_router() {
        let parts_built = Cell::new(false);
        let build_runtime_called = Cell::new(false);
        let launch_runtime_called = Cell::new(false);

        let status = assemble_claw_vpn_t1_target_session_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(dial_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            |_config| {
                parts_built.set(true);
                (
                    |_target_id| {
                        build_runtime_called.set(true);
                        Ok(None)
                    },
                    |_wiring| {
                        launch_runtime_called.set(true);
                        Ok(())
                    },
                )
            },
        );

        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::UnsupportedMode {
                mode: ClawVpnDevMode::Dial
            }
        ));
        assert!(!parts_built.get());
        assert!(!build_runtime_called.get());
        assert!(!launch_runtime_called.get());
    }

    #[test]
    fn t1_target_session_router_preflight_blockers_do_not_build_router_parts() {
        let parts_built = Cell::new(0);
        let build_runtime_called = Cell::new(false);
        let launch_runtime_called = Cell::new(false);

        macro_rules! assert_blocked {
            ($preflight:expr, $pattern:pat) => {{
                let status =
                    assemble_claw_vpn_t1_target_session_router::<FakeInterface, _, _, _, _, _>(
                        || Ok(Some(live_config())),
                        || $preflight,
                        |_config| {
                            parts_built.set(parts_built.get() + 1);
                            (
                                |_target_id| {
                                    build_runtime_called.set(true);
                                    Ok(None)
                                },
                                |_wiring| {
                                    launch_runtime_called.set(true);
                                    Ok(())
                                },
                            )
                        },
                    );
                assert!(matches!(status, $pattern));
            }};
        }

        assert_blocked!(
            PerClawVpnT1PreflightEvidence::missing(),
            ClawVpnT1CallerStatus::OwnerAuthorizationRequired {
                mode: ClawVpnDevMode::Live
            }
        );
        assert_blocked!(
            PerClawVpnT1PreflightEvidence::new(true, false, true),
            ClawVpnT1CallerStatus::RollbackRequired {
                mode: ClawVpnDevMode::Live
            }
        );
        assert_blocked!(
            PerClawVpnT1PreflightEvidence::new(true, true, false),
            ClawVpnT1CallerStatus::HardwareEvidenceRequired {
                mode: ClawVpnDevMode::Live
            }
        );

        assert_eq!(parts_built.get(), 0);
        assert!(!build_runtime_called.get());
        assert!(!launch_runtime_called.get());
    }

    #[test]
    fn t1_target_session_router_factory_is_created_only_after_preflight_is_present() {
        let build_runtime_called = Arc::new(AtomicUsize::new(0));
        let launch_runtime_called = Arc::new(AtomicUsize::new(0));
        let parts_built = Arc::new(AtomicUsize::new(0));

        let status = assemble_claw_vpn_t1_target_session_router_factory::<FakeInterface, _, _, _>(
            || Ok(Some(live_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            {
                let parts_built = Arc::clone(&parts_built);
                let build_runtime_called = Arc::clone(&build_runtime_called);
                let launch_runtime_called = Arc::clone(&launch_runtime_called);
                move |config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(config.mode(), ClawVpnDevMode::Live);
                    let build_runtime: ClawVpnT1TargetSessionRouterBuild<FakeInterface> =
                        Box::new(move |_target_id| {
                            build_runtime_called.fetch_add(1, Ordering::SeqCst);
                            Ok(None)
                        });
                    let launch_runtime: ClawVpnT1TargetSessionRouterLaunch<FakeInterface> =
                        Box::new(move |_wiring| {
                            launch_runtime_called.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        });
                    (build_runtime, launch_runtime)
                }
            },
        );

        assert!(status.is_ready());
        assert_eq!(parts_built.load(Ordering::SeqCst), 1);
        assert_eq!(build_runtime_called.load(Ordering::SeqCst), 0);
        assert_eq!(launch_runtime_called.load(Ordering::SeqCst), 0);

        let (mode, router_factory) = status.into_ready().unwrap();
        assert_eq!(mode, ClawVpnDevMode::Live);
        let _router = router_factory();
        assert_eq!(parts_built.load(Ordering::SeqCst), 1);
        assert_eq!(build_runtime_called.load(Ordering::SeqCst), 0);
        assert_eq!(launch_runtime_called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn t1_target_session_router_factory_rejects_dial_mode_without_building_factory() {
        let build_runtime_called = Arc::new(AtomicUsize::new(0));
        let launch_runtime_called = Arc::new(AtomicUsize::new(0));
        let parts_built = Arc::new(AtomicUsize::new(0));

        let status = assemble_claw_vpn_t1_target_session_router_factory::<FakeInterface, _, _, _>(
            || Ok(Some(dial_config())),
            || PerClawVpnT1PreflightEvidence::new(true, true, true),
            {
                let parts_built = Arc::clone(&parts_built);
                let build_runtime_called = Arc::clone(&build_runtime_called);
                let launch_runtime_called = Arc::clone(&launch_runtime_called);
                move |_config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    let build_runtime: ClawVpnT1TargetSessionRouterBuild<FakeInterface> =
                        Box::new(move |_target_id| {
                            build_runtime_called.fetch_add(1, Ordering::SeqCst);
                            Ok(None)
                        });
                    let launch_runtime: ClawVpnT1TargetSessionRouterLaunch<FakeInterface> =
                        Box::new(move |_wiring| {
                            launch_runtime_called.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        });
                    (build_runtime, launch_runtime)
                }
            },
        );

        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::UnsupportedMode {
                mode: ClawVpnDevMode::Dial
            }
        ));
        assert_eq!(parts_built.load(Ordering::SeqCst), 0);
        assert_eq!(build_runtime_called.load(Ordering::SeqCst), 0);
        assert_eq!(launch_runtime_called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn t1_target_session_router_factory_preflight_blockers_do_not_build_parts() {
        let build_runtime_called = Arc::new(AtomicUsize::new(0));
        let launch_runtime_called = Arc::new(AtomicUsize::new(0));
        let parts_built = Arc::new(AtomicUsize::new(0));

        macro_rules! assert_blocked {
            ($preflight:expr, $pattern:pat) => {{
                let status = assemble_claw_vpn_t1_target_session_router_factory::<
                    FakeInterface,
                    _,
                    _,
                    _,
                >(|| Ok(Some(live_config())), || $preflight, {
                    let parts_built = Arc::clone(&parts_built);
                    let build_runtime_called = Arc::clone(&build_runtime_called);
                    let launch_runtime_called = Arc::clone(&launch_runtime_called);
                    move |_config| {
                        parts_built.fetch_add(1, Ordering::SeqCst);
                        let build_runtime: ClawVpnT1TargetSessionRouterBuild<FakeInterface> =
                            Box::new(move |_target_id| {
                                build_runtime_called.fetch_add(1, Ordering::SeqCst);
                                Ok(None)
                            });
                        let launch_runtime: ClawVpnT1TargetSessionRouterLaunch<FakeInterface> =
                            Box::new(move |_wiring| {
                                launch_runtime_called.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            });
                        (build_runtime, launch_runtime)
                    }
                });
                assert!(matches!(status, $pattern));
            }};
        }

        assert_blocked!(
            PerClawVpnT1PreflightEvidence::missing(),
            ClawVpnT1CallerStatus::OwnerAuthorizationRequired {
                mode: ClawVpnDevMode::Live
            }
        );
        assert_blocked!(
            PerClawVpnT1PreflightEvidence::new(true, false, true),
            ClawVpnT1CallerStatus::RollbackRequired {
                mode: ClawVpnDevMode::Live
            }
        );
        assert_blocked!(
            PerClawVpnT1PreflightEvidence::new(true, true, false),
            ClawVpnT1CallerStatus::HardwareEvidenceRequired {
                mode: ClawVpnDevMode::Live
            }
        );

        assert_eq!(parts_built.load(Ordering::SeqCst), 0);
        assert_eq!(build_runtime_called.load(Ordering::SeqCst), 0);
        assert_eq!(launch_runtime_called.load(Ordering::SeqCst), 0);
    }
}
