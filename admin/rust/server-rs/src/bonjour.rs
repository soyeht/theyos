//! Bonjour (mDNS/DNS-SD) discovery: browser, publisher, trust classification
//! and the two platform backends.

pub mod browser;
#[cfg(target_os = "macos")]
pub mod impl_dns_sd;
#[cfg(not(target_os = "macos"))]
pub mod impl_mdns_sd;
pub mod publisher;
pub mod trust;
