//! Guest network identity and endpoint constants shared by Rust VM backends.
//!
//! This module owns the literals that bind the Linux Firecracker boot/build
//! paths to their guest network identity. Mac and Linux backends still execute
//! separately; they import only the shared values that must not drift.
//!
//! B1 status: Firecracker production boot/build paths use one guest MAC here.
//! If this value changes, rebuild affected Dev goldens and validate Dev boot
//! before any release/pin change.

use std::ops::RangeInclusive;

/// Expected Firecracker kernel filename (without directory).
pub const KERNEL_FILENAME: &str = "vmlinux-6.1.155";

/// Firecracker guest NIC name used by the kernel boot arguments.
pub const FIRECRACKER_GUEST_IFACE: &str = "eth0";

/// TAP device opened by Firecracker inside the private network namespace.
pub const FIRECRACKER_TAP_NAME: &str = "tap1";

/// TAP device owned by slirp4netns inside the private network namespace.
pub const SLIRP_TAP_NAME: &str = "tap0";

/// Host-side address on the Firecracker TAP link.
pub const FIRECRACKER_HOST_TAP_IP: &str = "172.16.0.1";

/// Host-side Firecracker TAP address in CIDR form.
pub const FIRECRACKER_HOST_TAP_CIDR: &str = "172.16.0.1/30";

/// Guest-side address configured by the kernel `ip=` boot argument.
pub const FIRECRACKER_GUEST_TAP_IP: &str = "172.16.0.2";

/// Netmask for the point-to-point Firecracker TAP link.
pub const FIRECRACKER_TAP_NETMASK: &str = "255.255.255.252";

/// MAC address used by Linux Firecracker runtime and golden image build paths.
///
/// This preserves the MAC that the runtime full-boot path already used before
/// B1 reconciliation. Rebuilding affected Dev goldens moves snapshot boot to
/// the same identity.
pub const FIRECRACKER_GUEST_MAC: &str = "06:00:ac:10:00:02";

/// Host address used for slirp host forwards.
pub const SLIRP_HOSTFWD_HOST_ADDR: &str = "127.0.0.1";

/// Guest address used by slirp host forwards.
///
/// This value intentionally preserves the existing slirp API target even
/// though the Firecracker kernel boot path configures a different TAP address.
pub const SLIRP_HOSTFWD_GUEST_ADDR: &str = "10.0.2.100";

/// Lowest host app port used by macOS VZ/executor forwarding.
pub const HOST_APP_PORT_RANGE_START: u16 = 18790;

/// Highest host app port used by macOS VZ/executor forwarding.
pub const HOST_APP_PORT_RANGE_END: u16 = 19999;

/// Lowest host SSH port used by Linux Firecracker slirp forwarding.
pub const SSH_HOST_PORT_RANGE_START: u16 = 22000;

/// Highest host SSH port used by Linux Firecracker slirp forwarding.
pub const SSH_HOST_PORT_RANGE_END: u16 = 23999;

/// Lowest host port used by public claw site forwarding.
pub const PUBLIC_SITE_HOST_PORT_RANGE_START: u16 = 24000;

/// Highest host port used by public claw site forwarding.
pub const PUBLIC_SITE_HOST_PORT_RANGE_END: u16 = 25999;

/// Inclusive host app port range used by macOS VZ/executor forwarding.
#[must_use]
pub fn host_app_port_range() -> RangeInclusive<u16> {
    HOST_APP_PORT_RANGE_START..=HOST_APP_PORT_RANGE_END
}

/// Inclusive host SSH port range used by Linux Firecracker slirp forwarding.
#[must_use]
pub fn ssh_host_port_range() -> RangeInclusive<u16> {
    SSH_HOST_PORT_RANGE_START..=SSH_HOST_PORT_RANGE_END
}

/// Inclusive host port range used by public claw site forwarding.
#[must_use]
pub fn public_site_host_port_range() -> RangeInclusive<u16> {
    PUBLIC_SITE_HOST_PORT_RANGE_START..=PUBLIC_SITE_HOST_PORT_RANGE_END
}

/// Kernel boot arguments for a full Firecracker boot.
#[must_use]
pub fn firecracker_boot_args() -> String {
    let guest_ip = FIRECRACKER_GUEST_TAP_IP;
    let host_ip = FIRECRACKER_HOST_TAP_IP;
    let netmask = FIRECRACKER_TAP_NETMASK;
    let iface = FIRECRACKER_GUEST_IFACE;

    format!(
        "console=ttyS0 reboot=k panic=1 pci=off ip={guest_ip}::{host_ip}:{netmask}::{iface}:off"
    )
}

/// Shell snippet that creates the dual-TAP Firecracker/slirp network namespace.
#[must_use]
pub fn firecracker_dual_tap_setup_script() -> String {
    let firecracker_tap = FIRECRACKER_TAP_NAME;
    let slirp_tap = SLIRP_TAP_NAME;
    let host_cidr = FIRECRACKER_HOST_TAP_CIDR;
    let guest_ip = FIRECRACKER_GUEST_TAP_IP;

    format!(
        r"ip link set lo up
ip tuntap add dev {firecracker_tap} mode tap
ip addr add {host_cidr} dev {firecracker_tap}
ip link set {firecracker_tap} up

(
  i=0; while [ $i -lt 50 ]; do
    if ip link show {slirp_tap} >/dev/null 2>&1; then break; fi
    sleep 0.1; i=$((i+1))
  done
  iptables -t nat -C POSTROUTING -o {slirp_tap} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {slirp_tap} -j MASQUERADE
  iptables -C FORWARD -i {firecracker_tap} -o {slirp_tap} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {firecracker_tap} -o {slirp_tap} -j ACCEPT
  iptables -C FORWARD -i {slirp_tap} -o {firecracker_tap} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {slirp_tap} -o {firecracker_tap} -j ACCEPT
  iptables -C FORWARD -i {slirp_tap} -o {firecracker_tap} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {slirp_tap} -o {firecracker_tap} -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -C PREROUTING -i {slirp_tap} -p tcp -j DNAT --to-destination {guest_ip} 2>/dev/null || iptables -t nat -A PREROUTING -i {slirp_tap} -p tcp -j DNAT --to-destination {guest_ip}
) &",
    )
}

/// JSON command payload for adding a slirp TCP host forward.
#[must_use]
pub fn slirp_add_hostfwd_payload(host_port: u16, guest_port: u16) -> String {
    let host_addr = SLIRP_HOSTFWD_HOST_ADDR;
    let guest_addr = SLIRP_HOSTFWD_GUEST_ADDR;

    format!(
        r#"{{"execute":"add_hostfwd","arguments":{{"proto":"tcp","host_addr":"{host_addr}","host_port":{host_port},"guest_addr":"{guest_addr}","guest_port":{guest_port}}}}}"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_boot_args_preserve_current_identity() {
        assert_eq!(
            firecracker_boot_args(),
            "console=ttyS0 reboot=k panic=1 pci=off ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off"
        );
    }

    #[test]
    fn dual_tap_script_preserves_current_identity() {
        let script = firecracker_dual_tap_setup_script();
        assert!(script.contains("ip addr add 172.16.0.1/30 dev tap1"));
        assert!(script.contains("DNAT --to-destination 172.16.0.2"));
        assert!(script.contains("ip link show tap0"));
    }

    #[test]
    fn slirp_hostfwd_payload_preserves_current_target() {
        let payload = slirp_add_hostfwd_payload(22003, 22);
        assert_eq!(
            payload,
            r#"{"execute":"add_hostfwd","arguments":{"proto":"tcp","host_addr":"127.0.0.1","host_port":22003,"guest_addr":"10.0.2.100","guest_port":22}}"#
        );
    }

    #[test]
    fn port_ranges_preserve_current_bounds() {
        assert_eq!(host_app_port_range(), 18790..=19999);
        assert_eq!(ssh_host_port_range(), 22000..=23999);
        assert_eq!(public_site_host_port_range(), 24000..=25999);
    }
}
