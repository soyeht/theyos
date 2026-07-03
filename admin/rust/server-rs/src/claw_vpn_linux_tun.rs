//! Linux-only TUN open primitive for the Product A per-Claw VPN dev proof.
//!
//! This module is intentionally not wired into bootstrap, bins, relay runtime,
//! route installation, storage, or flags. It only owns the narrow `/dev/net/tun`
//! FFI boundary needed by a future explicitly-gated tunnel-agent slice.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;

const LINUX_TUN_DEVICE: &str = "/dev/net/tun";
const LINUX_IFNAMSIZ: usize = 16;
const LINUX_TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const LINUX_IFF_TUN: libc::c_short = 0x0001;
const LINUX_IFF_NO_PI: libc::c_short = 0x1000;
const LINUX_IFF_TUN_EXCL: libc::c_short = i16::MIN;
const LINUX_TUN_FLAGS: libc::c_short = LINUX_IFF_TUN | LINUX_IFF_NO_PI | LINUX_IFF_TUN_EXCL;

pub const CLAW_VPN_LINUX_TUN_MAX_NAME_LEN: usize = LINUX_IFNAMSIZ - 1;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnLinuxTunName {
    value: String,
}

impl fmt::Debug for ClawVpnLinuxTunName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClawVpnLinuxTunName")
            .field(&"<redacted>")
            .finish()
    }
}

impl ClawVpnLinuxTunName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ClawVpnLinuxTunNameError> {
        let value = value.as_ref();
        validate_tun_name(value)?;
        Ok(Self {
            value: value.to_string(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    fn from_kernel_ifreq_name(name: &[libc::c_char; LINUX_IFNAMSIZ]) -> Result<Self, io::Error> {
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(LINUX_IFNAMSIZ);
        let bytes = name[..end]
            .iter()
            .map(|byte| {
                u8::try_from(*byte)
                    .map_err(|_| io::Error::other("kernel returned a non-ascii tun interface name"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::other("kernel returned a non-utf8 tun interface name"))?;
        Self::new(value)
            .map_err(|_| io::Error::other("kernel returned an invalid tun interface name"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClawVpnLinuxTunNameError {
    Empty,
    TooLong { max: usize },
    InvalidCharacter { index: usize },
}

impl fmt::Display for ClawVpnLinuxTunNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("tun interface name is required"),
            Self::TooLong { max } => {
                write!(f, "tun interface name must be at most {max} bytes")
            }
            Self::InvalidCharacter { index } => {
                write!(
                    f,
                    "tun interface name has an invalid character at byte {index}"
                )
            }
        }
    }
}

impl std::error::Error for ClawVpnLinuxTunNameError {}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnLinuxTunConfig {
    name: ClawVpnLinuxTunName,
}

impl fmt::Debug for ClawVpnLinuxTunConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnLinuxTunConfig")
            .field("name", &"<redacted>")
            .finish()
    }
}

impl ClawVpnLinuxTunConfig {
    #[must_use]
    pub fn new(name: ClawVpnLinuxTunName) -> Self {
        Self { name }
    }

    #[must_use]
    pub fn name(&self) -> &ClawVpnLinuxTunName {
        &self.name
    }
}

pub struct ClawVpnLinuxTunDevice {
    file: File,
    name: ClawVpnLinuxTunName,
}

impl fmt::Debug for ClawVpnLinuxTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnLinuxTunDevice")
            .field("name", &"<redacted>")
            .field("fd", &"<redacted>")
            .finish()
    }
}

impl ClawVpnLinuxTunDevice {
    /// Open a Linux TUN device with `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`.
    ///
    /// This creates only the interface file descriptor. It does not assign an
    /// address, install routes, spawn a pump, dial a relay, or persist state.
    /// `IFF_TUN_EXCL` makes the primitive create-only: if the name already
    /// exists, Linux must reject instead of attaching to an existing device.
    pub fn open(config: &ClawVpnLinuxTunConfig) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(LINUX_TUN_DEVICE)?;
        let mut ifreq = build_tunsetiff_ifreq(config.name());
        apply_tunsetiff(file.as_raw_fd(), &mut ifreq)?;
        let assigned_name = ClawVpnLinuxTunName::from_kernel_ifreq_name(&ifreq.ifr_name)?;
        Ok(Self {
            file,
            name: assigned_name,
        })
    }

    #[must_use]
    pub fn name(&self) -> &ClawVpnLinuxTunName {
        &self.name
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.file.write_all(packet)
    }
}

impl ClawVpnPacketInterface for ClawVpnLinuxTunDevice {
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.file.write_all(packet)
    }
}

#[repr(C)]
struct LinuxIfReq {
    ifr_name: [libc::c_char; LINUX_IFNAMSIZ],
    ifr_ifru: LinuxIfReqIfru,
}

#[repr(C)]
union LinuxIfReqIfru {
    ifru_flags: libc::c_short,
    _ifru_align: [u64; 3],
    _ifru_bytes: [u8; 24],
}

fn build_tunsetiff_ifreq(name: &ClawVpnLinuxTunName) -> LinuxIfReq {
    let mut ifreq = zeroed_ifreq();
    for (index, byte) in name.as_str().as_bytes().iter().enumerate() {
        ifreq.ifr_name[index] =
            libc::c_char::try_from(*byte).expect("validated tun names are ascii");
    }
    ifreq.ifr_ifru.ifru_flags = LINUX_TUN_FLAGS;
    ifreq
}

#[allow(unsafe_code)]
fn zeroed_ifreq() -> LinuxIfReq {
    // SAFETY: zero is a valid byte pattern for `LinuxIfReq`: the name buffer is
    // NUL-filled and the union arms are integer arrays. The builder sets the
    // active `ifru_flags` field before the value crosses the FFI boundary.
    unsafe { MaybeUninit::<LinuxIfReq>::zeroed().assume_init() }
}

#[allow(unsafe_code)]
fn apply_tunsetiff(fd: std::os::fd::RawFd, ifreq: &mut LinuxIfReq) -> io::Result<()> {
    // SAFETY: `fd` is an open `/dev/net/tun` file descriptor owned by `file`;
    // `ifreq` is a stack-allocated `repr(C)` buffer matching the Linux x86_64
    // `struct ifreq` layout used by `TUNSETIFF`, and remains valid for the
    // duration of the syscall.
    let rc = unsafe { libc::ioctl(fd, LINUX_TUNSETIFF, ifreq) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)]
fn ifreq_flags(ifreq: &LinuxIfReq) -> libc::c_short {
    // SAFETY: `build_tunsetiff_ifreq` initializes the active union field as
    // `ifru_flags`, and tests call this helper only on values from that builder.
    unsafe { ifreq.ifr_ifru.ifru_flags }
}

#[cfg(test)]
#[allow(unsafe_code)]
fn ifreq_ifru_bytes(ifreq: &LinuxIfReq) -> [u8; 24] {
    // SAFETY: byte inspection of an initialized union value is valid for tests.
    unsafe { ifreq.ifr_ifru._ifru_bytes }
}

fn validate_tun_name(value: &str) -> Result<(), ClawVpnLinuxTunNameError> {
    if value.is_empty() {
        return Err(ClawVpnLinuxTunNameError::Empty);
    }
    if matches!(value, "." | "..") {
        return Err(ClawVpnLinuxTunNameError::InvalidCharacter { index: 0 });
    }
    if value.len() > CLAW_VPN_LINUX_TUN_MAX_NAME_LEN {
        return Err(ClawVpnLinuxTunNameError::TooLong {
            max: CLAW_VPN_LINUX_TUN_MAX_NAME_LEN,
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        let valid = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
        if !valid {
            return Err(ClawVpnLinuxTunNameError::InvalidCharacter { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun_name(value: &str) -> ClawVpnLinuxTunName {
        ClawVpnLinuxTunName::new(value).expect("test tun name is valid")
    }

    #[test]
    fn linux_tun_name_accepts_neutral_interface_names() {
        for name in ["clawvpn0", "claw-vpn.1", "claw_vpn_2", "a12345678901234"] {
            let parsed = ClawVpnLinuxTunName::new(name).expect("neutral tun name accepted");
            assert_eq!(parsed.as_str(), name);
        }
    }

    #[test]
    fn linux_tun_name_rejects_empty_too_long_and_unsafe_characters() {
        assert_eq!(
            ClawVpnLinuxTunName::new("").unwrap_err(),
            ClawVpnLinuxTunNameError::Empty
        );
        assert_eq!(
            ClawVpnLinuxTunName::new("a123456789012345").unwrap_err(),
            ClawVpnLinuxTunNameError::TooLong {
                max: CLAW_VPN_LINUX_TUN_MAX_NAME_LEN
            }
        );
        for name in ["claw vpn", "claw/vpn", "claw:vpn", "claw\u{0}vpn", "clawé"] {
            assert!(matches!(
                ClawVpnLinuxTunName::new(name),
                Err(ClawVpnLinuxTunNameError::InvalidCharacter { .. })
            ));
        }
        assert_eq!(
            ClawVpnLinuxTunName::new(".").unwrap_err(),
            ClawVpnLinuxTunNameError::InvalidCharacter { index: 0 }
        );
        assert_eq!(
            ClawVpnLinuxTunName::new("..").unwrap_err(),
            ClawVpnLinuxTunNameError::InvalidCharacter { index: 0 }
        );
    }

    #[test]
    fn linux_tun_ifreq_uses_tun_no_pi_and_nul_terminated_name() {
        let ifreq = build_tunsetiff_ifreq(&tun_name("clawvpn0"));
        assert_eq!(std::mem::size_of::<LinuxIfReq>(), 40);
        assert_eq!(std::mem::align_of::<LinuxIfReq>(), 8);
        assert_eq!(std::mem::size_of::<LinuxIfReqIfru>(), 24);
        assert_eq!(ifreq_flags(&ifreq), LINUX_TUN_FLAGS);
        assert_eq!(u16::from_ne_bytes(LINUX_TUN_FLAGS.to_ne_bytes()), 0x9001);
        let ifru_bytes = ifreq_ifru_bytes(&ifreq);
        assert_eq!(
            &ifru_bytes[..std::mem::size_of::<libc::c_short>()],
            LINUX_TUN_FLAGS.to_ne_bytes()
        );
        assert!(
            ifru_bytes[std::mem::size_of::<libc::c_short>()..]
                .iter()
                .all(|byte| *byte == 0)
        );

        let name_bytes = ifreq
            .ifr_name
            .iter()
            .map(|byte| u8::try_from(*byte).expect("ifreq name uses ascii bytes"))
            .collect::<Vec<_>>();
        assert_eq!(&name_bytes[..8], b"clawvpn0");
        assert!(name_bytes[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn linux_tun_debug_redacts_name_and_file_descriptor() {
        let name = tun_name("clawvpn0");
        let config = ClawVpnLinuxTunConfig::new(name.clone());
        let device = ClawVpnLinuxTunDevice {
            file: File::open("/dev/null").expect("test can open /dev/null"),
            name: name.clone(),
        };
        let debug_name = format!("{name:?}");
        let debug_config = format!("{config:?}");
        let debug_device = format!("{device:?}");

        assert!(debug_name.contains("<redacted>"));
        assert!(debug_config.contains("<redacted>"));
        assert!(debug_device.contains("<redacted>"));
        assert!(!debug_name.contains("clawvpn0"));
        assert!(!debug_config.contains("clawvpn0"));
        assert!(!debug_device.contains("clawvpn0"));
    }

    #[test]
    fn linux_tun_device_implements_packet_interface_without_exposing_fd_or_name() {
        fn assert_packet_interface<T: ClawVpnPacketInterface>() {}
        assert_packet_interface::<ClawVpnLinuxTunDevice>();

        let name = tun_name("clawvpn0");
        let mut device = ClawVpnLinuxTunDevice {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .expect("test can open /dev/null"),
            name,
        };
        let mut buf = [0u8; 8];
        let read_len = ClawVpnPacketInterface::read_packet(&mut device, &mut buf)
            .expect("/dev/null read succeeds");
        assert_eq!(read_len, 0);
        ClawVpnPacketInterface::write_packet(&mut device, &[0x45, 0, 0, 20])
            .expect("/dev/null write succeeds");

        let debug = format!("{device:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains(&device.file.as_raw_fd().to_string()));
    }
}
