//! macOS-only utun open primitive for the Product A per-Claw VPN dev proof.
//!
//! This module is intentionally not wired into bootstrap, bins, relay runtime,
//! route installation, storage, or flags. It only owns the narrow kernel-control
//! socket boundary needed by a future explicitly-gated tunnel-agent slice.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
use crate::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;

const MACOS_UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const MACOS_UTUN_MAX_NAME_LEN: usize = libc::IFNAMSIZ - 1;
const MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN: usize = 4;
const MACOS_UTUN_MAX_IPV4_PACKET_LEN: usize = u16::MAX as usize;
/// Bounded run of non-IPv4 utun frames (macOS emits IPv6/NDP on the interface)
/// to skip within one non-blocking read before yielding — never fatal, never a
/// forwarded packet.
const MACOS_UTUN_NONBLOCKING_SKIP_LIMIT: usize = 16;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnMacosUtunName {
    value: String,
}

impl fmt::Debug for ClawVpnMacosUtunName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClawVpnMacosUtunName")
            .field(&"<redacted>")
            .finish()
    }
}

impl ClawVpnMacosUtunName {
    fn from_kernel_name(name: &[libc::c_char]) -> Result<Self, io::Error> {
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        let bytes = name[..end]
            .iter()
            .map(|byte| {
                u8::try_from(*byte).map_err(|_| {
                    io::Error::other("kernel returned a non-ascii utun interface name")
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::other("kernel returned a non-utf8 utun interface name"))?;
        validate_utun_name(value)?;
        Ok(Self {
            value: value.to_string(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

pub struct ClawVpnMacosUtunDevice {
    file: File,
    name: ClawVpnMacosUtunName,
}

impl fmt::Debug for ClawVpnMacosUtunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMacosUtunDevice")
            .field("name", &"<redacted>")
            .field("fd", &"<redacted>")
            .finish()
    }
}

impl ClawVpnMacosUtunDevice {
    /// Open an automatically-assigned macOS utun interface.
    ///
    /// This creates only the utun file descriptor. It does not assign an
    /// address, install routes, spawn a pump, dial a relay, or persist state.
    pub fn open() -> io::Result<Self> {
        let fd = open_utun_control_socket()?;
        let file = file_from_owned_socket(fd);
        let mut ctl_info = build_utun_ctl_info();
        lookup_utun_control_id(file.as_raw_fd(), &mut ctl_info)?;
        let addr = build_utun_sockaddr(ctl_info.ctl_id);
        connect_utun_control(file.as_raw_fd(), &addr)?;
        let name = assigned_utun_name(file.as_raw_fd())?;
        Ok(Self { file, name })
    }

    #[must_use]
    pub fn name(&self) -> &ClawVpnMacosUtunName {
        &self.name
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_utun_ipv4_packet(&mut self.file, buf)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        write_utun_ipv4_packet(&mut self.file, packet)
    }

    /// Put the utun fd into non-blocking mode for the pollable datapath. Not
    /// done by `open()` — the blocking `ClawVpnPacketInterface` path is
    /// unchanged; only the pollable wiring calls this.
    #[allow(unsafe_code)]
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let fd = self.file.as_raw_fd();
        // SAFETY: `fd` is the open utun control socket owned by `self`; fcntl
        // only reads and sets the file-status flags.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl ClawVpnPollablePacketInterface for ClawVpnMacosUtunDevice {
    fn interface_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn read_packet_nonblocking(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        read_utun_ipv4_packet_nonblocking(&mut self.file, buf)
    }

    fn write_packet_nonblocking(&mut self, packet: &[u8]) -> io::Result<bool> {
        write_utun_ipv4_packet_nonblocking(&mut self.file, packet)
    }
}

impl ClawVpnPacketInterface for ClawVpnMacosUtunDevice {
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_utun_ipv4_packet(&mut self.file, buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        write_utun_ipv4_packet(&mut self.file, packet)
    }
}

fn read_utun_ipv4_packet(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut framed = vec![0; MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN + MACOS_UTUN_MAX_IPV4_PACKET_LEN];
    let frame_len = reader.read(&mut framed)?;
    decode_utun_ipv4_frame(&framed[..frame_len], buf)
}

fn write_utun_ipv4_packet(file: &mut impl Write, packet: &[u8]) -> io::Result<()> {
    let frame = encode_utun_ipv4_frame(packet)?;
    file.write_all(&frame)
}

/// Non-blocking utun read for the pollable datapath. `WouldBlock` and a bounded
/// run of non-IPv4 frames (macOS IPv6/NDP noise) both return `None` — never a
/// transfer, never fatal. A malformed frame or a real I/O error stays fatal.
fn read_utun_ipv4_packet_nonblocking(
    reader: &mut impl Read,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    for _ in 0..MACOS_UTUN_NONBLOCKING_SKIP_LIMIT {
        let mut framed =
            vec![0; MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN + MACOS_UTUN_MAX_IPV4_PACKET_LEN];
        let frame_len = match reader.read(&mut framed) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        if frame_len < MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun frame is missing the address-family header",
            ));
        }
        let family = u32::from_be_bytes(
            framed[..MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN]
                .try_into()
                .expect("utun address-family header has fixed length"),
        );
        if family != libc::AF_INET as u32 {
            // Non-IPv4 (IPv6/NDP) — skip it and try the next frame this cycle.
            continue;
        }
        return decode_utun_ipv4_frame(&framed[..frame_len], buf).map(Some);
    }
    // Too many consecutive non-IPv4 frames this cycle — yield; resume next poll.
    Ok(None)
}

/// Non-blocking utun write for the pollable datapath. utun writes are
/// packet-atomic: `Ok(true)` = the whole frame crossed; `Ok(false)` =
/// `WouldBlock` (retry the same packet). A partial write would corrupt the
/// tunnel, so it is fatal — this proves the atomicity assumption rather than
/// silently assuming it.
fn write_utun_ipv4_packet_nonblocking(
    writer: &mut impl Write,
    packet: &[u8],
) -> io::Result<bool> {
    let frame = encode_utun_ipv4_frame(packet)?;
    match writer.write(&frame) {
        Ok(n) if n == frame.len() => Ok(true),
        // A non-empty frame accepted as zero bytes is not `WouldBlock`
        // backpressure — it is a write-zero anomaly. Keep it fatal so the R->I
        // direction fails closed instead of quietly retrying (@safia).
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "utun accepted zero bytes of a packet (not backpressure)",
        )),
        Ok(_) => Err(io::Error::other(
            "utun accepted only part of a packet (non-atomic write)",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

fn encode_utun_ipv4_frame(packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.first().map(|byte| byte >> 4) != Some(4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "utun v1 only accepts IPv4 packets",
        ));
    }
    let mut frame = Vec::with_capacity(MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN + packet.len());
    frame.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

fn decode_utun_ipv4_frame(frame: &[u8], buf: &mut [u8]) -> io::Result<usize> {
    if frame.len() < MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun frame is missing the address-family header",
        ));
    }
    let family = u32::from_be_bytes(
        frame[..MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN]
            .try_into()
            .expect("utun address-family header has fixed length"),
    );
    if family != libc::AF_INET as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun frame is not IPv4",
        ));
    }
    let packet = &frame[MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN..];
    if packet.len() > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun frame packet is larger than the destination buffer",
        ));
    }
    buf[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}

#[allow(unsafe_code)]
fn open_utun_control_socket() -> io::Result<libc::c_int> {
    // SAFETY: `socket` has no Rust-side aliasing contract. Arguments are the
    // documented macOS kernel-control domain/protocol for utun.
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[allow(unsafe_code)]
fn file_from_owned_socket(fd: libc::c_int) -> File {
    // SAFETY: `fd` was returned by `socket` and is owned by this function. The
    // resulting `File` is only used as an owned fd wrapper and will close it on
    // drop if any later utun setup step fails.
    unsafe { File::from_raw_fd(fd) }
}

fn build_utun_ctl_info() -> libc::ctl_info {
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (index, byte) in MACOS_UTUN_CONTROL_NAME.as_bytes().iter().enumerate() {
        info.ctl_name[index] = libc::c_char::try_from(*byte).expect("utun control name is ascii");
    }
    info
}

#[allow(unsafe_code)]
fn lookup_utun_control_id(fd: libc::c_int, info: &mut libc::ctl_info) -> io::Result<()> {
    // SAFETY: `fd` is an open PF_SYSTEM/SYSPROTO_CONTROL socket. `info` is a
    // valid, initialized `ctl_info` buffer with a NUL-terminated control name,
    // and remains valid for the duration of the syscall.
    let rc = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, info) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn build_utun_sockaddr(control_id: u32) -> libc::sockaddr_ctl {
    libc::sockaddr_ctl {
        sc_len: u8::try_from(mem::size_of::<libc::sockaddr_ctl>())
            .expect("sockaddr_ctl size fits in u8"),
        sc_family: u8::try_from(libc::AF_SYSTEM).expect("AF_SYSTEM fits in u8"),
        ss_sysaddr: u16::try_from(libc::AF_SYS_CONTROL).expect("AF_SYS_CONTROL fits in u16"),
        sc_id: control_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    }
}

#[allow(unsafe_code)]
fn connect_utun_control(fd: libc::c_int, addr: &libc::sockaddr_ctl) -> io::Result<()> {
    // SAFETY: `addr` is a fully initialized `sockaddr_ctl`; the cast preserves
    // the address and length expected by `connect` for PF_SYSTEM controls.
    let rc = unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(addr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ctl>())
                .expect("sockaddr_ctl size fits in socklen_t"),
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn assigned_utun_name(fd: libc::c_int) -> io::Result<ClawVpnMacosUtunName> {
    let mut name = [0; libc::IFNAMSIZ];
    let mut len = libc::socklen_t::try_from(name.len()).expect("IFNAMSIZ fits in socklen_t");
    // SAFETY: `name` is a writable IFNAMSIZ-sized buffer and `len` points to
    // its length. macOS `UTUN_OPT_IFNAME` writes the assigned interface name.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    ClawVpnMacosUtunName::from_kernel_name(&name)
}

fn validate_utun_name(value: &str) -> Result<(), io::Error> {
    if !value.starts_with("utun") {
        return Err(io::Error::other(
            "kernel returned a non-utun interface name",
        ));
    }
    let suffix = &value[4..];
    if suffix.is_empty() || suffix.len() > MACOS_UTUN_MAX_NAME_LEN - 4 {
        return Err(io::Error::other("kernel returned an invalid utun name"));
    }
    if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::other("kernel returned an invalid utun name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_utun_control_info_is_nul_terminated() {
        let info = build_utun_ctl_info();
        let expected = MACOS_UTUN_CONTROL_NAME.as_bytes();
        for (index, byte) in expected.iter().enumerate() {
            assert_eq!(info.ctl_name[index], libc::c_char::try_from(*byte).unwrap());
        }
        assert_eq!(info.ctl_name[expected.len()], 0);
        assert!(
            info.ctl_name[expected.len() + 1..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn macos_utun_sockaddr_uses_kernel_control_address() {
        let addr = build_utun_sockaddr(0x1234_5678);
        assert_eq!(
            usize::from(addr.sc_len),
            mem::size_of::<libc::sockaddr_ctl>()
        );
        assert_eq!(i32::from(addr.sc_family), libc::AF_SYSTEM);
        assert_eq!(i32::from(addr.ss_sysaddr), libc::AF_SYS_CONTROL);
        assert_eq!(addr.sc_id, 0x1234_5678);
        assert_eq!(addr.sc_unit, 0);
        assert_eq!(addr.sc_reserved, [0; 5]);
    }

    #[test]
    fn macos_utun_kernel_name_accepts_only_utun_digits() {
        let mut name = [0; libc::IFNAMSIZ];
        for (index, byte) in b"utun42".iter().enumerate() {
            name[index] = libc::c_char::try_from(*byte).unwrap();
        }
        let parsed = ClawVpnMacosUtunName::from_kernel_name(&name).unwrap();
        assert_eq!(parsed.as_str(), "utun42");

        let mut wrong_prefix = [0; libc::IFNAMSIZ];
        for (index, byte) in b"en0".iter().enumerate() {
            wrong_prefix[index] = libc::c_char::try_from(*byte).unwrap();
        }
        assert!(ClawVpnMacosUtunName::from_kernel_name(&wrong_prefix).is_err());

        let mut wrong_suffix = [0; libc::IFNAMSIZ];
        for (index, byte) in b"utunx".iter().enumerate() {
            wrong_suffix[index] = libc::c_char::try_from(*byte).unwrap();
        }
        assert!(ClawVpnMacosUtunName::from_kernel_name(&wrong_suffix).is_err());
    }

    #[test]
    fn macos_utun_frames_wrap_and_unwrap_ipv4_packets() {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 192, 0, 2, 20,
        ];
        let frame = encode_utun_ipv4_frame(&packet).unwrap();
        assert_eq!(
            &frame[..MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN],
            &(libc::AF_INET as u32).to_be_bytes()
        );
        assert_eq!(&frame[MACOS_UTUN_ADDRESS_FAMILY_HEADER_LEN..], packet);

        let mut decoded = [0; 20];
        let decoded_len = decode_utun_ipv4_frame(&frame, &mut decoded).unwrap();
        assert_eq!(decoded_len, packet.len());
        assert_eq!(decoded, packet);
    }

    #[test]
    fn macos_utun_frames_reject_non_ipv4_and_short_frames() {
        let ipv6_packet = [0x60, 0, 0, 0];
        assert_eq!(
            encode_utun_ipv4_frame(&ipv6_packet).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let mut decoded = [0; 20];
        assert_eq!(
            decode_utun_ipv4_frame(&[0, 0, 0], &mut decoded)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut non_ipv4 = (libc::AF_INET6 as u32).to_be_bytes().to_vec();
        non_ipv4.extend_from_slice(&[0x60, 0, 0, 0]);
        assert_eq!(
            decode_utun_ipv4_frame(&non_ipv4, &mut decoded)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized_for_destination = (libc::AF_INET as u32).to_be_bytes().to_vec();
        oversized_for_destination.extend_from_slice(&[0x45, 0]);
        let mut too_small = [0; 1];
        assert_eq!(
            decode_utun_ipv4_frame(&oversized_for_destination, &mut too_small)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut reader = io::Cursor::new(oversized_for_destination);
        assert_eq!(
            read_utun_ipv4_packet(&mut reader, &mut too_small)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn macos_utun_debug_redacts_name_and_file_descriptor() {
        let mut name = [0; libc::IFNAMSIZ];
        for (index, byte) in b"utun7".iter().enumerate() {
            name[index] = libc::c_char::try_from(*byte).unwrap();
        }
        let name = ClawVpnMacosUtunName::from_kernel_name(&name).unwrap();
        let file = File::open("/dev/null").expect("/dev/null exists on macOS");
        let device = ClawVpnMacosUtunDevice {
            file,
            name: name.clone(),
        };

        let name_debug = format!("{name:?}");
        let device_debug = format!("{device:?}");
        assert!(!name_debug.contains("utun7"));
        assert!(!device_debug.contains("utun7"));
        assert!(!device_debug.contains(&device.file.as_raw_fd().to_string()));
        assert!(name_debug.contains("<redacted>"));
        assert!(device_debug.contains("<redacted>"));
    }

    #[test]
    fn macos_utun_device_implements_packet_interface_for_ipv4_reads_and_writes() {
        fn assert_packet_interface<T: ClawVpnPacketInterface>() {}
        assert_packet_interface::<ClawVpnMacosUtunDevice>();

        let mut name = [0; libc::IFNAMSIZ];
        for (index, byte) in b"utun7".iter().enumerate() {
            name[index] = libc::c_char::try_from(*byte).unwrap();
        }
        let name = ClawVpnMacosUtunName::from_kernel_name(&name).unwrap();
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 192, 0, 2, 20,
        ];

        let mut framed_file = tempfile::tempfile().expect("test can create temp utun file");
        let frame = encode_utun_ipv4_frame(&packet).unwrap();
        std::io::Write::write_all(&mut framed_file, &frame).expect("test can write framed packet");
        std::io::Seek::rewind(&mut framed_file).expect("test can rewind framed packet");
        let mut read_device = ClawVpnMacosUtunDevice {
            file: framed_file,
            name: name.clone(),
        };
        let mut decoded = [0; 20];
        let decoded_len = ClawVpnPacketInterface::read_packet(&mut read_device, &mut decoded)
            .expect("trait read decodes utun IPv4 frame");
        assert_eq!(decoded_len, packet.len());
        assert_eq!(decoded, packet);

        let mut write_device = ClawVpnMacosUtunDevice {
            file: File::options()
                .write(true)
                .open("/dev/null")
                .expect("/dev/null exists on macOS"),
            name,
        };
        ClawVpnPacketInterface::write_packet(&mut write_device, &packet)
            .expect("/dev/null write succeeds");

        let read_debug = format!("{read_device:?}");
        let write_debug = format!("{write_device:?}");
        assert!(read_debug.contains("<redacted>"));
        assert!(write_debug.contains("<redacted>"));
        assert!(!read_debug.contains("utun7"));
        assert!(!write_debug.contains("utun7"));
        assert!(!read_debug.contains(&read_device.file.as_raw_fd().to_string()));
        assert!(!write_debug.contains(&write_device.file.as_raw_fd().to_string()));
    }
}
