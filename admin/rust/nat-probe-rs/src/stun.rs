//! Minimal RFC 5389 STUN client codec: binding request out, mapped address in.
//!
//! Hand-rolled rather than taken from a STUN crate for one structural reason:
//! M0a's whole question is what two *different* servers report about the *same*
//! UDP socket, and a client that owns its socket cannot express that. Here the
//! caller owns the socket and this module only encodes and decodes bytes.
//!
//! Only the binding transaction is implemented. No authentication, no
//! `CHANGE-REQUEST`, no `OTHER-ADDRESS`: RFC 5780's filtering tests need a
//! server that answers from a second address, and M0a deliberately measures
//! mapping only (see the crate doc).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// RFC 5389 §6 magic cookie. Present in every conformant response, and the XOR
/// key for the address half of `XOR-MAPPED-ADDRESS`.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// High 16 bits of [`MAGIC_COOKIE`] — the XOR key for the port half. Written as
/// a literal so no truncating cast appears in the codec at all;
/// `magic_cookie_high_is_the_top_half` proves the two agree.
const MAGIC_COOKIE_HIGH: u16 = 0x2112;

/// RFC 5389 §6: the transaction id is 96 bits.
pub const TRANSACTION_ID_BYTES: usize = 12;

/// RFC 5389 §6: type, length, cookie, transaction id.
pub const HEADER_BYTES: usize = 20;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// The 96-bit transaction id echoed by the server.
pub type TransactionId = [u8; TRANSACTION_ID_BYTES];

/// Why a datagram could not be read as a binding success response.
///
/// Every variant is a reason to *discard the datagram and keep waiting*, never
/// to fail the probe: a socket bound to a wildcard port can receive unrelated
/// traffic, and treating a stray packet as an answer is how a probe reports a
/// mapping that was never observed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunDecodeError {
    /// Shorter than the fixed header.
    #[error("datagram is shorter than the {HEADER_BYTES}-byte STUN header")]
    ShorterThanHeader,
    /// Not a binding success response (an error response, or another method).
    #[error("message type {0:#06x} is not a binding success response")]
    NotBindingSuccess(u16),
    /// No RFC 5389 magic cookie: an RFC 3489 peer, or not STUN at all.
    #[error("magic cookie absent — not an RFC 5389 response")]
    WrongMagicCookie,
    /// A well-formed response to somebody else's request.
    #[error("transaction id does not match the request")]
    TransactionIdMismatch,
    /// The header's declared attribute length runs past the received bytes.
    #[error("declared attribute length runs past the datagram")]
    LengthPastDatagram,
    /// An attribute's own length runs past the message, or its value is short.
    #[error("attribute {attribute:#06x} is malformed or truncated")]
    MalformedAttribute {
        /// The attribute type that failed to parse.
        attribute: u16,
    },
    /// Address family is neither IPv4 (`0x01`) nor IPv6 (`0x02`).
    #[error("address family {0:#04x} is neither IPv4 nor IPv6")]
    UnknownAddressFamily(u8),
    /// A valid response that carries no address at all.
    #[error("no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute present")]
    NoMappedAddress,
}

/// Encode a binding request carrying `transaction_id`.
///
/// A bare request: zero attributes, so the message length is zero and the
/// datagram is exactly the header.
#[must_use]
pub fn encode_binding_request(transaction_id: &TransactionId) -> [u8; HEADER_BYTES] {
    let mut out = [0u8; HEADER_BYTES];
    out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..HEADER_BYTES].copy_from_slice(transaction_id);
    out
}

/// Read the reflexive transport address out of a binding success response.
///
/// `expected` must be the transaction id of the request this datagram is
/// claimed to answer; a mismatch is an error rather than a silently accepted
/// address.
pub fn decode_mapped_address(
    datagram: &[u8],
    expected: &TransactionId,
) -> Result<SocketAddr, StunDecodeError> {
    if datagram.len() < HEADER_BYTES {
        return Err(StunDecodeError::ShorterThanHeader);
    }

    let message_type = u16::from_be_bytes([datagram[0], datagram[1]]);
    if message_type != BINDING_SUCCESS_RESPONSE {
        return Err(StunDecodeError::NotBindingSuccess(message_type));
    }

    let cookie = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunDecodeError::WrongMagicCookie);
    }

    if datagram[8..HEADER_BYTES] != expected[..] {
        return Err(StunDecodeError::TransactionIdMismatch);
    }

    let declared = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    let end = HEADER_BYTES + declared;
    if end > datagram.len() {
        return Err(StunDecodeError::LengthPastDatagram);
    }

    // XOR-MAPPED-ADDRESS wins when both are present. MAPPED-ADDRESS carries the
    // address in the clear, which is exactly what some NATs rewrite in flight —
    // the reason RFC 5389 introduced the XOR form. The legacy value is kept only
    // as a fallback for servers that send nothing else.
    let mut legacy: Option<SocketAddr> = None;
    let mut offset = HEADER_BYTES;

    while offset + 4 <= end {
        let attribute = u16::from_be_bytes([datagram[offset], datagram[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            datagram[offset + 2],
            datagram[offset + 3],
        ]));
        let value_start = offset + 4;
        let value_end = value_start + length;
        if value_end > end {
            return Err(StunDecodeError::MalformedAttribute { attribute });
        }
        let value = &datagram[value_start..value_end];

        match attribute {
            ATTR_XOR_MAPPED_ADDRESS => {
                return decode_address(value, attribute, expected, true);
            }
            ATTR_MAPPED_ADDRESS if legacy.is_none() => {
                legacy = Some(decode_address(value, attribute, expected, false)?);
            }
            _ => {}
        }

        // RFC 5389 §15: attribute values are padded to a 4-byte boundary and the
        // padding is not counted in the declared length.
        offset = value_start + length.div_ceil(4) * 4;
    }

    legacy.ok_or(StunDecodeError::NoMappedAddress)
}

fn decode_address(
    value: &[u8],
    attribute: u16,
    transaction_id: &TransactionId,
    xor: bool,
) -> Result<SocketAddr, StunDecodeError> {
    if value.len() < 4 {
        return Err(StunDecodeError::MalformedAttribute { attribute });
    }

    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        raw_port ^ MAGIC_COOKIE_HIGH
    } else {
        raw_port
    };

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunDecodeError::MalformedAttribute { attribute });
            }
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let bits = if xor { raw ^ MAGIC_COOKIE } else { raw };
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(bits)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunDecodeError::MalformedAttribute { attribute });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                // RFC 5389 §15.2: the IPv6 key is the cookie followed by the
                // transaction id — which is why decoding needs the request's id
                // and not only the datagram.
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                key[4..].copy_from_slice(transaction_id);
                for (byte, mask) in octets.iter_mut().zip(key.iter()) {
                    *byte ^= *mask;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(StunDecodeError::UnknownAddressFamily(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn response_header(attributes_len: u16, cookie: u32, txid: &TransactionId) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
        out.extend_from_slice(&attributes_len.to_be_bytes());
        out.extend_from_slice(&cookie.to_be_bytes());
        out.extend_from_slice(txid);
        out
    }

    fn xor_mapped_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut value = vec![0x00, FAMILY_IPV4];
        value.extend_from_slice(&(port ^ MAGIC_COOKIE_HIGH).to_be_bytes());
        value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&value);
        out
    }

    #[test]
    fn magic_cookie_high_is_the_top_half() {
        assert_eq!(u32::from(MAGIC_COOKIE_HIGH), MAGIC_COOKIE >> 16);
    }

    #[test]
    fn request_is_a_bare_header_with_cookie_and_txid() {
        let request = encode_binding_request(&TXID);
        assert_eq!(request.len(), HEADER_BYTES);
        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]),
            BINDING_REQUEST
        );
        assert_eq!(
            u16::from_be_bytes([request[2], request[3]]),
            0,
            "a bare request declares zero attribute bytes"
        );
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(request[8..], TXID[..]);
    }

    #[test]
    fn decodes_xor_mapped_ipv4() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let attribute = xor_mapped_v4(ip, 51_820);
        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID).unwrap(),
            SocketAddr::new(IpAddr::V4(ip), 51_820)
        );
    }

    #[test]
    fn decodes_xor_mapped_ipv6_using_the_transaction_id_as_key() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let port = 4_242u16;

        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&TXID);
        let mut obfuscated = ip.octets();
        for (byte, mask) in obfuscated.iter_mut().zip(key.iter()) {
            *byte ^= *mask;
        }

        let mut value = vec![0x00, FAMILY_IPV6];
        value.extend_from_slice(&(port ^ MAGIC_COOKIE_HIGH).to_be_bytes());
        value.extend_from_slice(&obfuscated);

        let mut attribute = Vec::new();
        attribute.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attribute.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        attribute.extend_from_slice(&value);

        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID).unwrap(),
            SocketAddr::new(IpAddr::V6(ip), port)
        );
    }

    #[test]
    fn prefers_xor_mapped_over_legacy_mapped_address() {
        // A NAT that rewrites the cleartext MAPPED-ADDRESS but cannot see the
        // XOR form is the exact case RFC 5389 added the XOR form for, so the two
        // attributes are made to disagree and the XOR one must win.
        let legacy_ip = Ipv4Addr::new(192, 0, 2, 1);
        let mut legacy_value = vec![0x00, FAMILY_IPV4];
        legacy_value.extend_from_slice(&1234u16.to_be_bytes());
        legacy_value.extend_from_slice(&legacy_ip.octets());
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        legacy.extend_from_slice(&u16::try_from(legacy_value.len()).unwrap().to_be_bytes());
        legacy.extend_from_slice(&legacy_value);

        let xor_ip = Ipv4Addr::new(203, 0, 113, 9);
        let xor = xor_mapped_v4(xor_ip, 51_821);

        let total = u16::try_from(legacy.len() + xor.len()).unwrap();
        let mut datagram = response_header(total, MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&legacy);
        datagram.extend_from_slice(&xor);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID).unwrap(),
            SocketAddr::new(IpAddr::V4(xor_ip), 51_821)
        );
    }

    #[test]
    fn falls_back_to_legacy_mapped_address_when_alone() {
        let ip = Ipv4Addr::new(198, 51, 100, 4);
        let mut value = vec![0x00, FAMILY_IPV4];
        value.extend_from_slice(&9_000u16.to_be_bytes());
        value.extend_from_slice(&ip.octets());
        let mut attribute = Vec::new();
        attribute.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attribute.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        attribute.extend_from_slice(&value);

        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID).unwrap(),
            SocketAddr::new(IpAddr::V4(ip), 9_000)
        );
    }

    #[test]
    fn skips_unknown_attributes_including_odd_lengths() {
        // A 3-byte SOFTWARE-like attribute is padded to 4; getting the padding
        // wrong desynchronises the walk and loses the address that follows.
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0xFFFFu16.to_be_bytes());
        unknown.extend_from_slice(&3u16.to_be_bytes());
        unknown.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00]);

        let ip = Ipv4Addr::new(203, 0, 113, 11);
        let xor = xor_mapped_v4(ip, 7_777);

        let total = u16::try_from(unknown.len() + xor.len()).unwrap();
        let mut datagram = response_header(total, MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&unknown);
        datagram.extend_from_slice(&xor);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID).unwrap(),
            SocketAddr::new(IpAddr::V4(ip), 7_777)
        );
    }

    #[test]
    fn rejects_a_response_to_another_transaction() {
        let attribute = xor_mapped_v4(Ipv4Addr::new(203, 0, 113, 7), 51_820);
        let other = [9u8; TRANSACTION_ID_BYTES];
        let mut datagram = response_header(
            u16::try_from(attribute.len()).unwrap(),
            MAGIC_COOKIE,
            &other,
        );
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::TransactionIdMismatch)
        );
    }

    #[test]
    fn rejects_a_datagram_without_the_magic_cookie() {
        let attribute = xor_mapped_v4(Ipv4Addr::new(203, 0, 113, 7), 51_820);
        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), 0xDEAD_BEEF, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::WrongMagicCookie)
        );
    }

    #[test]
    fn rejects_non_success_message_types() {
        let mut datagram = response_header(0, MAGIC_COOKIE, &TXID);
        datagram[0..2].copy_from_slice(&0x0111u16.to_be_bytes());

        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::NotBindingSuccess(0x0111))
        );
    }

    #[test]
    fn rejects_a_header_declaring_more_than_was_received() {
        let datagram = response_header(64, MAGIC_COOKIE, &TXID);
        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::LengthPastDatagram)
        );
    }

    #[test]
    fn rejects_an_attribute_whose_value_is_truncated() {
        // Declares a 20-byte IPv6 value but only 8 bytes are present.
        let mut attribute = Vec::new();
        attribute.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attribute.extend_from_slice(&8u16.to_be_bytes());
        attribute.extend_from_slice(&[0x00, FAMILY_IPV6, 0, 0, 0, 0, 0, 0]);

        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::MalformedAttribute {
                attribute: ATTR_XOR_MAPPED_ADDRESS
            })
        );
    }

    #[test]
    fn rejects_an_unknown_address_family() {
        let mut attribute = Vec::new();
        attribute.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attribute.extend_from_slice(&8u16.to_be_bytes());
        attribute.extend_from_slice(&[0x00, 0x07, 0, 0, 0, 0, 0, 0]);

        let mut datagram =
            response_header(u16::try_from(attribute.len()).unwrap(), MAGIC_COOKIE, &TXID);
        datagram.extend_from_slice(&attribute);

        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::UnknownAddressFamily(0x07))
        );
    }

    #[test]
    fn reports_a_success_response_carrying_no_address() {
        let datagram = response_header(0, MAGIC_COOKIE, &TXID);
        assert_eq!(
            decode_mapped_address(&datagram, &TXID),
            Err(StunDecodeError::NoMappedAddress)
        );
    }

    #[test]
    fn rejects_a_datagram_shorter_than_the_header() {
        assert_eq!(
            decode_mapped_address(&[0u8; 8], &TXID),
            Err(StunDecodeError::ShorterThanHeader)
        );
    }
}
