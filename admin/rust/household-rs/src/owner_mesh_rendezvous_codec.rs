//! Pure, inert codec for owner-mesh rendezvous frames.
//!
//! The wire format is pinned by `docs/owner-mesh-rendezvous/wire-encoding-v1.md`.
//! This module deliberately contains no transport, authority, replay, minting,
//! persistence, or signature-verification behavior. In particular,
//! `signed_offer` is an opaque, bounded byte string.

use ciborium::value::Value;

use crate::cbor;

/// The owner-mesh rendezvous protocol domain.
pub const DOMAIN: &str = "soyeht/owner-mesh/rendezvous/v1";
/// The only supported owner-mesh rendezvous wire version.
pub const VERSION: u64 = 1;
/// Maximum raw frame size, enforced before CBOR decoding.
pub const MAX_FRAME_BYTES: usize = 3_072;
/// Maximum number of candidates in one frame.
pub const MAX_CANDIDATES_PER_FRAME: usize = 8;
/// Maximum number of relay candidates in one frame.
pub const MAX_RELAY_CANDIDATES_PER_FRAME: usize = 2;
/// Maximum opaque signed-offer length.
pub const MAX_SIGNED_OFFER_BYTES: usize = 1_024;
/// Exact rendezvous identifier length.
pub const RENDEZVOUS_ID_BYTES: usize = 16;

/// The eleven byte-level failures defined by the frozen wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CodecError {
    #[error("err.oversized_frame")]
    OversizedFrame,
    #[error("err.malformed_cbor")]
    MalformedCbor,
    #[error("err.truncated_frame")]
    TruncatedFrame,
    #[error("err.noncanonical_cbor")]
    NoncanonicalCbor,
    #[error("err.wrong_domain")]
    WrongDomain,
    #[error("err.version_unsupported")]
    VersionUnsupported,
    #[error("err.unknown_frame")]
    UnknownFrame,
    #[error("err.wrong_shape")]
    WrongShape,
    #[error("err.unknown_field")]
    UnknownField,
    #[error("err.frame_too_large")]
    FrameTooLarge,
    #[error("err.signed_offer_too_large")]
    SignedOfferTooLarge,
}

impl CodecError {
    /// Stable wire-contract identifier for this local error.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::OversizedFrame => "err.oversized_frame",
            Self::MalformedCbor => "err.malformed_cbor",
            Self::TruncatedFrame => "err.truncated_frame",
            Self::NoncanonicalCbor => "err.noncanonical_cbor",
            Self::WrongDomain => "err.wrong_domain",
            Self::VersionUnsupported => "err.version_unsupported",
            Self::UnknownFrame => "err.unknown_frame",
            Self::WrongShape => "err.wrong_shape",
            Self::UnknownField => "err.unknown_field",
            Self::FrameTooLarge => "err.frame_too_large",
            Self::SignedOfferTooLarge => "err.signed_offer_too_large",
        }
    }
}

/// Opaque 16-byte rendezvous identifier. R1a transports but never generates it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RendezvousId([u8; RENDEZVOUS_ID_BYTES]);

impl RendezvousId {
    #[must_use]
    pub const fn new(bytes: [u8; RENDEZVOUS_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RENDEZVOUS_ID_BYTES] {
        &self.0
    }
}

/// An IPv4 or IPv6 address represented only as opaque network-order bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpBytes(Vec<u8>);

impl IpBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CodecError> {
        if matches!(bytes.len(), 4 | 16) {
            Ok(Self(bytes))
        } else {
            Err(CodecError::WrongShape)
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A numeric endpoint. DNS names and proxy instructions are not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    ip: IpBytes,
    port: u16,
}

impl Endpoint {
    pub fn new(ip: IpBytes, port: u16) -> Result<Self, CodecError> {
        if port == 0 {
            return Err(CodecError::WrongShape);
        }
        Ok(Self { ip, port })
    }

    #[must_use]
    pub const fn ip(&self) -> &IpBytes {
        &self.ip
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// A relay endpoint plus its opaque, bounded signed offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayCandidate {
    endpoint: Endpoint,
    signed_offer: Vec<u8>,
}

impl RelayCandidate {
    pub fn new(endpoint: Endpoint, signed_offer: Vec<u8>) -> Result<Self, CodecError> {
        if signed_offer.len() > MAX_SIGNED_OFFER_BYTES {
            return Err(CodecError::SignedOfferTooLarge);
        }
        Ok(Self {
            endpoint,
            signed_offer,
        })
    }

    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns opaque bytes. The codec never parses or verifies their contents.
    #[must_use]
    pub fn signed_offer(&self) -> &[u8] {
        &self.signed_offer
    }
}

/// An unknown candidate class preserved as canonical, opaque CBOR.
///
/// R1a does not interpret the class-specific key set. Policy decides whether
/// the class is admissible downstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherCandidate {
    class: u64,
    raw: Vec<u8>,
}

impl OtherCandidate {
    #[must_use]
    pub const fn class(&self) -> u64 {
        self.class
    }

    /// Returns the candidate map's byte-exact canonical CBOR encoding.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

/// A known owner-mesh candidate shape or an opaque unknown class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Candidate {
    Lan(Endpoint),
    Reflexive(Endpoint),
    Relay(RelayCandidate),
    Other(OtherCandidate),
}

impl Candidate {
    #[must_use]
    pub const fn class(&self) -> u64 {
        match self {
            Self::Lan(_) => 0,
            Self::Reflexive(_) => 1,
            Self::Relay(_) => 2,
            Self::Other(other) => other.class,
        }
    }
}

/// A validated Hello payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloFrame {
    rendezvous_id: RendezvousId,
    candidates: Vec<Candidate>,
}

/// A validated Peer payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerFrame {
    rendezvous_id: RendezvousId,
    peer_candidates: Vec<Candidate>,
    observed_reflexive: Endpoint,
}

/// The four owner-mesh rendezvous frame shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    Hello(HelloFrame),
    Peer(PeerFrame),
    Ok(RendezvousId),
    Close(RendezvousId),
}

impl Frame {
    pub fn hello(
        rendezvous_id: RendezvousId,
        candidates: Vec<Candidate>,
    ) -> Result<Self, CodecError> {
        validate_candidate_budgets(&candidates)?;
        Ok(Self::Hello(HelloFrame {
            rendezvous_id,
            candidates,
        }))
    }

    pub fn peer(
        rendezvous_id: RendezvousId,
        peer_candidates: Vec<Candidate>,
        observed_reflexive: Endpoint,
    ) -> Result<Self, CodecError> {
        validate_candidate_budgets(&peer_candidates)?;
        Ok(Self::Peer(PeerFrame {
            rendezvous_id,
            peer_candidates,
            observed_reflexive,
        }))
    }

    #[must_use]
    pub const fn ok(rendezvous_id: RendezvousId) -> Self {
        Self::Ok(rendezvous_id)
    }

    #[must_use]
    pub const fn close(rendezvous_id: RendezvousId) -> Self {
        Self::Close(rendezvous_id)
    }

    #[must_use]
    pub const fn kind(&self) -> u64 {
        match self {
            Self::Hello(_) => 1,
            Self::Peer(_) => 2,
            Self::Ok(_) => 3,
            Self::Close(_) => 4,
        }
    }

    #[must_use]
    pub const fn rendezvous_id(&self) -> &RendezvousId {
        match self {
            Self::Hello(frame) => &frame.rendezvous_id,
            Self::Peer(frame) => &frame.rendezvous_id,
            Self::Ok(id) | Self::Close(id) => id,
        }
    }

    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        match self {
            Self::Hello(frame) => &frame.candidates,
            Self::Peer(frame) => &frame.peer_candidates,
            Self::Ok(_) | Self::Close(_) => &[],
        }
    }

    #[must_use]
    pub const fn observed_reflexive(&self) -> Option<&Endpoint> {
        match self {
            Self::Peer(frame) => Some(&frame.observed_reflexive),
            Self::Hello(_) | Self::Ok(_) | Self::Close(_) => None,
        }
    }
}

/// Encodes a validated frame with the workspace canonical-CBOR helper.
///
/// All values admitted by the public constructors are representable as a
/// `ciborium::Value`; serialization into a `Vec<u8>` is therefore infallible.
///
/// # Panics
///
/// Panics only if the canonical-CBOR helper cannot encode the in-memory
/// `ciborium::Value` built from validated fields, which would violate this
/// module's internal representation invariant.
#[must_use]
pub fn encode(frame: &Frame) -> Vec<u8> {
    cbor::to_canonical_vec(&frame_value(frame))
        .expect("validated owner-mesh rendezvous Value must encode")
}

/// Decodes and validates one complete owner-mesh rendezvous frame.
pub fn decode(bytes: &[u8]) -> Result<Frame, CodecError> {
    decode_with(bytes, decode_cbor_value)
}

fn decode_with<F>(bytes: &[u8], decode_cbor: F) -> Result<Frame, CodecError>
where
    F: FnOnce(&[u8]) -> Result<Value, CodecError>,
{
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(CodecError::OversizedFrame);
    }

    let value = decode_cbor(bytes)?;
    let canonical = cbor::to_canonical_vec(&value).map_err(|_| CodecError::MalformedCbor)?;
    if canonical != bytes {
        return Err(CodecError::NoncanonicalCbor);
    }

    parse_frame(&value)
}

fn decode_cbor_value(bytes: &[u8]) -> Result<Value, CodecError> {
    match ciborium::de::from_reader(bytes) {
        Ok(value) => Ok(value),
        Err(ciborium::de::Error::Io(_)) => Err(CodecError::TruncatedFrame),
        Err(
            ciborium::de::Error::Syntax(_)
            | ciborium::de::Error::Semantic(_, _)
            | ciborium::de::Error::RecursionLimitExceeded,
        ) => Err(CodecError::MalformedCbor),
    }
}

fn parse_frame(value: &Value) -> Result<Frame, CodecError> {
    let entries = as_map(value)?;

    let domain = required_text(entries, "domain")?;
    if domain != DOMAIN {
        return Err(CodecError::WrongDomain);
    }

    let version = required_u64(entries, "version")?;
    if version != VERSION {
        return Err(CodecError::VersionUnsupported);
    }

    let kind = required_u64(entries, "kind")?;
    if !(1..=4).contains(&kind) {
        return Err(CodecError::UnknownFrame);
    }

    reject_duplicate_map_keys(value)?;

    let parsed = match kind {
        1 => parse_hello(entries)?,
        2 => parse_peer(entries)?,
        3 => parse_terminal(entries, false)?,
        4 => parse_terminal(entries, true)?,
        _ => unreachable!("kind range checked above"),
    };

    if parsed.has_unknown_field {
        return Err(CodecError::UnknownField);
    }
    if parsed.candidate_count > MAX_CANDIDATES_PER_FRAME
        || parsed.relay_count > MAX_RELAY_CANDIDATES_PER_FRAME
    {
        return Err(CodecError::FrameTooLarge);
    }
    if parsed.signed_offer_too_large {
        return Err(CodecError::SignedOfferTooLarge);
    }
    Ok(parsed.frame)
}

struct ParsedFrame {
    frame: Frame,
    has_unknown_field: bool,
    candidate_count: usize,
    relay_count: usize,
    signed_offer_too_large: bool,
}

fn parse_hello(entries: &[(Value, Value)]) -> Result<ParsedFrame, CodecError> {
    let rendezvous_id = required_rendezvous_id(entries)?;
    let candidates = parse_candidate_array(required_field(entries, "candidates")?)?;
    let has_unknown_field = has_unknown_field(
        entries,
        &["kind", "domain", "version", "candidates", "rendezvous_id"],
    ) || candidates.has_unknown_field;

    Ok(ParsedFrame {
        frame: Frame::Hello(HelloFrame {
            rendezvous_id,
            candidates: candidates.values,
        }),
        has_unknown_field,
        candidate_count: candidates.candidate_count,
        relay_count: candidates.relay_count,
        signed_offer_too_large: candidates.signed_offer_too_large,
    })
}

fn parse_peer(entries: &[(Value, Value)]) -> Result<ParsedFrame, CodecError> {
    let rendezvous_id = required_rendezvous_id(entries)?;
    let candidates = parse_candidate_array(required_field(entries, "peer_candidates")?)?;
    let observed = parse_candidate(required_field(entries, "observed_reflexive")?, true)?;
    let Some(Candidate::Reflexive(observed_reflexive)) = observed.value else {
        return Err(CodecError::WrongShape);
    };
    let has_unknown_field = has_unknown_field(
        entries,
        &[
            "kind",
            "domain",
            "version",
            "rendezvous_id",
            "peer_candidates",
            "observed_reflexive",
        ],
    ) || candidates.has_unknown_field
        || observed.has_unknown_field;

    Ok(ParsedFrame {
        frame: Frame::Peer(PeerFrame {
            rendezvous_id,
            peer_candidates: candidates.values,
            observed_reflexive,
        }),
        has_unknown_field,
        candidate_count: candidates.candidate_count,
        relay_count: candidates.relay_count,
        signed_offer_too_large: candidates.signed_offer_too_large,
    })
}

fn parse_terminal(entries: &[(Value, Value)], close: bool) -> Result<ParsedFrame, CodecError> {
    let rendezvous_id = required_rendezvous_id(entries)?;
    let frame = if close {
        Frame::Close(rendezvous_id)
    } else {
        Frame::Ok(rendezvous_id)
    };
    Ok(ParsedFrame {
        frame,
        has_unknown_field: has_unknown_field(
            entries,
            &["kind", "domain", "version", "rendezvous_id"],
        ),
        candidate_count: 0,
        relay_count: 0,
        signed_offer_too_large: false,
    })
}

struct ParsedCandidates {
    values: Vec<Candidate>,
    has_unknown_field: bool,
    candidate_count: usize,
    relay_count: usize,
    signed_offer_too_large: bool,
}

fn parse_candidate_array(value: &Value) -> Result<ParsedCandidates, CodecError> {
    let Value::Array(values) = value else {
        return Err(CodecError::WrongShape);
    };
    let mut candidates = Vec::with_capacity(values.len().min(MAX_CANDIDATES_PER_FRAME));
    let mut has_unknown = false;
    let mut relay_count = 0;
    let mut signed_offer_too_large = false;
    for value in values {
        let retain = candidates.len() < MAX_CANDIDATES_PER_FRAME;
        let parsed = parse_candidate(value, retain)?;
        relay_count += usize::from(parsed.is_relay);
        has_unknown |= parsed.has_unknown_field;
        signed_offer_too_large |= parsed.signed_offer_too_large;
        if let Some(candidate) = parsed.value {
            candidates.push(candidate);
        }
    }
    Ok(ParsedCandidates {
        values: candidates,
        has_unknown_field: has_unknown,
        candidate_count: values.len(),
        relay_count,
        signed_offer_too_large,
    })
}

struct ParsedCandidate {
    value: Option<Candidate>,
    is_relay: bool,
    has_unknown_field: bool,
    signed_offer_too_large: bool,
}

fn parse_candidate(value: &Value, retain: bool) -> Result<ParsedCandidate, CodecError> {
    let entries = as_map(value)?;
    let class = required_u64(entries, "class")?;
    match class {
        0 | 1 => {
            let endpoint = parse_endpoint(entries, retain)?;
            let value = endpoint.map(|endpoint| {
                if class == 0 {
                    Candidate::Lan(endpoint)
                } else {
                    Candidate::Reflexive(endpoint)
                }
            });
            Ok(ParsedCandidate {
                value,
                is_relay: false,
                has_unknown_field: has_unknown_field(entries, &["ip", "port", "class"]),
                signed_offer_too_large: false,
            })
        }
        2 => {
            let endpoint_entries = as_map(required_field(entries, "relay_endpoint")?)?;
            let endpoint = parse_endpoint(endpoint_entries, retain)?;
            let signed_offer = required_bytes(entries, "signed_offer")?;
            let signed_offer_too_large = signed_offer.len() > MAX_SIGNED_OFFER_BYTES;
            let value = endpoint.map(|endpoint| {
                let signed_offer = if signed_offer_too_large {
                    Vec::new()
                } else {
                    signed_offer.to_vec()
                };
                Candidate::Relay(RelayCandidate {
                    endpoint,
                    signed_offer,
                })
            });
            Ok(ParsedCandidate {
                value,
                is_relay: true,
                has_unknown_field: has_unknown_field(
                    entries,
                    &["class", "signed_offer", "relay_endpoint"],
                ) || has_unknown_field(endpoint_entries, &["ip", "port"]),
                signed_offer_too_large,
            })
        }
        _ => {
            let value = if retain {
                let raw = cbor::to_canonical_vec(value).map_err(|_| CodecError::MalformedCbor)?;
                Some(Candidate::Other(OtherCandidate { class, raw }))
            } else {
                None
            };
            Ok(ParsedCandidate {
                value,
                is_relay: false,
                has_unknown_field: false,
                signed_offer_too_large: false,
            })
        }
    }
}

fn parse_endpoint(
    entries: &[(Value, Value)],
    retain: bool,
) -> Result<Option<Endpoint>, CodecError> {
    let ip = required_bytes(entries, "ip")?;
    if !matches!(ip.len(), 4 | 16) {
        return Err(CodecError::WrongShape);
    }
    let port = required_u64(entries, "port")?;
    let port = u16::try_from(port).map_err(|_| CodecError::WrongShape)?;
    if port == 0 {
        return Err(CodecError::WrongShape);
    }
    if retain {
        Ok(Some(Endpoint {
            ip: IpBytes(ip.to_vec()),
            port,
        }))
    } else {
        Ok(None)
    }
}

fn required_rendezvous_id(entries: &[(Value, Value)]) -> Result<RendezvousId, CodecError> {
    let bytes = required_bytes(entries, "rendezvous_id")?;
    let bytes = <[u8; RENDEZVOUS_ID_BYTES]>::try_from(bytes).map_err(|_| CodecError::WrongShape)?;
    Ok(RendezvousId(bytes))
}

fn as_map(value: &Value) -> Result<&[(Value, Value)], CodecError> {
    let Value::Map(entries) = value else {
        return Err(CodecError::WrongShape);
    };
    Ok(entries)
}

fn required_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value, CodecError> {
    let mut matches = entries.iter().filter_map(|(key, value)| match key {
        Value::Text(key) if key == name => Some(value),
        _ => None,
    });
    let value = matches.next().ok_or(CodecError::WrongShape)?;
    if matches.next().is_some() {
        return Err(CodecError::WrongShape);
    }
    Ok(value)
}

fn required_text<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a str, CodecError> {
    let Value::Text(value) = required_field(entries, name)? else {
        return Err(CodecError::WrongShape);
    };
    Ok(value)
}

fn required_u64(entries: &[(Value, Value)], name: &str) -> Result<u64, CodecError> {
    let Value::Integer(value) = required_field(entries, name)? else {
        return Err(CodecError::WrongShape);
    };
    u64::try_from(*value).map_err(|_| CodecError::WrongShape)
}

fn required_bytes<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a [u8], CodecError> {
    let Value::Bytes(value) = required_field(entries, name)? else {
        return Err(CodecError::WrongShape);
    };
    Ok(value)
}

fn has_unknown_field(entries: &[(Value, Value)], allowed: &[&str]) -> bool {
    entries.iter().any(|(key, _)| {
        let Value::Text(key) = key else {
            return true;
        };
        !allowed.contains(&key.as_str())
    })
}

fn reject_duplicate_map_keys(value: &Value) -> Result<(), CodecError> {
    match value {
        Value::Array(values) => {
            for value in values {
                reject_duplicate_map_keys(value)?;
            }
        }
        Value::Map(entries) => {
            let mut previous_key = None;
            for (key, value) in entries {
                let key_bytes = canonical_key_bytes(key)?;
                if previous_key.as_ref() == Some(&key_bytes) {
                    return Err(CodecError::WrongShape);
                }
                previous_key = Some(key_bytes);
                reject_duplicate_map_keys(key)?;
                reject_duplicate_map_keys(value)?;
            }
        }
        Value::Tag(_, inner) => reject_duplicate_map_keys(inner)?,
        _ => {}
    }
    Ok(())
}

fn canonical_key_bytes(value: &Value) -> Result<Vec<u8>, CodecError> {
    let mut bytes = Vec::with_capacity(32);
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_| CodecError::MalformedCbor)?;
    Ok(bytes)
}

fn validate_candidate_budgets(candidates: &[Candidate]) -> Result<(), CodecError> {
    let relay_count = candidates
        .iter()
        .filter(|candidate| matches!(candidate, Candidate::Relay(_)))
        .count();
    if candidates.len() > MAX_CANDIDATES_PER_FRAME || relay_count > MAX_RELAY_CANDIDATES_PER_FRAME {
        return Err(CodecError::FrameTooLarge);
    }
    if candidates.iter().any(|candidate| {
        matches!(candidate, Candidate::Relay(relay) if relay.signed_offer.len() > MAX_SIGNED_OFFER_BYTES)
    }) {
        return Err(CodecError::SignedOfferTooLarge);
    }
    Ok(())
}

fn frame_value(frame: &Frame) -> Value {
    let common = |kind, rendezvous_id: &RendezvousId| {
        vec![
            pair("kind", integer(kind)),
            pair("domain", Value::Text(DOMAIN.to_owned())),
            pair("version", integer(VERSION)),
            pair(
                "rendezvous_id",
                Value::Bytes(rendezvous_id.as_bytes().to_vec()),
            ),
        ]
    };

    match frame {
        Frame::Hello(hello) => {
            let mut entries = common(1, &hello.rendezvous_id);
            entries.push(pair(
                "candidates",
                Value::Array(hello.candidates.iter().map(candidate_value).collect()),
            ));
            Value::Map(entries)
        }
        Frame::Peer(peer) => {
            let mut entries = common(2, &peer.rendezvous_id);
            entries.push(pair(
                "peer_candidates",
                Value::Array(peer.peer_candidates.iter().map(candidate_value).collect()),
            ));
            entries.push(pair(
                "observed_reflexive",
                direct_candidate_value(1, &peer.observed_reflexive),
            ));
            Value::Map(entries)
        }
        Frame::Ok(rendezvous_id) => Value::Map(common(3, rendezvous_id)),
        Frame::Close(rendezvous_id) => Value::Map(common(4, rendezvous_id)),
    }
}

fn candidate_value(candidate: &Candidate) -> Value {
    match candidate {
        Candidate::Lan(endpoint) => direct_candidate_value(0, endpoint),
        Candidate::Reflexive(endpoint) => direct_candidate_value(1, endpoint),
        Candidate::Relay(relay) => Value::Map(vec![
            pair("class", integer(2)),
            pair("signed_offer", Value::Bytes(relay.signed_offer.clone())),
            pair("relay_endpoint", endpoint_value(&relay.endpoint)),
        ]),
        Candidate::Other(other) => ciborium::de::from_reader(other.raw.as_slice())
            .expect("decoded opaque candidate remains valid canonical CBOR"),
    }
}

fn direct_candidate_value(class: u64, endpoint: &Endpoint) -> Value {
    let mut entries = endpoint_entries(endpoint);
    entries.push(pair("class", integer(class)));
    Value::Map(entries)
}

fn endpoint_value(endpoint: &Endpoint) -> Value {
    Value::Map(endpoint_entries(endpoint))
}

fn endpoint_entries(endpoint: &Endpoint) -> Vec<(Value, Value)> {
    vec![
        pair("ip", Value::Bytes(endpoint.ip.as_bytes().to_vec())),
        pair("port", integer(u64::from(endpoint.port))),
    ]
}

fn pair(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.to_owned()), value)
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn oversized_input_never_reaches_cbor_decoder() {
        let reached = Cell::new(false);
        let bytes = vec![0xff; MAX_FRAME_BYTES + 1];
        let result = decode_with(&bytes, |_| {
            reached.set(true);
            Err(CodecError::MalformedCbor)
        });
        assert_eq!(result, Err(CodecError::OversizedFrame));
        assert!(!reached.get());
    }

    #[test]
    fn candidate_border_scans_for_precedence_but_retains_at_most_the_cap() {
        let candidate = direct_candidate_value(
            0,
            &Endpoint::new(IpBytes::new(vec![192, 0, 2, 1]).unwrap(), 443).unwrap(),
        );
        let parsed =
            parse_candidate_array(&Value::Array(vec![candidate; MAX_CANDIDATES_PER_FRAME + 1]))
                .unwrap();
        assert_eq!(parsed.candidate_count, MAX_CANDIDATES_PER_FRAME + 1);
        assert_eq!(parsed.values.len(), MAX_CANDIDATES_PER_FRAME);
    }

    #[test]
    fn oversized_signed_offer_is_measured_without_a_second_copy() {
        let candidate = Value::Map(vec![
            pair("class", integer(2)),
            pair(
                "signed_offer",
                Value::Bytes(vec![0xa5; MAX_SIGNED_OFFER_BYTES + 1]),
            ),
            pair(
                "relay_endpoint",
                endpoint_value(
                    &Endpoint::new(IpBytes::new(vec![192, 0, 2, 1]).unwrap(), 443).unwrap(),
                ),
            ),
        ]);
        let parsed = parse_candidate(&candidate, true).unwrap();
        assert!(parsed.signed_offer_too_large);
        let Some(Candidate::Relay(relay)) = parsed.value else {
            panic!("relay candidate expected");
        };
        assert!(relay.signed_offer.is_empty());
    }

    #[test]
    fn candidate_beyond_cap_is_scanned_without_materializing_or_copying_offer() {
        let candidate = Value::Map(vec![
            pair("class", integer(2)),
            pair("signed_offer", Value::Bytes(vec![0xa5; 32])),
            pair(
                "relay_endpoint",
                endpoint_value(
                    &Endpoint::new(IpBytes::new(vec![192, 0, 2, 1]).unwrap(), 443).unwrap(),
                ),
            ),
        ]);
        let parsed = parse_candidate(&candidate, false).unwrap();
        assert!(parsed.is_relay);
        assert!(!parsed.signed_offer_too_large);
        assert!(parsed.value.is_none());
    }
}
