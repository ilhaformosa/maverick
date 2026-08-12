use std::fmt;

const QUIC_V1: u32 = 1;
const MAX_CONNECTION_ID_LENGTH: u8 = 20;
const RETRY_INTEGRITY_TAG_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationSubject {
    Quiche,
    Chrome,
}

impl ObservationSubject {
    pub const ALL: [Self; 2] = [Self::Quiche, Self::Chrome];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Quiche => "quiche",
            Self::Chrome => "chrome",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightBlocker {
    CurrentMainQuicheAdapterUnavailable,
    LegacyChromeQuicDisabled,
}

impl fmt::Display for PreflightBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CurrentMainQuicheAdapterUnavailable => "current main quiche adapter unavailable",
            Self::LegacyChromeQuicDisabled => "legacy Chrome QUIC disabled",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightState {
    Ready,
    Blocked(PreflightBlocker),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectPreflight {
    pub subject: ObservationSubject,
    pub state: PreflightState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightReport {
    pub subjects: [SubjectPreflight; 2],
}

impl PreflightReport {
    pub fn blockers(&self) -> impl Iterator<Item = (ObservationSubject, PreflightBlocker)> + '_ {
        self.subjects.iter().filter_map(|subject| {
            let PreflightState::Blocked(blocker) = subject.state else {
                return None;
            };
            Some((subject.subject, blocker))
        })
    }

    pub fn require_all_ready(&self) -> Result<(), PreflightFailure> {
        let blockers = self.blockers().collect::<Vec<_>>();
        if blockers.is_empty() {
            Ok(())
        } else {
            Err(PreflightFailure { blockers })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightFailure {
    pub blockers: Vec<(ObservationSubject, PreflightBlocker)>,
}

impl fmt::Display for PreflightFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backend bakeoff preflight blocked before network")
    }
}

impl std::error::Error for PreflightFailure {}

pub fn current_main_preflight() -> PreflightReport {
    PreflightReport {
        subjects: [
            SubjectPreflight {
                subject: ObservationSubject::Quiche,
                state: PreflightState::Blocked(
                    PreflightBlocker::CurrentMainQuicheAdapterUnavailable,
                ),
            },
            SubjectPreflight {
                subject: ObservationSubject::Chrome,
                state: PreflightState::Blocked(PreflightBlocker::LegacyChromeQuicDisabled),
            },
        ],
    }
}

pub fn run_after_current_main_preflight<T>(
    observer: impl FnOnce() -> T,
) -> Result<T, PreflightFailure> {
    current_main_preflight().require_all_ready()?;
    Ok(observer())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicOuterPacketType {
    VersionNegotiation,
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicOuterPacketObservation {
    pub packet_type: QuicOuterPacketType,
    pub packet_length: usize,
    pub version: Option<u32>,
    pub destination_connection_id_length: Option<u8>,
    pub source_connection_id_length: Option<u8>,
    pub token_length: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicOuterObservation {
    pub udp_payload_length: usize,
    pub meets_initial_minimum_size: bool,
    pub packets: Vec<QuicOuterPacketObservation>,
}

impl QuicOuterObservation {
    pub fn contains(&self, packet_type: QuicOuterPacketType) -> bool {
        self.packets
            .iter()
            .any(|packet| packet.packet_type == packet_type)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicOuterParseError {
    EmptyDatagram,
    Truncated(&'static str),
    InvalidFixedBit,
    InvalidConnectionIdLength,
    UnsupportedLongHeaderVersion(u32),
    InvalidVersionNegotiationListLength,
    RetryMissingIntegrityTag,
    DeclaredPacketLengthExceedsDatagram,
    LengthDoesNotFitPlatform,
}

impl fmt::Display for QuicOuterParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => formatter.write_str("empty UDP payload"),
            Self::Truncated(field) => write!(formatter, "truncated QUIC {field}"),
            Self::InvalidFixedBit => formatter.write_str("invalid QUIC fixed bit"),
            Self::InvalidConnectionIdLength => {
                formatter.write_str("invalid QUIC connection ID length")
            }
            Self::UnsupportedLongHeaderVersion(version) => {
                write!(
                    formatter,
                    "unsupported QUIC long-header version 0x{version:08x}"
                )
            }
            Self::InvalidVersionNegotiationListLength => {
                formatter.write_str("invalid QUIC version-negotiation list length")
            }
            Self::RetryMissingIntegrityTag => {
                formatter.write_str("QUIC Retry is shorter than its integrity tag")
            }
            Self::DeclaredPacketLengthExceedsDatagram => {
                formatter.write_str("declared QUIC packet length exceeds UDP payload")
            }
            Self::LengthDoesNotFitPlatform => {
                formatter.write_str("declared QUIC length does not fit this platform")
            }
        }
    }
}

impl std::error::Error for QuicOuterParseError {}

pub fn observe_quic_v1_outer(
    udp_payload: &[u8],
) -> Result<QuicOuterObservation, QuicOuterParseError> {
    if udp_payload.is_empty() {
        return Err(QuicOuterParseError::EmptyDatagram);
    }

    let mut packets = Vec::new();
    let mut cursor = 0;
    while cursor < udp_payload.len() {
        let packet_start = cursor;
        let first = udp_payload[cursor];
        if first & 0x80 == 0 {
            if first & 0x40 == 0 {
                return Err(QuicOuterParseError::InvalidFixedBit);
            }
            packets.push(QuicOuterPacketObservation {
                packet_type: QuicOuterPacketType::Short,
                packet_length: udp_payload.len() - cursor,
                version: None,
                destination_connection_id_length: None,
                source_connection_id_length: None,
                token_length: None,
            });
            break;
        }

        cursor += 1;
        let version = read_u32(udp_payload, &mut cursor, "version")?;
        let destination_connection_id_length =
            take_u8(udp_payload, &mut cursor, "destination connection ID length")?;
        if version == QUIC_V1 {
            validate_connection_id_length(destination_connection_id_length)?;
        }
        take(
            udp_payload,
            &mut cursor,
            usize::from(destination_connection_id_length),
            "destination connection ID",
        )?;
        let source_connection_id_length =
            take_u8(udp_payload, &mut cursor, "source connection ID length")?;
        if version == QUIC_V1 {
            validate_connection_id_length(source_connection_id_length)?;
        }
        take(
            udp_payload,
            &mut cursor,
            usize::from(source_connection_id_length),
            "source connection ID",
        )?;

        if version == 0 {
            let list_length = udp_payload.len() - cursor;
            if list_length == 0 || !list_length.is_multiple_of(4) {
                return Err(QuicOuterParseError::InvalidVersionNegotiationListLength);
            }
            packets.push(QuicOuterPacketObservation {
                packet_type: QuicOuterPacketType::VersionNegotiation,
                packet_length: udp_payload.len() - packet_start,
                version: Some(version),
                destination_connection_id_length: Some(destination_connection_id_length),
                source_connection_id_length: Some(source_connection_id_length),
                token_length: None,
            });
            break;
        }
        if version != QUIC_V1 {
            return Err(QuicOuterParseError::UnsupportedLongHeaderVersion(version));
        }
        if first & 0x40 == 0 {
            return Err(QuicOuterParseError::InvalidFixedBit);
        }

        let packet_type = match (first >> 4) & 0x03 {
            0 => QuicOuterPacketType::Initial,
            1 => QuicOuterPacketType::ZeroRtt,
            2 => QuicOuterPacketType::Handshake,
            3 => QuicOuterPacketType::Retry,
            _ => unreachable!("two-bit QUIC packet type"),
        };

        let token_length = match packet_type {
            QuicOuterPacketType::Initial => {
                let length = read_varint(udp_payload, &mut cursor, "Initial token length")?;
                let length = usize::try_from(length)
                    .map_err(|_| QuicOuterParseError::LengthDoesNotFitPlatform)?;
                take(udp_payload, &mut cursor, length, "Initial token")?;
                Some(length)
            }
            QuicOuterPacketType::Retry => {
                let remaining = udp_payload.len() - cursor;
                if remaining < RETRY_INTEGRITY_TAG_LENGTH {
                    return Err(QuicOuterParseError::RetryMissingIntegrityTag);
                }
                let length = remaining - RETRY_INTEGRITY_TAG_LENGTH;
                packets.push(QuicOuterPacketObservation {
                    packet_type,
                    packet_length: udp_payload.len() - packet_start,
                    version: Some(version),
                    destination_connection_id_length: Some(destination_connection_id_length),
                    source_connection_id_length: Some(source_connection_id_length),
                    token_length: Some(length),
                });
                break;
            }
            QuicOuterPacketType::ZeroRtt | QuicOuterPacketType::Handshake => None,
            QuicOuterPacketType::VersionNegotiation | QuicOuterPacketType::Short => {
                unreachable!("handled before QUIC v1 payload length")
            }
        };

        let payload_length = read_varint(udp_payload, &mut cursor, "payload length")?;
        let payload_length = usize::try_from(payload_length)
            .map_err(|_| QuicOuterParseError::LengthDoesNotFitPlatform)?;
        let packet_end = cursor
            .checked_add(payload_length)
            .ok_or(QuicOuterParseError::DeclaredPacketLengthExceedsDatagram)?;
        if packet_end > udp_payload.len() {
            return Err(QuicOuterParseError::DeclaredPacketLengthExceedsDatagram);
        }
        packets.push(QuicOuterPacketObservation {
            packet_type,
            packet_length: packet_end - packet_start,
            version: Some(version),
            destination_connection_id_length: Some(destination_connection_id_length),
            source_connection_id_length: Some(source_connection_id_length),
            token_length,
        });
        cursor = packet_end;
    }

    Ok(QuicOuterObservation {
        udp_payload_length: udp_payload.len(),
        meets_initial_minimum_size: udp_payload.len() >= 1200,
        packets,
    })
}

fn take_u8(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u8, QuicOuterParseError> {
    let value = *bytes
        .get(*cursor)
        .ok_or(QuicOuterParseError::Truncated(field))?;
    *cursor += 1;
    Ok(value)
}

fn validate_connection_id_length(length: u8) -> Result<(), QuicOuterParseError> {
    if length <= MAX_CONNECTION_ID_LENGTH {
        Ok(())
    } else {
        Err(QuicOuterParseError::InvalidConnectionIdLength)
    }
}

fn read_u32(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u32, QuicOuterParseError> {
    let value = take(bytes, cursor, 4, field)?;
    Ok(u32::from_be_bytes(
        value
            .try_into()
            .expect("take returned the requested four bytes"),
    ))
}

fn read_varint(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u64, QuicOuterParseError> {
    let first = *bytes
        .get(*cursor)
        .ok_or(QuicOuterParseError::Truncated(field))?;
    let length = 1usize << (first >> 6);
    let encoded = take(bytes, cursor, length, field)?;
    let mut value = u64::from(encoded[0] & 0x3f);
    for byte in &encoded[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], QuicOuterParseError> {
    let end = cursor
        .checked_add(length)
        .ok_or(QuicOuterParseError::Truncated(field))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QuicOuterParseError::Truncated(field))?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn current_main_preflight_is_a_network_before_red() {
        let observer_called = AtomicBool::new(false);
        let error = run_after_current_main_preflight(|| {
            observer_called.store(true, Ordering::SeqCst);
        })
        .unwrap_err();

        assert!(!observer_called.load(Ordering::SeqCst));
        assert_eq!(
            error.blockers,
            vec![
                (
                    ObservationSubject::Quiche,
                    PreflightBlocker::CurrentMainQuicheAdapterUnavailable,
                ),
                (
                    ObservationSubject::Chrome,
                    PreflightBlocker::LegacyChromeQuicDisabled,
                ),
            ]
        );
        assert_eq!(
            error.blockers[0].1.to_string(),
            "current main quiche adapter unavailable"
        );
        assert_eq!(
            error.blockers[1].1.to_string(),
            "legacy Chrome QUIC disabled"
        );
    }

    #[test]
    fn observes_a_padded_quic_v1_initial_without_retaining_bytes() {
        let mut datagram = long_header_prefix(0xc0, 1, &[1, 2, 3, 4], &[5, 6]);
        datagram.push(0);
        let payload_length = 1200 - datagram.len() - 2;
        datagram.extend_from_slice(&encode_varint(payload_length as u64));
        datagram.resize(1200, 0xa5);

        let observed = observe_quic_v1_outer(&datagram).unwrap();

        assert_eq!(observed.udp_payload_length, 1200);
        assert!(observed.meets_initial_minimum_size);
        assert_eq!(
            observed.packets,
            vec![QuicOuterPacketObservation {
                packet_type: QuicOuterPacketType::Initial,
                packet_length: 1200,
                version: Some(1),
                destination_connection_id_length: Some(4),
                source_connection_id_length: Some(2),
                token_length: Some(0),
            }]
        );
    }

    #[test]
    fn observes_coalesced_packet_types_lengths_and_initial_token_length() {
        let mut datagram = long_header_prefix(0xc0, 1, &[1, 2], &[3]);
        datagram.push(3);
        datagram.extend_from_slice(&[9, 8, 7]);
        datagram.push(3);
        datagram.extend_from_slice(&[0x11, 0x22, 0x33]);
        let initial_length = datagram.len();

        let handshake = long_packet(0xe0, &[4], &[5, 6], &[0x44, 0x55]);
        let handshake_length = handshake.len();
        datagram.extend_from_slice(&handshake);

        let observed = observe_quic_v1_outer(&datagram).unwrap();

        assert!(!observed.meets_initial_minimum_size);
        assert_eq!(observed.packets.len(), 2);
        assert_eq!(
            observed.packets[0].packet_type,
            QuicOuterPacketType::Initial
        );
        assert_eq!(observed.packets[0].packet_length, initial_length);
        assert_eq!(observed.packets[0].token_length, Some(3));
        assert_eq!(
            observed.packets[1],
            QuicOuterPacketObservation {
                packet_type: QuicOuterPacketType::Handshake,
                packet_length: handshake_length,
                version: Some(1),
                destination_connection_id_length: Some(1),
                source_connection_id_length: Some(2),
                token_length: None,
            }
        );
    }

    #[test]
    fn observes_zero_rtt_and_a_final_short_header_remainder() {
        let mut datagram = long_packet(0xd0, &[1], &[2], &[0x11]);
        let zero_rtt_length = datagram.len();
        datagram.extend_from_slice(&[0x40, 0x22, 0x33]);

        let observed = observe_quic_v1_outer(&datagram).unwrap();

        assert_eq!(
            observed.packets,
            vec![
                QuicOuterPacketObservation {
                    packet_type: QuicOuterPacketType::ZeroRtt,
                    packet_length: zero_rtt_length,
                    version: Some(1),
                    destination_connection_id_length: Some(1),
                    source_connection_id_length: Some(1),
                    token_length: None,
                },
                QuicOuterPacketObservation {
                    packet_type: QuicOuterPacketType::Short,
                    packet_length: 3,
                    version: None,
                    destination_connection_id_length: None,
                    source_connection_id_length: None,
                    token_length: None,
                },
            ]
        );
    }

    #[test]
    fn observes_version_negotiation_and_retry_without_parsing_secret_material() {
        let mut version_negotiation = long_header_prefix(0x80, 0, &[1; 21], &[2; 21]);
        version_negotiation.extend_from_slice(&1u32.to_be_bytes());
        version_negotiation.extend_from_slice(&0x6b33_43cfu32.to_be_bytes());
        let negotiation = observe_quic_v1_outer(&version_negotiation).unwrap();
        assert!(negotiation.contains(QuicOuterPacketType::VersionNegotiation));
        assert_eq!(
            negotiation.packets[0].destination_connection_id_length,
            Some(21)
        );
        assert_eq!(negotiation.packets[0].source_connection_id_length, Some(21));
        assert_eq!(negotiation.packets[0].token_length, None);

        let mut retry = long_header_prefix(0xf0, 1, &[1, 2], &[3]);
        retry.extend_from_slice(&[0x55; 4]);
        retry.extend_from_slice(&[0xaa; RETRY_INTEGRITY_TAG_LENGTH]);
        let observed_retry = observe_quic_v1_outer(&retry).unwrap();
        assert!(observed_retry.contains(QuicOuterPacketType::Retry));
        assert_eq!(observed_retry.packets[0].token_length, Some(4));
    }

    #[test]
    fn malformed_or_out_of_contract_datagrams_fail_closed() {
        assert_eq!(
            observe_quic_v1_outer(&[]),
            Err(QuicOuterParseError::EmptyDatagram)
        );

        let unsupported = long_header_prefix(0xc0, 2, &[], &[]);
        assert_eq!(
            observe_quic_v1_outer(&unsupported),
            Err(QuicOuterParseError::UnsupportedLongHeaderVersion(2))
        );

        let mut too_long = long_header_prefix(0xc0, 1, &[], &[]);
        too_long.push(0);
        too_long.push(4);
        too_long.extend_from_slice(&[0; 3]);
        assert_eq!(
            observe_quic_v1_outer(&too_long),
            Err(QuicOuterParseError::DeclaredPacketLengthExceedsDatagram)
        );

        assert_eq!(
            observe_quic_v1_outer(&[0x00, 0x11]),
            Err(QuicOuterParseError::InvalidFixedBit)
        );

        let long_without_fixed_bit = long_header_prefix(0x80, 1, &[], &[]);
        assert_eq!(
            observe_quic_v1_outer(&long_without_fixed_bit),
            Err(QuicOuterParseError::InvalidFixedBit)
        );

        let destination_too_long = long_header_prefix(0xc0, 1, &[0; 21], &[]);
        assert_eq!(
            observe_quic_v1_outer(&destination_too_long),
            Err(QuicOuterParseError::InvalidConnectionIdLength)
        );

        let source_too_long = long_header_prefix(0xc0, 1, &[], &[0; 21]);
        assert_eq!(
            observe_quic_v1_outer(&source_too_long),
            Err(QuicOuterParseError::InvalidConnectionIdLength)
        );
    }

    #[test]
    fn truncation_and_special_long_header_shapes_fail_closed() {
        assert!(matches!(
            observe_quic_v1_outer(&[0xc0, 0, 0]),
            Err(QuicOuterParseError::Truncated("version"))
        ));

        let mut truncated_connection_id = vec![0xc0];
        truncated_connection_id.extend_from_slice(&1u32.to_be_bytes());
        truncated_connection_id.extend_from_slice(&[2, 0x11]);
        assert!(matches!(
            observe_quic_v1_outer(&truncated_connection_id),
            Err(QuicOuterParseError::Truncated("destination connection ID"))
        ));

        let mut truncated_varint = long_header_prefix(0xc0, 1, &[], &[]);
        truncated_varint.push(0x40);
        assert!(matches!(
            observe_quic_v1_outer(&truncated_varint),
            Err(QuicOuterParseError::Truncated("Initial token length"))
        ));

        let malformed_version_negotiation = long_header_prefix(0x80, 0, &[], &[]);
        assert_eq!(
            observe_quic_v1_outer(&malformed_version_negotiation),
            Err(QuicOuterParseError::InvalidVersionNegotiationListLength)
        );

        let mut short_retry = long_header_prefix(0xf0, 1, &[], &[]);
        short_retry.extend_from_slice(&[0; RETRY_INTEGRITY_TAG_LENGTH - 1]);
        assert_eq!(
            observe_quic_v1_outer(&short_retry),
            Err(QuicOuterParseError::RetryMissingIntegrityTag)
        );
    }

    fn long_packet(first: u8, destination: &[u8], source: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut packet = long_header_prefix(first, 1, destination, source);
        packet.extend_from_slice(&encode_varint(payload.len() as u64));
        packet.extend_from_slice(payload);
        packet
    }

    fn long_header_prefix(first: u8, version: u32, destination: &[u8], source: &[u8]) -> Vec<u8> {
        let mut packet = vec![first];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push(destination.len().try_into().unwrap());
        packet.extend_from_slice(destination);
        packet.push(source.len().try_into().unwrap());
        packet.extend_from_slice(source);
        packet
    }

    fn encode_varint(value: u64) -> Vec<u8> {
        if value < (1 << 6) {
            vec![value as u8]
        } else if value < (1 << 14) {
            let value = (value as u16) | 0x4000;
            value.to_be_bytes().to_vec()
        } else {
            panic!("test helper only needs one- and two-byte QUIC varints")
        }
    }
}
