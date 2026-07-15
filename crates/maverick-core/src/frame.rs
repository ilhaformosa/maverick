use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

pub const FRAME_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    OpenTcp = 0x03,
    TcpData = 0x04,
    TcpFin = 0x05,
    TcpReset = 0x06,
    OpenUdp = 0x07,
    UdpPacket = 0x08,
    CloseFlow = 0x09,
    Ping = 0x0A,
    Pong = 0x0B,
    WindowUpdate = 0x0C,
    Error = 0x0D,
    DnsQuery = 0x0E,
    DnsResponse = 0x0F,
    Padding = 0x10,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x03 => Ok(Self::OpenTcp),
            0x04 => Ok(Self::TcpData),
            0x05 => Ok(Self::TcpFin),
            0x06 => Ok(Self::TcpReset),
            0x07 => Ok(Self::OpenUdp),
            0x08 => Ok(Self::UdpPacket),
            0x09 => Ok(Self::CloseFlow),
            0x0A => Ok(Self::Ping),
            0x0B => Ok(Self::Pong),
            0x0C => Ok(Self::WindowUpdate),
            0x0D => Ok(Self::Error),
            0x0E => Ok(Self::DnsQuery),
            0x0F => Ok(Self::DnsResponse),
            0x10 => Ok(Self::Padding),
            other => Err(Error::UnknownFrameType(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub flow_id: u64,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(frame_type: FrameType, flags: u8, flow_id: u64, payload: impl Into<Bytes>) -> Self {
        Self {
            frame_type,
            flags,
            flow_id,
            payload: payload.into(),
        }
    }

    pub fn encode(&self, max_frame_size: usize) -> Result<Bytes> {
        if self.payload.len() > max_frame_size {
            return Err(Error::FrameTooLarge {
                length: self.payload.len(),
                max: max_frame_size,
            });
        }
        let encoded_len = FRAME_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(Error::MalformedFrame("frame length overflow"))?;
        let mut out = BytesMut::with_capacity(encoded_len);
        out.put_u8(self.frame_type as u8);
        out.put_u8(self.flags);
        out.put_u64(self.flow_id);
        out.put_u32(self.payload.len() as u32);
        out.extend_from_slice(&self.payload);
        Ok(out.freeze())
    }

    pub fn decode_from(buf: &mut BytesMut, max_frame_size: usize) -> Result<Option<Self>> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let length = u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]) as usize;
        if length > max_frame_size {
            return Err(Error::FrameTooLarge {
                length,
                max: max_frame_size,
            });
        }
        let encoded_len = FRAME_HEADER_LEN
            .checked_add(length)
            .ok_or(Error::MalformedFrame("frame length overflow"))?;
        if buf.len() < encoded_len {
            return Ok(None);
        }
        let frame_type = FrameType::try_from(buf[0])?;
        let mut header = buf.split_to(FRAME_HEADER_LEN);
        header.advance(1);
        let flags = header.get_u8();
        let flow_id = header.get_u64();
        let payload_len = header.get_u32() as usize;
        let payload = buf.split_to(payload_len).freeze();
        Ok(Some(Self {
            frame_type,
            flags,
            flow_id,
            payload,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetAddr {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl TargetAddr {
    pub fn to_authority(&self, port: u16) -> String {
        match self {
            Self::Domain(host) => format!("{host}:{port}"),
            Self::Ipv4(addr) => format!("{addr}:{port}"),
            Self::Ipv6(addr) => format!("[{addr}]:{port}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenTcpPayload {
    pub target: TargetAddr,
    pub port: u16,
    pub initial_data: Bytes,
}

impl OpenTcpPayload {
    pub fn new(target: TargetAddr, port: u16) -> Self {
        Self {
            target,
            port,
            initial_data: Bytes::new(),
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::new();
        match &self.target {
            TargetAddr::Domain(host) => {
                if host.len() > u16::MAX as usize {
                    return Err(Error::MalformedFrame("domain too long"));
                }
                out.put_u8(0x03);
                out.put_u16(host.len() as u16);
                out.extend_from_slice(host.as_bytes());
            }
            TargetAddr::Ipv4(addr) => {
                out.put_u8(0x01);
                out.extend_from_slice(&addr.octets());
            }
            TargetAddr::Ipv6(addr) => {
                out.put_u8(0x04);
                out.extend_from_slice(&addr.octets());
            }
        }
        out.put_u16(self.port);
        out.put_u32(self.initial_data.len() as u32);
        out.extend_from_slice(&self.initial_data);
        Ok(out.freeze())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if !buf.has_remaining() {
            return Err(Error::MalformedFrame("missing address type"));
        }
        let target = match buf.get_u8() {
            0x01 => {
                if buf.remaining() < 4 {
                    return Err(Error::MalformedFrame("truncated ipv4 address"));
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                TargetAddr::Ipv4(Ipv4Addr::from(octets))
            }
            0x03 => {
                if buf.remaining() < 2 {
                    return Err(Error::MalformedFrame("missing domain length"));
                }
                let len = buf.get_u16() as usize;
                if len == 0 || buf.remaining() < len {
                    return Err(Error::MalformedFrame("truncated domain"));
                }
                let bytes = buf.copy_to_bytes(len);
                let host = String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::MalformedFrame("domain is not utf-8"))?;
                TargetAddr::Domain(host)
            }
            0x04 => {
                if buf.remaining() < 16 {
                    return Err(Error::MalformedFrame("truncated ipv6 address"));
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                TargetAddr::Ipv6(Ipv6Addr::from(octets))
            }
            _ => return Err(Error::MalformedFrame("unknown address type")),
        };
        if buf.remaining() < 2 + 4 {
            return Err(Error::MalformedFrame("truncated open tcp payload"));
        }
        let port = buf.get_u16();
        let initial_len = buf.get_u32() as usize;
        if buf.remaining() < initial_len {
            return Err(Error::MalformedFrame("truncated initial data"));
        }
        let initial_data = buf.copy_to_bytes(initial_len);
        if buf.has_remaining() {
            return Err(Error::MalformedFrame("open tcp trailing bytes"));
        }
        Ok(Self {
            target,
            port,
            initial_data,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacketPayload {
    pub target: TargetAddr,
    pub port: u16,
    pub data: Bytes,
}

impl UdpPacketPayload {
    pub fn new(target: TargetAddr, port: u16, data: impl Into<Bytes>) -> Self {
        Self {
            target,
            port,
            data: data.into(),
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let tcp_like = OpenTcpPayload {
            target: self.target.clone(),
            port: self.port,
            initial_data: self.data.clone(),
        };
        tcp_like.encode()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let decoded = OpenTcpPayload::decode(input)?;
        Ok(Self {
            target: decoded.target,
            port: decoded.port,
            data: decoded.initial_data,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenUdpPayload {
    pub idle_timeout_ms: u64,
}

impl OpenUdpPayload {
    pub fn new(idle_timeout_ms: u64) -> Self {
        Self { idle_timeout_ms }
    }

    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(8);
        out.put_u64(self.idle_timeout_ms);
        out.freeze()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() != 8 {
            return Err(Error::MalformedFrame("invalid open udp payload"));
        }
        Ok(Self {
            idle_timeout_ms: buf.get_u64(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    TargetConnectFailed = 1,
    FlowNotFound = 2,
    FlowLimitExceeded = 3,
    ProtocolError = 4,
    InternalError = 5,
}

impl ErrorCode {
    pub fn encode(self) -> Bytes {
        let mut out = BytesMut::with_capacity(2);
        out.put_u16(self as u16);
        out.freeze()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() != 2 {
            return Err(Error::MalformedFrame("invalid error code payload"));
        }
        match buf.get_u16() {
            1 => Ok(Self::TargetConnectFailed),
            2 => Ok(Self::FlowNotFound),
            3 => Ok(Self::FlowLimitExceeded),
            4 => Ok(Self::ProtocolError),
            5 => Ok(Self::InternalError),
            _ => Err(Error::MalformedFrame("unknown error code")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame::new(FrameType::TcpData, 0, 42, Bytes::from_static(b"hello"));
        let encoded = frame.encode(1024).unwrap();
        let mut buf = BytesMut::from(encoded.as_ref());
        let decoded = Frame::decode_from(&mut buf, 1024).unwrap().unwrap();
        assert_eq!(frame, decoded);
        assert!(buf.is_empty());
    }

    #[test]
    fn padding_frame_roundtrip() {
        let frame = Frame::new(FrameType::Padding, 0, 0, Bytes::from_static(b"noise"));
        let encoded = frame.encode(1024).unwrap();
        let mut buf = BytesMut::from(encoded.as_ref());
        let decoded = Frame::decode_from(&mut buf, 1024).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn malformed_frame_length_rejected() {
        let frame = Frame::new(FrameType::TcpData, 0, 42, Bytes::from_static(b"hello"));
        assert!(frame.encode(4).is_err());
    }

    #[test]
    fn oversized_configured_frame_length_does_not_overflow() {
        let mut buf = BytesMut::new();
        buf.put_u8(FrameType::TcpData as u8);
        buf.put_u8(0);
        buf.put_u64(1);
        buf.put_u32(u32::MAX);

        assert!(Frame::decode_from(&mut buf, usize::MAX).is_ok());
        assert_eq!(buf.len(), FRAME_HEADER_LEN);
    }

    #[test]
    fn unknown_frame_type_does_not_consume_buffer() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xff);
        buf.put_u8(0);
        buf.put_u64(1);
        buf.put_u32(0);
        let before = buf.clone();

        assert!(matches!(
            Frame::decode_from(&mut buf, 1024),
            Err(Error::UnknownFrameType(0xff))
        ));
        assert_eq!(buf, before);
    }

    #[test]
    fn open_tcp_domain_roundtrip() {
        let payload = OpenTcpPayload::new(TargetAddr::Domain("example.com".into()), 443);
        let decoded = OpenTcpPayload::decode(&payload.encode().unwrap()).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn udp_packet_roundtrip() {
        let payload = UdpPacketPayload::new(
            TargetAddr::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            53,
            Bytes::from_static(b"dns"),
        );
        let decoded = UdpPacketPayload::decode(&payload.encode().unwrap()).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn open_udp_roundtrip() {
        let payload = OpenUdpPayload::new(30_000);
        let decoded = OpenUdpPayload::decode(&payload.encode()).unwrap();
        assert_eq!(payload, decoded);
        assert!(OpenUdpPayload::decode(&[]).is_err());
    }

    #[test]
    fn error_code_roundtrip() {
        let encoded = ErrorCode::FlowLimitExceeded.encode();
        assert_eq!(
            ErrorCode::decode(&encoded).unwrap(),
            ErrorCode::FlowLimitExceeded
        );
        assert!(ErrorCode::decode(&[0, 99]).is_err());
    }

    proptest! {
        #[test]
        fn random_bytes_do_not_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut buf = BytesMut::from(data.as_slice());
            let _ = Frame::decode_from(&mut buf, 64 * 1024);
        }
    }
}
