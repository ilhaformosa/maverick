use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::frame::{Frame, FRAME_HEADER_LEN};

const GRPC_MESSAGE_HEADER_LEN: usize = 5;

pub fn encode_grpc_message(message: Bytes) -> Bytes {
    let mut out = BytesMut::with_capacity(GRPC_MESSAGE_HEADER_LEN + message.len());
    out.put_u8(0);
    out.put_u32(message.len() as u32);
    out.extend_from_slice(&message);
    out.freeze()
}

pub fn encode_grpc_frame(frame: Frame, max_frame_size: usize) -> Result<Bytes> {
    Ok(encode_grpc_message(frame.encode(max_frame_size)?))
}

pub fn decode_grpc_frame_from(buf: &mut BytesMut, max_frame_size: usize) -> Result<Option<Frame>> {
    if buf.len() < GRPC_MESSAGE_HEADER_LEN {
        return Ok(None);
    }
    if buf[0] != 0 {
        return Err(Error::MalformedFrame(
            "compressed grpc messages are unsupported",
        ));
    }

    let message_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let max_message_len = FRAME_HEADER_LEN + max_frame_size;
    if message_len > max_message_len {
        return Err(Error::FrameTooLarge {
            length: message_len,
            max: max_message_len,
        });
    }
    if buf.len() < GRPC_MESSAGE_HEADER_LEN + message_len {
        return Ok(None);
    }

    let _header = buf.split_to(GRPC_MESSAGE_HEADER_LEN);
    let mut message = buf.split_to(message_len);
    let frame = Frame::decode_from(&mut message, max_frame_size)?.ok_or(Error::MalformedFrame(
        "grpc message did not contain a complete frame",
    ))?;
    if !message.is_empty() {
        return Err(Error::MalformedFrame(
            "grpc message contained trailing bytes",
        ));
    }
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[test]
    fn grpc_frame_roundtrip() {
        let original = Frame::new(FrameType::Ping, 0, 7, Bytes::from_static(b"hello"));
        let encoded = encode_grpc_frame(original.clone(), 65_536).unwrap();
        assert_eq!(encoded[0], 0);

        let mut buf = BytesMut::from(encoded.as_ref());
        let decoded = decode_grpc_frame_from(&mut buf, 65_536).unwrap().unwrap();
        assert_eq!(decoded, original);
        assert!(buf.is_empty());
    }

    #[test]
    fn grpc_frame_waits_for_complete_message() {
        let original = Frame::new(FrameType::Ping, 0, 7, Bytes::from_static(b"hello"));
        let encoded = encode_grpc_frame(original, 65_536).unwrap();
        let mut buf = BytesMut::from(&encoded[..encoded.len() - 1]);
        assert!(decode_grpc_frame_from(&mut buf, 65_536).unwrap().is_none());
    }

    #[test]
    fn grpc_frame_rejects_compressed_messages() {
        let original = Frame::new(FrameType::Ping, 0, 7, Bytes::from_static(b"hello"));
        let encoded = encode_grpc_frame(original, 65_536).unwrap();
        let mut encoded = BytesMut::from(encoded.as_ref());
        encoded[0] = 1;
        assert!(matches!(
            decode_grpc_frame_from(&mut encoded, 65_536),
            Err(Error::MalformedFrame(_))
        ));
    }
}
