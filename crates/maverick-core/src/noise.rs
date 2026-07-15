use bytes::{Buf, BufMut, Bytes, BytesMut};
use snow::params::NoiseParams;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{NoisePrologueContext, NoiseTransportContext};
use crate::error::{Error, Result};
use crate::frame::{Frame, FRAME_HEADER_LEN};

pub const NOISE_XX_25519_CHACHAPOLY_SHA256: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const NOISE_MESSAGE_LEN_SIZE: usize = 2;
pub const MAX_NOISE_MESSAGE_SIZE: usize = u16::MAX as usize;
pub const NOISE_TRANSPORT_TAG_SIZE: usize = 16;
pub const MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE: usize =
    MAX_NOISE_MESSAGE_SIZE - NOISE_TRANSPORT_TAG_SIZE;
pub const DEFAULT_NOISE_RUNTIME_MAX_FRAME_SIZE: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoiseRuntimeConfig {
    pub transport_context: NoiseTransportContext,
    pub local_static_private: [u8; 32],
    pub expected_remote_static_public: Option<[u8; 32]>,
    pub max_frame_size: usize,
}

impl NoiseRuntimeConfig {
    pub fn native_no_domain_research(local_static_private: [u8; 32]) -> Self {
        Self {
            transport_context: NoiseTransportContext::NativeNoDomainResearch,
            local_static_private,
            expected_remote_static_public: None,
            max_frame_size: DEFAULT_NOISE_RUNTIME_MAX_FRAME_SIZE,
        }
    }

    pub fn with_expected_remote_static_public(mut self, expected: [u8; 32]) -> Self {
        self.expected_remote_static_public = Some(expected);
        self
    }

    pub fn with_transport_context(mut self, transport_context: NoiseTransportContext) -> Self {
        self.transport_context = transport_context;
        self
    }

    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    pub fn prologue_context(&self) -> NoisePrologueContext {
        NoisePrologueContext::xx25519_chachapoly_v1(self.transport_context)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_frame_size == 0 {
            return Err(Error::Config(
                "noise runtime max_frame_size must not be zero".into(),
            ));
        }
        let plaintext_len = self
            .max_frame_size
            .checked_add(FRAME_HEADER_LEN)
            .ok_or_else(|| Error::Config("noise runtime max_frame_size overflow".into()))?;
        if plaintext_len > MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE {
            return Err(Error::Config(format!(
                "noise runtime max_frame_size exceeds transport plaintext limit {MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE}"
            )));
        }
        Ok(())
    }
}

impl Drop for NoiseRuntimeConfig {
    fn drop(&mut self) {
        self.local_static_private.zeroize();
    }
}

pub struct NoiseInitiator {
    handshake: snow::HandshakeState,
    config: NoiseRuntimeConfig,
}

pub struct NoiseResponder {
    handshake: snow::HandshakeState,
    config: NoiseRuntimeConfig,
}

pub struct NoiseHandshakeOutput {
    pub message: Bytes,
    pub transport: NoiseTransportSession,
}

pub struct NoiseTransportSession {
    transport: snow::TransportState,
    max_frame_size: usize,
}

impl NoiseInitiator {
    pub fn new(config: NoiseRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let handshake = build_handshake(&config, NoiseRole::Initiator)?;
        Ok(Self { handshake, config })
    }

    pub fn write_message_1(&mut self) -> Result<Bytes> {
        write_handshake_message(&mut self.handshake)
    }

    pub fn read_message_2(&mut self, message: &[u8]) -> Result<()> {
        read_empty_handshake_payload(&mut self.handshake, message)?;
        verify_expected_remote_static(&self.handshake, &self.config)
    }

    pub fn write_message_3(mut self) -> Result<NoiseHandshakeOutput> {
        let message = write_handshake_message(&mut self.handshake)?;
        let transport = self.handshake.into_transport_mode().map_err(noise_error)?;
        Ok(NoiseHandshakeOutput {
            message,
            transport: NoiseTransportSession {
                transport,
                max_frame_size: self.config.max_frame_size,
            },
        })
    }
}

impl NoiseResponder {
    pub fn new(config: NoiseRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let handshake = build_handshake(&config, NoiseRole::Responder)?;
        Ok(Self { handshake, config })
    }

    pub fn read_message_1(&mut self, message: &[u8]) -> Result<()> {
        read_empty_handshake_payload(&mut self.handshake, message)
    }

    pub fn write_message_2(&mut self) -> Result<Bytes> {
        write_handshake_message(&mut self.handshake)
    }

    pub fn read_message_3(mut self, message: &[u8]) -> Result<NoiseTransportSession> {
        read_empty_handshake_payload(&mut self.handshake, message)?;
        verify_expected_remote_static(&self.handshake, &self.config)?;
        let transport = self.handshake.into_transport_mode().map_err(noise_error)?;
        Ok(NoiseTransportSession {
            transport,
            max_frame_size: self.config.max_frame_size,
        })
    }
}

impl NoiseTransportSession {
    pub fn encrypt_frame(&mut self, frame: Frame) -> Result<Bytes> {
        let plaintext = frame.encode(self.max_frame_size)?;
        if plaintext.len() > MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE {
            return Err(Error::FrameTooLarge {
                length: plaintext.len(),
                max: MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE,
            });
        }
        let mut ciphertext = vec![0u8; plaintext.len() + NOISE_TRANSPORT_TAG_SIZE];
        let len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(noise_error)?;
        encode_noise_message(&ciphertext[..len])
    }

    pub fn decrypt_next_frame(&mut self, input: &mut BytesMut) -> Result<Option<Frame>> {
        let Some(ciphertext) = decode_noise_message_from(input)? else {
            return Ok(None);
        };
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(noise_error)?;
        let mut frame_buf = BytesMut::from(&plaintext[..len]);
        let frame = Frame::decode_from(&mut frame_buf, self.max_frame_size)?
            .ok_or(Error::MalformedFrame("truncated decrypted noise frame"))?;
        if !frame_buf.is_empty() {
            return Err(Error::MalformedFrame(
                "decrypted noise frame has trailing bytes",
            ));
        }
        Ok(Some(frame))
    }

    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }
}

pub fn encode_noise_message(message: &[u8]) -> Result<Bytes> {
    if message.len() > MAX_NOISE_MESSAGE_SIZE {
        return Err(Error::FrameTooLarge {
            length: message.len(),
            max: MAX_NOISE_MESSAGE_SIZE,
        });
    }
    let mut out = BytesMut::with_capacity(NOISE_MESSAGE_LEN_SIZE + message.len());
    out.put_u16(message.len() as u16);
    out.extend_from_slice(message);
    Ok(out.freeze())
}

pub fn decode_noise_message_from(input: &mut BytesMut) -> Result<Option<Bytes>> {
    if input.len() < NOISE_MESSAGE_LEN_SIZE {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() < NOISE_MESSAGE_LEN_SIZE + message_len {
        return Ok(None);
    }
    input.advance(NOISE_MESSAGE_LEN_SIZE);
    Ok(Some(input.split_to(message_len).freeze()))
}

pub fn noise_static_public_key(mut private: [u8; 32]) -> Result<[u8; 32]> {
    let params = noise_params()?;
    let resolver = DefaultResolver;
    let mut dh = resolver
        .resolve_dh(&params.dh)
        .ok_or_else(|| Error::Noise("missing Snow 25519 resolver".into()))?;
    dh.set(&private);
    private.zeroize();
    let public = dh.pubkey();
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| Error::Noise("unexpected Snow 25519 public key length".into()))?;
    Ok(public)
}

fn build_handshake(config: &NoiseRuntimeConfig, role: NoiseRole) -> Result<snow::HandshakeState> {
    let prologue = config.prologue_context().canonical_prologue();
    let mut local_static_private = config.local_static_private;
    let builder = snow::Builder::new(noise_params()?)
        .local_private_key(&local_static_private)
        .map_err(noise_error)?
        .prologue(&prologue)
        .map_err(noise_error)?;
    local_static_private.zeroize();
    match role {
        NoiseRole::Initiator => builder.build_initiator().map_err(noise_error),
        NoiseRole::Responder => builder.build_responder().map_err(noise_error),
    }
}

fn noise_params() -> Result<NoiseParams> {
    NOISE_XX_25519_CHACHAPOLY_SHA256
        .parse()
        .map_err(noise_error)
}

fn write_handshake_message(handshake: &mut snow::HandshakeState) -> Result<Bytes> {
    let mut out = [0u8; 1024];
    let len = handshake
        .write_message(&[], &mut out)
        .map_err(noise_error)?;
    Ok(Bytes::copy_from_slice(&out[..len]))
}

fn read_empty_handshake_payload(
    handshake: &mut snow::HandshakeState,
    message: &[u8],
) -> Result<()> {
    let mut payload = [0u8; 1024];
    let len = handshake
        .read_message(message, &mut payload)
        .map_err(noise_error)?;
    if len != 0 {
        return Err(Error::MalformedFrame(
            "noise handshake payloads must be empty",
        ));
    }
    Ok(())
}

fn verify_expected_remote_static(
    handshake: &snow::HandshakeState,
    config: &NoiseRuntimeConfig,
) -> Result<()> {
    let Some(expected) = config.expected_remote_static_public else {
        return Ok(());
    };
    let actual = handshake
        .get_remote_static()
        .ok_or_else(|| Error::Noise("missing remote Noise static key".into()))?;
    if actual.ct_eq(expected.as_slice()).into() {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}

fn noise_error(err: snow::Error) -> Error {
    Error::Noise(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameType, TargetAddr};
    use crate::OpenTcpPayload;

    #[test]
    fn noise_static_public_key_is_stable_for_fixed_private_key() {
        let public = noise_static_public_key(sequential_key(0x20)).unwrap();
        assert_eq!(
            hex_encode(public),
            "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        );
    }

    #[test]
    fn noise_runtime_pair_roundtrips_maverick_frames() {
        let (mut initiator_transport, mut responder_transport) = handshake_pair(
            NoiseTransportContext::NativeNoDomainResearch,
            NoiseTransportContext::NativeNoDomainResearch,
        )
        .unwrap();

        let open = OpenTcpPayload::new(TargetAddr::Domain("example.com".into()), 443);
        let encrypted = initiator_transport
            .encrypt_frame(Frame::new(FrameType::OpenTcp, 0, 7, open.encode().unwrap()))
            .unwrap();
        let mut incoming = BytesMut::from(encrypted.as_ref());
        let decoded = responder_transport
            .decrypt_next_frame(&mut incoming)
            .unwrap()
            .unwrap();
        assert!(incoming.is_empty());
        assert_eq!(decoded.frame_type, FrameType::OpenTcp);
        assert_eq!(decoded.flow_id, 7);
        assert_eq!(OpenTcpPayload::decode(&decoded.payload).unwrap(), open);

        let encrypted = responder_transport
            .encrypt_frame(Frame::new(
                FrameType::TcpData,
                0,
                7,
                Bytes::from_static(b"noise response"),
            ))
            .unwrap();
        let mut incoming = BytesMut::from(encrypted.as_ref());
        let decoded = initiator_transport
            .decrypt_next_frame(&mut incoming)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.frame_type, FrameType::TcpData);
        assert_eq!(decoded.payload.as_ref(), b"noise response");
    }

    #[test]
    fn noise_runtime_rejects_wrong_expected_remote_static() {
        let initiator_static = sequential_key(0x00);
        let responder_static = sequential_key(0x20);
        let wrong_public = noise_static_public_key(sequential_key(0x40)).unwrap();
        let mut initiator = NoiseInitiator::new(
            NoiseRuntimeConfig::native_no_domain_research(initiator_static)
                .with_expected_remote_static_public(wrong_public),
        )
        .unwrap();
        let mut responder = NoiseResponder::new(NoiseRuntimeConfig::native_no_domain_research(
            responder_static,
        ))
        .unwrap();

        let message_1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&message_1).unwrap();
        let message_2 = responder.write_message_2().unwrap();
        assert!(matches!(
            initiator.read_message_2(&message_2),
            Err(Error::Auth)
        ));
    }

    #[test]
    fn noise_runtime_rejects_transport_context_mismatch() {
        let mut initiator = NoiseInitiator::new(NoiseRuntimeConfig::native_no_domain_research(
            sequential_key(0x00),
        ))
        .unwrap();
        let mut responder = NoiseResponder::new(
            NoiseRuntimeConfig::native_no_domain_research(sequential_key(0x20))
                .with_transport_context(NoiseTransportContext::H2),
        )
        .unwrap();

        let message_1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&message_1).unwrap();
        let message_2 = responder.write_message_2().unwrap();
        assert!(initiator.read_message_2(&message_2).is_err());
    }

    #[test]
    fn noise_transport_decodes_fragmented_envelopes() {
        let (mut initiator_transport, mut responder_transport) = handshake_pair(
            NoiseTransportContext::NativeNoDomainResearch,
            NoiseTransportContext::NativeNoDomainResearch,
        )
        .unwrap();
        let encrypted = initiator_transport
            .encrypt_frame(Frame::new(
                FrameType::TcpData,
                0,
                9,
                Bytes::from_static(b"fragmented"),
            ))
            .unwrap();

        let split_at = 3;
        let mut incoming = BytesMut::from(&encrypted[..split_at]);
        assert!(responder_transport
            .decrypt_next_frame(&mut incoming)
            .unwrap()
            .is_none());
        incoming.extend_from_slice(&encrypted[split_at..]);
        let decoded = responder_transport
            .decrypt_next_frame(&mut incoming)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.payload.as_ref(), b"fragmented");
    }

    #[test]
    fn noise_transport_rejects_oversize_plaintext_before_encrypt() {
        let (mut initiator_transport, _) = handshake_pair(
            NoiseTransportContext::NativeNoDomainResearch,
            NoiseTransportContext::NativeNoDomainResearch,
        )
        .unwrap();
        let too_large = vec![0u8; DEFAULT_NOISE_RUNTIME_MAX_FRAME_SIZE + 1];
        let err = initiator_transport
            .encrypt_frame(Frame::new(FrameType::TcpData, 0, 1, too_large))
            .unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }));
    }

    #[test]
    fn noise_message_envelope_roundtrips_without_consuming_partial_input() {
        let encoded = encode_noise_message(b"abc").unwrap();
        let mut partial = BytesMut::from(&encoded[..encoded.len() - 1]);
        let before = partial.clone();
        assert!(decode_noise_message_from(&mut partial).unwrap().is_none());
        assert_eq!(partial, before);

        partial.extend_from_slice(&encoded[encoded.len() - 1..]);
        assert_eq!(
            decode_noise_message_from(&mut partial).unwrap().unwrap(),
            Bytes::from_static(b"abc")
        );
        assert!(partial.is_empty());
    }

    fn handshake_pair(
        initiator_context: NoiseTransportContext,
        responder_context: NoiseTransportContext,
    ) -> Result<(NoiseTransportSession, NoiseTransportSession)> {
        let initiator_static = sequential_key(0x00);
        let responder_static = sequential_key(0x20);
        let initiator_public = noise_static_public_key(initiator_static)?;
        let responder_public = noise_static_public_key(responder_static)?;
        let mut initiator = NoiseInitiator::new(
            NoiseRuntimeConfig::native_no_domain_research(initiator_static)
                .with_transport_context(initiator_context)
                .with_expected_remote_static_public(responder_public),
        )?;
        let mut responder = NoiseResponder::new(
            NoiseRuntimeConfig::native_no_domain_research(responder_static)
                .with_transport_context(responder_context)
                .with_expected_remote_static_public(initiator_public),
        )?;
        let message_1 = initiator.write_message_1()?;
        responder.read_message_1(&message_1)?;
        let message_2 = responder.write_message_2()?;
        initiator.read_message_2(&message_2)?;
        let output = initiator.write_message_3()?;
        let responder_transport = responder.read_message_3(&output.message)?;
        Ok((output.transport, responder_transport))
    }

    fn sequential_key(start: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (offset, byte) in key.iter_mut().enumerate() {
            *byte = start + u8::try_from(offset).unwrap();
        }
        key
    }

    fn hex_encode(input: impl AsRef<[u8]>) -> String {
        input
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}
