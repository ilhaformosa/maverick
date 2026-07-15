use bytes::{Buf, BufMut, BytesMut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::config::{Mode, SecretString};
use crate::error::{Error, Result};

pub const PROTOCOL_VERSION: u16 = 1;
pub const AUTH_V2_PROTOCOL_VERSION: u16 = 2;
pub const CLIENT_HELLO_AUTH_LABEL: &[u8] = b"Maverick v1 client hello";
pub const SERVER_HELLO_AUTH_LABEL: &[u8] = b"Maverick v1 server hello";
pub const CLIENT_HELLO_V2_AUTH_LABEL: &[u8] = b"Maverick v2 client hello";
pub const SERVER_HELLO_V2_AUTH_LABEL: &[u8] = b"Maverick v2 server hello";
pub const AUTH_V1_MAX_CREDENTIAL_ID_LEN: usize = 512;
pub const AUTH_V2_MAX_CREDENTIAL_HINT_LEN: usize = 512;
pub const FEATURE_TLS_CHANNEL_BINDING: u64 = 1 << 63;
pub const TLS_CHANNEL_BINDING_EXPORTER_LABEL: &[u8] = b"maverick tls channel binding v1";

const AUTH_V2_EPOCH_SALT_LABEL: &[u8] = b"Maverick auth v2 epoch";
const AUTH_V2_CLIENT_INFO: &[u8] = b"Maverick auth v2 client mac";
const AUTH_V2_SERVER_INFO: &[u8] = b"Maverick auth v2 server mac";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsChannelBinding([u8; 32]);

impl TlsChannelBinding {
    pub fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for TlsChannelBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub client_nonce: [u8; 32],
    pub timestamp_unix: i64,
    pub credential_id: String,
    pub mode: Mode,
    pub feature_flags: u64,
    pub auth_tag: [u8; 32],
}

impl ClientHello {
    pub fn new(
        credential_id: impl Into<String>,
        secret: &SecretString,
        tunnel_path: &str,
        mode: Mode,
        feature_flags: u64,
    ) -> Result<Self> {
        Self::try_new(credential_id, secret, tunnel_path, mode, feature_flags)
    }

    pub fn try_new(
        credential_id: impl Into<String>,
        secret: &SecretString,
        tunnel_path: &str,
        mode: Mode,
        feature_flags: u64,
    ) -> Result<Self> {
        Self::try_new_with_channel_binding(
            credential_id,
            secret,
            tunnel_path,
            mode,
            feature_flags,
            None,
        )
    }

    pub fn try_new_with_channel_binding(
        credential_id: impl Into<String>,
        secret: &SecretString,
        tunnel_path: &str,
        mode: Mode,
        feature_flags: u64,
        channel_binding: Option<TlsChannelBinding>,
    ) -> Result<Self> {
        if feature_flags & FEATURE_TLS_CHANNEL_BINDING != 0 && channel_binding.is_none() {
            return Err(Error::Config(
                "tls channel binding feature flag requires channel binding material".into(),
            ));
        }
        let mut client_nonce = [0u8; 32];
        fill_random(&mut client_nonce)?;
        let timestamp_unix = current_unix();
        let credential_id = credential_id.into();
        let transcript = ClientAuthTranscript {
            version: PROTOCOL_VERSION,
            nonce: &client_nonce,
            timestamp: timestamp_unix,
            credential_id: &credential_id,
            tunnel_path,
            mode,
            feature_flags,
            channel_binding,
        };
        let auth_tag = client_auth_tag(secret, transcript);
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            client_nonce,
            timestamp_unix,
            credential_id,
            mode,
            feature_flags,
            auth_tag,
        })
    }

    pub fn verify(&self, secret: &SecretString, tunnel_path: &str) -> bool {
        self.verify_with_channel_binding(secret, tunnel_path, None)
    }

    pub fn verify_with_channel_binding(
        &self,
        secret: &SecretString,
        tunnel_path: &str,
        channel_binding: Option<TlsChannelBinding>,
    ) -> bool {
        let channel_binding = selected_channel_binding(self.feature_flags, channel_binding);
        let Some(channel_binding) = channel_binding else {
            return false;
        };
        let transcript = ClientAuthTranscript {
            version: self.protocol_version,
            nonce: &self.client_nonce,
            timestamp: self.timestamp_unix,
            credential_id: &self.credential_id,
            tunnel_path,
            mode: self.mode,
            feature_flags: self.feature_flags,
            channel_binding,
        };
        let expected = client_auth_tag(secret, transcript);
        verify_tag(&expected, &self.auth_tag)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            BytesMut::with_capacity(2 + 32 + 8 + 2 + self.credential_id.len() + 1 + 8 + 32);
        out.put_u16(self.protocol_version);
        out.extend_from_slice(&self.client_nonce);
        out.put_i64(self.timestamp_unix);
        put_string(&mut out, &self.credential_id);
        out.put_u8(self.mode.wire_id());
        out.put_u64(self.feature_flags);
        out.extend_from_slice(&self.auth_tag);
        out.to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() < 2 + 32 + 8 + 2 + 1 + 8 + 32 {
            return Err(Error::MalformedFrame("client hello too short"));
        }
        let protocol_version = buf.get_u16();
        let mut client_nonce = [0u8; 32];
        buf.copy_to_slice(&mut client_nonce);
        let timestamp_unix = buf.get_i64();
        let credential_id = get_bounded_string(
            &mut buf,
            AUTH_V1_MAX_CREDENTIAL_ID_LEN,
            "credential id too long",
        )?;
        if buf.remaining() < 1 + 8 + 32 {
            return Err(Error::MalformedFrame("client hello truncated"));
        }
        let mode = Mode::from_wire_id(buf.get_u8())?;
        let feature_flags = buf.get_u64();
        let mut auth_tag = [0u8; 32];
        buf.copy_to_slice(&mut auth_tag);
        if buf.has_remaining() {
            return Err(Error::MalformedFrame("client hello trailing bytes"));
        }
        Ok(Self {
            protocol_version,
            client_nonce,
            timestamp_unix,
            credential_id,
            mode,
            feature_flags,
            auth_tag,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    pub protocol_version_selected: u16,
    pub server_nonce: [u8; 32],
    pub session_id: Vec<u8>,
    pub max_frame_size: u32,
    pub max_concurrent_flows: u32,
    pub feature_flags_selected: u64,
    pub server_auth_tag: [u8; 32],
}

impl ServerHello {
    pub fn new(
        secret: &SecretString,
        client_nonce: &[u8; 32],
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
    ) -> Result<Self> {
        Self::try_new(
            secret,
            client_nonce,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
        )
    }

    pub fn try_new(
        secret: &SecretString,
        client_nonce: &[u8; 32],
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
    ) -> Result<Self> {
        Self::try_new_with_channel_binding(
            secret,
            client_nonce,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            None,
        )
    }

    pub fn try_new_with_channel_binding(
        secret: &SecretString,
        client_nonce: &[u8; 32],
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
        channel_binding: Option<TlsChannelBinding>,
    ) -> Result<Self> {
        if feature_flags_selected & FEATURE_TLS_CHANNEL_BINDING != 0 && channel_binding.is_none() {
            return Err(Error::Config(
                "tls channel binding feature flag requires channel binding material".into(),
            ));
        }
        let mut server_nonce = [0u8; 32];
        let mut session_id = vec![0u8; 16];
        fill_random(&mut server_nonce)?;
        fill_random(&mut session_id)?;
        let transcript = ServerAuthTranscript {
            client_nonce,
            server_nonce: &server_nonce,
            session_id: &session_id,
            protocol_version_selected: PROTOCOL_VERSION,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            channel_binding,
        };
        let tag = server_auth_tag(secret, transcript);
        Ok(Self {
            protocol_version_selected: PROTOCOL_VERSION,
            server_nonce,
            session_id,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            server_auth_tag: tag,
        })
    }

    pub fn verify(&self, secret: &SecretString, client_nonce: &[u8; 32]) -> bool {
        self.verify_with_channel_binding(secret, client_nonce, None)
    }

    pub fn verify_with_channel_binding(
        &self,
        secret: &SecretString,
        client_nonce: &[u8; 32],
        channel_binding: Option<TlsChannelBinding>,
    ) -> bool {
        let channel_binding =
            selected_channel_binding(self.feature_flags_selected, channel_binding);
        let Some(channel_binding) = channel_binding else {
            return false;
        };
        let transcript = ServerAuthTranscript {
            client_nonce,
            server_nonce: &self.server_nonce,
            session_id: &self.session_id,
            protocol_version_selected: self.protocol_version_selected,
            max_frame_size: self.max_frame_size,
            max_concurrent_flows: self.max_concurrent_flows,
            feature_flags_selected: self.feature_flags_selected,
            channel_binding,
        };
        let expected = server_auth_tag(secret, transcript);
        verify_tag(&expected, &self.server_auth_tag)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(2 + 32 + 1 + self.session_id.len() + 4 + 4 + 8 + 32);
        out.put_u16(self.protocol_version_selected);
        out.extend_from_slice(&self.server_nonce);
        out.put_u8(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.put_u32(self.max_frame_size);
        out.put_u32(self.max_concurrent_flows);
        out.put_u64(self.feature_flags_selected);
        out.extend_from_slice(&self.server_auth_tag);
        out.to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() < 2 + 32 + 1 + 4 + 4 + 8 + 32 {
            return Err(Error::MalformedFrame("server hello too short"));
        }
        let protocol_version_selected = buf.get_u16();
        let mut server_nonce = [0u8; 32];
        buf.copy_to_slice(&mut server_nonce);
        let session_len = buf.get_u8() as usize;
        if session_len == 0 || session_len > 32 || buf.remaining() < session_len + 4 + 4 + 8 + 32 {
            return Err(Error::MalformedFrame("bad session id length"));
        }
        let mut session_id = vec![0u8; session_len];
        buf.copy_to_slice(&mut session_id);
        let max_frame_size = buf.get_u32();
        let max_concurrent_flows = buf.get_u32();
        let feature_flags_selected = buf.get_u64();
        let mut server_auth_tag = [0u8; 32];
        buf.copy_to_slice(&mut server_auth_tag);
        if buf.has_remaining() {
            return Err(Error::MalformedFrame("server hello trailing bytes"));
        }
        Ok(Self {
            protocol_version_selected,
            server_nonce,
            session_id,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            server_auth_tag,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloV2 {
    pub protocol_version: u16,
    pub auth_epoch: u64,
    pub client_nonce: [u8; 32],
    pub timestamp_unix: i64,
    pub credential_hint: Vec<u8>,
    pub mode: Mode,
    pub feature_flags: u64,
    pub rotation_flags: u32,
    pub auth_tag: [u8; 32],
}

pub struct ClientHelloV2Params<'a> {
    pub credential_hint: Vec<u8>,
    pub secret: &'a SecretString,
    pub auth_epoch: u64,
    pub tunnel_path: &'a str,
    pub mode: Mode,
    pub feature_flags: u64,
    pub rotation_flags: u32,
    pub channel_binding: Option<TlsChannelBinding>,
}

impl ClientHelloV2 {
    pub fn new(
        credential_hint: impl Into<Vec<u8>>,
        secret: &SecretString,
        auth_epoch: u64,
        tunnel_path: &str,
        mode: Mode,
        feature_flags: u64,
        rotation_flags: u32,
    ) -> Result<Self> {
        Self::new_with_channel_binding(ClientHelloV2Params {
            credential_hint: credential_hint.into(),
            secret,
            auth_epoch,
            tunnel_path,
            mode,
            feature_flags,
            rotation_flags,
            channel_binding: None,
        })
    }

    pub fn new_with_channel_binding(params: ClientHelloV2Params<'_>) -> Result<Self> {
        let ClientHelloV2Params {
            credential_hint,
            secret,
            auth_epoch,
            tunnel_path,
            mode,
            feature_flags,
            rotation_flags,
            channel_binding,
        } = params;
        if feature_flags & FEATURE_TLS_CHANNEL_BINDING != 0 && channel_binding.is_none() {
            return Err(Error::Config(
                "tls channel binding feature flag requires channel binding material".into(),
            ));
        }
        validate_credential_hint(&credential_hint)?;
        let mut client_nonce = [0u8; 32];
        fill_random(&mut client_nonce)?;
        let timestamp_unix = current_unix();
        let transcript = ClientAuthV2Transcript {
            version: AUTH_V2_PROTOCOL_VERSION,
            auth_epoch,
            nonce: &client_nonce,
            timestamp: timestamp_unix,
            credential_hint: &credential_hint,
            tunnel_path,
            mode,
            feature_flags,
            rotation_flags,
            channel_binding,
        };
        let auth_tag = client_auth_v2_tag(secret, transcript)?;
        Ok(Self {
            protocol_version: AUTH_V2_PROTOCOL_VERSION,
            auth_epoch,
            client_nonce,
            timestamp_unix,
            credential_hint,
            mode,
            feature_flags,
            rotation_flags,
            auth_tag,
        })
    }

    pub fn verify(&self, secret: &SecretString, tunnel_path: &str) -> bool {
        self.verify_with_channel_binding(secret, tunnel_path, None)
    }

    pub fn verify_with_channel_binding(
        &self,
        secret: &SecretString,
        tunnel_path: &str,
        channel_binding: Option<TlsChannelBinding>,
    ) -> bool {
        let channel_binding = selected_channel_binding(self.feature_flags, channel_binding);
        let Some(channel_binding) = channel_binding else {
            return false;
        };
        let transcript = ClientAuthV2Transcript {
            version: self.protocol_version,
            auth_epoch: self.auth_epoch,
            nonce: &self.client_nonce,
            timestamp: self.timestamp_unix,
            credential_hint: &self.credential_hint,
            tunnel_path,
            mode: self.mode,
            feature_flags: self.feature_flags,
            rotation_flags: self.rotation_flags,
            channel_binding,
        };
        client_auth_v2_tag(secret, transcript)
            .map(|expected| verify_tag(&expected, &self.auth_tag))
            .unwrap_or(false)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_credential_hint(&self.credential_hint)?;
        let mut out = BytesMut::with_capacity(
            2 + 8 + 32 + 8 + 2 + self.credential_hint.len() + 1 + 8 + 4 + 32,
        );
        out.put_u16(self.protocol_version);
        out.put_u64(self.auth_epoch);
        out.extend_from_slice(&self.client_nonce);
        out.put_i64(self.timestamp_unix);
        put_bytes_u16(&mut out, &self.credential_hint)?;
        out.put_u8(self.mode.wire_id());
        out.put_u64(self.feature_flags);
        out.put_u32(self.rotation_flags);
        out.extend_from_slice(&self.auth_tag);
        Ok(out.to_vec())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() < 2 + 8 + 32 + 8 + 2 + 1 + 8 + 4 + 32 {
            return Err(Error::MalformedFrame("client hello v2 too short"));
        }
        let protocol_version = buf.get_u16();
        let auth_epoch = buf.get_u64();
        let mut client_nonce = [0u8; 32];
        buf.copy_to_slice(&mut client_nonce);
        let timestamp_unix = buf.get_i64();
        let credential_hint = get_bounded_bytes(
            &mut buf,
            AUTH_V2_MAX_CREDENTIAL_HINT_LEN,
            "empty credential hint",
            "credential hint too long",
        )?;
        if buf.remaining() < 1 + 8 + 4 + 32 {
            return Err(Error::MalformedFrame("client hello v2 truncated"));
        }
        let mode = Mode::from_wire_id(buf.get_u8())?;
        let feature_flags = buf.get_u64();
        let rotation_flags = buf.get_u32();
        let mut auth_tag = [0u8; 32];
        buf.copy_to_slice(&mut auth_tag);
        if buf.has_remaining() {
            return Err(Error::MalformedFrame("client hello v2 trailing bytes"));
        }
        Ok(Self {
            protocol_version,
            auth_epoch,
            client_nonce,
            timestamp_unix,
            credential_hint,
            mode,
            feature_flags,
            rotation_flags,
            auth_tag,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHelloV2 {
    pub protocol_version_selected: u16,
    pub selected_epoch: u64,
    pub server_nonce: [u8; 32],
    pub session_id: Vec<u8>,
    pub max_frame_size: u32,
    pub max_concurrent_flows: u32,
    pub feature_flags_selected: u64,
    pub rotation_window_secs: u32,
    pub server_auth_tag: [u8; 32],
}

pub struct ServerHelloV2Params<'a> {
    pub secret: &'a SecretString,
    pub selected_epoch: u64,
    pub client_nonce: &'a [u8; 32],
    pub max_frame_size: u32,
    pub max_concurrent_flows: u32,
    pub feature_flags_selected: u64,
    pub rotation_window_secs: u32,
    pub channel_binding: Option<TlsChannelBinding>,
}

impl ServerHelloV2 {
    pub fn new(
        secret: &SecretString,
        selected_epoch: u64,
        client_nonce: &[u8; 32],
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
        rotation_window_secs: u32,
    ) -> Result<Self> {
        Self::try_new(
            secret,
            selected_epoch,
            client_nonce,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
        )
    }

    pub fn try_new(
        secret: &SecretString,
        selected_epoch: u64,
        client_nonce: &[u8; 32],
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
        rotation_window_secs: u32,
    ) -> Result<Self> {
        Self::try_new_with_channel_binding(ServerHelloV2Params {
            secret,
            selected_epoch,
            client_nonce,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
            channel_binding: None,
        })
    }

    pub fn try_new_with_channel_binding(params: ServerHelloV2Params<'_>) -> Result<Self> {
        let ServerHelloV2Params {
            secret,
            selected_epoch,
            client_nonce,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
            channel_binding,
        } = params;
        if feature_flags_selected & FEATURE_TLS_CHANNEL_BINDING != 0 && channel_binding.is_none() {
            return Err(Error::Config(
                "tls channel binding feature flag requires channel binding material".into(),
            ));
        }
        let mut server_nonce = [0u8; 32];
        let mut session_id = vec![0u8; 16];
        fill_random(&mut server_nonce)?;
        fill_random(&mut session_id)?;
        let transcript = ServerAuthV2Transcript {
            client_nonce,
            server_nonce: &server_nonce,
            session_id: &session_id,
            protocol_version_selected: AUTH_V2_PROTOCOL_VERSION,
            selected_epoch,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
            channel_binding,
        };
        let tag = server_auth_v2_tag(secret, transcript);
        Ok(Self {
            protocol_version_selected: AUTH_V2_PROTOCOL_VERSION,
            selected_epoch,
            server_nonce,
            session_id,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
            server_auth_tag: tag,
        })
    }

    pub fn verify(&self, secret: &SecretString, client_nonce: &[u8; 32]) -> bool {
        self.verify_with_channel_binding(secret, client_nonce, None)
    }

    pub fn verify_with_channel_binding(
        &self,
        secret: &SecretString,
        client_nonce: &[u8; 32],
        channel_binding: Option<TlsChannelBinding>,
    ) -> bool {
        let channel_binding =
            selected_channel_binding(self.feature_flags_selected, channel_binding);
        let Some(channel_binding) = channel_binding else {
            return false;
        };
        let transcript = ServerAuthV2Transcript {
            client_nonce,
            server_nonce: &self.server_nonce,
            session_id: &self.session_id,
            protocol_version_selected: self.protocol_version_selected,
            selected_epoch: self.selected_epoch,
            max_frame_size: self.max_frame_size,
            max_concurrent_flows: self.max_concurrent_flows,
            feature_flags_selected: self.feature_flags_selected,
            rotation_window_secs: self.rotation_window_secs,
            channel_binding,
        };
        server_auth_v2_tag_checked(secret, transcript)
            .map(|expected| verify_tag(&expected, &self.server_auth_tag))
            .unwrap_or(false)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.session_id.is_empty() || self.session_id.len() > 32 {
            return Err(Error::MalformedFrame("bad session id length"));
        }
        let mut out =
            BytesMut::with_capacity(2 + 8 + 32 + 1 + self.session_id.len() + 4 + 4 + 8 + 4 + 32);
        out.put_u16(self.protocol_version_selected);
        out.put_u64(self.selected_epoch);
        out.extend_from_slice(&self.server_nonce);
        out.put_u8(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.put_u32(self.max_frame_size);
        out.put_u32(self.max_concurrent_flows);
        out.put_u64(self.feature_flags_selected);
        out.put_u32(self.rotation_window_secs);
        out.extend_from_slice(&self.server_auth_tag);
        Ok(out.to_vec())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut buf = input;
        if buf.remaining() < 2 + 8 + 32 + 1 + 4 + 4 + 8 + 4 + 32 {
            return Err(Error::MalformedFrame("server hello v2 too short"));
        }
        let protocol_version_selected = buf.get_u16();
        let selected_epoch = buf.get_u64();
        let mut server_nonce = [0u8; 32];
        buf.copy_to_slice(&mut server_nonce);
        let session_len = buf.get_u8() as usize;
        if session_len == 0
            || session_len > 32
            || buf.remaining() < session_len + 4 + 4 + 8 + 4 + 32
        {
            return Err(Error::MalformedFrame("bad session id length"));
        }
        let mut session_id = vec![0u8; session_len];
        buf.copy_to_slice(&mut session_id);
        let max_frame_size = buf.get_u32();
        let max_concurrent_flows = buf.get_u32();
        let feature_flags_selected = buf.get_u64();
        let rotation_window_secs = buf.get_u32();
        let mut server_auth_tag = [0u8; 32];
        buf.copy_to_slice(&mut server_auth_tag);
        if buf.has_remaining() {
            return Err(Error::MalformedFrame("server hello v2 trailing bytes"));
        }
        Ok(Self {
            protocol_version_selected,
            selected_epoch,
            server_nonce,
            session_id,
            max_frame_size,
            max_concurrent_flows,
            feature_flags_selected,
            rotation_window_secs,
            server_auth_tag,
        })
    }
}

pub fn current_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::Random("OS random generator failed"))
}

struct ClientAuthTranscript<'a> {
    version: u16,
    nonce: &'a [u8; 32],
    timestamp: i64,
    credential_id: &'a str,
    tunnel_path: &'a str,
    mode: Mode,
    feature_flags: u64,
    channel_binding: Option<TlsChannelBinding>,
}

fn client_auth_tag(secret: &SecretString, transcript: ClientAuthTranscript<'_>) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(CLIENT_HELLO_AUTH_LABEL);
    mac.update(&transcript.version.to_be_bytes());
    mac.update(transcript.nonce);
    mac.update(&transcript.timestamp.to_be_bytes());
    mac.update(&(transcript.credential_id.len() as u16).to_be_bytes());
    mac.update(transcript.credential_id.as_bytes());
    mac.update(&(transcript.tunnel_path.len() as u16).to_be_bytes());
    mac.update(transcript.tunnel_path.as_bytes());
    mac.update(&[transcript.mode.wire_id()]);
    mac.update(&transcript.feature_flags.to_be_bytes());
    update_channel_binding(&mut mac, transcript.channel_binding);
    mac.finalize().into_bytes().into()
}

struct ServerAuthTranscript<'a> {
    client_nonce: &'a [u8; 32],
    server_nonce: &'a [u8; 32],
    session_id: &'a [u8],
    protocol_version_selected: u16,
    max_frame_size: u32,
    max_concurrent_flows: u32,
    feature_flags_selected: u64,
    channel_binding: Option<TlsChannelBinding>,
}

fn server_auth_tag(secret: &SecretString, transcript: ServerAuthTranscript<'_>) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(SERVER_HELLO_AUTH_LABEL);
    mac.update(transcript.client_nonce);
    mac.update(transcript.server_nonce);
    mac.update(&(transcript.session_id.len() as u8).to_be_bytes());
    mac.update(transcript.session_id);
    mac.update(&transcript.protocol_version_selected.to_be_bytes());
    mac.update(&transcript.max_frame_size.to_be_bytes());
    mac.update(&transcript.max_concurrent_flows.to_be_bytes());
    mac.update(&transcript.feature_flags_selected.to_be_bytes());
    update_channel_binding(&mut mac, transcript.channel_binding);
    mac.finalize().into_bytes().into()
}

struct ClientAuthV2Transcript<'a> {
    version: u16,
    auth_epoch: u64,
    nonce: &'a [u8; 32],
    timestamp: i64,
    credential_hint: &'a [u8],
    tunnel_path: &'a str,
    mode: Mode,
    feature_flags: u64,
    rotation_flags: u32,
    channel_binding: Option<TlsChannelBinding>,
}

fn client_auth_v2_tag(
    secret: &SecretString,
    transcript: ClientAuthV2Transcript<'_>,
) -> Result<[u8; 32]> {
    validate_credential_hint(transcript.credential_hint)?;
    let mut key = auth_v2_epoch_key(secret, transcript.auth_epoch, AUTH_V2_CLIENT_INFO);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    key.zeroize();
    mac.update(CLIENT_HELLO_V2_AUTH_LABEL);
    mac.update(&transcript.version.to_be_bytes());
    mac.update(&transcript.auth_epoch.to_be_bytes());
    mac.update(transcript.nonce);
    mac.update(&transcript.timestamp.to_be_bytes());
    mac.update(&(transcript.credential_hint.len() as u16).to_be_bytes());
    mac.update(transcript.credential_hint);
    mac.update(&(transcript.tunnel_path.len() as u16).to_be_bytes());
    mac.update(transcript.tunnel_path.as_bytes());
    mac.update(&[transcript.mode.wire_id()]);
    mac.update(&transcript.feature_flags.to_be_bytes());
    mac.update(&transcript.rotation_flags.to_be_bytes());
    update_channel_binding(&mut mac, transcript.channel_binding);
    Ok(mac.finalize().into_bytes().into())
}

struct ServerAuthV2Transcript<'a> {
    client_nonce: &'a [u8; 32],
    server_nonce: &'a [u8; 32],
    session_id: &'a [u8],
    protocol_version_selected: u16,
    selected_epoch: u64,
    max_frame_size: u32,
    max_concurrent_flows: u32,
    feature_flags_selected: u64,
    rotation_window_secs: u32,
    channel_binding: Option<TlsChannelBinding>,
}

fn server_auth_v2_tag(secret: &SecretString, transcript: ServerAuthV2Transcript<'_>) -> [u8; 32] {
    server_auth_v2_tag_checked(secret, transcript).expect("generated server hello v2 is valid")
}

fn server_auth_v2_tag_checked(
    secret: &SecretString,
    transcript: ServerAuthV2Transcript<'_>,
) -> Result<[u8; 32]> {
    if transcript.session_id.is_empty() || transcript.session_id.len() > 32 {
        return Err(Error::MalformedFrame("bad session id length"));
    }
    let mut key = auth_v2_epoch_key(secret, transcript.selected_epoch, AUTH_V2_SERVER_INFO);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    key.zeroize();
    mac.update(SERVER_HELLO_V2_AUTH_LABEL);
    mac.update(transcript.client_nonce);
    mac.update(transcript.server_nonce);
    mac.update(&(transcript.session_id.len() as u8).to_be_bytes());
    mac.update(transcript.session_id);
    mac.update(&transcript.protocol_version_selected.to_be_bytes());
    mac.update(&transcript.selected_epoch.to_be_bytes());
    mac.update(&transcript.max_frame_size.to_be_bytes());
    mac.update(&transcript.max_concurrent_flows.to_be_bytes());
    mac.update(&transcript.feature_flags_selected.to_be_bytes());
    mac.update(&transcript.rotation_window_secs.to_be_bytes());
    update_channel_binding(&mut mac, transcript.channel_binding);
    Ok(mac.finalize().into_bytes().into())
}

fn selected_channel_binding(
    feature_flags: u64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<Option<TlsChannelBinding>> {
    if feature_flags & FEATURE_TLS_CHANNEL_BINDING == 0 {
        return Some(None);
    }
    channel_binding.map(Some)
}

fn update_channel_binding(mac: &mut HmacSha256, channel_binding: Option<TlsChannelBinding>) {
    if let Some(channel_binding) = channel_binding {
        mac.update(TLS_CHANNEL_BINDING_EXPORTER_LABEL);
        mac.update(&channel_binding.as_bytes());
    }
}

fn auth_v2_epoch_key(secret: &SecretString, auth_epoch: u64, info: &[u8]) -> [u8; 32] {
    let mut salt = BytesMut::with_capacity(AUTH_V2_EPOCH_SALT_LABEL.len() + 8);
    salt.extend_from_slice(AUTH_V2_EPOCH_SALT_LABEL);
    salt.put_u64(auth_epoch);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret.expose_secret().as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .expect("32-byte HKDF output length is valid");
    salt.zeroize();
    key
}

fn verify_tag(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    expected.ct_eq(actual).into()
}

fn validate_credential_hint(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(Error::MalformedFrame("empty credential hint"));
    }
    if value.len() > AUTH_V2_MAX_CREDENTIAL_HINT_LEN {
        return Err(Error::MalformedFrame("credential hint too long"));
    }
    Ok(())
}

fn put_string(out: &mut BytesMut, value: &str) {
    out.put_u16(value.len() as u16);
    out.extend_from_slice(value.as_bytes());
}

fn put_bytes_u16(out: &mut BytesMut, value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(Error::MalformedFrame("byte string too long"));
    }
    out.put_u16(value.len() as u16);
    out.extend_from_slice(value);
    Ok(())
}

fn get_bounded_string(
    buf: &mut &[u8],
    max_len: usize,
    too_long_error: &'static str,
) -> Result<String> {
    if buf.remaining() < 2 {
        return Err(Error::MalformedFrame("missing string length"));
    }
    let len = buf.get_u16() as usize;
    if len > max_len {
        return Err(Error::MalformedFrame(too_long_error));
    }
    if buf.remaining() < len {
        return Err(Error::MalformedFrame("truncated string"));
    }
    let bytes = buf.copy_to_bytes(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::MalformedFrame("invalid utf-8 string"))
}

fn get_bounded_bytes(
    buf: &mut &[u8],
    max_len: usize,
    empty_error: &'static str,
    too_long_error: &'static str,
) -> Result<Vec<u8>> {
    if buf.remaining() < 2 {
        return Err(Error::MalformedFrame("missing byte string length"));
    }
    let len = buf.get_u16() as usize;
    if len == 0 {
        return Err(Error::MalformedFrame(empty_error));
    }
    if len > max_len {
        return Err(Error::MalformedFrame(too_long_error));
    }
    if buf.remaining() < len {
        return Err(Error::MalformedFrame("truncated byte string"));
    }
    Ok(buf.copy_to_bytes(len).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretString;

    #[test]
    fn verify_tag_accepts_exact_match_and_rejects_mismatch() {
        let expected = [7u8; 32];
        let mut actual = expected;
        assert!(verify_tag(&expected, &actual));
        actual[31] ^= 1;
        assert!(!verify_tag(&expected, &actual));
    }

    #[test]
    fn auth_tag_valid() {
        let secret = SecretString::generate();
        let hello = ClientHello::new("u_abc", &secret, "/assets/upload", Mode::Auto, 0).unwrap();
        assert!(hello.verify(&secret, "/assets/upload"));
    }

    #[test]
    fn auth_tag_invalid_for_path() {
        let secret = SecretString::generate();
        let hello = ClientHello::new("u_abc", &secret, "/assets/upload", Mode::Auto, 0).unwrap();
        assert!(!hello.verify(&secret, "/wrong"));
    }

    #[test]
    fn client_hello_channel_binding_is_bound_to_tag() {
        let secret = SecretString::generate();
        let binding = TlsChannelBinding::new([7u8; 32]);
        let wrong_binding = TlsChannelBinding::new([8u8; 32]);
        let hello = ClientHello::try_new_with_channel_binding(
            "u_abc",
            &secret,
            "/assets/upload",
            Mode::Auto,
            FEATURE_TLS_CHANNEL_BINDING,
            Some(binding),
        )
        .unwrap();

        assert!(hello.verify_with_channel_binding(&secret, "/assets/upload", Some(binding)));
        assert!(!hello.verify(&secret, "/assets/upload"));
        assert!(!hello.verify_with_channel_binding(&secret, "/assets/upload", Some(wrong_binding)));
    }

    #[test]
    fn client_hello_roundtrip() {
        let secret = SecretString::generate();
        let hello = ClientHello::new("u_abc", &secret, "/assets/upload", Mode::Private, 7).unwrap();
        let decoded = ClientHello::decode(&hello.encode()).unwrap();
        assert_eq!(hello, decoded);
    }

    #[test]
    fn client_hello_rejects_oversized_v1_credential_id_before_copy() {
        let mut encoded = BytesMut::new();
        encoded.put_u16(PROTOCOL_VERSION);
        encoded.extend_from_slice(&[0u8; 32]);
        encoded.put_i64(1);
        encoded.put_u16((AUTH_V1_MAX_CREDENTIAL_ID_LEN + 1) as u16);
        encoded.extend_from_slice(&vec![b'a'; AUTH_V1_MAX_CREDENTIAL_ID_LEN + 1]);
        encoded.put_u8(Mode::Auto.wire_id());
        encoded.put_u64(0);
        encoded.extend_from_slice(&[0u8; 32]);

        assert!(matches!(
            ClientHello::decode(&encoded),
            Err(Error::MalformedFrame("credential id too long"))
        ));
    }

    #[test]
    fn server_hello_roundtrip_and_verify() {
        let secret = SecretString::generate();
        let client_nonce = [7u8; 32];
        let hello = ServerHello::new(&secret, &client_nonce, 65_536, 128, 0).unwrap();
        let decoded = ServerHello::decode(&hello.encode()).unwrap();
        assert_eq!(hello, decoded);
        assert!(decoded.verify(&secret, &client_nonce));
    }

    #[test]
    fn server_hello_channel_binding_is_bound_to_tag() {
        let secret = SecretString::generate();
        let client_nonce = [7u8; 32];
        let binding = TlsChannelBinding::new([9u8; 32]);
        let wrong_binding = TlsChannelBinding::new([10u8; 32]);
        let hello = ServerHello::try_new_with_channel_binding(
            &secret,
            &client_nonce,
            65_536,
            128,
            FEATURE_TLS_CHANNEL_BINDING,
            Some(binding),
        )
        .unwrap();

        assert!(hello.verify_with_channel_binding(&secret, &client_nonce, Some(binding)));
        assert!(!hello.verify(&secret, &client_nonce));
        assert!(!hello.verify_with_channel_binding(&secret, &client_nonce, Some(wrong_binding)));
    }

    #[test]
    fn client_hello_v2_roundtrip_and_verify() {
        let secret = SecretString::generate();
        let hello = ClientHelloV2::new(
            b"epoch-hint-2026-07".to_vec(),
            &secret,
            202607,
            "/assets/upload",
            Mode::Private,
            7,
            3,
        )
        .unwrap();
        let encoded = hello.encode().unwrap();
        let decoded = ClientHelloV2::decode(&encoded).unwrap();
        assert_eq!(hello, decoded);
        assert!(decoded.verify(&secret, "/assets/upload"));
        assert!(!decoded.verify(&secret, "/wrong"));
    }

    #[test]
    fn client_hello_v2_epoch_is_bound_to_tag() {
        let secret = SecretString::generate();
        let mut hello = ClientHelloV2::new(
            b"epoch-hint-2026-07".to_vec(),
            &secret,
            202607,
            "/assets/upload",
            Mode::Auto,
            0,
            0,
        )
        .unwrap();
        assert!(hello.verify(&secret, "/assets/upload"));
        hello.auth_epoch += 1;
        assert!(!hello.verify(&secret, "/assets/upload"));
    }

    #[test]
    fn client_hello_v2_channel_binding_is_bound_to_tag() {
        let secret = SecretString::generate();
        let binding = TlsChannelBinding::new([11u8; 32]);
        let wrong_binding = TlsChannelBinding::new([12u8; 32]);
        let hello = ClientHelloV2::new_with_channel_binding(ClientHelloV2Params {
            credential_hint: b"epoch-hint-2026-07".to_vec(),
            secret: &secret,
            auth_epoch: 202607,
            tunnel_path: "/assets/upload",
            mode: Mode::Auto,
            feature_flags: FEATURE_TLS_CHANNEL_BINDING,
            rotation_flags: 0,
            channel_binding: Some(binding),
        })
        .unwrap();

        assert!(hello.verify_with_channel_binding(&secret, "/assets/upload", Some(binding)));
        assert!(!hello.verify(&secret, "/assets/upload"));
        assert!(!hello.verify_with_channel_binding(&secret, "/assets/upload", Some(wrong_binding)));
    }

    #[test]
    fn client_hello_v2_rejects_unbounded_hint() {
        let secret = SecretString::generate();
        assert!(ClientHelloV2::new(
            Vec::<u8>::new(),
            &secret,
            202607,
            "/assets/upload",
            Mode::Auto,
            0,
            0,
        )
        .is_err());
        assert!(ClientHelloV2::new(
            vec![0u8; AUTH_V2_MAX_CREDENTIAL_HINT_LEN + 1],
            &secret,
            202607,
            "/assets/upload",
            Mode::Auto,
            0,
            0,
        )
        .is_err());
    }

    #[test]
    fn server_hello_v2_roundtrip_and_verify() {
        let secret = SecretString::generate();
        let client_nonce = [9u8; 32];
        let hello =
            ServerHelloV2::new(&secret, 202607, &client_nonce, 65_536, 128, 7, 86_400).unwrap();
        let encoded = hello.encode().unwrap();
        let decoded = ServerHelloV2::decode(&encoded).unwrap();
        assert_eq!(hello, decoded);
        assert!(decoded.verify(&secret, &client_nonce));
        assert!(!decoded.verify(&secret, &[8u8; 32]));
    }

    #[test]
    fn server_hello_v2_channel_binding_is_bound_to_tag() {
        let secret = SecretString::generate();
        let client_nonce = [9u8; 32];
        let binding = TlsChannelBinding::new([13u8; 32]);
        let wrong_binding = TlsChannelBinding::new([14u8; 32]);
        let hello = ServerHelloV2::try_new_with_channel_binding(ServerHelloV2Params {
            secret: &secret,
            selected_epoch: 202607,
            client_nonce: &client_nonce,
            max_frame_size: 65_536,
            max_concurrent_flows: 128,
            feature_flags_selected: FEATURE_TLS_CHANNEL_BINDING,
            rotation_window_secs: 86_400,
            channel_binding: Some(binding),
        })
        .unwrap();

        assert!(hello.verify_with_channel_binding(&secret, &client_nonce, Some(binding)));
        assert!(!hello.verify(&secret, &client_nonce));
        assert!(!hello.verify_with_channel_binding(&secret, &client_nonce, Some(wrong_binding)));
    }

    #[test]
    fn server_hello_v2_rejects_bad_session_lengths() {
        let secret = SecretString::generate();
        let client_nonce = [9u8; 32];
        let mut hello =
            ServerHelloV2::new(&secret, 202607, &client_nonce, 65_536, 128, 0, 120).unwrap();
        hello.session_id.clear();
        assert!(hello.encode().is_err());
        hello.session_id = vec![0u8; 33];
        assert!(hello.encode().is_err());
    }
}
