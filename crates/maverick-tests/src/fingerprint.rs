use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TlsClientHelloObservation {
    pub legacy_version: u16,
    pub record_lengths: Vec<usize>,
    pub handshake_length: usize,
    pub session_id_length: usize,
    pub cipher_suites: Vec<u16>,
    pub normalized_cipher_suites: Vec<u16>,
    pub extension_order: Vec<u16>,
    pub normalized_extension_order: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub normalized_supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub normalized_signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub normalized_supported_versions: Vec<u16>,
    pub alpn_protocols: Vec<String>,
    pub server_name_present: bool,
    pub ja3_input: String,
    pub ja4_inputs: Ja4Inputs,
    pub observed_sha256: String,
    pub normalized_set_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ja4Inputs {
    pub transport: String,
    pub highest_supported_version: Option<u16>,
    pub server_name_present: bool,
    pub cipher_count: usize,
    pub extension_count: usize,
    pub first_alpn: Option<String>,
    pub sorted_ciphers: Vec<u16>,
    pub sorted_extensions_without_sni_alpn: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct H2ClientPrefaceObservation {
    pub preface_present: bool,
    pub frames: Vec<H2FrameObservation>,
    pub settings: Vec<H2SettingObservation>,
    pub connection_window_updates: Vec<u32>,
    pub observed_sha256: String,
    pub normalized_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct H2FrameObservation {
    pub frame_type: u8,
    pub frame_type_name: String,
    pub flags: u8,
    pub stream_id: u32,
    pub payload_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct H2SettingObservation {
    pub id: u16,
    pub name: String,
    pub value: u32,
}

pub fn parse_tls_client_hello(stream: &[u8]) -> Result<TlsClientHelloObservation> {
    let (handshake, record_lengths) = collect_client_hello_handshake(stream)?;
    let mut cursor = Cursor::new(&handshake);
    let handshake_type = cursor.read_u8()?;
    if handshake_type != CLIENT_HELLO_HANDSHAKE_TYPE {
        bail!("first TLS handshake message is not ClientHello");
    }
    let handshake_length = cursor.read_u24()? as usize;
    let body = cursor.read_exact(handshake_length)?;
    let mut hello = Cursor::new(body);

    let legacy_version = hello.read_u16()?;
    hello.skip(32).context("ClientHello random is truncated")?;
    let session_id_length = hello.read_u8()? as usize;
    hello
        .skip(session_id_length)
        .context("ClientHello session id is truncated")?;

    let cipher_bytes = hello.read_u16()? as usize;
    if !cipher_bytes.is_multiple_of(2) {
        bail!("ClientHello cipher suite list has odd length");
    }
    let cipher_suites = read_u16_list(hello.read_exact(cipher_bytes)?)?;

    let compression_length = hello.read_u8()? as usize;
    hello
        .skip(compression_length)
        .context("ClientHello compression list is truncated")?;

    let mut extension_order = Vec::new();
    let mut supported_groups = Vec::new();
    let mut point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut supported_versions = Vec::new();
    let mut alpn_protocols = Vec::new();
    let mut server_name_present = false;

    if hello.remaining() > 0 {
        let extension_bytes = hello.read_u16()? as usize;
        let mut extensions = Cursor::new(hello.read_exact(extension_bytes)?);
        while extensions.remaining() > 0 {
            let extension_id = extensions.read_u16()?;
            let extension_length = extensions.read_u16()? as usize;
            let extension = extensions.read_exact(extension_length)?;
            extension_order.push(extension_id);
            match extension_id {
                0 => server_name_present = parse_sni_presence(extension)?,
                10 => supported_groups = parse_u16_vector(extension)?,
                11 => point_formats = parse_u8_vector(extension)?,
                13 => signature_algorithms = parse_u16_vector(extension)?,
                16 => alpn_protocols = parse_alpn(extension)?,
                43 => supported_versions = parse_u16_vector_u8_length(extension)?,
                _ => {}
            }
        }
    }

    let normalized_cipher_suites = without_grease(&cipher_suites);
    let normalized_extension_order = without_grease(&extension_order);
    let normalized_supported_groups = without_grease(&supported_groups);
    let normalized_signature_algorithms = without_grease(&signature_algorithms);
    let normalized_supported_versions = without_grease(&supported_versions);
    let ja3_input = format!(
        "{},{},{},{},{}",
        legacy_version,
        join_u16(&normalized_cipher_suites, "-"),
        join_u16(&normalized_extension_order, "-"),
        join_u16(&normalized_supported_groups, "-"),
        point_formats
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    );

    let mut sorted_ciphers = normalized_cipher_suites.clone();
    sorted_ciphers.sort_unstable();
    let mut sorted_extensions_without_sni_alpn = normalized_extension_order
        .iter()
        .copied()
        .filter(|extension| !matches!(extension, 0 | 16))
        .collect::<Vec<_>>();
    sorted_extensions_without_sni_alpn.sort_unstable();
    let highest_supported_version = normalized_supported_versions.iter().copied().max();
    let ja4_inputs = Ja4Inputs {
        transport: "tcp".into(),
        highest_supported_version,
        server_name_present,
        cipher_count: normalized_cipher_suites.len(),
        extension_count: normalized_extension_order.len(),
        first_alpn: alpn_protocols.first().cloned(),
        sorted_ciphers,
        sorted_extensions_without_sni_alpn,
        signature_algorithms: normalized_signature_algorithms.clone(),
    };
    let observed_input = format!(
        "ja3={ja3_input};versions={};sig={};alpn={}",
        join_u16(&supported_versions, "-"),
        join_u16(&signature_algorithms, "-"),
        alpn_protocols.join("-")
    );
    let mut sorted_groups = normalized_supported_groups.clone();
    sorted_groups.sort_unstable();
    let mut sorted_signatures = normalized_signature_algorithms.clone();
    sorted_signatures.sort_unstable();
    let mut sorted_versions = normalized_supported_versions.clone();
    sorted_versions.sort_unstable();
    let normalized_set_input = format!(
        "version={legacy_version};sni={server_name_present};ciphers={};extensions={};groups={};versions={};sig={};alpn={}",
        join_u16(&ja4_inputs.sorted_ciphers, "-"),
        join_u16(&ja4_inputs.sorted_extensions_without_sni_alpn, "-"),
        join_u16(&sorted_groups, "-"),
        join_u16(&sorted_versions, "-"),
        join_u16(&sorted_signatures, "-"),
        alpn_protocols.join("-")
    );

    Ok(TlsClientHelloObservation {
        legacy_version,
        record_lengths,
        handshake_length,
        session_id_length,
        cipher_suites,
        normalized_cipher_suites,
        extension_order,
        normalized_extension_order,
        supported_groups,
        normalized_supported_groups,
        signature_algorithms,
        normalized_signature_algorithms,
        supported_versions,
        normalized_supported_versions,
        alpn_protocols,
        server_name_present,
        ja3_input,
        ja4_inputs,
        observed_sha256: sha256_hex(observed_input.as_bytes()),
        normalized_set_sha256: sha256_hex(normalized_set_input.as_bytes()),
    })
}

pub fn parse_h2_client_preface(stream: &[u8]) -> Result<H2ClientPrefaceObservation> {
    if !stream.starts_with(H2_PREFACE) {
        bail!("HTTP/2 client preface is missing");
    }
    let mut cursor = Cursor::new(&stream[H2_PREFACE.len()..]);
    let mut frames = Vec::new();
    let mut settings = Vec::new();
    let mut connection_window_updates = Vec::new();

    while cursor.remaining() >= 9 {
        let payload_length = cursor.read_u24()? as usize;
        let frame_type = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        let stream_id = cursor.read_u32()? & 0x7fff_ffff;
        if cursor.remaining() < payload_length {
            break;
        }
        let payload = cursor.read_exact(payload_length)?;
        frames.push(H2FrameObservation {
            frame_type,
            frame_type_name: h2_frame_type_name(frame_type).into(),
            flags,
            stream_id,
            payload_length,
        });

        if frame_type == 4 && flags & 0x1 == 0 && stream_id == 0 {
            if payload.len() % 6 != 0 {
                bail!("HTTP/2 SETTINGS payload has invalid length");
            }
            let mut setting_cursor = Cursor::new(payload);
            while setting_cursor.remaining() > 0 {
                let id = setting_cursor.read_u16()?;
                let value = setting_cursor.read_u32()?;
                settings.push(H2SettingObservation {
                    id,
                    name: h2_setting_name(id),
                    value,
                });
            }
        }
        if frame_type == 8 && stream_id == 0 && payload.len() == 4 {
            let mut update = Cursor::new(payload);
            connection_window_updates.push(update.read_u32()? & 0x7fff_ffff);
        }
    }

    let stable_input = format!(
        "settings={};window={};frames={}",
        settings
            .iter()
            .map(|setting| format!("{}:{}", setting.id, setting.value))
            .collect::<Vec<_>>()
            .join(","),
        connection_window_updates
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
        frames
            .iter()
            .map(|frame| format!(
                "{}:{}:{}:{}",
                frame.frame_type, frame.flags, frame.stream_id, frame.payload_length
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let normalized_input = format!(
        "settings={};window={}",
        settings
            .iter()
            .map(|setting| format!("{}:{}", setting.id, setting.value))
            .collect::<Vec<_>>()
            .join(","),
        connection_window_updates
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );

    Ok(H2ClientPrefaceObservation {
        preface_present: true,
        frames,
        settings,
        connection_window_updates,
        observed_sha256: sha256_hex(stable_input.as_bytes()),
        normalized_sha256: sha256_hex(normalized_input.as_bytes()),
    })
}

fn collect_client_hello_handshake(stream: &[u8]) -> Result<(Vec<u8>, Vec<usize>)> {
    let mut cursor = Cursor::new(stream);
    let mut handshake = Vec::new();
    let mut record_lengths = Vec::new();
    while cursor.remaining() >= 5 {
        let content_type = cursor.read_u8()?;
        cursor.skip(2)?;
        let record_length = cursor.read_u16()? as usize;
        let record = cursor.read_exact(record_length)?;
        record_lengths.push(record_length);
        if content_type == TLS_HANDSHAKE_CONTENT_TYPE {
            handshake.extend_from_slice(record);
            if handshake.len() >= 4 {
                let expected = 4
                    + ((handshake[1] as usize) << 16)
                    + ((handshake[2] as usize) << 8)
                    + handshake[3] as usize;
                if handshake.len() >= expected {
                    handshake.truncate(expected);
                    return Ok((handshake, record_lengths));
                }
            }
        }
    }
    bail!("complete TLS ClientHello was not captured")
}

fn parse_sni_presence(input: &[u8]) -> Result<bool> {
    let mut cursor = Cursor::new(input);
    let list_length = cursor.read_u16()? as usize;
    let mut names = Cursor::new(cursor.read_exact(list_length)?);
    while names.remaining() > 0 {
        let name_type = names.read_u8()?;
        let name_length = names.read_u16()? as usize;
        names.skip(name_length)?;
        if name_type == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_u16_vector(input: &[u8]) -> Result<Vec<u16>> {
    let mut cursor = Cursor::new(input);
    let length = cursor.read_u16()? as usize;
    read_u16_list(cursor.read_exact(length)?)
}

fn parse_u16_vector_u8_length(input: &[u8]) -> Result<Vec<u16>> {
    let mut cursor = Cursor::new(input);
    let length = cursor.read_u8()? as usize;
    read_u16_list(cursor.read_exact(length)?)
}

fn parse_u8_vector(input: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(input);
    let length = cursor.read_u8()? as usize;
    Ok(cursor.read_exact(length)?.to_vec())
}

fn parse_alpn(input: &[u8]) -> Result<Vec<String>> {
    let mut cursor = Cursor::new(input);
    let length = cursor.read_u16()? as usize;
    let mut protocols = Cursor::new(cursor.read_exact(length)?);
    let mut result = Vec::new();
    while protocols.remaining() > 0 {
        let protocol_length = protocols.read_u8()? as usize;
        let protocol = protocols.read_exact(protocol_length)?;
        result.push(String::from_utf8_lossy(protocol).into_owned());
    }
    Ok(result)
}

fn read_u16_list(input: &[u8]) -> Result<Vec<u16>> {
    if !input.len().is_multiple_of(2) {
        bail!("u16 vector has odd length");
    }
    let mut cursor = Cursor::new(input);
    let mut result = Vec::new();
    while cursor.remaining() > 0 {
        result.push(cursor.read_u16()?);
    }
    Ok(result)
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn join_u16(values: &[u16], separator: &str) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(separator)
}

fn h2_frame_type_name(frame_type: u8) -> &'static str {
    match frame_type {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

fn h2_setting_name(id: u16) -> String {
    match id {
        1 => "HEADER_TABLE_SIZE".into(),
        2 => "ENABLE_PUSH".into(),
        3 => "MAX_CONCURRENT_STREAMS".into(),
        4 => "INITIAL_WINDOW_SIZE".into(),
        5 => "MAX_FRAME_SIZE".into(),
        6 => "MAX_HEADER_LIST_SIZE".into(),
        8 => "ENABLE_CONNECT_PROTOCOL".into(),
        _ => format!("UNKNOWN_{id}"),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(length).context("length overflow")?;
        if end > self.input.len() {
            bail!("input is truncated");
        }
        let result = &self.input[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn skip(&mut self, length: usize) -> Result<()> {
        self.read_exact(length).map(|_| ())
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.read_exact(2)?.try_into()?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24(&mut self) -> Result<u32> {
        let bytes = self.read_exact(3)?;
        Ok(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.read_exact(4)?.try_into()?;
        Ok(u32::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normalized_client_hello_inputs() -> Result<()> {
        let stream = synthetic_client_hello();
        let observation = parse_tls_client_hello(&stream)?;

        assert_eq!(observation.legacy_version, 0x0303);
        assert_eq!(observation.normalized_cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(
            observation.normalized_extension_order,
            vec![0, 10, 11, 13, 16, 43]
        );
        assert_eq!(observation.normalized_supported_groups, vec![29, 23]);
        assert_eq!(observation.alpn_protocols, vec!["h2", "http/1.1"]);
        assert!(observation.server_name_present);
        assert_eq!(
            observation.ja3_input,
            "771,4865-4866,0-10-11-13-16-43,29-23,0"
        );
        Ok(())
    }

    #[test]
    fn parses_h2_settings_order_and_connection_window() -> Result<()> {
        let mut bytes = H2_PREFACE.to_vec();
        bytes.extend_from_slice(&[0, 0, 12, 4, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 4, 0, 16, 0, 0]);
        bytes.extend_from_slice(&[0, 1, 0, 0, 16, 0]);
        bytes.extend_from_slice(&[0, 0, 4, 8, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&1_000_000u32.to_be_bytes());

        let observation = parse_h2_client_preface(&bytes)?;

        assert_eq!(observation.settings.len(), 2);
        assert_eq!(observation.settings[0].name, "INITIAL_WINDOW_SIZE");
        assert_eq!(observation.settings[1].name, "HEADER_TABLE_SIZE");
        assert_eq!(observation.connection_window_updates, vec![1_000_000]);
        Ok(())
    }

    #[test]
    fn rejects_incomplete_client_hello() {
        let err = parse_tls_client_hello(&[22, 3, 1, 0, 5, 1]).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    fn synthetic_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        let ciphers: [u16; 3] = [0x0a0a, 0x1301, 0x1302];
        body.extend_from_slice(&(ciphers.len() as u16 * 2).to_be_bytes());
        for cipher in ciphers {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);

        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x1a1a, &[]);
        push_extension(&mut extensions, 0, &[0, 6, 0, 0, 3, b'l', b'a', b'b']);
        push_extension(&mut extensions, 10, &[0, 6, 0x2a, 0x2a, 0, 29, 0, 23]);
        push_extension(&mut extensions, 11, &[1, 0]);
        push_extension(&mut extensions, 13, &[0, 4, 4, 3, 8, 4]);
        push_extension(
            &mut extensions,
            16,
            &[
                0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        );
        push_extension(&mut extensions, 43, &[4, 3, 4, 3, 3]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        let length = body.len() as u32;
        handshake.extend_from_slice(&[
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_extension(target: &mut Vec<u8>, id: u16, payload: &[u8]) {
        target.extend_from_slice(&id.to_be_bytes());
        target.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        target.extend_from_slice(payload);
    }
}
