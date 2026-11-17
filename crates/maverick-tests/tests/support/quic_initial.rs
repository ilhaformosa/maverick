//! Test-only QUIC v1 client Initial observer, using public Initial key derivation
//! from RFC 9001. Never reads TLS session secrets or decrypts application traffic.
//! Only metadata leaves this module. This is not a general-purpose QUIC parser.
use anyhow::{ensure, Context, Result};
use boring::hash::MessageDigest;
use boring::hkdf::HkdfSuite;
use boring::symm::{decrypt_aead, Cipher, Crypter, Mode};
use maverick_tests::backend_capture::{observe_quic_v1_outer, QuicOuterPacketType};
use maverick_tests::fingerprint::parse_tls_client_hello;
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_HELLO: usize = 16_384;

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(size)
            .context("field length overflow")?;
        let result = self
            .bytes
            .get(self.position..end)
            .context("truncated Initial field")?;
        self.position = end;
        Ok(result)
    }

    fn varint(&mut self) -> Result<u64> {
        let first = self.take(1)?[0];
        let mut value = u64::from(first & 0x3f);
        for byte in self.take((1 << (first >> 6)) - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn expand<const N: usize>(secret: &[u8], label: &[u8]) -> Result<[u8; N]> {
    let mut info = (N as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context
    let mut output = [0; N];
    HkdfSuite::new(MessageDigest::sha256()).expand(secret, &info, &mut output)?;
    Ok(output)
}

impl InitialKeys {
    fn from_dcid(dcid: &[u8]) -> Result<Self> {
        // Public protocol salt, not a credential or session secret.
        let salt = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        let initial = HkdfSuite::new(MessageDigest::sha256()).extract(&salt, dcid)?;
        let secret = expand::<32>(&initial, b"client in")?;
        Ok(Self {
            key: expand(&secret, b"quic key")?,
            iv: expand(&secret, b"quic iv")?,
            hp: expand(&secret, b"quic hp")?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PacketLayout {
    pub datagram: usize,
    pub packet_number: u64,
    pub packet_bytes: usize,
    pub trailing_zero_bytes: usize,
    pub crypto: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlightSummary {
    pub datagram_lengths: Vec<usize>,
    pub packets: Vec<PacketLayout>,
    pub client_hello_bytes: usize,
    pub sni_range: (usize, usize),
    #[serde(skip)]
    pub hello_hash: [u8; 32],
}

#[derive(Default)]
pub struct InitialFlight {
    keys: Option<InitialKeys>,
    expected_pn: u64,
    hello: Vec<Option<u8>>,
    datagrams: Vec<usize>,
    packets: Vec<PacketLayout>,
    complete: Option<FlightSummary>,
}

impl InitialFlight {
    pub fn summary(&self) -> Option<&FlightSummary> {
        self.complete.as_ref()
    }

    pub fn observe(&mut self, datagram: &[u8]) -> Result<()> {
        if self.complete.is_some() {
            return Ok(());
        }
        ensure!(datagram.len() <= 1350, "out-of-scope datagram size");
        if datagram.first().is_none_or(|first| first & 0xf0 != 0xc0) {
            ensure!(!datagram.is_empty(), "empty datagram");
            return Ok(());
        }
        // quiche 0.30.1 pads short Initial datagrams with trailing zero bytes
        // outside the protected packet. The retained outer parser intentionally
        // rejects that suffix as another invalid packet. Parse the declared
        // packet first, then account for that concrete upstream padding shape.
        let mut header = Cursor {
            bytes: datagram,
            position: 5,
        };
        for _ in 0..2 {
            let length = header.take(1)?[0] as usize;
            header.take(length)?;
        }
        let token_length = usize::try_from(header.varint()?)?;
        header.take(token_length)?;
        let length = usize::try_from(header.varint()?)?;
        let end = header
            .position
            .checked_add(length)
            .context("Initial length overflow")?;
        let packet = datagram.get(..end).context("truncated Initial packet")?;
        let outer = observe_quic_v1_outer(packet)?;
        ensure!(outer.packets.len() == 1 && outer.contains(QuicOuterPacketType::Initial));
        ensure!(
            datagram[end..].iter().all(|byte| *byte == 0),
            "coalesced non-Initial packet outside first-flight experiment"
        );
        ensure!(datagram.len() >= 1200, "client Initial datagram too short");
        ensure!(
            self.datagrams.len() < 16,
            "Initial observation budget exhausted"
        );
        let index = self.datagrams.len();
        self.datagrams.push(datagram.len());
        let mut layout = self.decode(packet, index)?;
        layout.trailing_zero_bytes = datagram.len() - end;
        self.packets.push(layout);
        if self.hello.len() >= 4 && self.hello[..4].iter().all(Option::is_some) {
            let size = 4 + u32::from_be_bytes([
                0,
                self.hello[1].unwrap(),
                self.hello[2].unwrap(),
                self.hello[3].unwrap(),
            ]) as usize;
            ensure!(size <= MAX_HELLO, "ClientHello exceeds observation bound");
            if self.hello.len() == size && self.hello.iter().all(Option::is_some) {
                let hello: Vec<u8> = self.hello.iter().map(|value| value.unwrap()).collect();
                let sni = super::client_hello::sni_range(&hello)?;
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&(size as u16).to_be_bytes());
                record.extend_from_slice(&hello);
                ensure!(parse_tls_client_hello(&record)?.server_name_present);
                self.complete = Some(FlightSummary {
                    datagram_lengths: self.datagrams.clone(),
                    packets: self.packets.clone(),
                    client_hello_bytes: size,
                    sni_range: (sni.start, sni.end),
                    hello_hash: Sha256::digest(&hello).into(),
                });
                self.hello.clear();
                self.keys = None;
            }
        }
        Ok(())
    }

    fn decode(&mut self, packet: &[u8], datagram: usize) -> Result<PacketLayout> {
        let mut cursor = Cursor {
            bytes: packet,
            position: 5,
        };
        let dcid_length = cursor.take(1)?[0] as usize;
        let dcid = cursor.take(dcid_length)?;
        if self.keys.is_none() {
            self.keys = Some(InitialKeys::from_dcid(dcid)?);
        }
        let scid_length = cursor.take(1)?[0] as usize;
        cursor.take(scid_length)?;
        let token_length = usize::try_from(cursor.varint()?)?;
        ensure!(
            token_length == 0,
            "Retry is outside this first-flight experiment"
        );
        let length = usize::try_from(cursor.varint()?)?;
        let pn_offset = cursor.position;
        ensure!(pn_offset + length == packet.len());
        let keys = self.keys.as_ref().context("missing Initial keys")?;
        let sample = packet
            .get(pn_offset + 4..pn_offset + 20)
            .context("short header sample")?;
        let mut ecb = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &keys.hp, None)?;
        ecb.pad(false);
        let mut mask = [0; 32];
        let used = ecb.update(sample, &mut mask)?;
        ensure!(used + ecb.finalize(&mut mask[used..])? == 16);
        let first = packet[0] ^ (mask[0] & 0x0f);
        ensure!(first & 0x0c == 0, "nonzero reserved bits");
        let pn_len = (first & 3) as usize + 1;
        let mut header = packet[..pn_offset + pn_len].to_vec();
        header[0] = first;
        let mut number = 0;
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[1 + i];
            number = (number << 8) | u64::from(header[pn_offset + i]);
        }
        let window = 1u64 << (pn_len * 8);
        number |= self.expected_pn & !(window - 1);
        if number + window / 2 <= self.expected_pn {
            number += window;
        } else if number > self.expected_pn + window / 2 && number >= window {
            number -= window;
        }
        let mut nonce = keys.iv;
        for (byte, number) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *byte ^= number;
        }
        let encrypted = packet.get(header.len()..).context("missing ciphertext")?;
        ensure!(encrypted.len() >= 16);
        let tag_offset = encrypted.len() - 16;
        let plain = decrypt_aead(
            Cipher::aes_128_gcm(),
            &keys.key,
            Some(&nonce),
            &header,
            &encrypted[..tag_offset],
            &encrypted[tag_offset..],
        )?;
        self.expected_pn = self.expected_pn.max(number + 1);
        let mut layout = PacketLayout {
            datagram,
            packet_number: number,
            packet_bytes: packet.len(),
            trailing_zero_bytes: 0,
            crypto: Vec::new(),
        };
        let mut frames = Cursor {
            bytes: &plain,
            position: 0,
        };
        while frames.position < plain.len() {
            match frames.varint()? {
                0 | 1 => {} // PADDING / PING
                kind @ (2 | 3) => {
                    frames.varint()?;
                    frames.varint()?;
                    let ranges = frames.varint()?;
                    ensure!(ranges <= plain.len() as u64);
                    frames.varint()?;
                    for _ in 0..ranges {
                        frames.varint()?;
                        frames.varint()?;
                    }
                    if kind == 3 {
                        for _ in 0..3 {
                            frames.varint()?;
                        }
                    }
                }
                6 => {
                    let offset = usize::try_from(frames.varint()?)?;
                    let length = usize::try_from(frames.varint()?)?;
                    let end = offset
                        .checked_add(length)
                        .context("CRYPTO range overflow")?;
                    ensure!(end <= MAX_HELLO);
                    let bytes = frames.take(length)?;
                    if self.hello.len() < end {
                        self.hello.resize(end, None);
                    }
                    for (slot, byte) in self.hello[offset..end].iter_mut().zip(bytes) {
                        ensure!(
                            slot.is_none_or(|previous| previous == *byte),
                            "conflicting CRYPTO bytes"
                        );
                        *slot = Some(*byte);
                    }
                    layout.crypto.push((offset, length));
                }
                _ => anyhow::bail!("unsupported frame in observed client Initial"),
            }
        }
        Ok(layout)
    }
}

#[test]
fn rfc9001_client_initial_vector_and_corruption() -> Result<()> {
    let hex: String = include_str!("../../fixtures/quic-v1-client-initial.hex")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<String>()
        .split_whitespace()
        .collect();
    let packet: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut observer = InitialFlight::default();
    observer.observe(&packet)?;
    let summary = observer
        .summary()
        .context("RFC ClientHello not reconstructed")?;
    ensure!(summary.client_hello_bytes == 241 && summary.packets.len() == 1);
    ensure!(summary.packets[0].packet_number == 2);
    ensure!(summary.packets[0].crypto == [(0, 241)]);
    ensure!(summary.sni_range.1 - summary.sni_range.0 == 11);
    let mut decoded = InitialFlight::default();
    decoded.decode(&packet, 0)?;
    let hello: Vec<u8> = decoded.hello.iter().map(|value| value.unwrap()).collect();
    let name = super::client_hello::sni_range(&hello)?;
    ensure!(&hello[name] == b"example.com", "RFC SNI location mismatch");
    ensure!(super::client_hello::sni_range(&hello[..hello.len() - 1]).is_err());
    let mut padded = packet.clone();
    padded.extend_from_slice(&[0; 150]);
    let mut padded_observer = InitialFlight::default();
    padded_observer.observe(&padded)?;
    ensure!(
        padded_observer
            .summary()
            .context("padded vector incomplete")?
            .packets[0]
            .trailing_zero_bytes
            == 150
    );
    *padded.last_mut().unwrap() = 1;
    ensure!(InitialFlight::default().observe(&padded).is_err());
    let mut corrupted = packet.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    ensure!(InitialFlight::default().observe(&corrupted).is_err());
    for length in [0, 5, 21, 1199] {
        ensure!(InitialFlight::default().observe(&packet[..length]).is_err());
    }
    Ok(())
}
