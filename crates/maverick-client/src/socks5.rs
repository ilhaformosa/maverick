use std::net::{Ipv4Addr, Ipv6Addr};

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use maverick_core::frame::{TargetAddr, UdpPacketPayload};
use maverick_core::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::OwnedSemaphorePermit;

use crate::ClientTunnelPool;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksRequest {
    pub command: SocksCommand,
    pub target: TargetAddr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

pub async fn read_connect_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(stream).await?;
    if request.command != SocksCommand::Connect {
        bail!("expected SOCKS CONNECT request");
    }
    Ok(request)
}

pub async fn read_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("unsupported SOCKS version");
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        bail!("SOCKS no-auth method not offered");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("unsupported SOCKS request version");
    }
    let command = match req[1] {
        0x01 => SocksCommand::Connect,
        0x03 => SocksCommand::UdpAssociate,
        _ => {
            write_reply(stream, 0x07).await?;
            bail!("unsupported SOCKS command");
        }
    };
    if req[2] != 0x00 {
        write_reply(stream, 0x01).await?;
        bail!("malformed SOCKS request");
    }

    let target = match req[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ipv4(Ipv4Addr::from(octets))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                write_reply(stream, 0x04).await?;
                bail!("empty domain");
            }
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            TargetAddr::Domain(String::from_utf8(domain).map_err(|_| anyhow!("invalid domain"))?)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ipv6(Ipv6Addr::from(octets))
        }
        _ => {
            write_reply(stream, 0x08).await?;
            bail!("unsupported address type");
        }
    };
    let port = stream.read_u16().await?;
    Ok(SocksRequest {
        command,
        target,
        port,
    })
}

pub async fn write_success<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_reply(stream, 0x00).await
}

pub async fn write_udp_associate_success<S>(stream: &mut S, bind_addr: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    match bind_addr {
        SocketAddr::V4(addr) => {
            let mut reply = Vec::with_capacity(10);
            reply.extend_from_slice(&[0x05, 0x00, 0x00, 0x01]);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
            stream.write_all(&reply).await?;
        }
        SocketAddr::V6(addr) => {
            let mut reply = Vec::with_capacity(22);
            reply.extend_from_slice(&[0x05, 0x00, 0x00, 0x04]);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
            stream.write_all(&reply).await?;
        }
    }
    stream.flush().await?;
    Ok(())
}

pub async fn write_failure<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_reply(stream, 0x05).await
}

async fn write_reply<S>(stream: &mut S, code: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    Ok(())
}

pub async fn serve_udp_associate(
    control: TcpStream,
    config: Arc<ClientConfig>,
    flow_permit: OwnedSemaphorePermit,
    control_peer: Option<SocketAddr>,
) -> Result<()> {
    let tunnel_pool = Arc::new(ClientTunnelPool::new(config));
    let result =
        serve_udp_associate_with_pool(control, Arc::clone(&tunnel_pool), flow_permit, control_peer)
            .await;
    tunnel_pool.shutdown();
    result
}

pub(crate) async fn serve_udp_associate_with_pool(
    mut control: TcpStream,
    tunnel_pool: Arc<ClientTunnelPool>,
    _flow_permit: OwnedSemaphorePermit,
    control_peer: Option<SocketAddr>,
) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bind_addr = socket.local_addr()?;
    write_udp_associate_success(&mut control, bind_addr).await?;
    let mut association = None;
    let mut control_buf = [0u8; 1];
    let mut udp_buf = vec![0u8; 65_535];
    let mut associated_udp_peer = None;

    loop {
        tokio::select! {
            control_read = control.read(&mut control_buf) => {
                if control_read? == 0 {
                    break;
                }
            }
            datagram = socket.recv_from(&mut udp_buf) => {
                let (len, peer) = datagram?;
                let packet = match decode_udp_request(&udp_buf[..len]) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::debug!(error = %err, "dropping malformed SOCKS UDP packet");
                        continue;
                    }
                };
                if !accept_udp_peer(&mut associated_udp_peer, peer, control_peer) {
                    let allowed = associated_udp_peer.unwrap_or(peer);
                    tracing::debug!(
                        %peer,
                        %allowed,
                        "dropping SOCKS UDP packet from unassociated peer"
                    );
                    continue;
                }
                if association.is_none() {
                    match crate::udp::UdpAssociation::open_with_pool(&tunnel_pool).await {
                        Ok(opened) => association = Some(opened),
                        Err(err) => {
                            tracing::debug!(error = %err, "SOCKS UDP association open failed");
                            continue;
                        }
                    }
                }
                let relay = association.as_mut().unwrap().relay_packet(packet);
                let response = tokio::select! {
                    control_read = control.read(&mut control_buf) => {
                        if control_read? == 0 {
                            break;
                        }
                        continue;
                    }
                    response = relay => match response {
                        Ok(response) => response,
                        Err(err) => {
                            tracing::debug!(error = %err, "SOCKS UDP relay failed");
                            association = None;
                            continue;
                        }
                    },
                };
                if let Ok(encoded) = encode_udp_response(&response) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        }
    }
    if let Some(association) = association {
        let _ = association.close().await;
    }
    Ok(())
}

fn accept_udp_peer(
    associated_peer: &mut Option<SocketAddr>,
    peer: SocketAddr,
    control_peer: Option<SocketAddr>,
) -> bool {
    if let Some(control_peer) = control_peer {
        if peer.ip() != control_peer.ip() {
            return false;
        }
    }
    match *associated_peer {
        Some(allowed) => allowed == peer,
        None => {
            *associated_peer = Some(peer);
            true
        }
    }
}

fn decode_udp_request(input: &[u8]) -> Result<UdpPacketPayload> {
    let mut buf = input;
    if buf.remaining() < 4 {
        bail!("SOCKS UDP packet too short");
    }
    let reserved = buf.get_u16();
    let frag = buf.get_u8();
    if reserved != 0 || frag != 0 {
        bail!("fragmented SOCKS UDP packets are not supported");
    }
    let target = match buf.get_u8() {
        0x01 => {
            if buf.remaining() < 4 {
                bail!("truncated UDP IPv4 address");
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            TargetAddr::Ipv4(Ipv4Addr::from(octets))
        }
        0x03 => {
            if !buf.has_remaining() {
                bail!("missing UDP domain length");
            }
            let len = buf.get_u8() as usize;
            if len == 0 || buf.remaining() < len {
                bail!("truncated UDP domain");
            }
            let domain = buf.copy_to_bytes(len);
            TargetAddr::Domain(String::from_utf8(domain.to_vec()).context("invalid UDP domain")?)
        }
        0x04 => {
            if buf.remaining() < 16 {
                bail!("truncated UDP IPv6 address");
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            TargetAddr::Ipv6(Ipv6Addr::from(octets))
        }
        _ => bail!("unsupported UDP address type"),
    };
    if buf.remaining() < 2 {
        bail!("missing UDP port");
    }
    let port = buf.get_u16();
    Ok(UdpPacketPayload::new(
        target,
        port,
        Bytes::copy_from_slice(buf),
    ))
}

fn encode_udp_response(packet: &UdpPacketPayload) -> Result<Bytes> {
    let mut out = BytesMut::new();
    out.put_u16(0);
    out.put_u8(0);
    match &packet.target {
        TargetAddr::Ipv4(addr) => {
            out.put_u8(0x01);
            out.extend_from_slice(&addr.octets());
        }
        TargetAddr::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                bail!("UDP domain too long");
            }
            out.put_u8(0x03);
            out.put_u8(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ipv6(addr) => {
            out.put_u8(0x04);
            out.extend_from_slice(&addr.octets());
        }
    }
    out.put_u16(packet.port);
    out.extend_from_slice(&packet.data);
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn handshake_success_domain_connect() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move { read_connect_request(&mut server).await });
        client.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .unwrap();
        let req = server_task.await.unwrap().unwrap();
        assert_eq!(req.command, SocksCommand::Connect);
        assert_eq!(req.target, TargetAddr::Domain("example.com".into()));
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn unsupported_method_rejected() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move { read_connect_request(&mut server).await });
        client.write_all(&[0x05, 1, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unsupported_command_rejected() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move { read_connect_request(&mut server).await });
        client.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);
        assert!(server_task.await.unwrap().is_err());
    }

    #[test]
    fn socks_udp_packet_roundtrip() {
        let packet = UdpPacketPayload::new(
            TargetAddr::Domain("example.com".into()),
            53,
            Bytes::from_static(b"payload"),
        );
        let encoded = encode_udp_response(&packet).unwrap();
        let decoded = decode_udp_request(&encoded).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn socks_udp_associate_pins_first_valid_udp_peer() {
        let first: SocketAddr = "127.0.0.1:30000".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let mut associated = None;

        assert!(accept_udp_peer(&mut associated, first, None));
        assert_eq!(associated, Some(first));
        assert!(accept_udp_peer(&mut associated, first, None));
        assert!(!accept_udp_peer(&mut associated, second, None));
        assert_eq!(associated, Some(first));
    }

    #[test]
    fn socks_udp_associate_rejects_peer_from_different_control_ip() {
        let control_peer: SocketAddr = "127.0.0.1:25000".parse().unwrap();
        let udp_peer: SocketAddr = "127.0.0.2:30000".parse().unwrap();
        let mut associated = None;

        assert!(!accept_udp_peer(
            &mut associated,
            udp_peer,
            Some(control_peer)
        ));
        assert_eq!(associated, None);
    }
}
