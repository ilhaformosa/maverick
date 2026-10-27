//! Local-only end-to-end exercise shared by the CLI smoke and integration test.
use anyhow::{ensure, Context, Result};
use maverick_core::config::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proxy::{self, LocalConnection};

pub const PATH: &str = "/loopback-auth";
pub const MAX_FRAME: usize = 65_536;
pub const PAYLOAD_SIZE: usize = 512 * 1024;

pub fn configs(connection: &LocalConnection, v2: bool) -> Result<(ClientConfig, ServerConfig)> {
    let secret = SecretString::generate();
    let mut client = ClientConfig {
        version: 1,
        mode: Mode::Stable,
        local: LocalConfig {
            socks5: Socks5Config {
                listen: "127.0.0.1:0".parse()?,
            },
            dns: None,
            http_connect: None,
        },
        server: ClientServerConfig {
            address: connection.server_addr.to_string(),
            server_name: "localhost".into(),
            tunnel_path: PATH.into(),
            credential_id: "local-test-user".into(),
            secret: secret.clone(),
            ca_cert: Some(connection.cert_path.clone()),
            cert_pin: None,
        },
        auth: ClientAuthConfig::default(),
        log: LogConfig::default(),
        advanced: ClientAdvancedConfig::default(),
    };
    let mut server = ServerConfig::from_yaml_str(&format!(
        "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: cert.pem\n  key_path: key.pem\nmaverick:\n  tunnel_path: {PATH}\n  mode_default: stable\nusers:\n  - id: local-test-user\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: public\n",
        secret.expose_secret()
    ))?;
    server.tls.cert_path = connection.cert_path.clone();
    server.tls.key_path = connection.key_path.clone();
    client.auth.channel_binding.require = true;
    server.auth.channel_binding.require = true;
    client.auth.v2.enabled = v2;
    server.auth.v2.enabled = v2;
    server.auth.v2.require = v2;
    if v2 {
        client.auth.rotation.active_epoch = Some("202607".into());
        server.auth.v2.accepted_epochs = vec![202607];
    }
    client.advanced.connect_timeout_ms = 3_000;
    client.advanced.idle_timeout_secs = 5;
    server.advanced.handshake_timeout_ms = 3_000;
    server.advanced.idle_timeout_secs = 5;
    server.advanced.max_frame_size = MAX_FRAME as u32;
    server.advanced.egress.allow_loopback = true;
    client.validate()?;
    server.validate()?;
    Ok((client, server))
}

/// Performs a real SOCKS5 CONNECT; returns the server's reply code.
pub async fn socks_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<u8> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting rejected");
    let IpAddr::V4(ip) = target.ip() else {
        anyhow::bail!("local IPv4 target required")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    ensure!(reply[0] == 5 && reply[3] == 1, "invalid SOCKS response");
    Ok(reply[1])
}

#[derive(Clone, Copy, Debug)]
pub enum TransferMode {
    ClientFirst,
    ServerFirst,
    Simultaneous,
    SlowDownload,
    GoAway,
}

pub async fn run(v2: bool) -> Result<usize> {
    run_with_mode(v2, TransferMode::ClientFirst).await
}

pub async fn run_with_mode(v2: bool, mode: TransferMode) -> Result<usize> {
    tokio::time::timeout(
        Duration::from_secs(15),
        transfer(v2, mode, proxy::PeerInput::None),
    )
    .await
    .context("local H3 proxy smoke timed out")?
}

pub async fn run_with_peer_input(v2: bool, peer: proxy::PeerInput) -> Result<usize> {
    tokio::time::timeout(
        Duration::from_secs(15),
        transfer(v2, TransferMode::ClientFirst, peer),
    )
    .await
    .context("local H3 peer-input smoke timed out")?
}

async fn transfer(v2: bool, mode: TransferMode, peer: proxy::PeerInput) -> Result<usize> {
    let connection = if matches!(mode, TransferMode::GoAway) {
        proxy::connect_with_server_goaway(PATH, MAX_FRAME, 4).await?
    } else {
        proxy::connect_with_peer_input(PATH, MAX_FRAME, peer).await?
    };
    let (mut client, mut server) = configs(&connection, v2)?;
    if matches!(mode, TransferMode::SlowDownload) {
        client.advanced.idle_timeout_secs = 1;
        server.advanced.idle_timeout_secs = 1;
    }
    let server = maverick_server::h3::Server::new(server)?;
    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let target = origin.local_addr()?;
    let socks = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks.local_addr()?;
    let payload: Vec<_> = (0..PAYLOAD_SIZE).map(|n| (n % 251) as u8).collect();
    let expected = payload.clone();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await?;
        let response: Vec<_> = expected.iter().rev().copied().collect();
        let send_first = match mode {
            TransferMode::ClientFirst | TransferMode::GoAway => Some(false),
            TransferMode::ServerFirst | TransferMode::SlowDownload => Some(true),
            TransferMode::Simultaneous => None,
        };
        let received = if matches!(mode, TransferMode::SlowDownload) {
            for chunk in response.chunks(32 * 1024) {
                stream.write_all(chunk).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            stream.shutdown().await?;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await?;
            received
        } else {
            exchange(&mut stream, &response, send_first).await?
        };
        ensure!(received == expected, "upstream payload differs");
        Ok::<_, anyhow::Error>(())
    });
    let server_task = tokio::spawn(async move {
        server
            .serve(
                connection.server,
                connection.client_addr,
                PATH,
                connection.server_binding,
            )
            .await
    });
    let client_task = tokio::spawn(async move {
        let (local, _) = socks.accept().await?;
        maverick_client::h3::proxy_socks_connection(
            local,
            &client,
            connection.client,
            connection.client_binding,
        )
        .await
    });
    let mut stream = TcpStream::connect(socks_addr).await?;
    ensure!(
        socks_connect(&mut stream, target).await? == 0,
        "SOCKS CONNECT failed"
    );
    let send_first = match mode {
        TransferMode::ClientFirst | TransferMode::GoAway => Some(true),
        TransferMode::ServerFirst | TransferMode::SlowDownload => Some(false),
        TransferMode::Simultaneous => None,
    };
    let received = exchange(&mut stream, &payload, send_first).await?;
    ensure!(
        received.iter().eq(payload.iter().rev()),
        "downstream payload differs"
    );
    origin_task.await??;
    client_task.await??;
    server_task.await??;
    connection.transport.shutdown().await?;
    Ok(received.len())
}

async fn exchange(
    stream: &mut TcpStream,
    payload: &[u8],
    send_first: Option<bool>,
) -> Result<Vec<u8>> {
    let mut received = Vec::new();
    match send_first {
        Some(true) => {
            stream.write_all(payload).await?;
            stream.shutdown().await?;
            stream.read_to_end(&mut received).await?;
        }
        Some(false) => {
            stream.read_to_end(&mut received).await?;
            stream.write_all(payload).await?;
            stream.shutdown().await?;
        }
        None => {
            let (mut reader, mut writer) = stream.split();
            tokio::try_join!(
                async {
                    writer.write_all(payload).await?;
                    writer.shutdown().await
                },
                async { reader.read_to_end(&mut received).await }
            )?;
        }
    }
    Ok(received)
}
