use std::sync::Arc;

use anyhow::{Context, Result};
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use maverick_core::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{client_async, WebSocketStream};

use crate::transport::CloudflareWsTunnel;

pub type WsClientStream = WebSocketStream<TlsStream<TcpStream>>;

pub async fn connect(config: &ClientConfig) -> Result<CloudflareWsTunnel> {
    timeout(
        Duration::from_millis(config.advanced.connect_timeout_ms),
        connect_inner(config),
    )
    .await
    .context("Maverick websocket connection timed out")?
}

async fn connect_inner(config: &ClientConfig) -> Result<CloudflareWsTunnel> {
    let tcp = TcpStream::connect(&config.server.address)
        .await
        .with_context(|| format!("connect {}", config.server.address))?;
    let mut tls_config = crate::h2_transport::rustls_client_config(config)?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name =
        ServerName::try_from(config.server.server_name.clone()).context("invalid server_name")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
    let channel_binding =
        rustls_client_channel_binding(tls.get_ref().1, config.auth.channel_binding.enabled)?;

    let uri = format!(
        "wss://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let (ws, _response) = client_async(uri.as_str(), tls)
        .await
        .context("websocket handshake failed")?;
    Ok(CloudflareWsTunnel {
        stream: ws,
        channel_binding,
    })
}

fn rustls_client_channel_binding(
    connection: &rustls::ClientConnection,
    enabled: bool,
) -> Result<Option<TlsChannelBinding>> {
    if !enabled {
        return Ok(None);
    }
    let output = connection
        .export_keying_material([0u8; 32], TLS_CHANNEL_BINDING_EXPORTER_LABEL, None)
        .context("export TLS channel binding")?;
    Ok(Some(TlsChannelBinding::new(output)))
}
