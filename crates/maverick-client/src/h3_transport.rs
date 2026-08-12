use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::Request;
use maverick_core::ClientConfig;
use quinn::crypto::rustls::QuicClientConfig;
use tokio::time::Duration;

pub type H3ClientRequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub struct H3RequestSender {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver: tokio::task::JoinHandle<()>,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl H3RequestSender {
    pub async fn send_request(&mut self, request: Request<()>) -> Result<H3ClientRequestStream> {
        self.send_request
            .send_request(request)
            .await
            .context("send h3 tunnel request")
    }
}

impl Drop for H3RequestSender {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"maverick-h3-client");
        self.endpoint.close(0u32.into(), b"maverick-h3-client");
        self.driver.abort();
    }
}

pub async fn connect(config: &ClientConfig) -> Result<H3RequestSender> {
    crate::reject_retired_v1_h3(config)?;
    Err(anyhow::Error::new(maverick_core::Error::Config(
        "legacy Quinn H3 transport is retired".into(),
    )))
}

#[allow(dead_code)] // Retained only until the later Quinn deletion slice.
async fn connect_inner(config: &ClientConfig) -> Result<H3RequestSender> {
    let server_addr = resolve_server_addr(&config.server.address).await?;
    let mut tls_config = crate::h2_transport::rustls_client_config(config)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.enable_early_data = false;

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(config.advanced.idle_timeout_secs).try_into()?,
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client(bind_addr_for(server_addr))?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(server_addr, config.server.server_name.as_str())?
        .await
        .context("QUIC handshake failed")?;

    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .context("h3 client handshake failed")?;
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    Ok(H3RequestSender {
        endpoint,
        connection,
        driver,
        send_request,
    })
}

#[allow(dead_code)] // Retained only until the later Quinn deletion slice.
async fn resolve_server_addr(address: &str) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(address)
        .await
        .with_context(|| format!("resolve {address}"))?;
    addrs
        .next()
        .with_context(|| format!("no addresses resolved for {address}"))
}

#[allow(dead_code)] // Retained only until the later Quinn deletion slice.
fn bind_addr_for(remote: SocketAddr) -> SocketAddr {
    match remote.ip() {
        IpAddr::V4(addr) if addr.is_loopback() => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        IpAddr::V6(addr) if addr.is_loopback() => SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{Mode, SecretString};

    fn test_config() -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "127.0.0.1".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_test".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }

    #[test]
    fn h3_feature_stub_is_compiled() {
        assert!(cfg!(feature = "h3"));
    }

    #[tokio::test]
    async fn direct_h3_connect_is_retired_even_when_config_flag_is_false() {
        let error = match connect(&test_config()).await {
            Ok(_) => panic!("retired direct H3 entry unexpectedly connected"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "configuration error: legacy Quinn H3 transport is retired"
        );
    }

    #[tokio::test]
    async fn direct_h3_connect_uses_uniform_true_config_tombstone() {
        let mut config = test_config();
        config.advanced.experimental_h3 = true;
        let error = match connect(&config).await {
            Ok(_) => panic!("retired direct H3 entry unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
    }
}
