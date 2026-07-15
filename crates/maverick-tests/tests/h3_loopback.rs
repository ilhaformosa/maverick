#![cfg(feature = "h3")]

use std::convert::TryInto;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use h3::{client, server};
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;

#[tokio::test]
async fn h3_loopback_request_response_uses_ephemeral_local_udp() -> Result<()> {
    let (cert, key) = build_certs()?;
    let server_endpoint = server_endpoint(cert.clone(), key)?;
    let server_addr = server_endpoint.local_addr()?;
    assert_loopback(server_addr);

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.context("accept h3 client")?;
        let connection = incoming.await.context("complete quic server handshake")?;
        assert_h3_alpn(&connection)?;

        let mut incoming_requests =
            server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let request_resolver = incoming_requests
            .accept()
            .await?
            .context("missing h3 request")?;
        let (request, mut stream) = request_resolver.resolve_request().await?;
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/maverick/h3-smoke");

        stream
            .send_response(Response::builder().status(200).body(())?)
            .await?;
        stream
            .send_data(Bytes::from_static(b"maverick-h3-smoke"))
            .await?;
        stream.finish().await?;
        let _ = incoming_requests.accept().await;
        Result::<()>::Ok(())
    });

    let client_endpoint = client_endpoint(cert)?;
    let client_addr = client_endpoint.local_addr()?;
    assert_loopback(client_addr);

    let connection = client_endpoint
        .connect(server_addr, "localhost")?
        .await
        .context("complete quic client handshake")?;
    assert_h3_alpn(&connection)?;

    let (mut driver, mut send_request) =
        client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let mut stream = send_request
        .send_request(
            Request::get("https://localhost/maverick/h3-smoke")
                .body(())
                .context("build h3 request")?,
        )
        .await?;
    stream.finish().await?;

    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = stream.recv_data().await?.context("missing h3 body")?;
    assert_eq!(body.chunk(), b"maverick-h3-smoke");

    connection.close(0u32.into(), b"h3-smoke-complete");
    let _ = timeout(Duration::from_secs(2), driver_task).await;
    server_task.await??;
    Ok(())
}

fn build_certs() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    Ok((
        certified.cert.into(),
        PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
    ))
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::Endpoint> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.max_early_data_size = 0;

    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()?));

    quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("bind h3 server endpoint")
}

fn client_endpoint(cert: CertificateDer<'static>) -> Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.enable_early_data = false;

    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()?));

    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("bind h3 client endpoint")?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn transport_config() -> Result<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .max_idle_timeout(Some(Duration::from_secs(5).try_into()?))
        .initial_rtt(Duration::from_millis(10));
    Ok(config)
}

fn assert_h3_alpn(connection: &quinn::Connection) -> Result<()> {
    let handshake = connection
        .handshake_data()
        .context("missing quic handshake data")?;
    let handshake = handshake
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow!("unexpected quic handshake data type"))?;
    let protocol = handshake.protocol.context("missing negotiated ALPN")?;
    assert_eq!(protocol.as_slice(), b"h3");
    Ok(())
}

fn assert_loopback(addr: SocketAddr) {
    assert!(matches!(addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST));
}
