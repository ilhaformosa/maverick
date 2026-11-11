//! A complete SDK consumer using only loopback targets and ephemeral test trust.
//! Run from the checkout: cargo run -p maverick-sdk --example connector_loopback
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use maverick_sdk::{
    client_config_builder, server_config_builder, Bytes, ClientAdvancedConfig, ClientAuthConfig,
    MaverickServer, ProxyConnector, SecretString, ServerAdvancedConfig, TargetAddr, UdpPolicy,
};
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() <= 2,
        "usage: connector_loopback [h2|h3|auto] [allow_reliable|native_required]"
    );
    let carrier = args.first().map(String::as_str).unwrap_or("h2");
    ensure!(matches!(carrier, "h2" | "h3" | "auto"), "unknown carrier");
    ensure!(
        carrier == "h2" || cfg!(feature = "experimental-h3"),
        "h3/auto needs --features experimental-h3"
    );
    let policy = match args.get(1).map(String::as_str).unwrap_or("allow_reliable") {
        "allow_reliable" => UdpPolicy::AllowReliable,
        "native_required" => UdpPolicy::NativeRequired,
        _ => anyhow::bail!("unknown UDP policy"),
    };
    ensure!(
        carrier != "h2" || policy != UdpPolicy::NativeRequired,
        "native_required needs h3/auto"
    );

    // Test-only trust. A real consumer receives independently verified server
    // identity and credentials; it must never disable certificate verification.
    let files = tempfile::tempdir()?;
    let public = files.path().join("public");
    std::fs::create_dir(&public)?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = files.path().join("cert.pem");
    let key_path = files.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    let pin = format!(
        "sha256/{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(cert.cert.der()))
    );
    let secret = SecretString::generate();
    let mut server_options = ServerAdvancedConfig {
        quiche_h3: carrier == "h3",
        dual_h2_h3: carrier == "auto",
        ..Default::default()
    };
    // Only this embedded demonstration may forward to its loopback targets.
    server_options.egress.allow_loopback = true;
    let server = MaverickServer::start(
        server_config_builder()
            .listen("127.0.0.1:0".parse()?)
            .tls_paths(&cert_path, &key_path)
            .user("sdk-example", secret.clone())
            .static_fallback_dir(public)
            .advanced(server_options)
            .build()?,
    )
    .await?;
    let mut auth = ClientAuthConfig::default();
    auth.channel_binding.require = true;
    let client = client_config_builder()
        .server_address(
            server
                .local_addr()
                .context("server has no listener")?
                .to_string(),
        )
        .server_name("localhost")
        .ca_cert(cert_path)
        .cert_pin(pin)
        .credential("sdk-example", secret)
        .auth(auth)
        .advanced(ClientAdvancedConfig {
            quiche_h3: carrier == "h3",
            auto_h3: carrier == "auto",
            udp_policy: Some(policy),
            ..Default::default()
        })
        .build()?;
    // No local proxy listener: reuse this connector across application flows.
    let proxy = ProxyConnector::new(client)?;
    let result = timeout(Duration::from_secs(20), async {
        tcp(&proxy).await?;
        udp(&proxy).await
    })
    .await
    .context("loopback example timed out")
    .and_then(|result| result);
    // Sessions/futures belong to the consumer and have ended before this close.
    proxy.close();
    let stopped = server.shutdown().await;
    result?;
    stopped?;
    println!("SDK loopback OK ({carrier}, {policy:?}); no field connectivity claim");
    Ok(())
}

async fn tcp(proxy: &ProxyConnector) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let session = proxy
        .connect_tcp(
            TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            target.local_addr()?.port(),
        )
        .await?;
    println!("TCP admitted via {:?}", session.carrier());
    // The caller can supply any AsyncRead + AsyncWrite stream. A duplex pair
    // stands in for the embedding application's accepted connection here.
    let (mut app, input) = tokio::io::duplex(64);
    let application = async {
        app.write_all(b"request").await?;
        app.shutdown().await?; // Upload FIN does not stop the response.
        let mut response = Vec::new();
        app.read_to_end(&mut response).await?;
        ensure!(response == b"response", "unexpected TCP response");
        Ok::<_, anyhow::Error>(())
    };
    let destination = async {
        let (mut socket, _) = target.accept().await?;
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await?;
        ensure!(request == b"request", "unexpected TCP request");
        socket.write_all(b"response").await?;
        socket.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(application, destination, session.relay(input))?;
    Ok(())
}

async fn udp(proxy: &ProxyConnector) -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let mut session = proxy
        .open_udp(
            TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            target.local_addr()?.port(),
        )
        .await?;
    println!(
        "UDP admitted via {:?}, payload limit {} bytes",
        session.carrier(),
        session.max_payload()
    );
    // Queue two messages without waiting for replies. true means queued only.
    ensure!(
        session.send(Bytes::from_static(b"first"))?,
        "first datagram not queued"
    );
    ensure!(
        session.send(Bytes::from_static(b"second"))?,
        "second datagram not queued"
    );
    let destination = async {
        let mut buffer = [0; 64];
        let (n, source) = target.recv_from(&mut buffer).await?;
        let mut requests = vec![buffer[..n].to_vec()];
        let (n, next_source) = target.recv_from(&mut buffer).await?;
        ensure!(
            source == next_source,
            "session changed its target-facing port"
        );
        requests.push(buffer[..n].to_vec());
        requests.sort();
        ensure!(
            requests == [b"first".to_vec(), b"second".to_vec()],
            "unexpected UDP requests"
        );
        // Three independent replies, including an empty packet: no pairing.
        for reply in [b"one".as_slice(), b"two".as_slice(), b""] {
            target.send_to(reply, source).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let application = async {
        let mut replies = Vec::new();
        for _ in 0..3 {
            replies.push(session.recv().await?.to_vec());
        }
        replies.sort(); // Native datagrams do not promise delivery or ordering.
        ensure!(
            replies == [vec![], b"one".to_vec(), b"two".to_vec()],
            "unexpected UDP replies"
        );
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(destination, application)?;
    session.close().await
}
