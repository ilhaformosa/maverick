use super::{Relay, DEADLINE};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use maverick_client::connector::{ProxyConnector, TargetAddr, UdpCarrier};
use maverick_core::{ClientConfig, SecretString, ServerConfig};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use sha2::{Digest, Sha256};
use std::{fs, net::Ipv4Addr, path::Path};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

struct Leaf {
    pem: String,
    key: String,
    pin: String,
}

impl Leaf {
    fn issue(issuer: &rcgen::Issuer<'_, KeyPair>) -> Result<Self> {
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec!["localhost".into()])?.signed_by(&key, issuer)?;
        Ok(Self {
            pin: format!(
                "sha256/{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(cert.der()))
            ),
            pem: cert.pem(),
            key: key.serialize_pem(),
        })
    }

    fn install(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        fs::write(cert_path, &self.pem)?;
        fs::write(key_path, &self.key)?;
        Ok(())
    }
}

fn parse_client(yaml: &str) -> Result<ClientConfig> {
    ClientConfig::from_yaml_str(yaml)
        .map_err(|_| anyhow::anyhow!("invalid rotation client configuration"))
}

fn parse_server(yaml: &str) -> Result<ServerConfig> {
    ServerConfig::from_yaml_str(yaml)
        .map_err(|_| anyhow::anyhow!("invalid rotation server configuration"))
}

async fn exercise(
    client_path: &Path,
    tcp: &TcpListener,
    udp: &UdpSocket,
    matched: bool,
) -> Result<()> {
    // A fresh connector forces an inner TLS handshake for each configuration.
    let config = parse_client(&fs::read_to_string(client_path)?)?;
    let connector = ProxyConnector::new(config)?;
    let target = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
    let stream = connector
        .connect_tcp(target.clone(), tcp.local_addr()?.port())
        .await;
    let datagrams = connector.open_udp(target, udp.local_addr()?.port()).await;
    if !matched {
        for error in [stream.err(), datagrams.err()] {
            let error = error.context("stale origin pin admitted a session")?;
            ensure!(
                error
                    .chain()
                    .any(|cause| cause.to_string() == "end-to-end origin TLS verification failed"),
                "rejection did not occur at inner origin verification"
            );
            ensure!(
                error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::get_ref)
                        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                        .is_some_and(|e| {
                            matches!(
                                e,
                                rustls::Error::InvalidCertificate(
                                    rustls::CertificateError::ApplicationVerificationFailure
                                )
                            )
                        })
                }),
                "inner TLS did not reject the leaf pin"
            );
        }
        ensure!(
            timeout(std::time::Duration::from_millis(80), tcp.accept())
                .await
                .is_err(),
            "rejected TCP open reached target"
        );
        ensure!(
            matches!(udp.try_recv_from(&mut [0; 64]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
        connector.close();
        return Ok(());
    }
    let stream = stream?;
    let mut datagrams = datagrams?;
    ensure!(datagrams.carrier() == UdpCarrier::H2Reliable);
    let (mut app, relay_io) = tokio::io::duplex(128);
    let endpoints = async {
        let (mut peer, _) = tcp.accept().await?;
        app.write_all(b"upload").await?;
        app.shutdown().await?;
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await?;
        ensure!(bytes == b"upload");
        peer.write_all(b"download").await?;
        peer.shutdown().await?;
        bytes.clear();
        app.read_to_end(&mut bytes).await?;
        ensure!(bytes == b"download");
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(stream.relay(relay_io), endpoints)?;
    ensure!(datagrams.send(Bytes::from_static(b"request"))?);
    let mut buf = [0; 64];
    let (len, source) = udp.recv_from(&mut buf).await?;
    ensure!(&buf[..len] == b"request");
    for reply in [b"first".as_slice(), b"second"] {
        udp.send_to(reply, source).await?;
        ensure!(datagrams.recv().await?.as_ref() == reply);
    }
    datagrams.close().await?;
    connector.close();
    Ok(())
}

#[tokio::test]
async fn protected_h2_origin_certificate_rotation_and_rollback() -> Result<()> {
    let drill = async {
        let dir = tempfile::tempdir()?;
        let web = dir.path().join("public");
        fs::create_dir(&web)?;
        fs::write(web.join("index.html"), b"test page")?;
        let file = || NamedTempFile::new_in(dir.path());
        let (ca_file, cert, key, client, server_file) =
            (file()?, file()?, file()?, file()?, file()?);
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "Maverick rotation test CA");
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate()?;
        fs::write(ca_file.path(), ca.self_signed(&ca_key)?.pem())?;
        let issuer = rcgen::Issuer::from_params(&ca, ca_key);
        let original = Leaf::issue(&issuer)?;
        let replacement = Leaf::issue(&issuer)?;
        ensure!(
            original.pin != replacement.pin,
            "expected distinct origin certificates"
        );
        original.install(cert.path(), key.path())?;
        let secret = SecretString::generate();
        let loopback = "127.0.0.1:0";
        let server_yaml = format!(
            "version: 1\nlisten: '{loopback}'\ntls:\n  cert_path: {}\n  key_path: {}\nmaverick:\n  tunnel_path: /rotate\nusers:\n  - id: test\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: {}\nadvanced:\n  end_to_end: true\n  egress:\n    allow_loopback: true\n",
            serde_json::to_string(cert.path())?, serde_json::to_string(key.path())?,
            secret.expose_secret(), serde_json::to_string(&web)?);
        let mut origin = maverick_server::start_server(parse_server(&server_yaml)?).await?;
        let address = origin.local_addr;
        let server_yaml = server_yaml.replacen(loopback, &address.to_string(), 1);
        fs::write(server_file.path(), &server_yaml)?;
        let client_yaml = |address, outer_ca: &Path| -> Result<String> {
            Ok(format!(
                "version: 1\nlocal:\n  socks5:\n    listen: '{loopback}'\nserver:\n  address: '{address}'\n  server_name: localhost\n  tunnel_path: /rotate\n  credential_id: test\n  secret: '{}'\n  ca_cert: {}\nadvanced:\n  udp_policy: allow_reliable\n  end_to_end:\n    server_name: localhost\n    ca_cert: {}\n    cert_pin: '{}'\n",
                secret.expose_secret(), serde_json::to_string(outer_ca)?, serde_json::to_string(ca_file.path())?, original.pin))
        };
        let direct = parse_client(&client_yaml(address.to_string(), ca_file.path())?)?;
        let relay = Relay::start(direct).await?;
        let original_client = client_yaml(
            relay.config.server.address.clone(),
            relay
                .config
                .server
                .ca_cert
                .as_deref()
                .context("missing relay CA")?,
        )?;
        fs::write(client.path(), &original_client)?;
        let (cert_backup, key_backup, client_backup, server_backup) =
            (file()?, file()?, file()?, file()?);
        for (live, backup) in [
            (&cert, &cert_backup),
            (&key, &key_backup),
            (&client, &client_backup),
            (&server_file, &server_backup),
        ] {
            fs::copy(live.path(), backup.path())?;
        }
        let tcp = TcpListener::bind(loopback).await?;
        let udp = UdpSocket::bind(loopback).await?;
        exercise(client.path(), &tcp, &udp, true)
            .await
            .context("original pair")?;
        origin.shutdown().await?;
        replacement.install(cert.path(), key.path())?;
        let load_server =
            || -> Result<ServerConfig> { parse_server(&fs::read_to_string(server_file.path())?) };
        origin = maverick_server::start_server(load_server()?).await?;
        exercise(client.path(), &tcp, &udp, false)
            .await
            .context("old pin against replacement")?;
        ensure!(original_client.matches(&original.pin).count() == 1);
        fs::write(
            client.path(),
            original_client.replacen(&original.pin, &replacement.pin, 1),
        )?;
        exercise(client.path(), &tcp, &udp, true)
            .await
            .context("replacement pair")?;
        origin.shutdown().await?;
        fs::copy(cert_backup.path(), cert.path())?;
        fs::copy(key_backup.path(), key.path())?;
        fs::copy(server_backup.path(), server_file.path())?;
        ensure!(
            fs::read_to_string(cert.path())? == original.pem
                && fs::read_to_string(key.path())? == original.key,
            "original certificate/key bytes were not restored"
        );
        origin = maverick_server::start_server(load_server()?).await?;
        exercise(client.path(), &tcp, &udp, false)
            .await
            .context("replacement pin against restored origin")?;
        fs::copy(client_backup.path(), client.path())?;
        ensure!(
            fs::read_to_string(client.path())? == original_client
                && fs::read_to_string(server_file.path())? == server_yaml,
            "original config bytes were not restored"
        );
        exercise(client.path(), &tcp, &udp, true)
            .await
            .context("restored pair")?;
        drop(relay);
        origin.shutdown().await
    };
    timeout(DEADLINE, drill)
        .await
        .context("protected origin rotation drill timed out")?
}
