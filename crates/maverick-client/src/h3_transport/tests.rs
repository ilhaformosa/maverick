use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use boring::ssl::SslFiletype;
use bytes::Bytes;
use maverick_core::config::{ClientAdvancedConfig, ClientServerConfig, LocalConfig, Socks5Config};
use maverick_core::{Frame, FrameType, Mode, SecretString};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{advance, pause, timeout};

const MAX_FRAME: usize = 65_536;

struct Peer {
    address: SocketAddr,
    ca: PathBuf,
    certificate: Vec<u8>,
    accepted: mpsc::Receiver<maverick_quiche::Connected>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
    _directory: TempDir,
}

impl Peer {
    async fn start() -> Result<Self> {
        let directory = TempDir::new()?;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca = directory.path().join("certificate.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&ca, certificate.cert.pem())?;
        std::fs::write(&key, certificate.key_pair.serialize_pem())?;
        let mut tls = SslContext::builder(SslMethod::tls())?;
        tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        tls.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        tls.set_certificate_chain_file(&ca)?;
        tls.set_private_key_file(&key, SslFiletype::PEM)?;
        tls.check_private_key()?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let (send, accepted) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(maverick_quiche::serve(
            socket,
            tls,
            maverick_quiche::ServeOptions {
                path: "/candidate-test".into(),
                limits: maverick_quiche::Limits {
                    max_frame_size: MAX_FRAME,
                    handshake_timeout: Duration::from_secs(5),
                    // Keep idle expiry distinct from the client's 5-second auth budget.
                    idle_timeout: Duration::from_secs(30),
                },
                max_connections: 2,
                max_connections_per_source: 2,
                admission: Arc::new(Semaphore::new(2)),
            },
            send,
            stopped,
        ));
        Ok(Self {
            address,
            ca,
            certificate: certificate.cert.der().to_vec(),
            accepted,
            stop,
            task,
            _directory: directory,
        })
    }

    fn config(&self) -> ClientConfig {
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
                address: self.address.to_string(),
                server_name: "localhost".into(),
                tunnel_path: "/candidate-test".into(),
                credential_id: "candidate-test".into(),
                secret: SecretString::generate(),
                ca_cert: Some(self.ca.clone()),
                cert_pin: Some(format!(
                    "sha256/{}",
                    URL_SAFE_NO_PAD.encode(Sha256::digest(&self.certificate))
                )),
            },
            auth: Default::default(),
            log: Default::default(),
            advanced: ClientAdvancedConfig {
                quiche_h3: true,
                connect_timeout_ms: 5_000,
                ..Default::default()
            },
        }
    }

    async fn shutdown(self) -> Result<()> {
        let _ = self.stop.send(());
        self.task.await?
    }
}

#[tokio::test]
async fn failed_first_address_reaches_next_verified_h3_peer() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut peer = Peer::start().await?;
        let refused = UdpSocket::bind("127.0.0.1:0").await?;
        let addresses = [refused.local_addr()?, peer.address];
        // A closed ephemeral UDP port gives the connected client an I/O failure.
        drop(refused);
        let config = peer.config();
        let mut connected = connect_to(&config, addresses.as_slice()).await?;
        assert_eq!(connected.peer, peer.address);
        let mut remote = peer
            .accepted
            .recv()
            .await
            .context("H3 peer was not accepted")?;
        connected
            .channel
            .send(
                Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"upload")),
                false,
                MAX_FRAME,
            )
            .await?;
        let upload = remote
            .channel
            .read(MAX_FRAME)
            .await?
            .context("missing upload")?;
        assert_eq!(upload.payload, Bytes::from_static(b"upload"));
        remote
            .channel
            .send(
                Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"download")),
                false,
                MAX_FRAME,
            )
            .await?;
        let download = connected
            .channel
            .read(MAX_FRAME)
            .await?
            .context("missing download")?;
        assert_eq!(download.payload, Bytes::from_static(b"download"));
        drop(connected);
        drop(remote);
        peer.shutdown().await
    })
    .await
    .context("H3 candidate forwarding test timed out")?
}

#[tokio::test]
async fn mismatched_request_path_is_rejected_without_an_authentication_timeout() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let peer = Peer::start().await?;
        let mut config = peer.config();
        config.server.tunnel_path = "/wrong-path".into();
        let connected = connect_to(&config, peer.address).await?;
        let result = crate::h3::open(&config, connected.channel, connected.binding).await;
        peer.shutdown().await?;
        let error = result
            .err()
            .context("mismatched H3 request path was accepted")?;
        assert!(
            !error
                .chain()
                .any(|cause| cause.to_string().contains("H3 authentication timed out")),
            "the rejected request waited for the client's authentication timeout"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("H3 request-path rejection test timed out")?
}

#[tokio::test]
async fn pin_mismatch_stops_before_the_next_address_or_application_frame() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut peer = Peer::start().await?;
        let later = UdpSocket::bind("127.0.0.1:0").await?;
        let addresses = [peer.address, later.local_addr()?];
        let mut config = peer.config();
        let mut wrong_pin = Sha256::digest(&peer.certificate);
        wrong_pin[0] ^= 0xff;
        config.server.cert_pin = Some(format!("sha256/{}", URL_SAFE_NO_PAD.encode(wrong_pin)));
        let result = connect_to(&config, addresses.as_slice()).await;
        let error = result.err().context("incorrect pin was accepted")?;
        assert!(error
            .to_string()
            .contains("H3 server certificate pin mismatch"));
        let mut remote = peer
            .accepted
            .recv()
            .await
            .context("H3 peer was not accepted")?;
        assert!(
            !matches!(remote.channel.inbound.recv().await, Some(Ok(Some(_)))),
            "pin mismatch sent an application frame"
        );
        let mut packet = [0; 1350];
        assert_eq!(
            later.try_recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(remote);
        peer.shutdown().await
    })
    .await
    .context("H3 pin rejection test timed out")?
}

#[tokio::test]
async fn silent_first_address_keeps_the_original_total_budget() -> Result<()> {
    let peer = Peer::start().await?;
    let silent = UdpSocket::bind("127.0.0.1:0").await?;
    let later = UdpSocket::bind("127.0.0.1:0").await?;
    let addresses = [silent.local_addr()?, later.local_addr()?];
    let config = peer.config();
    let attempt = connect_to(&config, addresses.as_slice());
    tokio::pin!(attempt);
    let mut packet = [0; 1350];
    let (_, client_address) = tokio::select! {
        result = &mut attempt => {
            anyhow::bail!("silent peer connection ended before its first datagram: {}", result.is_ok());
        }
        packet = silent.recv_from(&mut packet) => packet?,
    };
    pause();
    advance(Duration::from_millis(config.advanced.connect_timeout_ms)).await;
    let result = timeout(Duration::from_millis(1), &mut attempt)
        .await
        .context("each address received a fresh connection timeout")?;
    let error = result.err().context("silent peer unexpectedly connected")?;
    assert_eq!(error.to_string(), "H3 connection timed out");
    assert_eq!(
        later.try_recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    // Cancellation of the timed-out handshake releases its client UDP socket.
    let _rebound = std::net::UdpSocket::bind(client_address)?;
    peer.shutdown().await
}
