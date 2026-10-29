use anyhow::{ensure, Context, Result};
use maverick_core::config::{ClientDnsConfig, HttpConnectConfig};
use maverick_sdk::{
    client_config_builder, GuiClientRuntime, GuiConnectionState, GuiErrorClass, GuiTransportStatus,
    SecretString,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;

fn local_runtime(peer: SocketAddr) -> Result<GuiClientRuntime> {
    let mut config = client_config_builder()
        .local_socks5("127.0.0.1:0".parse()?)
        .server_address(peer.to_string())
        .server_name("localhost")
        .credential("local-readiness-test", SecretString::generate())
        .build()?;
    config.advanced.connect_timeout_ms = 1_000;
    GuiClientRuntime::new("local-test", config)
}

#[tokio::test]
async fn startup_does_not_claim_remote_connection() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        // Keep the ephemeral TCP address reserved without listening on it.
        let unavailable = TcpSocket::new_v4()?;
        unavailable.bind("127.0.0.1:0".parse()?)?;
        let mut runtime = local_runtime(unavailable.local_addr()?)?;
        assert!(!runtime.is_listening());
        let initial = runtime.diagnostics();
        assert_eq!(initial.connection_state, GuiConnectionState::Disconnected);
        assert_eq!(initial.transport_status, GuiTransportStatus::Unverified);
        runtime.connect().await?;
        assert!(runtime.is_listening());
        #[allow(deprecated)]
        {
            // The old name remains an alias for local lifecycle state only.
            assert!(runtime.is_connected());
        }
        let started = runtime.diagnostics();
        let local_addr = runtime.local_addr().context("missing local listener")?;
        runtime.disconnect().await?;
        assert!(!runtime.is_listening());
        #[allow(deprecated)]
        {
            assert!(!runtime.is_connected());
        }
        let stopped = runtime.diagnostics();
        let _rebound = TcpListener::bind(local_addr).await?;

        assert_eq!(started.connection_state, GuiConnectionState::Listening);
        assert_eq!(started.transport_status, GuiTransportStatus::Unverified);
        assert_eq!(stopped.connection_state, GuiConnectionState::Disconnected);
        assert_eq!(stopped.transport_status, GuiTransportStatus::Unverified);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK local startup test timed out")?
}

#[tokio::test]
async fn no_unsolicited_probe_and_rejected_request_does_not_claim_connection() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let peer = TcpListener::bind("127.0.0.1:0").await?;
        let peer_addr = peer.local_addr()?;
        let mut runtime = local_runtime(peer_addr)?;
        runtime.connect().await?;
        assert!(runtime.is_listening());
        let started = runtime.diagnostics();
        let local_addr = runtime.local_addr().context("missing local listener")?;
        ensure!(
            timeout(Duration::from_millis(100), peer.accept())
                .await
                .is_err(),
            "SDK startup or diagnostics initiated an unsolicited remote connection"
        );

        // Only this explicit local SOCKS request should contact the test peer.
        let request = async {
            let mut local = TcpStream::connect(local_addr).await?;
            local.write_all(&[5, 1, 0]).await?;
            let mut greeting = [0; 2];
            local.read_exact(&mut greeting).await?;
            ensure!(greeting == [5, 0], "SOCKS greeting failed");
            let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
            connect.extend_from_slice(&peer_addr.port().to_be_bytes());
            local.write_all(&connect).await?;
            let mut reply = [0; 10];
            local.read_exact(&mut reply).await?;
            ensure!(
                reply[0] == 5 && reply[1] != 0,
                "rejecting test peer did not fail the SOCKS request"
            );
            Ok::<_, anyhow::Error>(())
        };
        let reject = async {
            let (connection, _) = peer.accept().await?;
            drop(connection);
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(request, reject)?;
        let rejected = runtime.diagnostics();
        assert!(runtime.is_listening());
        runtime.disconnect().await?;
        assert!(!runtime.is_listening());

        assert_eq!(started.connection_state, GuiConnectionState::Listening);
        assert_eq!(started.transport_status, GuiTransportStatus::Unverified);
        assert_eq!(rejected.connection_state, GuiConnectionState::Listening);
        assert_eq!(rejected.transport_status, GuiTransportStatus::Unverified);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK readiness and no-probe test timed out")?
}

#[tokio::test]
async fn local_bind_failure_is_error_without_a_listening_handle() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let occupied = TcpListener::bind("127.0.0.1:0").await?;
        let address = occupied.local_addr()?;
        let config = client_config_builder()
            .local_socks5(address)
            .server_address(address.to_string())
            .server_name("localhost")
            .credential("local-readiness-test", SecretString::generate())
            .build()?;
        let mut runtime = GuiClientRuntime::new("local-test", config)?;
        let error = runtime
            .connect()
            .await
            .expect_err("occupied local listener unexpectedly started");
        ensure!(
            error.to_string().contains("bind local.socks5.listen"),
            "startup did not fail at the occupied local listener"
        );
        let snapshot = runtime.diagnostics();
        assert_eq!(snapshot.connection_state, GuiConnectionState::Error);
        assert_eq!(snapshot.transport_status, GuiTransportStatus::Unverified);
        assert_eq!(snapshot.last_error_class, Some(GuiErrorClass::Network));
        assert!(!runtime.is_listening());
        assert!(runtime.local_addr().is_none());
        runtime.disconnect().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK occupied-listener test timed out")?
}

#[tokio::test(flavor = "current_thread")]
async fn optional_listener_failure_allows_immediate_sdk_retry() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let socks = std::net::TcpListener::bind("127.0.0.1:0")?;
        let socks_addr = socks.local_addr()?;
        let dns = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let dns_addr = dns.local_addr()?;
        let occupied_http = std::net::TcpListener::bind("127.0.0.1:0")?;
        let http_addr = occupied_http.local_addr()?;
        let unavailable = TcpSocket::new_v4()?;
        unavailable.bind("127.0.0.1:0".parse()?)?;
        let mut config = client_config_builder()
            .local_socks5(socks_addr)
            .server_address(unavailable.local_addr()?.to_string())
            .server_name("localhost")
            .credential("local-startup-test", SecretString::generate())
            .build()?;
        config.local.dns = Some(ClientDnsConfig {
            enabled: true,
            listen: Some(dns_addr),
        });
        config.local.http_connect = Some(HttpConnectConfig {
            enabled: true,
            listen: Some(http_addr),
        });
        let mut runtime = GuiClientRuntime::new("local-test", config)?;
        drop(socks);
        drop(dns);

        let error = runtime
            .connect()
            .await
            .expect_err("occupied HTTP listener unexpectedly started");
        ensure!(
            error.to_string().contains("bind local.http_connect.listen"),
            "startup did not reach the occupied HTTP listener"
        );
        let failed = runtime.diagnostics();
        assert_eq!(failed.connection_state, GuiConnectionState::Error);
        assert_eq!(failed.last_error_class, Some(GuiErrorClass::Network));
        assert!(!runtime.is_listening());
        assert!(runtime.local_addr().is_none());

        // Retry in the same task, without a sleep or yield to clean up failed startup.
        drop(occupied_http);
        runtime
            .connect()
            .await
            .context("immediate SDK retry failed")?;
        assert!(runtime.is_listening());
        assert_eq!(runtime.local_addr(), Some(socks_addr));
        let started = runtime.diagnostics();
        assert_eq!(started.connection_state, GuiConnectionState::Listening);
        assert_eq!(started.transport_status, GuiTransportStatus::Unverified);
        assert_eq!(started.last_error_class, None);

        runtime.disconnect().await?;
        assert!(!runtime.is_listening());
        let _socks_rebound = std::net::TcpListener::bind(socks_addr)?;
        let _dns_rebound = std::net::UdpSocket::bind(dns_addr)?;
        let _http_rebound = std::net::TcpListener::bind(http_addr)?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK retry test timed out")?
}
