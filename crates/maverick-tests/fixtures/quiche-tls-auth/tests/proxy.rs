use maverick_quiche_tls_auth::{proxy, smoke};

#[tokio::test]
async fn transport_starts_and_stops() -> anyhow::Result<()> {
    let connection = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
    connection.transport.shutdown().await
}

#[tokio::test]
async fn socks_tcp_auth_v1_large_half_close() -> anyhow::Result<()> {
    assert_eq!(smoke::run(false).await?, smoke::PAYLOAD_SIZE);
    Ok(())
}

#[tokio::test]
async fn socks_tcp_auth_v2_large_half_close() -> anyhow::Result<()> {
    assert_eq!(smoke::run(true).await?, smoke::PAYLOAD_SIZE);
    Ok(())
}

async fn rejected_before_origin(kind: &str) -> anyhow::Result<()> {
    use anyhow::ensure;
    use maverick_core::config::SecretString;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    tokio::time::timeout(Duration::from_secs(10), async {
        let connection = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
        let (mut client, mut config) = smoke::configs(&connection, true)?;
        match kind {
            "wrong_secret" => client.server.secret = SecretString::generate(),
            "unknown_user" => client.server.credential_id = "unknown-test-user".into(),
            "disabled_user" => config.users[0].enabled = false,
            "epoch" => client.auth.rotation.active_epoch = Some("202608".into()),
            "binding" => {
                client.auth.channel_binding.enabled = false;
                client.auth.channel_binding.require = false;
            }
            "egress" => config.advanced.egress.allow_loopback = false,
            _ => unreachable!(),
        }
        let server = maverick_server::h3::Server::new(config)?;
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let target = origin.local_addr()?;
        let socks = TcpListener::bind("127.0.0.1:0").await?;
        let socks_addr = socks.local_addr()?;
        let server_task = tokio::spawn(async move {
            server
                .serve(
                    connection.server,
                    connection.client_addr,
                    smoke::PATH,
                    connection.server_binding,
                )
                .await
        });
        let client_task = tokio::spawn(async move {
            let (stream, _) = socks.accept().await?;
            maverick_client::h3::proxy_socks_connection(
                stream,
                &client,
                connection.client,
                connection.client_binding,
            )
            .await
        });
        let mut stream = TcpStream::connect(socks_addr).await?;
        ensure!(
            smoke::socks_connect(&mut stream, target).await? != 0,
            "rejected request opened SOCKS flow"
        );
        ensure!(
            client_task.await?.is_err(),
            "client accepted invalid session"
        );
        server_task.await??;
        ensure!(
            tokio::time::timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err(),
            "rejected request reached target"
        );
        connection.transport.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn wrong_secret_cannot_open_target() -> anyhow::Result<()> {
    rejected_before_origin("wrong_secret").await
}
#[tokio::test]
async fn unknown_user_cannot_open_target() -> anyhow::Result<()> {
    rejected_before_origin("unknown_user").await
}
#[tokio::test]
async fn disabled_user_cannot_open_target() -> anyhow::Result<()> {
    rejected_before_origin("disabled_user").await
}
#[tokio::test]
async fn unaccepted_epoch_cannot_open_target() -> anyhow::Result<()> {
    rejected_before_origin("epoch").await
}
#[tokio::test]
async fn required_binding_cannot_be_omitted() -> anyhow::Result<()> {
    rejected_before_origin("binding").await
}
#[tokio::test]
async fn egress_policy_blocks_target() -> anyhow::Result<()> {
    rejected_before_origin("egress").await
}

#[tokio::test]
async fn repeated_hello_uses_server_replay_cache() -> anyhow::Result<()> {
    use maverick_core::{auth::ClientHello, Frame, FrameType};
    use std::time::Duration;
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
        let (client, mut config) = smoke::configs(&first, false)?;
        // Disable optional binding only in this test, so a second TLS connection
        // reaches the replay cache with exactly the same authenticated Hello.
        config.auth.channel_binding.require = false;
        config.auth.channel_binding.enabled = false;
        let server = maverick_server::h3::Server::new(config)?;
        let hello = ClientHello::try_new_with_channel_binding(
            client.server.credential_id.clone(),
            &client.server.secret,
            smoke::PATH,
            client.mode,
            0,
            None,
        )?
        .encode();
        for (connection, accepted) in [
            (first, true),
            (proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?, false),
        ] {
            let server = server.clone();
            let mut channel = connection.client;
            let task = tokio::spawn(async move {
                server
                    .serve(
                        connection.server,
                        connection.client_addr,
                        smoke::PATH,
                        connection.server_binding,
                    )
                    .await
            });
            channel
                .send(
                    Frame::new(FrameType::ClientHello, 0, 0, hello.clone()),
                    false,
                    smoke::MAX_FRAME,
                )
                .await?;
            let reply = channel.read(smoke::MAX_FRAME).await;
            if accepted {
                assert_eq!(reply?.unwrap().frame_type, FrameType::ServerHello);
                channel
                    .send(
                        Frame::new(FrameType::CloseFlow, 0, 1, bytes::Bytes::new()),
                        true,
                        smoke::MAX_FRAME,
                    )
                    .await?;
                assert_eq!(
                    channel.read(smoke::MAX_FRAME).await?.unwrap().frame_type,
                    FrameType::Error
                );
                assert!(channel.read(smoke::MAX_FRAME).await?.is_none());
            } else {
                assert!(reply.is_err(), "repeated authenticated Hello accepted");
            }
            task.await??;
            connection.transport.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn concurrent_flow_limit_is_shared_across_h3_connections() -> anyhow::Result<()> {
    use maverick_core::{
        frame::{ErrorCode, OpenTcpPayload, TargetAddr},
        Frame, FrameType,
    };
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
        let (client, mut config) = smoke::configs(&first, true)?;
        config.users[0].max_concurrent_flows = Some(1);
        let server = maverick_server::h3::Server::new(config)?;
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let payload = OpenTcpPayload::new(
            TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            origin.local_addr()?.port(),
        )
        .encode()?;
        let first_server = server.clone();
        let first_task = tokio::spawn(async move {
            first_server
                .serve(
                    first.server,
                    first.client_addr,
                    smoke::PATH,
                    first.server_binding,
                )
                .await
        });
        let mut first_tunnel =
            maverick_client::h3::open(&client, first.client, first.client_binding).await?;
        first_tunnel
            .send_frame(Frame::new(FrameType::OpenTcp, 0, 1, payload.clone()), false)
            .await?;
        assert_eq!(
            first_tunnel.read_next_frame().await?.unwrap().frame_type,
            FrameType::WindowUpdate
        );
        let (mut target, _) = origin.accept().await?;
        let second = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
        let second_task = tokio::spawn(async move {
            server
                .serve(
                    second.server,
                    second.client_addr,
                    smoke::PATH,
                    second.server_binding,
                )
                .await
        });
        let mut second_tunnel =
            maverick_client::h3::open(&client, second.client, second.client_binding).await?;
        second_tunnel
            .send_frame(Frame::new(FrameType::OpenTcp, 0, 1, payload), false)
            .await?;
        let rejection = second_tunnel.read_next_frame().await?.unwrap();
        assert_eq!(rejection.frame_type, FrameType::Error);
        assert_eq!(
            ErrorCode::decode(&rejection.payload)?,
            ErrorCode::FlowLimitExceeded
        );
        second_tunnel
            .send_frame(
                Frame::new(FrameType::CloseFlow, 0, 1, bytes::Bytes::new()),
                true,
            )
            .await?;
        assert!(second_tunnel.read_next_frame().await?.is_none());
        second_task.await??;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err()
        );
        first_tunnel
            .send_frame(
                Frame::new(FrameType::TcpFin, 0, 1, bytes::Bytes::new()),
                true,
            )
            .await?;
        target.shutdown().await?;
        assert_eq!(
            first_tunnel.read_next_frame().await?.unwrap().frame_type,
            FrameType::TcpFin
        );
        assert!(first_tunnel.read_next_frame().await?.is_none());
        first_task.await??;
        first.transport.shutdown().await?;
        second.transport.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn server_half_close_preserves_remaining_upload() -> anyhow::Result<()> {
    for v2 in [false, true] {
        assert_eq!(
            smoke::run_with_mode(v2, smoke::TransferMode::ServerFirst).await?,
            smoke::PAYLOAD_SIZE
        );
    }
    Ok(())
}

#[tokio::test]
async fn simultaneous_large_upload_and_download() -> anyhow::Result<()> {
    for v2 in [false, true] {
        assert_eq!(
            smoke::run_with_mode(v2, smoke::TransferMode::Simultaneous).await?,
            smoke::PAYLOAD_SIZE
        );
    }
    Ok(())
}

#[tokio::test]
async fn active_download_survives_longer_than_idle_timeout() -> anyhow::Result<()> {
    assert_eq!(
        smoke::run_with_mode(true, smoke::TransferMode::SlowDownload).await?,
        smoke::PAYLOAD_SIZE
    );
    Ok(())
}

#[tokio::test]
async fn goaway_preserves_the_accepted_tcp_flow() -> anyhow::Result<()> {
    assert_eq!(
        smoke::run_with_mode(true, smoke::TransferMode::GoAway).await?,
        smoke::PAYLOAD_SIZE
    );
    Ok(())
}

#[tokio::test]
async fn goaway_rejecting_current_request_is_reported() -> anyhow::Result<()> {
    use std::time::Duration;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut connection =
            proxy::connect_with_server_goaway(smoke::PATH, smoke::MAX_FRAME, 0).await?;
        assert!(connection.client.read(smoke::MAX_FRAME).await.is_err());
        let result = connection.transport.shutdown().await.unwrap_err();
        assert!(result.to_string().contains("GOAWAY"));
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn transport_disconnect_releases_target_and_flow_slot() -> anyhow::Result<()> {
    use maverick_core::{
        frame::{OpenTcpPayload, TargetAddr},
        Frame, FrameType,
    };
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?;
        let (client, mut config) = smoke::configs(&first, true)?;
        config.users[0].max_concurrent_flows = Some(1);
        let server = maverick_server::h3::Server::new(config)?;
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let payload = OpenTcpPayload::new(
            TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            origin.local_addr()?.port(),
        )
        .encode()?;
        // The same one-slot server must accept a later connection after the first transport vanishes.
        for (connection, disconnect) in [
            (first, true),
            (proxy::connect(smoke::PATH, smoke::MAX_FRAME).await?, false),
        ] {
            let server = server.clone();
            let task = tokio::spawn(async move {
                server
                    .serve(
                        connection.server,
                        connection.client_addr,
                        smoke::PATH,
                        connection.server_binding,
                    )
                    .await
            });
            let mut tunnel =
                maverick_client::h3::open(&client, connection.client, connection.client_binding)
                    .await?;
            tunnel
                .send_frame(Frame::new(FrameType::OpenTcp, 0, 1, payload.clone()), false)
                .await?;
            assert_eq!(
                tunnel.read_next_frame().await?.unwrap().frame_type,
                FrameType::WindowUpdate
            );
            let (mut target, _) = origin.accept().await?;
            if disconnect {
                connection.transport.shutdown().await?;
                assert!(task.await?.is_err());
                assert!(tunnel.read_next_frame().await.is_err());
                let mut received = Vec::new();
                target.read_to_end(&mut received).await?;
                assert!(received.is_empty());
            } else {
                tunnel
                    .send_frame(
                        Frame::new(FrameType::TcpFin, 0, 1, bytes::Bytes::new()),
                        true,
                    )
                    .await?;
                target.shutdown().await?;
                assert_eq!(
                    tunnel.read_next_frame().await?.unwrap().frame_type,
                    FrameType::TcpFin
                );
                assert!(tunnel.read_next_frame().await?.is_none());
                task.await??;
                connection.transport.shutdown().await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
