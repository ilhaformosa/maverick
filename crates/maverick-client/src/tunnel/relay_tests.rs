use super::*;
use crate::session::{relay_stream_and_tunnel, RelayClose};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

async fn h2_pair(
    request_window: u32,
    stall_timeout: Duration,
) -> Result<(
    ClientTunnel,
    h2::RecvStream,
    h2::SendStream<Bytes>,
    JoinSet<Result<()>>,
)> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    let mut drivers = JoinSet::new();
    drivers.spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(request_window)
            .handshake(server_io)
            .await?;
        let (request, mut respond) = connection.accept().await.context("missing H2 request")??;
        let response = http::Response::builder()
            .header("content-type", "application/grpc")
            .body(())?;
        let response = respond.send_response(response, false)?;
        peer_tx
            .send((request.into_body(), response))
            .map_err(|_| anyhow::anyhow!("test peer closed"))?;
        while let Some(request) = connection.accept().await {
            request?;
        }
        Ok(())
    });

    let (sender, connection) = h2::client::handshake(client_io).await?;
    drivers.spawn(async move {
        connection.await?;
        Ok(())
    });
    let mut sender = sender.ready().await?;
    let request = http::Request::builder().method("POST").uri("/").body(())?;
    let (response, send_stream) = sender.send_request(request, false)?;
    let recv_stream = response.await?.into_body();
    let (request, response) = peer_rx.await?;
    let tunnel = ClientTunnel::H2(Box::new(H2ClientTunnel {
        send_stream,
        recv_stream,
        recv_buf: BytesMut::new(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        padding: RuntimePadding::disabled(),
        cover_traffic: RuntimeCoverTraffic::disabled(),
        batcher: RuntimeBatcher::disabled(),
        send_stall_timeout: stall_timeout,
        connection_lease: None,
    }));
    Ok((tunnel, request, response, drivers))
}

async fn request_frame(request: &mut h2::RecvStream, buffer: &mut BytesMut) -> Result<Frame> {
    loop {
        if let Some(frame) = decode_grpc_frame_from(buffer, DEFAULT_MAX_FRAME_SIZE)? {
            return Ok(frame);
        }
        let bytes = request
            .data()
            .await
            .context("request ended before frame")??;
        request.flow_control().release_capacity(bytes.len())?;
        buffer.extend_from_slice(&bytes);
    }
}

fn send_response_fin(response: &mut h2::SendStream<Bytes>) -> Result<()> {
    response.send_data(
        encode_grpc_frame(
            Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()),
            DEFAULT_MAX_FRAME_SIZE,
        )?,
        false,
    )?;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    response.send_trailers(trailers)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn blocked_h2_upload_still_receives_data_and_reset() -> Result<()> {
    timeout(Duration::from_secs(2), async {
        let (tunnel, _request, mut response, _drivers) =
            h2_pair(0, Duration::from_secs(10)).await?;
        let (local, mut app) = tokio::io::duplex(1);
        let relay = relay_stream_and_tunnel(local, tunnel, Duration::from_secs(10));
        let exchange = async {
            app.write_all(b"x").await?;
            // The second byte fits only after the relay reads the first one;
            // its H2 send then waits on the server's zero request window.
            app.write_all(b"y").await?;
            response.send_data(
                encode_grpc_frame(
                    Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"reply")),
                    DEFAULT_MAX_FRAME_SIZE,
                )?,
                false,
            )?;
            let mut reply = [0; 5];
            timeout(Duration::from_secs(1), app.read_exact(&mut reply))
                .await
                .context("blocked H2 upload prevented the download")??;
            assert_eq!(&reply, b"reply");
            response.send_data(
                encode_grpc_frame(
                    Frame::new(FrameType::TcpReset, 0, 1, Bytes::new()),
                    DEFAULT_MAX_FRAME_SIZE,
                )?,
                false,
            )?;
            Ok::<_, anyhow::Error>(())
        };
        let (close, ()) = tokio::try_join!(relay, exchange)?;
        assert_eq!(close, RelayClose::Reset);
        Ok(())
    })
    .await
    .context("H2 blocked-upload test did not finish")?
}

#[tokio::test(start_paused = true)]
async fn blocked_local_download_still_uploads_and_finishes_gracefully() -> Result<()> {
    timeout(Duration::from_secs(2), async {
        let (tunnel, mut request, mut response, _drivers) =
            h2_pair(65_535, Duration::from_secs(10)).await?;
        let (local, mut app) = tokio::io::duplex(1);
        let relay = relay_stream_and_tunnel(local, tunnel, Duration::from_secs(10));
        let exchange = async {
            response.send_data(
                encode_grpc_frame(
                    Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"reply")),
                    DEFAULT_MAX_FRAME_SIZE,
                )?,
                false,
            )?;
            let mut first = [0];
            app.read_exact(&mut first).await?;
            assert_eq!(&first, b"r");
            // Leave the rest of the download blocked in the one-byte local
            // sink while requiring upload and its FIN to reach the server.
            app.write_all(b"x").await?;
            let mut buffer = BytesMut::new();
            let upload = timeout(
                Duration::from_secs(1),
                request_frame(&mut request, &mut buffer),
            )
            .await
            .context("blocked local download prevented the upload")??;
            assert_eq!(
                upload,
                Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"x"))
            );
            app.shutdown().await?;
            let fin = request_frame(&mut request, &mut buffer).await?;
            assert_eq!(fin, Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()));
            assert!(request.data().await.is_none());
            send_response_fin(&mut response)?;
            let mut rest = Vec::new();
            app.read_to_end(&mut rest).await?;
            assert_eq!(&rest, b"eply");
            Ok::<_, anyhow::Error>(())
        };
        let (close, ()) = tokio::try_join!(relay, exchange)?;
        assert_eq!(close, RelayClose::Graceful);
        Ok(())
    })
    .await
    .context("H2 blocked-download test did not finish")?
}

#[tokio::test(start_paused = true)]
async fn partial_download_progress_keeps_silent_upload_open_after_response_fin() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let idle = Duration::from_secs(2);
        let (tunnel, mut request, mut response, _drivers) = h2_pair(65_535, idle).await?;
        let (local, mut app) = tokio::io::duplex(1);
        let relay = relay_stream_and_tunnel(local, tunnel, idle);
        let exchange = async {
            response.send_data(
                encode_grpc_frame(
                    Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"slow")),
                    DEFAULT_MAX_FRAME_SIZE,
                )?,
                false,
            )?;
            let mut reply = [0; 4];
            for byte in &mut reply {
                tokio::time::sleep(Duration::from_secs(1)).await;
                *byte = app.read_u8().await?;
            }
            assert_eq!(&reply, b"slow");
            send_response_fin(&mut response)?;
            assert_eq!(app.read(&mut [0]).await?, 0);

            app.write_all(b"after-fin").await?;
            app.shutdown().await?;
            let mut buffer = BytesMut::new();
            let mut uploaded = Vec::new();
            loop {
                let frame = request_frame(&mut request, &mut buffer).await?;
                assert_eq!(frame.flow_id, 1);
                if frame.frame_type == FrameType::TcpFin {
                    assert!(frame.payload.is_empty());
                    break;
                }
                assert_eq!(frame.frame_type, FrameType::TcpData);
                uploaded.extend_from_slice(&frame.payload);
            }
            assert_eq!(&uploaded, b"after-fin");
            assert!(request.data().await.is_none());
            Ok::<_, anyhow::Error>(())
        };
        let (close, ()) = tokio::try_join!(relay, exchange)?;
        assert_eq!(close, RelayClose::Graceful);
        Ok(())
    })
    .await
    .context("H2 partial-download progress test did not finish")?
}

#[tokio::test(start_paused = true)]
async fn partial_h2_send_progress_outlives_one_idle_window() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let idle = Duration::from_secs(2);
        let (tunnel, mut request, mut response, _drivers) = h2_pair(16, idle).await?;
        let (local, mut app) = tokio::io::duplex(256);
        let relay = relay_stream_and_tunnel(local, tunnel, idle);
        let exchange = async {
            let payload = Bytes::from(vec![0x5a; 128]);
            app.write_all(&payload).await?;
            app.shutdown().await?;
            let started = tokio::time::Instant::now();
            let mut buffer = BytesMut::new();
            while let Some(chunk) = request.data().await {
                let chunk = chunk?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                request.flow_control().release_capacity(chunk.len())?;
                buffer.extend_from_slice(&chunk);
            }
            assert!(started.elapsed() > idle);
            let data = decode_grpc_frame_from(&mut buffer, DEFAULT_MAX_FRAME_SIZE)?
                .context("missing complete upload")?;
            assert_eq!(data, Frame::new(FrameType::TcpData, 0, 1, payload));
            let fin = decode_grpc_frame_from(&mut buffer, DEFAULT_MAX_FRAME_SIZE)?
                .context("missing upload FIN")?;
            assert_eq!(fin, Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()));
            assert!(buffer.is_empty());
            send_response_fin(&mut response)?;
            assert_eq!(app.read(&mut [0]).await?, 0);
            Ok::<_, anyhow::Error>(())
        };
        let (close, ()) = tokio::try_join!(relay, exchange)?;
        assert_eq!(close, RelayClose::Graceful);
        Ok(())
    })
    .await
    .context("H2 partial-send progress test did not finish")?
}

#[tokio::test(start_paused = true)]
async fn stalled_h2_send_and_local_write_keep_error_results() -> Result<()> {
    for blocked_upload in [true, false] {
        let result = timeout(Duration::from_secs(3), async {
            let idle = Duration::from_secs(2);
            let window = if blocked_upload { 0 } else { 65_535 };
            let (tunnel, _request, mut response, _drivers) = h2_pair(window, idle).await?;
            let (local, mut app) = tokio::io::duplex(1);
            let relay = relay_stream_and_tunnel(local, tunnel, idle);
            let exchange = async {
                if blocked_upload {
                    app.write_all(b"x").await?;
                    app.write_all(b"y").await?;
                } else {
                    response.send_data(
                        encode_grpc_frame(
                            Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"blocked")),
                            DEFAULT_MAX_FRAME_SIZE,
                        )?,
                        false,
                    )?;
                }
                std::future::pending::<Result<()>>().await
            };
            let (close, ()) = tokio::try_join!(relay, exchange)?;
            Ok::<_, anyhow::Error>(close)
        })
        .await
        .context("H2 stalled operation exceeded its deadline")?;
        let error = result.expect_err("stalled operation was reported as graceful idle");
        if blocked_upload {
            assert!(error.downcast_ref::<H2SendStalled>().is_some());
        } else {
            assert!(error.to_string().contains("local relay write timed out"));
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn full_terminal_stops_upload_before_delayed_trailers() -> Result<()> {
    for (terminal, expected) in [
        (FrameType::CloseFlow, RelayClose::Graceful),
        (FrameType::Error, RelayClose::Reset),
    ] {
        timeout(Duration::from_secs(2), async {
            let (tunnel, mut request, mut response, _drivers) =
                h2_pair(65_535, Duration::from_secs(10)).await?;
            let (local, mut app) = tokio::io::duplex(1);
            let relay = relay_stream_and_tunnel(local, tunnel, Duration::from_secs(10));
            let exchange = async {
                response.send_data(
                    encode_grpc_frame(
                        Frame::new(terminal, 0, 1, Bytes::new()),
                        DEFAULT_MAX_FRAME_SIZE,
                    )?,
                    false,
                )?;
                assert_eq!(app.read(&mut [0]).await?, 0);
                let _ = app.write_all(b"x").await;
                let forwarded = timeout(Duration::from_millis(100), request.data()).await;
                assert!(
                    !matches!(forwarded, Ok(Some(Ok(_)))),
                    "full terminal frame allowed new upload while waiting for trailers"
                );
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                response.send_trailers(trailers)?;
                Ok::<_, anyhow::Error>(())
            };
            let (close, ()) = tokio::try_join!(relay, exchange)?;
            assert_eq!(close, expected);
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("H2 full-terminal test did not finish")??;
    }
    Ok(())
}
