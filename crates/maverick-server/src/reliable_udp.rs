//! Fixed-target UDP over the existing authenticated H2 stream.
use super::*;
use maverick_core::frame::{MAX_RELIABLE_UDP_PAYLOAD, RELIABLE_UDP_FLAGS};

pub(super) async fn serve(
    open: Frame,
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    mut buffer: BytesMut,
    state: &ServerState,
    user: &UserPolicy,
    maximum: usize,
) -> Result<()> {
    let target = match OpenTcpPayload::decode(&open.payload) {
        Ok(target) if target.initial_data.is_empty() && open.flow_id != 0 => target,
        _ => {
            return send_h2_server_frame(
                &mut send,
                relay::error_frame(open.flow_id, ErrorCode::ProtocolError),
                maximum,
                true,
                state,
            )
            .await;
        }
    };
    let setup = async {
        let address = relay::first_allowed_addr(
            &target.target.to_authority(target.port),
            state.config.advanced.tcp_connect_timeout_ms,
            &state.config.advanced.egress,
        )
        .await?;
        let socket = relay::bind_udp_for_target(address).await?;
        // macOS's default UDP send buffer cannot hold a maximum-sized packet.
        // Set bounded buffers on this owned socket, without changing host policy.
        let options = socket2::SockRef::from(&socket);
        options.set_send_buffer_size(131_072)?;
        options.set_recv_buffer_size(131_072)?;
        socket.connect(address).await?;
        Ok::<_, anyhow::Error>(socket)
    };
    let socket = tokio::select! {
        _ = std::future::poll_fn(|cx| send.poll_reset(cx)) => return Ok(()),
        result = timeout(Duration::from_millis(state.config.advanced.handshake_timeout_ms), setup) => {
            match result {
                Ok(Ok(socket)) => socket,
                _ => return send_h2_server_frame(&mut send,
                    relay::error_frame(open.flow_id, ErrorCode::TargetConnectFailed),
                    maximum, true, state).await,
            }
        }
    };
    let capacity = MAX_RELIABLE_UDP_PAYLOAD.min(maximum);
    send_h2_server_frame(
        &mut send,
        Frame::new(
            FrameType::WindowUpdate,
            RELIABLE_UDP_FLAGS,
            open.flow_id,
            Bytes::copy_from_slice(&(capacity as u16).to_be_bytes()),
        ),
        maximum,
        false,
        state,
    )
    .await?;

    let (activity, mut progress) = tokio::sync::watch::channel(());
    {
        let (close, mut closing) = oneshot::channel();
        let upload = async {
            loop {
                let frame = relay::read_next_frame(&mut recv, &mut buffer, maximum)
                    .await?
                    .context("reliable UDP request ended without CloseFlow")?;
                if frame.frame_type == FrameType::Padding {
                    continue;
                }
                anyhow::ensure!(frame.flow_id == open.flow_id, "UDP flow ID mismatch");
                if frame.frame_type == FrameType::CloseFlow {
                    anyhow::ensure!(
                        frame.flags == 0 && frame.payload.is_empty(),
                        "invalid UDP close"
                    );
                    return Ok::<_, anyhow::Error>(());
                }
                anyhow::ensure!(
                    frame.frame_type == FrameType::UdpPacket
                        && frame.flags == RELIABLE_UDP_FLAGS
                        && frame.payload.len() <= capacity,
                    "invalid reliable UDP packet"
                );
                if let Some(rate) = &user.rate_limiter {
                    rate.throttle(frame.payload.len()).await;
                }
                socket.send(&frame.payload).await?;
                activity.send_replace(());
            }
        };
        let download = async {
            let mut data = vec![0; capacity + 1];
            loop {
                let count = tokio::select! {
                    biased;
                    _ = &mut closing => break,
                    count = socket.recv(&mut data) => count?,
                };
                if count > capacity {
                    continue;
                }
                if let Some(rate) = &user.rate_limiter {
                    rate.throttle(count).await;
                }
                send_h2_server_frame(
                    &mut send,
                    Frame::new(
                        FrameType::UdpPacket,
                        RELIABLE_UDP_FLAGS,
                        open.flow_id,
                        Bytes::copy_from_slice(&data[..count]),
                    ),
                    maximum,
                    false,
                    state,
                )
                .await?;
                activity.send_replace(());
            }
            send_h2_server_frame(
                &mut send,
                Frame::new(FrameType::CloseFlow, 0, open.flow_id, Bytes::new()),
                maximum,
                true,
                state,
            )
            .await
        };
        tokio::pin!(upload, download);
        loop {
            tokio::select! {
                result = &mut upload => {
                    result?;
                    let _ = close.send(());
                    return download.await;
                },
                result = &mut download => return result,
                changed = timeout(Duration::from_millis(state.config.advanced.udp_idle_timeout_ms), progress.changed()) => {
                    if !matches!(changed, Ok(Ok(()))) {
                        let _ = close.send(());
                        return download.await;
                    }
                }
            }
        }
    }
}
