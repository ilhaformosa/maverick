//! Opt-in TCP session endpoint for a TLS-verified H3 frame channel.
//! The ordinary server listener and config-v1 transport selection do not use it.

use super::*;
use maverick_core::h3_channel::{self, FrameChannel, FrameSender};

#[derive(Clone)]
pub struct Server {
    state: ServerState,
}

impl Server {
    pub fn new(config: ServerConfig) -> Result<Self> {
        validate_runtime_features(&config)?;
        Ok(Self {
            state: server_state(config)?,
        })
    }

    /// The caller supplies the request path, peer address, and exporter from
    /// the verified QUIC connection that owns this channel.
    pub async fn serve(
        &self,
        mut tunnel: FrameChannel,
        peer: SocketAddr,
        path: &str,
        binding: TlsChannelBinding,
    ) -> Result<()> {
        let state = &self.state;
        anyhow::ensure!(
            path == state.config.maverick.tunnel_path,
            "unknown H3 tunnel path"
        );
        let Some(_connection) = try_connection_limit(state, peer) else {
            return Ok(());
        };
        let _active = ActiveConnectionMetricGuard::new(Arc::clone(&state.metrics));
        let Some(pre_auth) = try_pre_auth_admission(state) else {
            return Ok(());
        };
        let max = state.config.advanced.max_frame_size as usize;
        let first = timeout(
            unauthenticated_first_frame_timeout(&state.config),
            tunnel.read(max),
        )
        .await;
        let authenticated = match first {
            Ok(Ok(Some(frame))) => {
                authenticate_tunnel_frame(&frame, state, current_unix(), Some(binding)).await
            }
            _ => None,
        };
        let Some(authenticated) = authenticated else {
            state
                .metrics
                .unauthenticated_rejections
                .fetch_add(1, Ordering::Relaxed);
            record_auth_failure(state, peer).await;
            return Ok(());
        };
        drop(pre_auth);
        state
            .metrics
            .authenticated_sessions
            .fetch_add(1, Ordering::Relaxed);
        let user = state
            .policies
            .for_user(&authenticated.credential.user.id)
            .context("missing authenticated user policy")?;
        let max_flows = authenticated
            .credential
            .user
            .max_concurrent_flows
            .unwrap_or(state.config.maverick.max_concurrent_flows_per_user);
        let hello = authenticated.server_hello_payload(max as u32, max_flows, Some(binding))?;
        let policy = relay::TunnelRelayPolicy {
            idle_timeout: Duration::from_secs(state.config.advanced.idle_timeout_secs),
            rate_limiter: user.rate_limiter.clone(),
            padding: server_padding(state),
            cover_traffic: server_cover_traffic(state),
            shaping_metrics: Some(state.metrics.shaping_sinks()),
        };
        timeout(
            Duration::from_millis(state.config.advanced.handshake_timeout_ms),
            send(
                &tunnel.outbound,
                Frame::new(FrameType::ServerHello, 0, 0, hello),
                false,
                max,
                &policy,
            ),
        )
        .await
        .context("H3 ServerHello timed out")??;
        let open = timeout(
            Duration::from_millis(state.config.advanced.handshake_timeout_ms),
            tunnel.read(max),
        )
        .await;
        let open = match open {
            Ok(Ok(Some(frame))) if frame.frame_type == FrameType::OpenTcp => frame,
            _ => {
                return send(
                    &tunnel.outbound,
                    relay::error_frame(0, ErrorCode::ProtocolError),
                    true,
                    max,
                    &policy,
                )
                .await
            }
        };
        let target = match OpenTcpPayload::decode(&open.payload) {
            Ok(target) => target,
            Err(_) => {
                return send(
                    &tunnel.outbound,
                    relay::error_frame(open.flow_id, ErrorCode::ProtocolError),
                    true,
                    max,
                    &policy,
                )
                .await
            }
        };
        let Some(_flow) = try_user_flow_permit(state, &user) else {
            return send(
                &tunnel.outbound,
                relay::error_frame(open.flow_id, ErrorCode::FlowLimitExceeded),
                true,
                max,
                &policy,
            )
            .await;
        };
        let target = match relay::open_target_with_metrics(
            &target,
            state.config.advanced.tcp_connect_timeout_ms,
            &state.config.advanced.egress,
            &state.metrics.target_open_sinks(),
        )
        .await
        {
            Ok(target) => target,
            Err(_) => {
                return send(
                    &tunnel.outbound,
                    relay::error_frame(open.flow_id, ErrorCode::TargetConnectFailed),
                    true,
                    max,
                    &policy,
                )
                .await
            }
        };
        state.metrics.tcp_flows.fetch_add(1, Ordering::Relaxed);
        send(
            &tunnel.outbound,
            Frame::new(FrameType::WindowUpdate, 0, open.flow_id, Bytes::new()),
            false,
            max,
            &policy,
        )
        .await?;
        relay_tcp(target, tunnel, open.flow_id, max, policy).await
    }
}

async fn send(
    sender: &FrameSender,
    frame: Frame,
    end: bool,
    max: usize,
    policy: &relay::TunnelRelayPolicy,
) -> Result<()> {
    let mut emission = relay::PaddingEmission::default();
    timeout(policy.idle_timeout, async {
        if let Some(padding) =
            policy
                .padding
                .padding_frame(frame.frame_type, frame.payload.len(), max)
        {
            emission.padding_frames += 1;
            emission.padding_bytes += padding.payload.len();
            h3_channel::send_frame(sender, padding, false, max).await?;
        }
        for padding in
            policy
                .cover_traffic
                .padding_frames(frame.frame_type, frame.payload.len(), max)
        {
            emission.cover_traffic_padding_frames += 1;
            emission.cover_traffic_padding_bytes += padding.payload.len();
            h3_channel::send_frame(sender, padding, false, max).await?;
        }
        h3_channel::send_frame(sender, frame, end, max).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("H3 frame send timed out")??;
    policy.record_padding(emission);
    Ok(())
}

async fn relay_tcp(
    target: TcpStream,
    tunnel: FrameChannel,
    flow_id: u64,
    max: usize,
    policy: relay::TunnelRelayPolicy,
) -> Result<()> {
    let (mut read, mut write) = target.into_split();
    // Separate directions preserve receive progress while the H3 sender is
    // backpressured, including a response after the client's TCP half-close.
    let FrameChannel {
        outbound,
        mut inbound,
    } = tunnel;
    let (activity, mut progress) = tokio::sync::watch::channel(());
    let upstream = async {
        loop {
            let frame = h3_channel::read_frame(&mut inbound, max)
                .await?
                .context("H3 request ended without TCP FIN")?;
            activity.send_replace(());
            if frame.flow_id != flow_id {
                continue;
            }
            match frame.frame_type {
                FrameType::TcpData => {
                    if let Some(rate) = &policy.rate_limiter {
                        rate.throttle(frame.payload.len()).await;
                    }
                    timeout(policy.idle_timeout, write.write_all(&frame.payload))
                        .await
                        .context("target relay write timed out")??;
                }
                FrameType::TcpFin | FrameType::CloseFlow => {
                    write.shutdown().await?;
                    return Ok::<_, anyhow::Error>(());
                }
                FrameType::TcpReset => anyhow::bail!("client reset TCP flow"),
                _ => {}
            }
        }
    };
    let downstream = async {
        let mut buf = vec![0; (16 * 1024).min(max)];
        loop {
            let count = read.read(&mut buf).await?;
            activity.send_replace(());
            if count == 0 {
                send(
                    &outbound,
                    Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                    true,
                    max,
                    &policy,
                )
                .await?;
                return Ok::<_, anyhow::Error>(());
            }
            if let Some(rate) = &policy.rate_limiter {
                rate.throttle(count).await;
            }
            send(
                &outbound,
                Frame::new(
                    FrameType::TcpData,
                    0,
                    flow_id,
                    Bytes::copy_from_slice(&buf[..count]),
                ),
                false,
                max,
                &policy,
            )
            .await?;
        }
    };
    let relay = async {
        tokio::try_join!(upstream, downstream)?;
        Ok(())
    };
    tokio::pin!(relay);
    loop {
        tokio::select! {
            result = &mut relay => return result,
            changed = timeout(policy.idle_timeout, progress.changed()) => {
                changed.context("H3 relay idle timeout")??;
            }
        }
    }
}
