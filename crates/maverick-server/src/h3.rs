//! Opt-in TCP/native UDP session endpoint for a TLS-verified H3 frame channel.
//! Used by the explicit quiche listener and the isolated transport tests.

use super::*;
use maverick_core::h3_channel::{self, FrameChannel, FrameSender};

#[derive(Clone)]
pub struct Server {
    state: ServerState,
}

impl Server {
    pub fn new(config: ServerConfig) -> Result<Self> {
        anyhow::ensure!(
            !config.advanced.end_to_end,
            "end-to-end protection requires the H2 transport"
        );
        validate_runtime_features(&config)?;
        Ok(Self {
            state: server_state(config)?,
        })
    }

    /// The caller supplies the request path, peer address, and exporter from
    /// the verified QUIC connection that owns this channel.
    pub async fn serve(
        &self,
        tunnel: FrameChannel,
        peer: SocketAddr,
        path: &str,
        binding: TlsChannelBinding,
    ) -> Result<()> {
        anyhow::ensure!(
            path == self.state.config.maverick.tunnel_path,
            "unknown H3 tunnel path"
        );
        let Some(_connection) = try_connection_limit(&self.state, peer) else {
            return Ok(());
        };
        let _active = ActiveConnectionMetricGuard::new(Arc::clone(&self.state.metrics));
        self.serve_admitted(tunnel, peer, path, binding, None).await
    }

    async fn serve_admitted(
        &self,
        mut tunnel: FrameChannel,
        peer: SocketAddr,
        path: &str,
        binding: TlsChannelBinding,
        admission: Option<OwnedSemaphorePermit>,
    ) -> Result<()> {
        let state = &self.state;
        anyhow::ensure!(
            path == state.config.maverick.tunnel_path,
            "unknown H3 tunnel path"
        );
        let pre_auth = if let Some(permit) = admission {
            state
                .metrics
                .active_pre_auth
                .fetch_add(1, Ordering::Relaxed);
            PreAuthPermit {
                _permit: permit,
                metrics: Arc::clone(&state.metrics),
            }
        } else {
            let Some(permit) = try_pre_auth_admission(state) else {
                return Ok(());
            };
            permit
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
            Ok(Ok(Some(frame)))
                if frame.frame_type == FrameType::OpenTcp
                    || (frame.frame_type == FrameType::OpenUdp && frame.flags == 1) =>
            {
                frame
            }
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
        if open.frame_type == FrameType::OpenUdp {
            return serve_native_udp(tunnel, open, max, &policy, &user, state).await;
        }
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
        let target_metrics = state.metrics.target_open_sinks();
        // Transport loss cancels setup; a request FIN leaves this sender open.
        let target = tokio::select! {
            _ = tunnel.outbound.closed() => return Ok(()),
            result = relay::open_target_with_metrics(
                &target,
                state.config.advanced.tcp_connect_timeout_ms,
                &state.config.advanced.egress,
                &target_metrics,
            ) => result,
        };
        let target = match target {
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
        relay_tcp(target.into_split(), tunnel, open.flow_id, max, policy).await
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

async fn relay_tcp<R, W>(
    (mut read, mut write): (R, W),
    tunnel: FrameChannel,
    flow_id: u64,
    max: usize,
    policy: relay::TunnelRelayPolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Separate directions preserve receive progress while the H3 sender is
    // backpressured, including a response after the client's TCP half-close.
    let FrameChannel {
        outbound,
        mut inbound,
        ..
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
                    let mut bytes = frame.payload.as_ref();
                    while !bytes.is_empty() {
                        let written = timeout(policy.idle_timeout, write.write(bytes))
                            .await
                            .context("target relay write timed out")??;
                        anyhow::ensure!(
                            written > 0,
                            "target relay writer closed before the frame was complete"
                        );
                        bytes = &bytes[written..];
                        activity.send_replace(());
                    }
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
            // Once our response FIN is sent, this direction is done and the
            // remaining upload must survive the driver's normal sender closure.
            let count = tokio::select! {
                _ = outbound.closed() => anyhow::bail!("H3 response transport closed"),
                count = read.read(&mut buf) => count?,
            };
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

/// Starts the ordinary server command on UDP when explicitly configured for H3.
fn tls_context(config: &ServerConfig) -> Result<boring::ssl::SslContextBuilder> {
    use boring::ssl::{SslContext, SslFiletype, SslMethod, SslVersion};
    let mut tls = SslContext::builder(SslMethod::tls())?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_certificate_chain_file(&config.tls.cert_path)
        .context("load H3 certificate chain")?;
    tls.set_private_key_file(&config.tls.key_path, SslFiletype::PEM)
        .context("load H3 private key")?;
    tls.check_private_key()
        .context("H3 certificate/key mismatch")?;
    Ok(tls)
}

pub(super) async fn start(config: ServerConfig) -> Result<ServerHandle> {
    let tls = tls_context(&config)?;
    let server = Server::new(config.clone())?;
    let socket = tokio::net::UdpSocket::bind(config.listen).await?;
    let local_addr = socket.local_addr()?;
    let metrics_listener = bind_metrics_listener(&config).await?;
    let metrics_addr = metrics_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = tokio::spawn(serve_listener(
        socket,
        tls,
        server,
        metrics_listener,
        shutdown_rx,
    ));
    Ok(ServerHandle {
        local_addr,
        metrics_addr,
        shutdown: Some(shutdown_tx),
        join,
    })
}

/// Bind both carriers before publishing readiness. They share authentication,
/// replay, connection and per-user admission state.
pub(super) async fn start_dual(config: ServerConfig) -> Result<ServerHandle> {
    let acceptor = h2_acceptor::acceptor(&config)?;
    let tls = tls_context(&config)?;
    let state = server_state(config)?;
    let tcp = TcpListener::bind(state.config.listen).await?;
    let local_addr = tcp.local_addr()?;
    let udp = tokio::net::UdpSocket::bind(local_addr).await?;
    let metrics = bind_metrics_listener(&state.config).await?;
    let metrics_addr = metrics.as_ref().map(TcpListener::local_addr).transpose()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let (h2_stop, h2_rx) = oneshot::channel();
    let (h3_stop, h3_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        let h3 = serve_listener(
            udp,
            tls,
            Server {
                state: state.clone(),
            },
            None,
            h3_rx,
        );
        let h2 = super::serve(tcp, metrics, acceptor, state, h2_rx);
        tokio::pin!(h2, h3);
        enum End {
            Stop,
            H2(Result<()>),
            H3(Result<()>),
        }
        let end = tokio::select! {
            _ = &mut shutdown_rx => End::Stop,
            result = &mut h2 => End::H2(result),
            result = &mut h3 => End::H3(result),
        };
        let _ = h2_stop.send(());
        let _ = h3_stop.send(());
        match end {
            End::Stop => {
                let (a, b) = tokio::join!(h2, h3);
                a.and(b)
            }
            End::H2(result) => result.and(h3.await),
            End::H3(result) => result.and(h2.await),
        }
    });
    Ok(ServerHandle {
        local_addr,
        metrics_addr,
        shutdown: Some(shutdown_tx),
        join,
    })
}

async fn serve_listener(
    socket: tokio::net::UdpSocket,
    tls: boring::ssl::SslContextBuilder,
    server: Server,
    metrics_listener: Option<TcpListener>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let config = &server.state.config;
    let options = maverick_quiche::ServeOptions {
        path: config.maverick.tunnel_path.clone(),
        limits: maverick_quiche::Limits {
            max_frame_size: config.advanced.max_frame_size as usize,
            handshake_timeout: Duration::from_millis(config.advanced.handshake_timeout_ms),
            idle_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
        },
        max_connections: config.advanced.max_concurrent_connections as usize,
        max_connections_per_source: config.advanced.max_concurrent_connections_per_source as usize,
        admission: Arc::clone(&server.state.pre_auth_admission),
    };
    let (accepted, mut connections) = tokio::sync::mpsc::channel(1);
    let (stop_tx, stop_rx) = oneshot::channel();
    let driver =
        maverick_quiche::serve_with_admission(socket, tls, options, accepted, stop_rx, |peer| {
            let connection = try_connection_limit(&server.state, peer)?;
            let active = ActiveConnectionMetricGuard::new(Arc::clone(&server.state.metrics));
            Some((connection, active))
        });
    tokio::pin!(driver);
    let (metrics_stop, metrics_join) = if let Some(listener) = metrics_listener {
        let (tx, rx) = oneshot::channel();
        (
            Some(tx),
            Some(tokio::spawn(serve_metrics(
                listener,
                Arc::clone(&server.state.metrics),
                rx,
            ))),
        )
    } else {
        (None, None)
    };
    let mut tasks = JoinSet::new();
    let mut driver_finished = false;
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            result = &mut driver => { driver_finished = true; break result; }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined { break Err(error.into()); }
            }
            connection = connections.recv() => {
                let Some(connection) = connection else { break Ok(()); };
                let server = server.clone();
                tasks.spawn(async move {
                    if let Err(error) = server.serve_admitted(
                        connection.channel, connection.peer, &server.state.config.maverick.tunnel_path,
                        connection.binding, connection.admission,
                    ).await {
                        debug!(error = %error, "H3 session ended");
                    }
                });
            }
        }
    };
    let _ = stop_tx.send(());
    let driver_result = if driver_finished {
        Ok(())
    } else {
        driver.await
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Some(stop) = metrics_stop {
        let _ = stop.send(());
    }
    if let Some(join) = metrics_join {
        join.await??;
    }
    result.and(driver_result)
}

async fn serve_native_udp(
    tunnel: FrameChannel,
    open: Frame,
    max: usize,
    policy: &relay::TunnelRelayPolicy,
    user: &UserPolicy,
    state: &ServerState,
) -> Result<()> {
    let FrameChannel {
        outbound,
        mut inbound,
        mut datagrams,
    } = tunnel;
    let target = match OpenTcpPayload::decode(&open.payload) {
        Ok(target) if target.initial_data.is_empty() => target,
        _ => {
            return send(
                &outbound,
                relay::error_frame(open.flow_id, ErrorCode::ProtocolError),
                true,
                max,
                policy,
            )
            .await
        }
    };
    let Some(_flow) = try_user_flow_permit(state, user) else {
        return send(
            &outbound,
            relay::error_frame(open.flow_id, ErrorCode::FlowLimitExceeded),
            true,
            max,
            policy,
        )
        .await;
    };
    let setup = async {
        let capacity = datagrams.ready().await?;
        let address = relay::first_allowed_addr(
            &target.target.to_authority(target.port),
            state.config.advanced.tcp_connect_timeout_ms,
            &state.config.advanced.egress,
        )
        .await?;
        let socket = relay::bind_udp_for_target(address).await?;
        socket.connect(address).await?;
        Ok::<_, anyhow::Error>((socket, capacity))
    };
    let opened = tokio::select! {
        _ = outbound.closed() => return Ok(()),
        result = timeout(Duration::from_millis(state.config.advanced.handshake_timeout_ms), setup) => result,
    };
    let (socket, capacity) = match opened {
        Ok(Ok(value)) => value,
        _ => {
            return send(
                &outbound,
                relay::error_frame(open.flow_id, ErrorCode::TargetConnectFailed),
                true,
                max,
                policy,
            )
            .await
        }
    };
    let capacity = capacity.min(h3_channel::MAX_NATIVE_UDP_PAYLOAD);
    anyhow::ensure!(capacity > 0, "native datagrams unavailable");
    datagrams.enable();
    send(
        &outbound,
        Frame::new(
            FrameType::WindowUpdate,
            1,
            open.flow_id,
            Bytes::copy_from_slice(&(capacity as u16).to_be_bytes()),
        ),
        false,
        max,
        policy,
    )
    .await?;
    let (activity, mut progress) = tokio::sync::watch::channel(());
    let upload = async {
        while let Some(packet) = datagrams.inbound.recv().await {
            if packet.len() > capacity {
                continue;
            }
            if let Some(rate) = &policy.rate_limiter {
                rate.throttle(packet.len()).await;
            }
            socket.send(&packet).await?;
            activity.send_replace(());
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        let mut buffer = [0; h3_channel::MAX_NATIVE_UDP_PAYLOAD + 1];
        loop {
            let count = socket.recv(&mut buffer).await?;
            if count > capacity {
                continue;
            }
            if let Some(rate) = &policy.rate_limiter {
                rate.throttle(count).await;
            }
            match datagrams
                .outbound
                .try_send(Bytes::copy_from_slice(&buffer[..count]))
            {
                Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
            }
            activity.send_replace(());
        }
        Ok::<_, anyhow::Error>(())
    };
    let control = async {
        let frame = h3_channel::read_frame(&mut inbound, max).await?;
        anyhow::ensure!(
            frame
                .is_none_or(|frame| frame.frame_type == FrameType::CloseFlow
                    && frame.flow_id == open.flow_id),
            "unexpected native UDP control frame"
        );
        Ok::<_, anyhow::Error>(())
    };
    tokio::pin!(upload, download, control);
    let result = loop {
        tokio::select! {
            result = &mut upload => break result,
            result = &mut download => break result,
            result = &mut control => break result,
            _ = outbound.closed() => break Ok(()),
            changed = timeout(Duration::from_millis(state.config.advanced.udp_idle_timeout_ms), progress.changed()) => {
                if !matches!(changed, Ok(Ok(()))) { break Ok(()); }
            }
        }
    };
    let _ = send(
        &outbound,
        Frame::new(FrameType::CloseFlow, 0, open.flow_id, Bytes::new()),
        true,
        max,
        policy,
    )
    .await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use maverick_core::{frame::TargetAddr, Mode};
    use std::task::Poll;
    use tokio::time::{advance, Instant};

    fn relay_policy() -> relay::TunnelRelayPolicy {
        relay::TunnelRelayPolicy {
            idle_timeout: Duration::from_secs(2),
            rate_limiter: None,
            padding: RuntimePadding::disabled(),
            cover_traffic: RuntimeCoverTraffic::disabled(),
            shaping_metrics: None,
        }
    }

    #[test]
    fn h3_endpoint_rejects_h2_protection_before_loading_keys() -> Result<()> {
        let secret = SecretString::generate();
        let config = ServerConfig::from_yaml_str(&format!(
            "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: unavailable-cert.pem\n  key_path: unavailable-key.pem\nmaverick:\n  tunnel_path: /protected\nusers:\n  - id: test-user\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: public\nadvanced:\n  end_to_end: true\n",
            secret.expose_secret(),
        ))?;
        let error = match Server::new(config) {
            Ok(_) => anyhow::bail!("H3 endpoint accepted H2 protection"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "end-to-end protection requires the H2 transport"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn transport_loss_releases_silent_target_after_fin_or_blocked_upload() -> Result<()> {
        for upload_finished in [true, false] {
            let (channel, transport) = h3_channel::channel();
            let (target, mut peer) = tokio::io::duplex(1);
            let mut relay = Box::pin(relay_tcp(
                tokio::io::split(target),
                channel,
                1,
                65_536,
                relay_policy(),
            ));
            let frame = if upload_finished {
                Frame::new(FrameType::TcpFin, 0, 1, Bytes::new())
            } else {
                Frame::new(
                    FrameType::TcpData,
                    0,
                    1,
                    Bytes::from_static(b"blocked upload"),
                )
            };
            transport
                .inbound
                .try_send(Ok(Some(frame)))
                .map_err(|_| anyhow::anyhow!("cannot queue test upload"))?;
            let started = Instant::now();
            assert!(poll!(relay.as_mut()).is_pending());
            let mut first = [0];
            match poll!(Box::pin(peer.read(&mut first)).as_mut()) {
                Poll::Ready(result) => {
                    assert_eq!(result?, if upload_finished { 0 } else { 1 });
                    if !upload_finished {
                        assert_eq!(&first, b"b");
                    }
                }
                Poll::Pending => anyhow::bail!("upload did not reach the target"),
            }
            // In the data case the next byte fills the one-byte target buffer,
            // leaving the rest of the upload blocked while its read stays silent.
            assert!(poll!(relay.as_mut()).is_pending());
            drop(transport.outbound);
            match poll!(relay.as_mut()) {
                Poll::Ready(result) => {
                    assert!(
                        result.is_err(),
                        "transport loss completed as a graceful relay"
                    );
                }
                Poll::Pending => anyhow::bail!(
                    "transport loss retained a silent target (upload_finished={upload_finished})"
                ),
            }
            assert_eq!(
                Instant::now(),
                started,
                "cancellation waited for idle expiry"
            );
            assert!(transport.inbound.is_closed());
            match poll!(Box::pin(peer.write_all(b"late target response")).as_mut()) {
                Poll::Ready(result) => {
                    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
                }
                Poll::Pending => anyhow::bail!("cancelled relay retained its target reader"),
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn target_fin_preserves_upload_after_response_channel_closes() -> Result<()> {
        let (channel, mut transport) = h3_channel::channel();
        let (target, mut peer) = tokio::io::duplex(16);
        let mut relay = Box::pin(relay_tcp(
            tokio::io::split(target),
            channel,
            1,
            65_536,
            relay_policy(),
        ));
        peer.shutdown().await?;
        assert!(poll!(relay.as_mut()).is_pending());
        let (fin, ended) = transport.outbound.try_recv()?;
        assert_eq!(fin.frame_type, FrameType::TcpFin);
        assert!(ended);
        // The driver closes this receiver after sending the response FIN.
        // The target's read direction must still accept the client's upload.
        transport.outbound.close();
        let payload = b"late upload";
        transport
            .inbound
            .try_send(Ok(Some(Frame::new(
                FrameType::TcpData,
                0,
                1,
                Bytes::from_static(payload),
            ))))
            .map_err(|_| anyhow::anyhow!("cannot queue upload after target FIN"))?;
        assert!(poll!(relay.as_mut()).is_pending());
        let mut received = [0; 11];
        match poll!(Box::pin(peer.read_exact(&mut received)).as_mut()) {
            Poll::Ready(result) => {
                result?;
            }
            Poll::Pending => anyhow::bail!("target FIN prevented continued upload"),
        }
        assert_eq!(&received, payload);
        transport
            .inbound
            .try_send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
            .map_err(|_| anyhow::anyhow!("cannot queue final upload FIN"))?;
        match poll!(relay.as_mut()) {
            Poll::Ready(result) => result?,
            Poll::Pending => {
                anyhow::bail!("relay did not complete after both TCP directions ended")
            }
        }
        let mut byte = [0];
        match poll!(Box::pin(peer.read(&mut byte)).as_mut()) {
            Poll::Ready(result) => assert_eq!(result?, 0),
            Poll::Pending => anyhow::bail!("final upload FIN did not reach target"),
        }
        assert!(transport.inbound.is_closed());
        Ok(())
    }

    #[test]
    fn pending_target_resolution_releases_flow_when_transport_closes() -> Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()?
            .block_on(async {
                // Hold this private runtime's only blocking worker so the real
                // localhost resolver stays pending without network manipulation.
                // Dropping release also unblocks it if an assertion fails.
                let (release, released) = std::sync::mpsc::channel::<()>();
                let (entered, blocked) = oneshot::channel();
                let worker = tokio::task::spawn_blocking(move || {
                    let _ = entered.send(());
                    let _ = released.recv();
                });
                blocked.await?;

                let secret = SecretString::generate();
                let config = ServerConfig::from_yaml_str(&format!(
                    "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: cert.pem\n  key_path: key.pem\nmaverick:\n  tunnel_path: /pending-target\nusers:\n  - id: pending-target-user\n    secret: '{}'\n    max_concurrent_flows: 1\nfallback:\n  type: static\n  static_dir: public\nadvanced:\n  quiche_h3: true\n  egress:\n    allow_loopback: true\n",
                    secret.expose_secret(),
                ))?;
                let server = Server::new(config)?;
                let user = server
                    .state
                    .policies
                    .for_user("pending-target-user")
                    .context("missing test user policy")?;
                let metrics = &server.state.metrics;
                let target = TcpListener::bind("127.0.0.1:0").await?;
                let address = target.local_addr()?;
                let mut binding_bytes = [0; 32];
                boring::rand::rand_bytes(&mut binding_bytes)?;
                let binding = TlsChannelBinding::new(binding_bytes);
                let hello = ClientHello::try_new_with_channel_binding(
                    "pending-target-user",
                    &secret,
                    "/pending-target",
                    Mode::Stable,
                    FEATURE_TLS_CHANNEL_BINDING,
                    Some(binding),
                )?;
                let (channel, mut transport) = h3_channel::channel();
                let mut serving = Box::pin(server.serve(
                    channel,
                    address,
                    "/pending-target",
                    binding,
                ));
                transport
                    .inbound
                    .try_send(Ok(Some(Frame::new(
                        FrameType::ClientHello,
                        0,
                        0,
                        hello.encode(),
                    ))))
                    .map_err(|_| anyhow::anyhow!("cannot queue test ClientHello"))?;
                assert!(poll!(serving.as_mut()).is_pending());
                let (hello, ended) = transport.outbound.try_recv()?;
                assert_eq!(hello.frame_type, FrameType::ServerHello);
                assert!(!ended);

                let open = OpenTcpPayload::new(
                    TargetAddr::Domain("localhost".into()),
                    address.port(),
                );
                transport
                    .inbound
                    .try_send(Ok(Some(Frame::new(FrameType::OpenTcp, 0, 1, open.encode()?))))
                    .map_err(|_| anyhow::anyhow!("cannot queue test OpenTcp"))?;
                assert!(poll!(serving.as_mut()).is_pending());
                assert_eq!(metrics.active_flows.load(Ordering::Relaxed), 1);
                assert_eq!(user.flow_limit.available_permits(), 0);
                assert_eq!(metrics.target_open_sinks().resolution_latency.snapshot().count, 0);

                // Upload FIN does not mean the response transport disappeared.
                transport
                    .inbound
                    .try_send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
                    .map_err(|_| anyhow::anyhow!("cannot queue test TCP FIN"))?;
                assert!(poll!(serving.as_mut()).is_pending());
                assert_eq!(metrics.active_flows.load(Ordering::Relaxed), 1);

                drop(transport.outbound);
                match poll!(serving.as_mut()) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => anyhow::bail!(
                        "disconnected H3 transport retained the pending target and flow slot"
                    ),
                }
                assert_eq!(metrics.active_flows.load(Ordering::Relaxed), 0);
                assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
                assert_eq!(user.flow_limit.available_permits(), 1);
                assert_eq!(metrics.target_open_sinks().resolution_latency.snapshot().count, 0);

                let reused = try_user_flow_permit(&server.state, &user)
                    .context("cancelled target retained the only user flow slot")?;
                drop(reused);
                release.send(())?;
                worker.await?;
                assert!(poll!(Box::pin(target.accept()).as_mut()).is_pending());
                Ok(())
            })
    }

    #[tokio::test(start_paused = true)]
    async fn target_write_progress_outlives_idle_timeout() -> Result<()> {
        let (channel, mut transport) = h3_channel::channel();
        let (target, mut peer) = tokio::io::duplex(1);
        let task = tokio::spawn(relay_tcp(
            tokio::io::split(target),
            channel,
            1,
            65_536,
            relay_policy(),
        ));
        let payload = b"progress";
        transport
            .inbound
            .send(Ok(Some(Frame::new(
                FrameType::TcpData,
                0,
                1,
                Bytes::from_static(payload),
            ))))
            .await?;
        let started = Instant::now();
        for (index, expected) in payload.iter().enumerate() {
            let mut byte = [0];
            peer.read_exact(&mut byte)
                .await
                .context("target stopped while partial writes were advancing")?;
            assert_eq!(byte[0], *expected);
            if index + 1 < payload.len() {
                tokio::task::yield_now().await;
                advance(Duration::from_millis(500)).await;
            }
        }
        assert!(started.elapsed() > relay_policy().idle_timeout);
        transport
            .inbound
            .send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
            .await?;
        peer.shutdown().await?;
        task.await??;
        let (fin, ended) = transport
            .outbound
            .recv()
            .await
            .context("missing target FIN")?;
        assert_eq!(fin.frame_type, FrameType::TcpFin);
        assert!(ended);
        assert!(transport.outbound.recv().await.is_none());
        assert!(transport.inbound.is_closed());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn target_write_stall_times_out_after_progress() -> Result<()> {
        let (channel, mut transport) = h3_channel::channel();
        let (target, mut peer) = tokio::io::duplex(1);
        let task = tokio::spawn(relay_tcp(
            tokio::io::split(target),
            channel,
            1,
            65_536,
            relay_policy(),
        ));
        transport
            .inbound
            .send(Ok(Some(Frame::new(
                FrameType::TcpData,
                0,
                1,
                Bytes::from_static(b"progress then stop"),
            ))))
            .await?;
        let mut byte = [0];
        peer.read_exact(&mut byte).await?;
        assert_eq!(byte[0], b'p');
        tokio::task::yield_now().await;
        advance(Duration::from_secs(1)).await;
        peer.read_exact(&mut byte).await?;
        assert_eq!(byte[0], b'r');
        tokio::task::yield_now().await;
        // A partial write at t=1 must move the deadline past the original t=2.
        advance(Duration::from_millis(1500)).await;
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "target write expired before one idle window without progress"
        );
        advance(Duration::from_secs(1)).await;
        let error = task.await?.expect_err("stalled target write must time out");
        assert!(
            error.to_string().contains("target relay write timed out")
                || error.to_string().contains("H3 relay idle timeout")
        );
        assert!(transport.inbound.is_closed());
        assert!(transport.outbound.recv().await.is_none());
        Ok(())
    }
}
