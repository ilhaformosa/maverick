//! Explicit H3 frame-channel entry points. The default transport selector and
//! the retired config-v1 H3 flag do not activate this module.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use maverick_core::auth::TlsChannelBinding;
use maverick_core::h3_channel::{self, FrameChannel, FrameReceiver, FrameSender};
use maverick_core::padding::{RuntimeBatcher, RuntimeCoverTraffic, RuntimePadding};
use maverick_core::{ClientConfig, Frame, FrameType};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::tunnel::{
    prepare_outgoing_frames, validate_negotiated_max_frame_size, ClientHandshake, ClientTunnel,
};

pub struct H3ClientTunnel {
    udp_sessions: bool,
    sender: H3Sender,
    receiver: FrameReceiver,
    datagrams: h3_channel::DatagramChannel,
}

struct H3Sender {
    channel: FrameSender,
    max_frame_size: usize,
    padding: RuntimePadding,
    cover: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
    stall_timeout: Duration,
    request_ended: bool,
    flow_id: u64,
}

pub async fn open(
    config: &ClientConfig,
    mut channel: FrameChannel,
    binding: TlsChannelBinding,
) -> Result<ClientTunnel> {
    anyhow::ensure!(
        config.advanced.end_to_end.is_none(),
        "end-to-end protection requires the H2 transport"
    );
    config.validate()?;
    let budget = Duration::from_millis(config.advanced.connect_timeout_ms);
    let (max_frame_size, features) = timeout(budget, async {
        let hello = ClientHandshake::new(config, Some(binding))?;
        channel
            .send(
                Frame::new(FrameType::ClientHello, 0, 0, hello.encode()?),
                false,
                65_536,
            )
            .await?;
        let server = channel
            .read(65_536)
            .await?
            .context("missing H3 ServerHello")?;
        if server.frame_type != FrameType::ServerHello {
            bail!("server rejected H3 handshake");
        }
        let (maximum, features) = hello.verify_server_parameters(&server.payload)?;
        Ok::<_, anyhow::Error>((validate_negotiated_max_frame_size(maximum)?, features))
    })
    .await
    .context("H3 authentication timed out")??;
    Ok(ClientTunnel::H3(Box::new(H3ClientTunnel {
        udp_sessions: features & maverick_core::auth::FEATURE_UDP_SESSION != 0,
        receiver: channel.inbound,
        datagrams: channel.datagrams,
        sender: H3Sender {
            channel: channel.outbound,
            max_frame_size,
            padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
            cover: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
            batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
            stall_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
            request_ended: false,
            flow_id: 1,
        },
    })))
}

/// Serves one TCP SOCKS connection over an already TLS-verified H3 transport.
pub async fn proxy_socks_connection(
    mut local: TcpStream,
    config: &ClientConfig,
    channel: FrameChannel,
    binding: TlsChannelBinding,
) -> Result<()> {
    let budget = Duration::from_millis(config.advanced.connect_timeout_ms);
    let request = timeout(budget, crate::socks5::read_connect_request(&mut local))
        .await
        .context("SOCKS request timed out")??;
    let opened = async {
        let tunnel = open(config, channel, binding).await?;
        crate::session::open_tcp_on_tunnel(tunnel, request.target, request.port).await
    }
    .await;
    let tunnel = match opened {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let _ = crate::socks5::write_failure(&mut local).await;
            return Err(error);
        }
    };
    crate::socks5::write_success(&mut local).await?;
    crate::session::relay_stream_and_tunnel(
        local,
        tunnel,
        Duration::from_secs(config.advanced.idle_timeout_secs),
    )
    .await?;
    Ok(())
}

impl H3ClientTunnel {
    pub(crate) fn max_frame_size(&self) -> usize {
        self.sender.max_frame_size
    }

    pub(crate) async fn read_next_frame(&mut self) -> Result<Option<Frame>> {
        Ok(h3_channel::read_frame(&mut self.receiver, self.sender.max_frame_size).await?)
    }

    pub(crate) async fn send_frame(&mut self, frame: Frame, end: bool) -> Result<()> {
        self.sender.send_frame(frame, end).await
    }

    pub(crate) async fn finish_response(&mut self) -> Result<()> {
        timeout(self.sender.stall_timeout, async {
            if !self.sender.request_ended {
                self.sender
                    .send_frame(
                        Frame::new(FrameType::CloseFlow, 0, self.sender.flow_id, Bytes::new()),
                        true,
                    )
                    .await?;
            }
            if self.read_next_frame().await?.is_some() {
                bail!("unexpected H3 frame after flow completion");
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("H3 response completion timed out")?
    }

    pub(crate) async fn relay<S>(
        self,
        local: S,
        idle: Duration,
    ) -> Result<crate::session::RelayClose>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut read, mut write) = tokio::io::split(local);
        let Self {
            mut sender,
            mut receiver,
            ..
        } = self;
        let flow_id = sender.flow_id;
        let max = sender.max_frame_size;
        let (activity, mut progress) = tokio::sync::watch::channel(());
        let upload = async {
            let mut bytes = vec![0; (16 * 1024).min(max)];
            loop {
                // Watch only while uploading: the driver also closes this
                // sender after our FIN, while the response may still be live.
                let count = tokio::select! {
                    _ = sender.channel.closed() => bail!("H3 request transport closed"),
                    count = read.read(&mut bytes) => count?,
                };
                activity.send_replace(());
                let frame = if count == 0 {
                    Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new())
                } else {
                    Frame::new(
                        FrameType::TcpData,
                        0,
                        flow_id,
                        Bytes::copy_from_slice(&bytes[..count]),
                    )
                };
                sender.send_frame(frame, count == 0).await?;
                if count == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        };
        let download = async {
            loop {
                let frame = h3_channel::read_frame(&mut receiver, max)
                    .await?
                    .context("H3 response ended without TCP FIN")?;
                activity.send_replace(());
                if frame.flow_id != flow_id {
                    continue;
                }
                match frame.frame_type {
                    FrameType::TcpData => {
                        let mut bytes = frame.payload.as_ref();
                        while !bytes.is_empty() {
                            let written = timeout(idle, write.write(bytes))
                                .await
                                .context("local relay write timed out")??;
                            if written == 0 {
                                bail!("local relay writer closed before the frame was complete");
                            }
                            bytes = &bytes[written..];
                            activity.send_replace(());
                        }
                    }
                    FrameType::TcpFin | FrameType::CloseFlow => {
                        let full_close = frame.frame_type == FrameType::CloseFlow;
                        write.shutdown().await?;
                        if timeout(idle, h3_channel::read_frame(&mut receiver, max))
                            .await
                            .context("H3 response completion timed out")??
                            .is_some()
                        {
                            bail!("unexpected H3 frame after flow completion");
                        }
                        return Ok::<_, anyhow::Error>(full_close);
                    }
                    FrameType::Error | FrameType::TcpReset => bail!("server reset H3 TCP flow"),
                    _ => {}
                }
            }
        };
        // A TCP FIN ends only one direction. Keep receiving while an upload is
        // backpressured, and keep uploading after the target finishes sending.
        let relay = async {
            tokio::pin!(upload, download);
            tokio::select! {
                sent = &mut upload => { sent?; download.await?; }
                received = &mut download => {
                    if !received? { upload.await?; }
                }
            }
            Ok(crate::session::RelayClose::Graceful)
        };
        tokio::pin!(relay);
        loop {
            tokio::select! {
                result = &mut relay => return result,
                changed = timeout(idle, progress.changed()) => {
                    changed.context("H3 relay idle timeout")??;
                }
            }
        }
    }
}

impl H3Sender {
    pub(crate) async fn send_frame(&mut self, frame: Frame, end: bool) -> Result<()> {
        self.flow_id = frame.flow_id;
        let frames = prepare_outgoing_frames(frame, &mut self.batcher, &self.padding).await;
        let last = frames.len().saturating_sub(1);
        timeout(self.stall_timeout, async {
            for (index, frame) in frames.into_iter().enumerate() {
                if let Some(padding) = self.padding.padding_frame(
                    frame.frame_type,
                    frame.payload.len(),
                    self.max_frame_size,
                ) {
                    h3_channel::send_frame(&self.channel, padding, false, self.max_frame_size)
                        .await?;
                }
                for padding in self.cover.padding_frames(
                    frame.frame_type,
                    frame.payload.len(),
                    self.max_frame_size,
                ) {
                    h3_channel::send_frame(&self.channel, padding, false, self.max_frame_size)
                        .await?;
                }
                h3_channel::send_frame(
                    &self.channel,
                    frame,
                    end && index == last,
                    self.max_frame_size,
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("H3 send stalled")??;
        self.request_ended |= end;
        Ok(())
    }
}

/// One authenticated, fixed-target native UDP association. Sending is bounded
/// and unreliable; Ok(false) means the packet was dropped before transmission.
pub struct NativeUdpAssociation {
    sender: H3Sender,
    receiver: FrameReceiver,
    datagrams: h3_channel::DatagramChannel,
    max_payload: usize,
}

impl NativeUdpAssociation {
    pub async fn open(
        config: &ClientConfig,
        target: maverick_core::frame::TargetAddr,
        port: u16,
    ) -> Result<Self> {
        config.validate()?;
        anyhow::ensure!(
            config.advanced.quiche_h3 || config.advanced.auto_h3,
            "native UDP requires explicit H3"
        );
        timeout(
            Duration::from_millis(config.advanced.connect_timeout_ms),
            async {
                let connected = crate::h3_transport::connect(config).await?;
                Self::from_connected(config, connected, target, port, false).await
            },
        )
        .await
        .context("native UDP setup timed out")?
    }

    pub(crate) async fn from_connected(
        config: &ClientConfig,
        connected: maverick_quiche::Connected,
        target: maverick_core::frame::TargetAddr,
        port: u16,
        require_capability: bool,
    ) -> Result<Self> {
        let ClientTunnel::H3(tunnel) = open(config, connected.channel, connected.binding).await?
        else {
            bail!("native UDP requires H3");
        };
        anyhow::ensure!(
            !require_capability || tunnel.udp_sessions,
            crate::udp_session::UdpCapabilityUnsupported
        );
        let H3ClientTunnel {
            udp_sessions: _,
            mut sender,
            mut receiver,
            mut datagrams,
        } = *tunnel;
        let capacity = datagrams.ready().await?;
        let payload = maverick_core::frame::OpenTcpPayload {
            target,
            port,
            initial_data: Bytes::new(),
        }
        .encode()?;
        let frame = Frame::new(FrameType::OpenUdp, 1, sender.flow_id, payload);
        sender.send_frame(frame, false).await?;
        let ack = h3_channel::read_frame(&mut receiver, sender.max_frame_size)
            .await?
            .context("native UDP admission closed")?;
        anyhow::ensure!(
            ack.frame_type == FrameType::WindowUpdate
                && ack.flags == 1
                && ack.flow_id == sender.flow_id
                && ack.payload.len() == 2,
            "native UDP admission rejected"
        );
        let max_payload = usize::from(u16::from_be_bytes([ack.payload[0], ack.payload[1]]));
        anyhow::ensure!(
            max_payload > 0 && max_payload <= h3_channel::MAX_NATIVE_UDP_PAYLOAD,
            "invalid native UDP payload limit"
        );
        datagrams.enable();
        Ok(Self {
            sender,
            receiver,
            datagrams,
            max_payload: max_payload.min(capacity),
        })
    }

    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    pub fn send(&self, payload: Bytes) -> Result<bool> {
        if payload.len() > self.max_payload {
            return Ok(false);
        }
        match self.datagrams.outbound.try_send(payload) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                bail!("native UDP transport closed")
            }
        }
    }

    pub async fn recv(&mut self) -> Result<Bytes> {
        tokio::select! {
            packet = self.datagrams.inbound.recv() => packet.context("native UDP transport closed"),
            frame = h3_channel::read_frame(&mut self.receiver, self.sender.max_frame_size) => {
                let _ = frame?;
                bail!("native UDP association closed");
            }
        }
    }

    pub async fn close(mut self) -> Result<()> {
        self.sender
            .send_frame(
                Frame::new(FrameType::CloseFlow, 0, self.sender.flow_id, Bytes::new()),
                true,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use maverick_core::auth::{ClientHello, ServerHello};
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, Mode, ShapingConfig, Socks5Config,
    };
    use maverick_core::SecretString;
    use std::task::Poll;

    fn tunnel(channel: FrameChannel) -> H3ClientTunnel {
        let shaping = ShapingConfig::default();
        H3ClientTunnel {
            udp_sessions: false,
            receiver: channel.inbound,
            datagrams: channel.datagrams,
            sender: H3Sender {
                channel: channel.outbound,
                max_frame_size: 65_536,
                padding: RuntimePadding::from_config(Mode::Stable, &shaping),
                cover: RuntimeCoverTraffic::from_config(Mode::Stable, &shaping),
                batcher: RuntimeBatcher::from_config(Mode::Stable, &shaping),
                stall_timeout: Duration::from_secs(2),
                request_ended: false,
                flow_id: 1,
            },
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transport_loss_after_response_fin_releases_silent_upload() -> Result<()> {
        let (channel, transport) = h3_channel::channel();
        let (local, mut app) = tokio::io::duplex(1);
        let mut relay = Box::pin(tunnel(channel).relay(local, Duration::from_secs(2)));
        let started = tokio::time::Instant::now();
        transport
            .inbound
            .try_send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
            .map_err(|_| anyhow::anyhow!("cannot queue response FIN"))?;
        assert!(poll!(relay.as_mut()).is_pending());
        let mut byte = [0];
        match poll!(Box::pin(app.read(&mut byte)).as_mut()) {
            Poll::Ready(result) => assert_eq!(result?, 0),
            Poll::Pending => anyhow::bail!("response FIN did not reach the local application"),
        }
        transport
            .inbound
            .try_send(Ok(None))
            .map_err(|_| anyhow::anyhow!("cannot queue response EOF"))?;
        assert!(poll!(relay.as_mut()).is_pending());

        // The response is complete, but the local application's upload is
        // still open and silent when the transport disappears.
        drop(transport.outbound);
        match poll!(relay.as_mut()) {
            Poll::Ready(result) => {
                assert!(
                    result.is_err(),
                    "transport loss completed as a graceful relay"
                );
            }
            Poll::Pending => {
                anyhow::bail!("transport loss retained the silent upload after response completion")
            }
        }
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "cancellation waited for idle expiry"
        );
        assert!(transport.inbound.is_closed());
        match poll!(Box::pin(app.write_all(b"late local upload")).as_mut()) {
            Poll::Ready(result) => {
                assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
            }
            Poll::Pending => anyhow::bail!("cancelled relay retained its local reader"),
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn configured_shaping_preserves_data_and_fin_order() -> Result<()> {
        let mut config = ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse()?,
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "localhost:443".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "local-shaping-test".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: Default::default(),
            advanced: ClientAdvancedConfig {
                quiche_h3: true,
                shaping: ShapingConfig {
                    max_padding_bytes_per_frame: 16,
                    max_overhead_ratio: 0.25,
                    max_batch_bytes: 1024,
                    max_delay_ms: 11,
                    ..ShapingConfig::default()
                },
                ..ClientAdvancedConfig::default()
            },
        };
        config.auth.channel_binding.require = true;
        for (mode, enabled, cover, padding_count) in [
            (Mode::Auto, false, false, 0),
            (Mode::Auto, true, false, 1),
            (Mode::Auto, true, true, 2),
            (Mode::Stable, true, true, 0),
        ] {
            config.mode = mode;
            config.advanced.shaping.enabled = enabled;
            config.advanced.shaping.cover_traffic = cover;
            config.advanced.shaping.cover_traffic_operator_approved = cover;
            let (channel, mut transport) = h3_channel::channel();
            let binding = TlsChannelBinding::new([7; 32]);
            let authenticate = async {
                let (frame, end) = transport.outbound.recv().await.context("missing hello")?;
                assert_eq!(frame.frame_type, FrameType::ClientHello);
                assert!(!end);
                let hello = ClientHello::decode(&frame.payload)?;
                let reply = ServerHello::try_new_with_channel_binding(
                    &config.server.secret,
                    &hello.client_nonce,
                    65_536,
                    1,
                    hello.feature_flags,
                    Some(binding),
                )?;
                transport
                    .inbound
                    .send(Ok(Some(Frame::new(
                        FrameType::ServerHello,
                        0,
                        0,
                        reply.encode(),
                    ))))
                    .await?;
                Ok::<_, anyhow::Error>(())
            };
            let (mut tunnel, ()) = tokio::try_join!(open(&config, channel, binding), authenticate)?;
            let data = Frame::new(FrameType::TcpData, 2, 73, (0..128).collect::<Vec<u8>>());
            let fin = Frame::new(FrameType::TcpFin, 0, 73, Bytes::new());
            let send = async {
                tunnel.send_frame(data.clone(), false).await?;
                tunnel.send_frame(fin.clone(), true).await
            };
            let receive = async {
                let mut frames = Vec::new();
                loop {
                    let frame = transport.outbound.recv().await.context("missing frame")?;
                    let end = frame.1;
                    frames.push(frame);
                    if end {
                        return Ok::<_, anyhow::Error>(frames);
                    }
                }
            };
            let started = tokio::time::Instant::now();
            let ((), frames) = timeout(Duration::from_secs(1), async {
                tokio::try_join!(send, receive)
            })
            .await??;
            let elapsed = started.elapsed();
            if enabled && mode != Mode::Stable {
                // Allow timer rounding, but distinguish the configured batch
                // delay from Auto's fallback pacing, which is capped at 5 ms.
                assert!((Duration::from_millis(11)..=Duration::from_millis(13)).contains(&elapsed));
            } else {
                assert_eq!(elapsed, Duration::ZERO);
            }
            assert_eq!(frames.len(), padding_count + 2);
            for (padding, end) in &frames[..padding_count] {
                assert_eq!(padding.frame_type, FrameType::Padding);
                assert_eq!(padding.flow_id, 0);
                assert_eq!(padding.flags, 0);
                assert!((1..=16).contains(&padding.payload.len()));
                assert!(!end);
            }
            assert_eq!(frames[padding_count], (data, false));
            assert_eq!(frames[padding_count + 1], (fin, true));
            assert!(matches!(
                transport.outbound.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn blocked_upload_still_receives_data_and_reset() -> Result<()> {
        timeout(Duration::from_secs(2), async {
            let (channel, mut transport) = h3_channel::channel();
            let mut tunnel = tunnel(channel);
            // Occupy the one-frame send queue. The relay's next send must wait.
            tunnel
                .send_frame(
                    Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"queued")),
                    false,
                )
                .await?;
            let (local, mut app) = tokio::io::duplex(1);
            let task = tokio::spawn(tunnel.relay(local, Duration::from_secs(2)));
            app.write_all(b"x").await?;
            app.write_all(b"y").await?; // x was read; its send is blocked.
            transport
                .inbound
                .send(Ok(Some(Frame::new(
                    FrameType::TcpData,
                    0,
                    1,
                    Bytes::from_static(b"reply"),
                ))))
                .await?;
            let mut reply = [0; 5];
            app.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"reply");
            transport
                .inbound
                .send(Ok(Some(Frame::new(
                    FrameType::TcpReset,
                    0,
                    1,
                    Bytes::new(),
                ))))
                .await?;
            assert!(task.await?.is_err());
            assert_eq!(
                transport.outbound.recv().await.unwrap().0.payload.as_ref(),
                b"queued"
            );
            assert!(transport.outbound.recv().await.is_none());
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    #[tokio::test]
    async fn blocked_local_download_still_uploads() -> Result<()> {
        timeout(Duration::from_secs(2), async {
            let (channel, mut transport) = h3_channel::channel();
            let (local, mut app) = tokio::io::duplex(1);
            let task = tokio::spawn(tunnel(channel).relay(local, Duration::from_secs(2)));
            transport
                .inbound
                .send(Ok(Some(Frame::new(
                    FrameType::TcpData,
                    0,
                    1,
                    Bytes::from_static(b"reply"),
                ))))
                .await?;
            let mut first = [0];
            app.read_exact(&mut first).await?;
            assert_eq!(&first, b"r"); // remaining response cannot fit the local buffer.
            app.write_all(b"x").await?;
            let sent = transport.outbound.recv().await.unwrap().0;
            assert_eq!(sent.frame_type, FrameType::TcpData);
            assert_eq!(sent.payload.as_ref(), b"x");
            app.shutdown().await?;
            assert_eq!(
                transport.outbound.recv().await.unwrap().0.frame_type,
                FrameType::TcpFin
            );
            let mut rest = [0; 4];
            app.read_exact(&mut rest).await?;
            assert_eq!(&rest, b"eply");
            transport
                .inbound
                .send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
                .await?;
            transport.inbound.send(Ok(None)).await?;
            assert_eq!(task.await??, crate::session::RelayClose::Graceful);
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    #[tokio::test(start_paused = true)]
    async fn partial_download_progress_outlives_one_idle_window() -> Result<()> {
        let (channel, mut transport) = h3_channel::channel();
        let (local, mut app) = tokio::io::duplex(1);
        let idle = Duration::from_secs(2);
        let task = tokio::spawn(tunnel(channel).relay(local, idle));
        app.shutdown().await?;
        let (fin, end) = transport
            .outbound
            .recv()
            .await
            .context("missing upload FIN")?;
        assert_eq!(fin.frame_type, FrameType::TcpFin);
        assert!(end);

        // Sending request FIN closes the driver's upload receiver while the
        // response direction remains live.
        transport.outbound.close();
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
        let started = tokio::time::Instant::now();
        for (index, expected) in payload.iter().enumerate() {
            if index != 0 {
                tokio::time::advance(Duration::from_secs(1)).await;
            }
            let mut byte = [0];
            app.read_exact(&mut byte).await?;
            assert_eq!(byte[0], *expected);
            tokio::task::yield_now().await;
        }
        assert!(started.elapsed() > idle);
        transport
            .inbound
            .send(Ok(Some(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()))))
            .await?;
        transport.inbound.send(Ok(None)).await?;
        assert_eq!(task.await??, crate::session::RelayClose::Graceful);
        assert_eq!(app.read(&mut [0]).await?, 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn partial_download_still_times_out_when_progress_stops() -> Result<()> {
        let (channel, mut transport) = h3_channel::channel();
        let (local, mut app) = tokio::io::duplex(1);
        let task = tokio::spawn(tunnel(channel).relay(local, Duration::from_secs(2)));
        app.shutdown().await?;
        let (fin, end) = transport
            .outbound
            .recv()
            .await
            .context("missing upload FIN")?;
        assert_eq!(fin.frame_type, FrameType::TcpFin);
        assert!(end);
        transport
            .inbound
            .send(Ok(Some(Frame::new(
                FrameType::TcpData,
                0,
                1,
                Bytes::from_static(b"progress"),
            ))))
            .await?;
        let mut byte = [0];
        app.read_exact(&mut byte).await?;
        assert_eq!(&byte, b"p");
        tokio::time::advance(Duration::from_secs(1)).await;
        app.read_exact(&mut byte).await?;
        assert_eq!(&byte, b"r");
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_millis(1500)).await;
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "partial write progress must refresh the idle deadline"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = timeout(Duration::from_secs(1), task)
            .await
            .context("stalled partial download did not finish")??
            .unwrap_err();
        assert!(
            error.to_string().contains("timed out") || error.to_string().contains("idle timeout")
        );
        Ok(())
    }

    #[tokio::test]
    async fn response_eof_without_tcp_fin_is_an_error() -> Result<()> {
        let (channel, transport) = h3_channel::channel();
        let (local, _app) = tokio::io::duplex(1);
        transport.inbound.send(Ok(None)).await?;
        assert!(timeout(
            Duration::from_secs(1),
            tunnel(channel).relay(local, Duration::from_secs(2))
        )
        .await?
        .is_err());
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn active_download_keeps_idle_upload_alive() -> Result<()> {
        let (channel, transport) = h3_channel::channel();
        let (local, mut app) = tokio::io::duplex(16);
        let task = tokio::spawn(tunnel(channel).relay(local, Duration::from_secs(2)));
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(1)).await;
            transport
                .inbound
                .send(Ok(Some(Frame::new(
                    FrameType::TcpData,
                    0,
                    1,
                    Bytes::from_static(b"x"),
                ))))
                .await?;
            let mut reply = [0];
            app.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"x");
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(task
            .await?
            .unwrap_err()
            .to_string()
            .contains("idle timeout"));
        Ok(())
    }
}
