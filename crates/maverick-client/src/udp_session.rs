//! Persistent UDP sessions. Selection happens before any application data.
use crate::{connection_manager::ClientTunnelPool, tunnel::ClientTunnel};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use maverick_core::frame::{
    Frame, FrameType, OpenTcpPayload, TargetAddr, MAX_RELIABLE_UDP_PAYLOAD, RELIABLE_UDP_FLAGS,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct UdpCapabilityUnsupported;

impl std::fmt::Display for UdpCapabilityUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("peer does not support the required UDP session capability")
    }
}
impl std::error::Error for UdpCapabilityUnsupported {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCarrier {
    H2Reliable,
    H3Native,
}

pub enum DatagramSession {
    Reliable(ReliableUdpAssociation),
    #[cfg(feature = "experimental-h3")]
    Native(Box<crate::h3::NativeUdpAssociation>),
}

impl DatagramSession {
    pub(crate) async fn open(
        pool: &ClientTunnelPool,
        target: TargetAddr,
        port: u16,
    ) -> Result<Self> {
        tokio::time::timeout(
            std::time::Duration::from_millis(pool.config().advanced.connect_timeout_ms),
            Self::open_inner(pool, target, port),
        )
        .await
        .context("UDP session setup timed out")?
    }

    pub(crate) async fn open_for_socks(
        pool: &ClientTunnelPool,
        target: TargetAddr,
        port: u16,
    ) -> Result<Self> {
        if pool.config().advanced.udp_policy.is_some() {
            return Self::open(pool, target, port).await;
        }
        #[cfg(feature = "experimental-h3")]
        if pool.config().advanced.quiche_h3 || pool.config().advanced.auto_h3 {
            return Ok(Self::Native(Box::new(
                crate::h3::NativeUdpAssociation::open(pool.config(), target, port).await?,
            )));
        }
        bail!("legacy H2 UDP uses its request/response path")
    }

    async fn open_inner(pool: &ClientTunnelPool, target: TargetAddr, port: u16) -> Result<Self> {
        use maverick_core::config::UdpPolicy;
        let config = pool.config();
        let policy = config
            .advanced
            .udp_policy
            .context("UDP sessions require an explicit udp_policy")?;
        #[cfg(feature = "experimental-h3")]
        if config.advanced.quiche_h3 || config.advanced.auto_h3 {
            let connected = if config.advanced.auto_h3 {
                pool.connect_auto_h3().await?
            } else {
                Some(crate::h3_transport::connect(config).await?)
            };
            let native = match connected {
                Some(connected) => {
                    crate::h3::NativeUdpAssociation::from_connected(
                        config,
                        connected,
                        target.clone(),
                        port,
                        true,
                    )
                    .await
                }
                None => Err(maverick_quiche::NetworkUnavailable.into()),
            };
            match native {
                Ok(session) => return Ok(Self::Native(Box::new(session))),
                Err(error)
                    if config.advanced.auto_h3
                        && policy == UdpPolicy::AllowReliable
                        && (error
                            .downcast_ref::<maverick_quiche::NetworkUnavailable>()
                            .is_some()
                            || error.downcast_ref::<UdpCapabilityUnsupported>().is_some()) => {}
                Err(error) => return Err(error),
            }
        }
        anyhow::ensure!(
            policy == UdpPolicy::AllowReliable,
            "native UDP cannot use H2"
        );
        Ok(Self::Reliable(
            ReliableUdpAssociation::open(pool, target, port).await?,
        ))
    }

    pub fn carrier(&self) -> UdpCarrier {
        match self {
            Self::Reliable(_) => UdpCarrier::H2Reliable,
            #[cfg(feature = "experimental-h3")]
            Self::Native(_) => UdpCarrier::H3Native,
        }
    }
    pub fn max_payload(&self) -> usize {
        match self {
            Self::Reliable(session) => session.max_payload(),
            #[cfg(feature = "experimental-h3")]
            Self::Native(session) => session.max_payload(),
        }
    }
    pub fn send(&self, packet: Bytes) -> Result<bool> {
        match self {
            Self::Reliable(session) => session.send(packet),
            #[cfg(feature = "experimental-h3")]
            Self::Native(session) => session.send(packet),
        }
    }
    pub async fn recv(&mut self) -> Result<Bytes> {
        match self {
            Self::Reliable(session) => session.recv().await,
            #[cfg(feature = "experimental-h3")]
            Self::Native(session) => session.recv().await,
        }
    }
    pub async fn close(self) -> Result<()> {
        match self {
            Self::Reliable(session) => session.close().await,
            #[cfg(feature = "experimental-h3")]
            Self::Native(session) => session.close().await,
        }
    }
}

pub struct ReliableUdpAssociation {
    outgoing: mpsc::Sender<Bytes>,
    incoming: mpsc::Receiver<Result<Bytes>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
    maximum: usize,
    shutdown_timeout: std::time::Duration,
}

impl ReliableUdpAssociation {
    pub(crate) async fn open(
        pool: &ClientTunnelPool,
        target: TargetAddr,
        port: u16,
    ) -> Result<Self> {
        let ClientTunnel::H2(mut tunnel) = pool.open_h2().await? else {
            bail!("reliable UDP requires H2");
        };
        anyhow::ensure!(tunnel.udp_sessions, UdpCapabilityUnsupported);
        let payload = OpenTcpPayload {
            target,
            port,
            initial_data: Bytes::new(),
        }
        .encode()?;
        tunnel
            .split(None)
            .0
            .send_frame(
                Frame::new(FrameType::OpenUdp, RELIABLE_UDP_FLAGS, 1, payload),
                false,
            )
            .await?;
        let ack = tunnel
            .split(None)
            .1
            .read_next_frame()
            .await?
            .context("UDP admission closed")?;
        anyhow::ensure!(
            ack.frame_type == FrameType::WindowUpdate
                && ack.flags == RELIABLE_UDP_FLAGS
                && ack.flow_id == 1
                && ack.payload.len() == 2,
            "reliable UDP admission rejected"
        );
        let maximum = usize::from(u16::from_be_bytes([ack.payload[0], ack.payload[1]]));
        anyhow::ensure!(
            maximum > 0 && maximum <= MAX_RELIABLE_UDP_PAYLOAD && maximum <= tunnel.max_frame_size,
            "invalid reliable UDP payload limit"
        );
        let (outgoing, mut packets) = mpsc::channel::<Bytes>(32);
        let (received, incoming) = mpsc::channel(32);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut writer, mut reader) = tunnel.split(None);
            let upload = async {
                loop {
                    let packet = tokio::select! {
                        biased;
                        _ = &mut stopped => None,
                        packet = packets.recv() => packet,
                    };
                    let Some(packet) = packet else {
                        break;
                    };
                    writer
                        .send_frame(
                            Frame::new(FrameType::UdpPacket, RELIABLE_UDP_FLAGS, 1, packet),
                            false,
                        )
                        .await?;
                }
                writer
                    .send_frame(Frame::new(FrameType::CloseFlow, 0, 1, Bytes::new()), true)
                    .await
            };
            let download = async {
                loop {
                    let frame = reader
                        .read_next_frame()
                        .await?
                        .context("reliable UDP transport closed")?;
                    if frame.frame_type == FrameType::Padding {
                        continue;
                    }
                    anyhow::ensure!(frame.flow_id == 1, "UDP response flow ID mismatch");
                    if frame.frame_type == FrameType::CloseFlow {
                        anyhow::ensure!(
                            frame.flags == 0 && frame.payload.is_empty(),
                            "invalid UDP close"
                        );
                        reader.finish_response(false).await?;
                        return Ok::<_, anyhow::Error>(());
                    }
                    anyhow::ensure!(
                        frame.frame_type == FrameType::UdpPacket
                            && frame.flags == RELIABLE_UDP_FLAGS
                            && frame.payload.len() <= maximum,
                        "invalid reliable UDP response"
                    );
                    // Explicit close discards queued application replies while the
                    // reliable response is drained to its completion/trailers.
                    let _ = received.send(Ok(frame.payload)).await;
                }
            };
            let result = {
                tokio::pin!(upload, download);
                tokio::select! {
                    result = &mut upload => match result {
                        Ok(()) => download.await,
                        Err(error) => Err(error),
                    },
                    result = &mut download => result,
                }
            };
            if let Err(error) = &result {
                let _ = received.try_send(Err(anyhow::anyhow!(error.to_string())));
            }
            result
        });
        Ok(Self {
            outgoing,
            incoming,
            stop: Some(stop),
            task: Some(task),
            maximum,
            shutdown_timeout: std::time::Duration::from_millis(
                pool.config().advanced.connect_timeout_ms,
            ),
        })
    }

    pub fn max_payload(&self) -> usize {
        self.maximum
    }

    /// Queued is not delivered. Oversize/full queues drop without replay.
    pub fn send(&self, packet: Bytes) -> Result<bool> {
        if packet.len() > self.maximum {
            return Ok(false);
        }
        match self.outgoing.try_send(packet) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => bail!("reliable UDP session closed"),
        }
    }

    pub async fn recv(&mut self) -> Result<Bytes> {
        self.incoming
            .recv()
            .await
            .context("reliable UDP session closed")?
    }

    pub async fn close(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Do not let queued responses hold graceful shutdown behind the caller.
        self.incoming.close();
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(self.shutdown_timeout, &mut task).await {
                Ok(result) => result??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    bail!("reliable UDP close timed out");
                }
            }
        }
        Ok(())
    }
}

impl Drop for ReliableUdpAssociation {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Compatibility convenience operation; target silence never triggers a retry.
pub(crate) async fn exchange(
    pool: &ClientTunnelPool,
    packet: maverick_core::frame::UdpPacketPayload,
) -> Result<maverick_core::frame::UdpPacketPayload> {
    let mut session = DatagramSession::open(pool, packet.target.clone(), packet.port).await?;
    anyhow::ensure!(
        session.send(packet.data)?,
        "UDP packet exceeds capacity or queue is full"
    );
    let reply = tokio::time::timeout(
        std::time::Duration::from_millis(pool.config().advanced.udp_idle_timeout_ms),
        session.recv(),
    )
    .await;
    let _ = session.close().await;
    Ok(maverick_core::frame::UdpPacketPayload::new(
        packet.target,
        packet.port,
        reply.context("UDP response timed out")??,
    ))
}
