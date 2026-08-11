#[cfg(feature = "h3")]
use std::future::Future;
#[cfg(feature = "h3")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "h3")]
use std::sync::Arc;

use anyhow::{bail, Result};
use bytes::Bytes;
use maverick_core::auth::{FEATURE_OPEN_UDP_MODE_NEGOTIATION, FEATURE_TLS_CHANNEL_BINDING};
use maverick_core::frame::{
    Frame, FrameType, OpenUdpPayload, UdpPacketPayload, OPEN_UDP_FLAGS_SERIAL,
};
#[cfg(feature = "h3")]
use maverick_core::frame::{TargetAddr, OPEN_UDP_FLAG_DUPLEX};
use maverick_core::ClientConfig;
use tokio::time::{timeout, Duration};

use crate::tunnel::{self, ClientTunnel};
use crate::ClientTunnelPool;

const UDP_FLOW_ID: u64 = 1;
const UDP_ASSOCIATION_UNUSABLE: &str = "UDP association is no longer usable";
#[cfg(feature = "h3")]
const LEGACY_H3_DUPLEX_UDP_OPEN_FAILED: &str = "legacy-H3 duplex UDP open failed";
#[cfg(feature = "h3")]
const LEGACY_H3_DUPLEX_UDP_UNUSABLE: &str = "legacy-H3 duplex UDP association is no longer usable";
#[cfg(feature = "h3")]
const LEGACY_H3_DUPLEX_UDP_SEND_FAILED: &str = "legacy-H3 duplex UDP send failed";
#[cfg(feature = "h3")]
const LEGACY_H3_DUPLEX_UDP_RECEIVE_FAILED: &str = "legacy-H3 duplex UDP receive failed";
#[cfg(feature = "h3")]
const LEGACY_H3_DUPLEX_UDP_CLOSE_FAILED: &str = "legacy-H3 duplex UDP close failed";
const CLIENT_LEGACY_FEATURE_MASK: u64 =
    FEATURE_OPEN_UDP_MODE_NEGOTIATION | FEATURE_TLS_CHANNEL_BINDING;

pub async fn relay_udp_packet(
    config: &ClientConfig,
    packet: UdpPacketPayload,
) -> Result<UdpPacketPayload> {
    let mut association = UdpAssociation::open(config).await?;
    let response = association.relay_packet(packet).await;
    let _ = association.close().await;
    response
}

pub struct UdpAssociation {
    tunnel: Option<ClientTunnel>,
    flow_id: u64,
    response_timeout: Duration,
}

/// One opt-in, legacy-H3-only duplex UDP association with one fixed target.
///
/// This source-only library API never falls back to H2, WebSocket, the serial
/// UDP association, or direct-v3 H3. Its borrowed halves cannot be moved into
/// independent `'static` tasks. It promises neither fairness nor no-loss
/// delivery and is not a general SOCKS or TUN UDP contract.
#[cfg(feature = "h3")]
pub struct LegacyH3DuplexUdpAssociation {
    send_half: LegacyH3DuplexUdpSendHalf,
    receive_half: LegacyH3DuplexUdpReceiveHalf,
    _transport: crate::h3_transport::H3RequestSender,
}

/// The borrowed sending direction of a legacy-H3 duplex UDP association.
///
/// A successful send means only that one payload was completely submitted to
/// the tunnel. It does not acknowledge delivery by the fixed target.
#[cfg(feature = "h3")]
pub struct LegacyH3DuplexUdpSendHalf {
    tunnel: tunnel::H3DuplexSendHalf,
    target: TargetAddr,
    port: u16,
    flow_id: u64,
    operation_timeout: Duration,
    shared: Arc<LegacyH3DuplexShared>,
}

/// The borrowed receiving direction of a legacy-H3 duplex UDP association.
///
/// Received payloads have no request-response correlation and may be delayed,
/// duplicated, or unsolicited target datagrams.
#[cfg(feature = "h3")]
pub struct LegacyH3DuplexUdpReceiveHalf {
    tunnel: tunnel::H3DuplexReceiveHalf,
    target: TargetAddr,
    port: u16,
    flow_id: u64,
    operation_timeout: Duration,
    cleanly_closed: bool,
    shared: Arc<LegacyH3DuplexShared>,
}

#[cfg(feature = "h3")]
enum LegacyH3DuplexReceiveEvent {
    Packet(Bytes),
    Close,
}

#[cfg(feature = "h3")]
struct LegacyH3DuplexShared {
    unusable: AtomicBool,
    abort: LegacyH3DuplexAbort,
}

#[cfg(feature = "h3")]
enum LegacyH3DuplexAbort {
    Transport(crate::h3_transport::H3AbortHandle),
    #[cfg(test)]
    Probe(Arc<std::sync::atomic::AtomicUsize>),
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexAbort {
    fn abort(&self) {
        match self {
            Self::Transport(abort) => abort.abort(),
            #[cfg(test)]
            Self::Probe(count) => {
                count.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexShared {
    fn is_unusable(&self) -> bool {
        self.unusable.load(Ordering::Acquire)
    }

    fn invalidate_and_abort(&self) {
        if !self.unusable.swap(true, Ordering::AcqRel) {
            self.abort.abort();
        }
    }
}

#[cfg(feature = "h3")]
struct LegacyH3DuplexPoisonGuard {
    shared: Arc<LegacyH3DuplexShared>,
    armed: bool,
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexPoisonGuard {
    fn arm(shared: &Arc<LegacyH3DuplexShared>) -> Option<Self> {
        if shared.is_unusable() {
            return None;
        }
        Some(Self {
            shared: Arc::clone(shared),
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "h3")]
impl Drop for LegacyH3DuplexPoisonGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shared.invalidate_and_abort();
        }
    }
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexUdpAssociation {
    /// Open a dedicated legacy-H3 duplex association for one exact target.
    ///
    /// Opening is strict: authentication, feature selection, or duplex
    /// acknowledgement failure never retries or falls back to another carrier
    /// or to flags-zero serial mode.
    pub async fn open(config: &ClientConfig, target: TargetAddr, port: u16) -> Result<Self> {
        if config.validate().is_err()
            || !config.advanced.experimental_h3
            || config.advanced.tls_terminating_fronting_enabled()
            || config.auth.channel_binding.require
            || port == 0
            || UdpPacketPayload::new(target.clone(), port, Bytes::new())
                .encode()
                .is_err()
        {
            return legacy_h3_duplex_udp_open_failed();
        }
        let mut tunnel = match timeout(
            Duration::from_millis(config.advanced.connect_timeout_ms),
            tunnel::open_legacy_h3_direct(config),
        )
        .await
        {
            Ok(Ok(tunnel @ ClientTunnel::H3(_))) => tunnel,
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => return legacy_h3_duplex_udp_open_failed(),
        };
        if tunnel.feature_flags_selected() & FEATURE_OPEN_UDP_MODE_NEGOTIATION == 0 {
            return legacy_h3_duplex_udp_open_failed();
        }

        let open_result = timeout(
            Duration::from_millis(config.advanced.connect_timeout_ms),
            async {
                tunnel
                    .send_frame(
                        Frame::new(
                            FrameType::OpenUdp,
                            OPEN_UDP_FLAG_DUPLEX,
                            UDP_FLOW_ID,
                            OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
                        ),
                        false,
                    )
                    .await?;
                match tunnel.read_next_frame().await? {
                    Some(frame) if is_exact_duplex_open_udp_ack(&frame, UDP_FLOW_ID) => Ok(()),
                    _ => bail!(LEGACY_H3_DUPLEX_UDP_OPEN_FAILED),
                }
            },
        )
        .await;
        if !matches!(open_result, Ok(Ok(()))) {
            return legacy_h3_duplex_udp_open_failed();
        }
        let parts = match tunnel.into_legacy_h3_duplex_parts() {
            Ok(parts) => parts,
            Err(_) => return legacy_h3_duplex_udp_open_failed(),
        };
        let shared = Arc::new(LegacyH3DuplexShared {
            unusable: AtomicBool::new(false),
            abort: LegacyH3DuplexAbort::Transport(parts.transport.abort_handle()),
        });
        let operation_timeout = Duration::from_millis(config.advanced.udp_idle_timeout_ms);
        Ok(Self {
            send_half: LegacyH3DuplexUdpSendHalf {
                tunnel: parts.send,
                target: target.clone(),
                port,
                flow_id: UDP_FLOW_ID,
                operation_timeout,
                shared: Arc::clone(&shared),
            },
            receive_half: LegacyH3DuplexUdpReceiveHalf {
                tunnel: parts.receive,
                target,
                port,
                flow_id: UDP_FLOW_ID,
                operation_timeout,
                cleanly_closed: false,
                shared,
            },
            _transport: parts.transport,
        })
    }

    /// Borrow the independent sending and receiving directions together.
    pub fn split(
        &mut self,
    ) -> (
        &mut LegacyH3DuplexUdpSendHalf,
        &mut LegacyH3DuplexUdpReceiveHalf,
    ) {
        (&mut self.send_half, &mut self.receive_half)
    }

    /// Close the sole association owner without fallback or replay.
    pub async fn close(mut self) -> Result<()> {
        if self.receive_half.cleanly_closed {
            return Ok(());
        }
        let Some(mut guard) = LegacyH3DuplexPoisonGuard::arm(&self.send_half.shared) else {
            return legacy_h3_duplex_udp_unusable();
        };
        let close_frame = Frame::new(FrameType::CloseFlow, 0, UDP_FLOW_ID, Bytes::new());
        let send = self.send_half.tunnel.send_frame_with_deadline(
            close_frame,
            true,
            self.send_half.operation_timeout,
        );
        let receive = async {
            timeout(
                self.receive_half.operation_timeout,
                self.receive_half.drain_after_local_close(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("legacy-H3 close response timed out"))??;
            Result::<()>::Ok(())
        };
        if complete_legacy_h3_duplex_close(send, receive)
            .await
            .is_err()
            || self.send_half.shared.is_unusable()
        {
            return legacy_h3_duplex_udp_close_failed();
        }
        self.receive_half.cleanly_closed = true;
        guard.disarm();
        Ok(())
    }
}

#[cfg(feature = "h3")]
impl Drop for LegacyH3DuplexUdpAssociation {
    fn drop(&mut self) {
        self.send_half.shared.invalidate_and_abort();
    }
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexUdpSendHalf {
    /// Submit one payload for the target fixed when the association opened.
    pub async fn send_packet(&mut self, payload: Bytes) -> Result<()> {
        if self.shared.is_unusable() {
            return legacy_h3_duplex_udp_unusable();
        }
        let payload = match UdpPacketPayload::new(self.target.clone(), self.port, payload).encode()
        {
            Ok(payload) => payload,
            Err(_) => return legacy_h3_duplex_udp_send_failed(),
        };
        let Some(mut guard) = LegacyH3DuplexPoisonGuard::arm(&self.shared) else {
            return legacy_h3_duplex_udp_unusable();
        };
        if self
            .tunnel
            .send_frame_with_deadline(
                Frame::new(FrameType::UdpPacket, 0, self.flow_id, payload),
                false,
                self.operation_timeout,
            )
            .await
            .is_err()
            || self.shared.is_unusable()
        {
            return legacy_h3_duplex_udp_send_failed();
        }
        guard.disarm();
        Ok(())
    }
}

#[cfg(feature = "h3")]
impl LegacyH3DuplexUdpReceiveHalf {
    /// Receive the next target datagram, or `None` after a clean remote close.
    pub async fn receive_packet(&mut self) -> Result<Option<Bytes>> {
        if self.shared.is_unusable() {
            return legacy_h3_duplex_udp_unusable();
        }
        let frame = match self.tunnel.read_next_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => {
                self.shared.invalidate_and_abort();
                return legacy_h3_duplex_udp_receive_failed();
            }
        };
        match classify_legacy_h3_duplex_receive_frame(frame, self.flow_id, &self.target, self.port)
        {
            Ok(LegacyH3DuplexReceiveEvent::Packet(payload)) => {
                if self.shared.is_unusable() {
                    return legacy_h3_duplex_udp_unusable();
                }
                Ok(Some(payload))
            }
            Ok(LegacyH3DuplexReceiveEvent::Close) => {
                let Some(mut guard) = LegacyH3DuplexPoisonGuard::arm(&self.shared) else {
                    return legacy_h3_duplex_udp_unusable();
                };
                let finish_result =
                    timeout(self.operation_timeout, self.tunnel.finish_response()).await;
                if !matches!(finish_result, Ok(Ok(()))) {
                    return legacy_h3_duplex_udp_receive_failed();
                }
                self.cleanly_closed = true;
                self.shared.invalidate_and_abort();
                guard.disarm();
                Ok(None)
            }
            Err(_) => {
                self.shared.invalidate_and_abort();
                legacy_h3_duplex_udp_receive_failed()
            }
        }
    }

    async fn drain_after_local_close(&mut self) -> Result<()> {
        loop {
            match self.tunnel.read_next_frame().await? {
                Some(frame) => match classify_legacy_h3_duplex_receive_frame(
                    frame,
                    self.flow_id,
                    &self.target,
                    self.port,
                ) {
                    Ok(LegacyH3DuplexReceiveEvent::Packet(_)) => {}
                    Ok(LegacyH3DuplexReceiveEvent::Close) => {
                        return self.tunnel.finish_response().await;
                    }
                    Err(_) => bail!("legacy-H3 close received an invalid terminal frame"),
                },
                None => return self.tunnel.finish_trailers_after_body_end().await,
            }
        }
    }
}

#[cfg(feature = "h3")]
fn is_exact_duplex_open_udp_ack(frame: &Frame, flow_id: u64) -> bool {
    frame.frame_type == FrameType::WindowUpdate
        && frame.flags == OPEN_UDP_FLAG_DUPLEX
        && frame.flow_id == flow_id
        && frame.payload.is_empty()
}

#[cfg(feature = "h3")]
fn classify_legacy_h3_duplex_receive_frame(
    frame: Frame,
    flow_id: u64,
    target: &TargetAddr,
    port: u16,
) -> Result<LegacyH3DuplexReceiveEvent> {
    if frame.frame_type == FrameType::CloseFlow
        && frame.flags == 0
        && frame.flow_id == flow_id
        && frame.payload.is_empty()
    {
        return Ok(LegacyH3DuplexReceiveEvent::Close);
    }
    if frame.frame_type != FrameType::UdpPacket || frame.flags != 0 || frame.flow_id != flow_id {
        bail!("legacy-H3 duplex UDP received an invalid frame");
    }
    let packet = UdpPacketPayload::decode(&frame.payload)
        .map_err(|_| anyhow::anyhow!("legacy-H3 duplex UDP received an invalid packet"))?;
    if &packet.target != target || packet.port != port {
        bail!("legacy-H3 duplex UDP received a packet for a different target");
    }
    Ok(LegacyH3DuplexReceiveEvent::Packet(packet.data))
}

#[cfg(feature = "h3")]
async fn complete_legacy_h3_duplex_close<Send, Receive>(send: Send, receive: Receive) -> Result<()>
where
    Send: Future<Output = Result<()>>,
    Receive: Future<Output = Result<()>>,
{
    tokio::try_join!(send, receive)?;
    Ok(())
}

#[cfg(feature = "h3")]
fn legacy_h3_duplex_udp_open_failed<T>() -> Result<T> {
    Err(anyhow::Error::msg(LEGACY_H3_DUPLEX_UDP_OPEN_FAILED))
}

#[cfg(feature = "h3")]
fn legacy_h3_duplex_udp_unusable<T>() -> Result<T> {
    Err(anyhow::Error::msg(LEGACY_H3_DUPLEX_UDP_UNUSABLE))
}

#[cfg(feature = "h3")]
fn legacy_h3_duplex_udp_send_failed<T>() -> Result<T> {
    Err(anyhow::Error::msg(LEGACY_H3_DUPLEX_UDP_SEND_FAILED))
}

#[cfg(feature = "h3")]
fn legacy_h3_duplex_udp_receive_failed<T>() -> Result<T> {
    Err(anyhow::Error::msg(LEGACY_H3_DUPLEX_UDP_RECEIVE_FAILED))
}

#[cfg(feature = "h3")]
fn legacy_h3_duplex_udp_close_failed<T>() -> Result<T> {
    Err(anyhow::Error::msg(LEGACY_H3_DUPLEX_UDP_CLOSE_FAILED))
}

impl UdpAssociation {
    pub async fn open(config: &ClientConfig) -> Result<Self> {
        Self::open_with_tunnel(config, tunnel::open(config).await?).await
    }

    pub(crate) async fn open_with_pool(pool: &ClientTunnelPool) -> Result<Self> {
        Self::open_with_tunnel(pool.config(), pool.open().await?).await
    }

    async fn open_with_tunnel(config: &ClientConfig, mut tunnel: ClientTunnel) -> Result<Self> {
        let open_udp_flags = serial_open_udp_flags(tunnel.feature_flags_selected())?;
        tunnel
            .send_frame(
                Frame::new(
                    FrameType::OpenUdp,
                    open_udp_flags,
                    UDP_FLOW_ID,
                    OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
                ),
                false,
            )
            .await?;
        match tunnel.read_next_frame().await? {
            Some(frame) if is_exact_open_udp_ack(&frame, UDP_FLOW_ID) => Ok(Self {
                tunnel: Some(tunnel),
                flow_id: UDP_FLOW_ID,
                response_timeout: Duration::from_millis(config.advanced.udp_idle_timeout_ms),
            }),
            Some(frame) if frame.frame_type == FrameType::Error => {
                tunnel.finish_response().await?;
                bail!("UDP open failed")
            }
            _ => bail!("server closed before UDP flow opened"),
        }
    }

    pub async fn relay_packet(&mut self, packet: UdpPacketPayload) -> Result<UdpPacketPayload> {
        if self.tunnel.is_none() {
            bail!(UDP_ASSOCIATION_UNUSABLE);
        }
        let payload = packet.encode()?;
        let mut tunnel = self
            .tunnel
            .take()
            .ok_or_else(|| anyhow::anyhow!(UDP_ASSOCIATION_UNUSABLE))?;
        tunnel
            .send_frame(
                Frame::new(FrameType::UdpPacket, 0, self.flow_id, payload),
                false,
            )
            .await?;

        let response = timeout(self.response_timeout, async {
            loop {
                match tunnel.read_next_frame().await? {
                    Some(frame) => {
                        if frame.frame_type == FrameType::CloseFlow {
                            tunnel.finish_response().await?;
                        }
                        if let Some(packet) = udp_response_from_frame(frame, self.flow_id)? {
                            return Ok(packet);
                        }
                    }
                    None => bail!("server closed before UDP response"),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("UDP relay response timed out"))??;
        self.tunnel = Some(tunnel);
        Ok(response)
    }

    pub async fn close(mut self) -> Result<()> {
        let mut tunnel = self
            .tunnel
            .take()
            .ok_or_else(|| anyhow::anyhow!(UDP_ASSOCIATION_UNUSABLE))?;
        tunnel
            .send_frame(
                Frame::new(FrameType::CloseFlow, 0, self.flow_id, Bytes::new()),
                true,
            )
            .await?;
        tunnel.finish_response_after_explicit_udp_close().await
    }
}

fn serial_open_udp_flags(feature_flags_selected: u64) -> Result<u8> {
    if feature_flags_selected & !CLIENT_LEGACY_FEATURE_MASK != 0 {
        bail!("invalid selected feature mask");
    }
    // Selecting the mode gate only proves both peers understand the gate.
    // No nonzero production mode is supported by this client.
    Ok(OPEN_UDP_FLAGS_SERIAL)
}

fn is_exact_open_udp_ack(frame: &Frame, flow_id: u64) -> bool {
    frame.frame_type == FrameType::WindowUpdate
        && frame.flags == 0
        && frame.flow_id == flow_id
        && frame.payload.is_empty()
}

fn udp_response_from_frame(frame: Frame, flow_id: u64) -> Result<Option<UdpPacketPayload>> {
    if frame.frame_type == FrameType::UdpPacket && frame.flow_id == flow_id {
        return UdpPacketPayload::decode(&frame.payload)
            .map(Some)
            .map_err(Into::into);
    }
    if frame.frame_type == FrameType::Error {
        bail!("UDP relay failed");
    }
    if matches!(frame.frame_type, FrameType::CloseFlow | FrameType::TcpFin) {
        bail!("UDP flow closed");
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::frame::TargetAddr;

    #[cfg(feature = "h3")]
    fn duplex_probe_shared() -> (
        Arc<LegacyH3DuplexShared>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let aborts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Arc::new(LegacyH3DuplexShared {
                unusable: AtomicBool::new(false),
                abort: LegacyH3DuplexAbort::Probe(Arc::clone(&aborts)),
            }),
            aborts,
        )
    }

    #[cfg(feature = "h3")]
    #[test]
    fn legacy_h3_duplex_lifecycle_guard_is_sticky_and_aborts_once() {
        let (shared, aborts) = duplex_probe_shared();
        {
            let _guard = LegacyH3DuplexPoisonGuard::arm(&shared).unwrap();
        }
        assert!(shared.is_unusable());
        assert_eq!(aborts.load(Ordering::Acquire), 1);

        shared.invalidate_and_abort();
        assert_eq!(aborts.load(Ordering::Acquire), 1);
        assert!(LegacyH3DuplexPoisonGuard::arm(&shared).is_none());
    }

    #[cfg(feature = "h3")]
    #[test]
    fn legacy_h3_duplex_lifecycle_guard_disarm_preserves_usable_state() {
        let (shared, aborts) = duplex_probe_shared();
        {
            let mut guard = LegacyH3DuplexPoisonGuard::arm(&shared).unwrap();
            guard.disarm();
        }
        assert!(!shared.is_unusable());
        assert_eq!(aborts.load(Ordering::Acquire), 0);
    }

    #[cfg(feature = "h3")]
    #[tokio::test]
    async fn legacy_h3_duplex_lifecycle_close_failure_drops_pending_peer() {
        struct DropProbe(Arc<AtomicBool>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let probe = DropProbe(Arc::clone(&dropped));
        let pending = async move {
            let _probe = probe;
            futures::future::pending::<Result<()>>().await
        };
        let failed = async { Err::<(), _>(anyhow::anyhow!("fixed test failure")) };

        let result = timeout(
            Duration::from_millis(100),
            complete_legacy_h3_duplex_close(failed, pending),
        )
        .await
        .expect("close failure must not wait for the pending direction");

        assert!(result.is_err());
        assert!(dropped.load(Ordering::Acquire));
    }

    #[cfg(feature = "h3")]
    #[test]
    fn legacy_h3_duplex_lifecycle_ack_requires_exact_duplex_shape() {
        let exact = Frame::new(
            FrameType::WindowUpdate,
            OPEN_UDP_FLAG_DUPLEX,
            UDP_FLOW_ID,
            Bytes::new(),
        );
        assert!(is_exact_duplex_open_udp_ack(&exact, UDP_FLOW_ID));
        for wrong in [
            Frame::new(FrameType::WindowUpdate, 0, UDP_FLOW_ID, Bytes::new()),
            Frame::new(
                FrameType::WindowUpdate,
                OPEN_UDP_FLAG_DUPLEX,
                UDP_FLOW_ID + 1,
                Bytes::new(),
            ),
            Frame::new(
                FrameType::WindowUpdate,
                OPEN_UDP_FLAG_DUPLEX,
                UDP_FLOW_ID,
                Bytes::from_static(b"unexpected"),
            ),
        ] {
            assert!(!is_exact_duplex_open_udp_ack(&wrong, UDP_FLOW_ID));
        }
    }

    #[cfg(feature = "h3")]
    #[test]
    fn legacy_h3_duplex_lifecycle_receive_classifier_requires_exact_shape() -> Result<()> {
        let target = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST);
        let packet = UdpPacketPayload::new(
            target.clone(),
            53,
            Bytes::from_static(b"classified-payload"),
        )
        .encode()?;
        let event = classify_legacy_h3_duplex_receive_frame(
            Frame::new(FrameType::UdpPacket, 0, UDP_FLOW_ID, packet.clone()),
            UDP_FLOW_ID,
            &target,
            53,
        )?;
        assert!(matches!(
            event,
            LegacyH3DuplexReceiveEvent::Packet(payload)
                if payload == Bytes::from_static(b"classified-payload")
        ));

        for wrong in [
            Frame::new(FrameType::UdpPacket, 1, UDP_FLOW_ID, packet.clone()),
            Frame::new(FrameType::UdpPacket, 0, UDP_FLOW_ID + 1, packet.clone()),
            Frame::new(FrameType::UdpPacket, 0, UDP_FLOW_ID, Bytes::new()),
            Frame::new(
                FrameType::UdpPacket,
                0,
                UDP_FLOW_ID,
                UdpPacketPayload::new(
                    TargetAddr::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
                    53,
                    Bytes::from_static(b"wrong-target"),
                )
                .encode()?,
            ),
            Frame::new(
                FrameType::CloseFlow,
                0,
                UDP_FLOW_ID,
                Bytes::from_static(b"unexpected"),
            ),
        ] {
            assert!(
                classify_legacy_h3_duplex_receive_frame(wrong, UDP_FLOW_ID, &target, 53,).is_err()
            );
        }

        assert!(matches!(
            classify_legacy_h3_duplex_receive_frame(
                Frame::new(FrameType::CloseFlow, 0, UDP_FLOW_ID, Bytes::new()),
                UDP_FLOW_ID,
                &target,
                53,
            )?,
            LegacyH3DuplexReceiveEvent::Close
        ));
        Ok(())
    }

    #[test]
    fn udp_response_decodes_matching_packet() -> Result<()> {
        let packet = UdpPacketPayload::new(
            TargetAddr::Domain("example.com".into()),
            53,
            Bytes::from_static(b"query"),
        );
        let frame = Frame::new(FrameType::UdpPacket, 0, UDP_FLOW_ID, packet.encode()?);

        let decoded = udp_response_from_frame(frame, UDP_FLOW_ID)?.unwrap();

        assert_eq!(decoded, packet);
        Ok(())
    }

    #[test]
    fn udp_response_ignores_unrelated_packet_flow() -> Result<()> {
        let packet = UdpPacketPayload::new(
            TargetAddr::Domain("example.com".into()),
            53,
            Bytes::from_static(b"query"),
        );
        let frame = Frame::new(FrameType::UdpPacket, 0, UDP_FLOW_ID + 1, packet.encode()?);

        assert!(udp_response_from_frame(frame, UDP_FLOW_ID)?.is_none());
        Ok(())
    }

    #[test]
    fn udp_response_errors_on_remote_failure_frames() {
        let err = udp_response_from_frame(
            Frame::new(FrameType::Error, 0, UDP_FLOW_ID, Bytes::new()),
            UDP_FLOW_ID,
        )
        .unwrap_err();
        assert!(err.to_string().contains("UDP relay failed"));

        let err = udp_response_from_frame(
            Frame::new(FrameType::CloseFlow, 0, UDP_FLOW_ID, Bytes::new()),
            UDP_FLOW_ID,
        )
        .unwrap_err();
        assert!(err.to_string().contains("UDP flow closed"));
    }

    #[test]
    fn open_udp_ack_must_match_exact_shape_before_first_packet() {
        let exact = Frame::new(FrameType::WindowUpdate, 0, UDP_FLOW_ID, Bytes::new());
        assert!(is_exact_open_udp_ack(&exact, UDP_FLOW_ID));

        for wrong in [
            Frame::new(FrameType::Pong, 0, UDP_FLOW_ID, Bytes::new()),
            Frame::new(FrameType::WindowUpdate, 0, UDP_FLOW_ID + 1, Bytes::new()),
            Frame::new(FrameType::WindowUpdate, 1, UDP_FLOW_ID, Bytes::new()),
            Frame::new(
                FrameType::WindowUpdate,
                0,
                UDP_FLOW_ID,
                Bytes::from_static(b"unexpected"),
            ),
        ] {
            assert!(!is_exact_open_udp_ack(&wrong, UDP_FLOW_ID));
        }
    }

    #[test]
    fn selected_mask_decision_keeps_production_open_udp_serial() {
        for selected in [
            0,
            FEATURE_OPEN_UDP_MODE_NEGOTIATION,
            FEATURE_TLS_CHANNEL_BINDING,
            FEATURE_OPEN_UDP_MODE_NEGOTIATION | FEATURE_TLS_CHANNEL_BINDING,
        ] {
            assert_eq!(
                serial_open_udp_flags(selected).unwrap(),
                OPEN_UDP_FLAGS_SERIAL
            );
        }
        assert_eq!(
            serial_open_udp_flags(1 << 1).unwrap_err().to_string(),
            "invalid selected feature mask"
        );
    }

    #[tokio::test]
    async fn unusable_association_close_returns_fixed_error() {
        let association = UdpAssociation {
            tunnel: None,
            flow_id: UDP_FLOW_ID,
            response_timeout: Duration::from_secs(1),
        };

        let err = association.close().await.unwrap_err();

        assert_eq!(err.to_string(), UDP_ASSOCIATION_UNUSABLE);
    }

    #[tokio::test]
    async fn unusable_association_relay_precedes_packet_encode_error() {
        let mut association = UdpAssociation {
            tunnel: None,
            flow_id: UDP_FLOW_ID,
            response_timeout: Duration::from_secs(1),
        };
        let invalid_packet = UdpPacketPayload::new(
            TargetAddr::Domain("x".repeat(u16::MAX as usize + 1)),
            53,
            Bytes::new(),
        );

        let err = association.relay_packet(invalid_packet).await.unwrap_err();

        assert_eq!(err.to_string(), UDP_ASSOCIATION_UNUSABLE);
    }
}
