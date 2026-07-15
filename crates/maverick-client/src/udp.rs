use anyhow::{bail, Result};
use bytes::Bytes;
use maverick_core::frame::{Frame, FrameType, OpenUdpPayload, UdpPacketPayload};
use maverick_core::ClientConfig;
use tokio::time::{timeout, Duration};

use crate::tunnel::{self, ClientTunnel};
use crate::ClientTunnelPool;

const UDP_FLOW_ID: u64 = 1;

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
    tunnel: ClientTunnel,
    flow_id: u64,
    response_timeout: Duration,
}

impl UdpAssociation {
    pub async fn open(config: &ClientConfig) -> Result<Self> {
        Self::open_with_tunnel(config, tunnel::open(config).await?).await
    }

    pub(crate) async fn open_with_pool(pool: &ClientTunnelPool) -> Result<Self> {
        Self::open_with_tunnel(pool.config(), pool.open().await?).await
    }

    async fn open_with_tunnel(config: &ClientConfig, mut tunnel: ClientTunnel) -> Result<Self> {
        tunnel
            .send_frame(
                Frame::new(
                    FrameType::OpenUdp,
                    0,
                    UDP_FLOW_ID,
                    OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
                ),
                false,
            )
            .await?;
        match tunnel.read_next_frame().await? {
            Some(frame)
                if frame.frame_type == FrameType::WindowUpdate && frame.flow_id == UDP_FLOW_ID =>
            {
                Ok(Self {
                    tunnel,
                    flow_id: UDP_FLOW_ID,
                    response_timeout: Duration::from_millis(config.advanced.udp_idle_timeout_ms),
                })
            }
            Some(frame) if frame.frame_type == FrameType::Error => bail!("UDP open failed"),
            _ => bail!("server closed before UDP flow opened"),
        }
    }

    pub async fn relay_packet(&mut self, packet: UdpPacketPayload) -> Result<UdpPacketPayload> {
        self.tunnel
            .send_frame(
                Frame::new(FrameType::UdpPacket, 0, self.flow_id, packet.encode()?),
                false,
            )
            .await?;

        timeout(self.response_timeout, async {
            loop {
                match self.tunnel.read_next_frame().await? {
                    Some(frame) => {
                        if let Some(packet) = udp_response_from_frame(frame, self.flow_id)? {
                            return Ok(packet);
                        }
                    }
                    None => bail!("server closed before UDP response"),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("UDP relay response timed out"))?
    }

    pub async fn close(mut self) -> Result<()> {
        self.tunnel
            .send_frame(
                Frame::new(FrameType::CloseFlow, 0, self.flow_id, Bytes::new()),
                true,
            )
            .await
    }
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
}
