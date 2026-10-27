//! Explicit H3 frame-channel entry points. The default transport selector and
//! the retired config-v1 H3 flag do not activate this module.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use maverick_core::auth::TlsChannelBinding;
use maverick_core::h3_channel::FrameChannel;
use maverick_core::padding::{RuntimeBatcher, RuntimeCoverTraffic, RuntimePadding};
use maverick_core::{ClientConfig, Frame, FrameType};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::tunnel::{
    prepare_outgoing_frames, validate_negotiated_max_frame_size, ClientHandshake, ClientTunnel,
};

pub struct H3ClientTunnel {
    pub(crate) channel: FrameChannel,
    pub(crate) max_frame_size: usize,
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
    config.validate()?;
    let budget = Duration::from_millis(config.advanced.connect_timeout_ms);
    let max_frame_size = timeout(budget, async {
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
        validate_negotiated_max_frame_size(hello.verify_server_hello(&server.payload)?)
    })
    .await
    .context("H3 authentication timed out")??;
    Ok(ClientTunnel::H3(Box::new(H3ClientTunnel {
        channel,
        max_frame_size,
        padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
        cover: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
        batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
        stall_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
        request_ended: false,
        flow_id: 1,
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
                    self.channel
                        .send(padding, false, self.max_frame_size)
                        .await?;
                }
                for padding in self.cover.padding_frames(
                    frame.frame_type,
                    frame.payload.len(),
                    self.max_frame_size,
                ) {
                    self.channel
                        .send(padding, false, self.max_frame_size)
                        .await?;
                }
                self.channel
                    .send(frame, end && index == last, self.max_frame_size)
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("H3 send stalled")??;
        self.request_ended |= end;
        Ok(())
    }

    pub(crate) async fn finish_response(&mut self) -> Result<()> {
        timeout(self.stall_timeout, async {
            if !self.request_ended {
                self.channel
                    .send(
                        Frame::new(FrameType::CloseFlow, 0, self.flow_id, Bytes::new()),
                        true,
                        self.max_frame_size,
                    )
                    .await?;
                self.request_ended = true;
            }
            if self.channel.read(self.max_frame_size).await?.is_some() {
                bail!("unexpected H3 frame after flow completion");
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("H3 response completion timed out")?
    }
}
