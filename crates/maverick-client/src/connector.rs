//! Listener-free embedding API. The caller owns I/O, task scheduling and cancellation.
use std::sync::Arc;
use std::time::Duration;

pub use crate::udp_session::{UdpCapabilityUnsupported, UdpCarrier};
use anyhow::{Context, Result};
pub use bytes::Bytes;
pub use maverick_core::frame::{TargetAddr, UdpPacketPayload};
use maverick_core::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::connection_manager::{ClientTunnelPool, H2ConnectionPoolSnapshot};
use crate::tunnel::ClientTunnel;

/// A reusable client pool without SOCKS, HTTP, DNS or TUN listeners.
/// Construction validates configuration but does not contact the remote server.
pub struct ProxyConnector {
    pool: ClientTunnelPool,
    flows: Arc<Semaphore>,
}

impl ProxyConnector {
    pub fn new(config: ClientConfig) -> Result<Self> {
        config.validate()?;
        tokio::runtime::Handle::try_current().context("ProxyConnector requires a Tokio runtime")?;
        #[cfg(not(feature = "experimental-h3"))]
        anyhow::ensure!(
            !config.advanced.quiche_h3 && !config.advanced.auto_h3,
            "H3 requires the experimental-h3 client build feature"
        );
        anyhow::ensure!(
            !config.advanced.experimental_tun,
            "ProxyConnector does not start TUN"
        );
        Ok(Self {
            flows: Arc::new(Semaphore::new(
                config.advanced.max_concurrent_flows as usize,
            )),
            pool: ClientTunnelPool::new(Arc::new(config)),
        })
    }

    fn permit(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.flows)
            .try_acquire_owned()
            .context("connector closed or flow limit reached")
    }

    /// Verifies TLS/authentication and waits for remote target admission before returning.
    /// Dropping this future cancels opening; dropping the session releases its flow slot.
    pub async fn connect_tcp(&self, target: TargetAddr, port: u16) -> Result<TcpSession> {
        let permit = self.permit()?;
        let config = self.pool.config();
        let tunnel = timeout(
            Duration::from_millis(config.advanced.connect_timeout_ms),
            crate::session::open_tcp_tunnel(&self.pool, target, port),
        )
        .await
        .context("connector TCP open timed out")??;
        Ok(TcpSession {
            tunnel,
            _permit: permit,
            idle_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
        })
    }

    /// One request/response exchange, honoring an explicit UDP session policy.
    /// With omitted policy, H2 retains legacy exchanges and H3/auto stays native.
    /// Use open_udp for independent, persistent bidirectional traffic.
    pub async fn exchange_udp(&self, packet: UdpPacketPayload) -> Result<UdpPacketPayload> {
        let _permit = self.permit()?;
        let config = self.pool.config();
        if config.advanced.udp_policy.is_some() {
            return crate::udp_session::exchange(&self.pool, packet).await;
        }
        #[cfg(feature = "experimental-h3")]
        if config.advanced.quiche_h3 || config.advanced.auto_h3 {
            return crate::udp::relay_udp_packet(config, packet).await;
        }
        let mut association = timeout(
            Duration::from_millis(config.advanced.connect_timeout_ms),
            crate::udp::UdpAssociation::open_with_pool(&self.pool),
        )
        .await
        .context("connector UDP open timed out")??;
        let result = association.relay_packet(packet).await;
        let _ = association.close().await;
        result
    }

    /// Opens an independent, fixed-target native datagram session. Requires H3/auto.
    #[cfg(feature = "experimental-h3")]
    pub async fn open_native_udp(&self, target: TargetAddr, port: u16) -> Result<NativeUdpSession> {
        let permit = self.permit()?;
        let inner = crate::h3::NativeUdpAssociation::open(self.pool.config(), target, port).await?;
        Ok(NativeUdpSession {
            inner,
            _permit: permit,
        })
    }

    pub fn h2_pool_snapshot(&self) -> H2ConnectionPoolSnapshot {
        self.pool.h2_snapshot()
    }

    /// Opens a persistent fixed-target UDP session using the configured policy.
    /// Carrier choice is complete before this returns; sends are never replayed.
    pub async fn open_udp(&self, target: TargetAddr, port: u16) -> Result<UdpSession> {
        let permit = self.permit()?;
        let inner = crate::udp_session::DatagramSession::open(&self.pool, target, port).await?;
        Ok(UdpSession {
            inner,
            _permit: permit,
        })
    }

    /// Stops new opens and releases the pool's idle H2 ownership. Already returned
    /// sessions remain owned by the caller; drop them or cancel their relay futures.
    pub fn close(&self) {
        self.flows.close();
        self.pool.shutdown();
    }
}

pub struct UdpSession {
    inner: crate::udp_session::DatagramSession,
    _permit: OwnedSemaphorePermit,
}

impl UdpSession {
    pub fn carrier(&self) -> UdpCarrier {
        self.inner.carrier()
    }
    pub fn max_payload(&self) -> usize {
        self.inner.max_payload()
    }
    pub fn send(&self, packet: Bytes) -> Result<bool> {
        self.inner.send(packet)
    }
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.inner.recv().await
    }
    pub async fn close(self) -> Result<()> {
        self.inner.close().await
    }
}

impl Drop for ProxyConnector {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct TcpSession {
    tunnel: ClientTunnel,
    _permit: OwnedSemaphorePermit,
    idle_timeout: Duration,
}

impl TcpSession {
    pub fn carrier(&self) -> crate::transport::TransportKind {
        match &self.tunnel {
            ClientTunnel::H2(_) => crate::transport::TransportKind::H2,
            ClientTunnel::CloudflareWs(_) => crate::transport::TransportKind::CloudflareWs,
            #[cfg(feature = "experimental-h3")]
            ClientTunnel::H3(_) => crate::transport::TransportKind::H3,
        }
    }

    /// Forwards caller-owned I/O, including TCP half-close in either direction.
    /// Cancellation is ordinary Rust future cancellation: dropping this future
    /// drops the local I/O and tunnel. Runtime errors are returned to the caller.
    pub async fn relay<S>(self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Self {
            tunnel,
            _permit,
            idle_timeout,
        } = self;
        let result = crate::session::relay_stream_and_tunnel(stream, tunnel, idle_timeout).await?;
        anyhow::ensure!(
            result != crate::session::RelayClose::Reset,
            "remote TCP flow reset"
        );
        Ok(())
    }
}

#[cfg(feature = "experimental-h3")]
pub struct NativeUdpSession {
    inner: crate::h3::NativeUdpAssociation,
    _permit: OwnedSemaphorePermit,
}

#[cfg(feature = "experimental-h3")]
impl NativeUdpSession {
    pub fn max_payload(&self) -> usize {
        self.inner.max_payload()
    }
    /// true means queued, not delivered; false means oversize or queue-full drop.
    pub fn send(&self, payload: Bytes) -> Result<bool> {
        self.inner.send(payload)
    }
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.inner.recv().await
    }
    pub async fn close(self) -> Result<()> {
        self.inner.close().await
    }
}
