use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use maverick_core::frame::{TargetAddr, UdpPacketPayload};
use maverick_tun::{
    BoxFuture, BoxTcpFlow, Datagram, DatagramFlow, FlowConnector, FlowConnectorSnapshot, FlowError,
    FlowErrorKind,
};
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::connection_manager::ClientTunnelPool;
use crate::udp::UdpAssociation;

pub(crate) struct MaverickTunConnector {
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_limit: Arc<Semaphore>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    tcp_buffer_bytes: usize,
    dns_timeout: Duration,
    shutdown_timeout: Duration,
    resources: Arc<ConnectorResources>,
}

impl MaverickTunConnector {
    pub(crate) fn new(
        tunnel_pool: Arc<ClientTunnelPool>,
        flow_limit: Arc<Semaphore>,
        tcp_buffer_bytes: usize,
        dns_timeout: Duration,
        shutdown_timeout: Duration,
        max_tcp_tasks: usize,
    ) -> Self {
        Self {
            tunnel_pool,
            flow_limit,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            tcp_buffer_bytes,
            dns_timeout,
            shutdown_timeout,
            resources: Arc::new(ConnectorResources {
                active_tasks: AtomicUsize::new(0),
                peak_tasks: AtomicUsize::new(0),
                duplex_capacity_bytes: tcp_buffer_bytes.saturating_mul(2),
                max_tcp_tasks,
            }),
        }
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.cancel.cancel();
        self.tasks.close();
        timeout(self.shutdown_timeout, self.tasks.wait())
            .await
            .map_err(|_| anyhow::anyhow!("TUN connector shutdown timed out"))?;
        Ok(())
    }

    fn try_flow_permit(&self) -> Result<OwnedSemaphorePermit, FlowError> {
        self.flow_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| FlowError::new(FlowErrorKind::AdmissionRejected))
    }
}

impl Drop for MaverickTunConnector {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
    }
}

impl FlowConnector for MaverickTunConnector {
    fn snapshot(&self) -> FlowConnectorSnapshot {
        self.resources.snapshot()
    }

    fn open_tcp<'a>(
        &'a self,
        target: SocketAddr,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<BoxTcpFlow, FlowError>> {
        Box::pin(async move {
            let permit = self.try_flow_permit()?;
            let target_addr = target_addr(target.ip());
            let open =
                crate::session::open_tcp_tunnel(&self.tunnel_pool, target_addr, target.port());
            let tunnel = tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Err(FlowError::new(FlowErrorKind::Cancelled));
                }
                _ = cancel.cancelled() => {
                    return Err(FlowError::new(FlowErrorKind::Cancelled));
                }
                result = open => result.map_err(|_| FlowError::new(FlowErrorKind::RemoteConnection))?,
            };

            let (packet_stream, relay_stream) = duplex(self.tcp_buffer_bytes);
            let relay_failed = Arc::new(AtomicBool::new(false));
            let packet_stream = ConnectorTcpStream {
                inner: packet_stream,
                relay_failed: Arc::clone(&relay_failed),
            };
            let connector_cancel = self.cancel.child_token();
            let flow_cancel = cancel.clone();
            let task_guard = ConnectorTaskGuard::new(Arc::clone(&self.resources));
            let idle_timeout =
                Duration::from_secs(self.tunnel_pool.config().advanced.idle_timeout_secs);
            self.tasks.spawn(async move {
                let _task_guard = task_guard;
                let _permit = permit;
                let relay = async move {
                    let mut relay_stream = relay_stream;
                    let result = crate::session::relay_stream_and_tunnel(
                        &mut relay_stream,
                        tunnel,
                        idle_timeout,
                    )
                    .await;
                    if !matches!(result, Ok(crate::session::RelayClose::Graceful)) {
                        relay_failed.store(true, Ordering::Release);
                    }
                    drop(relay_stream);
                };
                tokio::select! {
                    _ = connector_cancel.cancelled() => {}
                    _ = flow_cancel.cancelled() => {}
                    _ = relay => {}
                }
            });
            Ok(Box::new(packet_stream) as BoxTcpFlow)
        })
    }

    fn exchange_dns<'a>(
        &'a self,
        query: Bytes,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Bytes, FlowError>> {
        Box::pin(async move {
            let _permit = self.try_flow_permit()?;
            tokio::select! {
                _ = self.cancel.cancelled() => Err(FlowError::new(FlowErrorKind::Cancelled)),
                _ = cancel.cancelled() => Err(FlowError::new(FlowErrorKind::Cancelled)),
                result = timeout(
                    self.dns_timeout,
                    crate::dns::resolve_via_pool(&self.tunnel_pool, query),
                ) => match result {
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(_)) => Err(FlowError::new(FlowErrorKind::DnsExchange)),
                    Err(_) => Err(FlowError::new(FlowErrorKind::TimedOut)),
                }
            }
        })
    }

    fn open_udp<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn DatagramFlow>, FlowError>> {
        Box::pin(async move {
            let permit = self.try_flow_permit()?;
            let association = tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Err(FlowError::new(FlowErrorKind::Cancelled));
                }
                _ = cancel.cancelled() => {
                    return Err(FlowError::new(FlowErrorKind::Cancelled));
                }
                result = UdpAssociation::open_with_pool(&self.tunnel_pool) => {
                    result.map_err(|_| FlowError::new(FlowErrorKind::RemoteConnection))?
                }
            };
            Ok(Box::new(MaverickDatagramFlow {
                association: Some(association),
                _permit: permit,
            }) as Box<dyn DatagramFlow>)
        })
    }
}

struct ConnectorTcpStream {
    inner: DuplexStream,
    relay_failed: Arc<AtomicBool>,
}

impl AsyncRead for ConnectorTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(()))
                if buffer.filled().len() == filled_before
                    && self.relay_failed.load(Ordering::Acquire) =>
            {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Maverick TCP relay failed",
                )))
            }
            result => result,
        }
    }
}

impl AsyncWrite for ConnectorTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ConnectorResources {
    active_tasks: AtomicUsize,
    peak_tasks: AtomicUsize,
    duplex_capacity_bytes: usize,
    max_tcp_tasks: usize,
}

impl ConnectorResources {
    fn snapshot(&self) -> FlowConnectorSnapshot {
        let active_tasks = self.active_tasks.load(Ordering::Relaxed);
        let peak_tasks = self.peak_tasks.load(Ordering::Relaxed).max(active_tasks);
        FlowConnectorSnapshot {
            active_tasks,
            peak_tasks,
            buffered_bytes: active_tasks.saturating_mul(self.duplex_capacity_bytes),
            peak_buffered_bytes: peak_tasks.saturating_mul(self.duplex_capacity_bytes),
            buffer_capacity_bytes: self
                .max_tcp_tasks
                .saturating_mul(self.duplex_capacity_bytes),
        }
    }
}

struct ConnectorTaskGuard(Arc<ConnectorResources>);

impl ConnectorTaskGuard {
    fn new(resources: Arc<ConnectorResources>) -> Self {
        let active = resources.active_tasks.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peak = resources.peak_tasks.load(Ordering::Relaxed);
        while active > peak {
            match resources.peak_tasks.compare_exchange_weak(
                peak,
                active,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
        Self(resources)
    }
}

impl Drop for ConnectorTaskGuard {
    fn drop(&mut self) {
        self.0.active_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

struct MaverickDatagramFlow {
    association: Option<UdpAssociation>,
    _permit: OwnedSemaphorePermit,
}

impl DatagramFlow for MaverickDatagramFlow {
    fn exchange<'a>(
        &'a mut self,
        datagram: Datagram,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Datagram, FlowError>> {
        Box::pin(async move {
            let association = self
                .association
                .as_mut()
                .ok_or_else(|| FlowError::new(FlowErrorKind::Closed))?;
            let packet = UdpPacketPayload::new(
                target_addr(datagram.endpoint.ip()),
                datagram.endpoint.port(),
                datagram.payload,
            );
            let response = tokio::select! {
                _ = cancel.cancelled() => {
                    return Err(FlowError::new(FlowErrorKind::Cancelled));
                }
                response = association.relay_packet(packet) => {
                    response.map_err(|_| FlowError::new(FlowErrorKind::DatagramExchange))?
                }
            };
            let endpoint = socket_addr(&response.target, response.port)
                .ok_or_else(|| FlowError::new(FlowErrorKind::DatagramExchange))?;
            Ok(Datagram::new(endpoint, response.data))
        })
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), FlowError>> {
        Box::pin(async move {
            let Some(association) = self.association.take() else {
                return Ok(());
            };
            association
                .close()
                .await
                .map_err(|_| FlowError::new(FlowErrorKind::Closed))
        })
    }
}

fn target_addr(address: IpAddr) -> TargetAddr {
    match address {
        IpAddr::V4(address) => TargetAddr::Ipv4(address),
        IpAddr::V6(address) => TargetAddr::Ipv6(address),
    }
}

fn socket_addr(target: &TargetAddr, port: u16) -> Option<SocketAddr> {
    match target {
        TargetAddr::Ipv4(address) => Some(SocketAddr::new(IpAddr::V4(*address), port)),
        TargetAddr::Ipv6(address) => Some(SocketAddr::new(IpAddr::V6(*address), port)),
        TargetAddr::Domain(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn relay_failure_becomes_connection_reset() {
        let (packet, relay) = duplex(8);
        let mut stream = ConnectorTcpStream {
            inner: packet,
            relay_failed: Arc::new(AtomicBool::new(true)),
        };
        drop(relay);

        let mut byte = [0; 1];
        let err = stream.read(&mut byte).await.unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn clean_relay_close_remains_eof() {
        let (packet, relay) = duplex(8);
        let mut stream = ConnectorTcpStream {
            inner: packet,
            relay_failed: Arc::new(AtomicBool::new(false)),
        };
        drop(relay);

        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    }
}
