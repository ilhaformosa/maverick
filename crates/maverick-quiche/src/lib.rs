//! Explicit, single-request HTTP/3 transport for Maverick TCP sessions.
//! Authentication and target policy remain in the client/server session layers.

#![forbid(unsafe_code)]

use anyhow::{bail, ensure, Context, Result};
use boring::ssl::{SslContextBuilder, SslRef, SslVersion};
use bytes::{Buf, Bytes, BytesMut};
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use maverick_core::frame::{Frame, FRAME_HEADER_LEN};
use maverick_core::h3_channel::{self, FrameChannel, TransportChannel};
use quiche::h3::{self, Header, NameValue};
use rand::{rngs::OsRng, TryRngCore};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

const MAX_UDP: usize = 1_350;
const CONNECTION_ID_LEN: usize = 16;
const PACKET_QUEUE: usize = 64;

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_frame_size: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

/// A TLS-verified channel. The client checks its configured certificate pin
/// before sending any authentication through `channel`.
pub struct Connected {
    pub channel: FrameChannel,
    pub binding: TlsChannelBinding,
    pub peer: SocketAddr,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub admission: Option<OwnedSemaphorePermit>,
}

pub struct ServeOptions {
    pub path: String,
    pub limits: Limits,
    pub max_connections: usize,
    pub max_connections_per_source: usize,
    pub admission: Arc<Semaphore>,
}

/// Existing established-connection fixtures use the same byte/framing driver
/// as the configured client and server.
pub struct EstablishedEndpoint {
    pub conn: quiche::Connection,
    pub socket: UdpSocket,
    pub h3: h3::Connection,
    pub peer: SocketAddr,
    pub server: bool,
    pub path: String,
    pub max_frame_size: usize,
}

pub type RunningEndpoint = (oneshot::Sender<()>, JoinHandle<Result<()>>);

pub fn spawn_established(endpoint: EstablishedEndpoint) -> Result<(FrameChannel, RunningEndpoint)> {
    let io = PacketIo::direct(endpoint.socket, endpoint.peer)?;
    let (channel, app) = h3_channel::channel();
    let (stop, stopped) = oneshot::channel();
    let driver = Driver {
        conn: endpoint.conn,
        io,
        h3: endpoint.h3,
        app,
        server: endpoint.server,
        path: endpoint.path,
        max_frame_size: endpoint.max_frame_size,
    };
    Ok((channel, (stop, tokio::spawn(driver.run(Some(stopped))))))
}

pub async fn connect(
    peer: SocketAddr,
    server_name: &str,
    path: &str,
    tls: SslContextBuilder,
    limits: Limits,
) -> Result<Connected> {
    let bind_ip = match (peer.is_ipv4(), peer.ip().is_loopback()) {
        (true, true) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (false, true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (true, false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (false, false) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    socket.connect(peer).await?;
    let mut io = PacketIo::direct(socket, peer)?;
    let mut config = transport_config(tls, limits)?;
    let id = random_id()?;
    let mut conn = quiche::connect(
        Some(server_name),
        &quiche::ConnectionId::from_ref(&id),
        io.local,
        peer,
        &mut config,
    )?;
    let ssl: &mut SslRef = conn.as_mut();
    ssl.set_enable_ech_grease(true);
    if let Err(error) = handshake(&mut conn, &mut io, limits.handshake_timeout).await {
        // TLS verification failure queues a QUIC close. Send it before dropping
        // the socket so the peer can release its pre-authentication admission.
        let _ = io.flush(&mut conn).await;
        return Err(error);
    }
    let binding = binding(&mut conn)?;
    let peer_certificate_der = conn.peer_cert().map(<[u8]>::to_vec);
    let mut h3 = h3_connection(&mut conn)?;
    let stream = h3.send_request(
        &mut conn,
        &[
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", server_name.as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"content-type", b"application/octet-stream"),
        ],
        false,
    )?;
    ensure!(stream == 0, "unexpected first H3 stream");
    let (channel, app) = h3_channel::channel();
    tokio::spawn(
        Driver {
            conn,
            io,
            h3,
            app,
            server: false,
            path: path.to_owned(),
            max_frame_size: limits.max_frame_size,
        }
        .run(None),
    );
    Ok(Connected {
        channel,
        binding,
        peer,
        peer_certificate_der,
        admission: None,
    })
}

struct Route {
    peer: SocketAddr,
    packets: mpsc::Sender<Vec<u8>>,
    primary: bool,
}

/// Serve one UDP listener. Each connection owns one request/TCP flow and one
/// bounded packet queue; dropping/stopping this task also aborts its drivers.
pub async fn serve(
    socket: UdpSocket,
    tls: SslContextBuilder,
    options: ServeOptions,
    accepted: mpsc::Sender<Connected>,
    mut stop: oneshot::Receiver<()>,
) -> Result<()> {
    let local = socket.local_addr()?;
    let socket = Arc::new(socket);
    let mut config = transport_config(tls, options.limits)?;
    let mut routes: HashMap<Vec<u8>, Route> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut packet = [0; MAX_UDP + 1];
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = accepted.closed() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok((initial, source))) = joined {
                    routes.remove(&initial);
                    routes.remove(&source);
                }
                // Closed senders also cover a cancelled/panicked connection task.
                routes.retain(|_, route| !route.packets.is_closed());
            }
            received = socket.recv_from(&mut packet) => {
                let (len, peer) = received?;
                if len > MAX_UDP { continue; }
                let header = match quiche::Header::from_slice(&mut packet[..len], CONNECTION_ID_LEN) {
                    Ok(header) => header,
                    Err(_) => continue,
                };
                let destination = header.dcid.to_vec();
                if let Some(route) = routes.get(&destination) {
                    if route.peer == peer {
                        // A full queue drops a datagram; QUIC handles packet loss.
                        let _ = route.packets.try_send(packet[..len].to_vec());
                    }
                    continue;
                }
                if header.ty != quiche::Type::Initial
                    || !quiche::version_is_supported(header.version)
                    || tasks.len() >= options.max_connections
                    || routes.values().filter(|r| r.primary && r.peer.ip() == peer.ip()).count()
                        >= options.max_connections_per_source
                {
                    continue;
                }
                let admission = match Arc::clone(&options.admission).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let source = random_id()?.to_vec();
                if routes.contains_key(&source) { continue; }
                let mut conn = match quiche::accept(
                    &quiche::ConnectionId::from_ref(&source), None, local, peer, &mut config,
                ) {
                    Ok(conn) => conn,
                    Err(_) => continue,
                };
                if conn.recv(&mut packet[..len], quiche::RecvInfo { from: peer, to: local }).is_err() {
                    continue;
                }
                let (send, incoming) = mpsc::channel(PACKET_QUEUE);
                routes.insert(destination.clone(), Route { peer, packets: send.clone(), primary: false });
                routes.insert(source.clone(), Route { peer, packets: send, primary: true });
                let mut io = PacketIo { socket: Arc::clone(&socket), local, peer, incoming: Some(incoming), connected: false };
                let accepted = accepted.clone();
                let path = options.path.clone();
                let limits = options.limits;
                tasks.spawn(async move {
                    let result: Result<()> = async {
                        handshake(&mut conn, &mut io, limits.handshake_timeout).await?;
                        let binding = binding(&mut conn)?;
                        let h3 = h3_connection(&mut conn)?;
                        let (channel, app) = h3_channel::channel();
                        let connected = Connected {
                            channel, binding, peer, peer_certificate_der: None,
                            admission: Some(admission),
                        };
                        accepted.send(connected).await.context("H3 session receiver closed")?;
                        Driver { conn, io, h3, app, server: true, path, max_frame_size: limits.max_frame_size }
                            .run(None).await
                    }.await;
                    // A failed handshake/session is isolated to its own connection.
                    let _ = result;
                    (destination, source)
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn random_id() -> Result<[u8; CONNECTION_ID_LEN]> {
    let mut id = [0; CONNECTION_ID_LEN];
    OsRng
        .try_fill_bytes(&mut id)
        .context("generate QUIC connection ID")?;
    Ok(id)
}

fn transport_config(tls: SslContextBuilder, limits: Limits) -> Result<quiche::Config> {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(limits.idle_timeout.as_millis().min(u128::from(u64::MAX)) as u64);
    config.set_max_recv_udp_payload_size(MAX_UDP);
    config.set_max_send_udp_payload_size(MAX_UDP);
    // One default Maverick frame of stream credit avoids the measured 8 KiB
    // flow-control bottleneck. Keep total receive credit bounded at 128 KiB.
    config.set_initial_max_data(131_072);
    config.set_initial_max_stream_data_bidi_local(65_536);
    config.set_initial_max_stream_data_bidi_remote(65_536);
    config.set_initial_max_stream_data_uni(4_096);
    config.set_max_connection_window(131_072);
    config.set_max_stream_window(65_536);
    config.set_initial_max_streams_bidi(1);
    config.set_initial_max_streams_uni(3);
    config.set_disable_active_migration(true);
    // The driver does not yet schedule quiche SendInfo pacing deadlines.
    config.enable_pacing(false);
    Ok(config)
}

fn h3_connection(conn: &mut quiche::Connection) -> Result<h3::Connection> {
    let mut config = h3::Config::new()?;
    config.set_max_field_section_size(4_096);
    Ok(h3::Connection::with_transport(conn, &config)?)
}

fn binding(conn: &mut quiche::Connection) -> Result<TlsChannelBinding> {
    ensure!(conn.application_proto() == b"h3", "expected H3 ALPN");
    let ssl: &mut SslRef = conn.as_mut();
    ensure!(
        ssl.version2() == Some(SslVersion::TLS1_3),
        "expected TLS 1.3"
    );
    let mut bytes = [0; 32];
    ssl.export_keying_material(
        &mut bytes,
        std::str::from_utf8(TLS_CHANNEL_BINDING_EXPORTER_LABEL)?,
        None,
    )?;
    Ok(TlsChannelBinding::new(bytes))
}

struct PacketIo {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    peer: SocketAddr,
    incoming: Option<mpsc::Receiver<Vec<u8>>>,
    connected: bool,
}

impl PacketIo {
    fn direct(socket: UdpSocket, peer: SocketAddr) -> Result<Self> {
        Ok(Self {
            local: socket.local_addr()?,
            connected: socket.peer_addr().is_ok(),
            socket: Arc::new(socket),
            peer,
            incoming: None,
        })
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        if let Some(incoming) = &mut self.incoming {
            return incoming.recv().await.context("H3 UDP listener closed");
        }
        let mut packet = [0; MAX_UDP + 1];
        loop {
            let (len, peer) = self.socket.recv_from(&mut packet).await?;
            if peer == self.peer && len <= MAX_UDP {
                return Ok(packet[..len].to_vec());
            }
        }
    }

    async fn flush(&self, conn: &mut quiche::Connection) -> Result<()> {
        let mut packet = [0; MAX_UDP];
        loop {
            match conn.send(&mut packet) {
                Ok((len, info)) => {
                    ensure!(info.to == self.peer, "unexpected QUIC peer");
                    if self.connected {
                        self.socket.send(&packet[..len]).await?;
                    } else {
                        self.socket.send_to(&packet[..len], info.to).await?;
                    }
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn receive(&self, conn: &mut quiche::Connection, packet: &mut [u8]) -> Result<()> {
        match conn.recv(
            packet,
            quiche::RecvInfo {
                from: self.peer,
                to: self.local,
            },
        ) {
            Ok(_) | Err(quiche::Error::Done | quiche::Error::InvalidPacket) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn receive_ready(&mut self, conn: &mut quiche::Connection) -> Result<()> {
        // Consume packets already available before flushing ACKs. Keep the
        // existing per-turn bound and never wait for more packets to arrive.
        let mut packet = [0; MAX_UDP + 1];
        for _ in 1..PACKET_QUEUE {
            if let Some(incoming) = &mut self.incoming {
                let Ok(mut queued) = incoming.try_recv() else {
                    break;
                };
                self.receive(conn, &mut queued)?;
            } else {
                match self.socket.try_recv_from(&mut packet) {
                    Ok((len, peer)) => {
                        if peer == self.peer && len <= MAX_UDP {
                            self.receive(conn, &mut packet[..len])?;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
}

async fn handshake(
    conn: &mut quiche::Connection,
    io: &mut PacketIo,
    deadline: Duration,
) -> Result<()> {
    tokio::time::timeout(deadline, async {
        loop {
            io.flush(conn).await?;
            ensure!(
                !conn.is_closed() && !conn.is_draining(),
                "QUIC handshake closed"
            );
            if conn.is_established() {
                return Ok(());
            }
            let wait = conn.timeout().unwrap_or(Duration::from_secs(1));
            tokio::select! {
                received = io.recv() => io.receive(conn, &mut received?)?,
                _ = tokio::time::sleep(wait) => conn.on_timeout(),
            }
        }
    })
    .await
    .context("QUIC handshake timed out")?
}

struct Driver {
    conn: quiche::Connection,
    io: PacketIo,
    h3: h3::Connection,
    app: TransportChannel,
    server: bool,
    path: String,
    max_frame_size: usize,
}

impl Driver {
    async fn run(mut self, mut stop: Option<oneshot::Receiver<()>>) -> Result<()> {
        let mut wire_in = BytesMut::new();
        let mut pending_in = None;
        let mut wire_out = Bytes::new();
        let mut end_out = false;
        let mut fin_sent = false;
        let mut app_finished = false;
        let mut end_in = false;
        let mut end_delivered = false;
        let mut body_readable = false;
        let mut headers = false;
        let mut response_pending = false;
        let mut can_send = !self.server;
        let inbound = self.app.inbound.clone();
        loop {
            loop {
                let (stream, event) = match self.h3.poll(&mut self.conn) {
                    Ok(event) => event,
                    Err(h3::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                };
                if matches!(event, h3::Event::GoAway) {
                    // RFC 9114 section 5.2: server IDs at/below our sole request
                    // reject it. A higher ID lets stream 0 finish; client IDs
                    // refer only to pushes, which this carrier never creates.
                    ensure!(
                        self.server || stream > 0,
                        "server rejected H3 request with GOAWAY"
                    );
                    continue;
                }
                ensure!(stream == 0, "unexpected H3 stream");
                match event {
                    h3::Event::Headers { list, .. } => {
                        ensure!(!headers, "unexpected extra H3 headers");
                        let value =
                            |name: &[u8]| list.iter().find(|h| h.name() == name).map(|h| h.value());
                        if self.server {
                            ensure!(
                                value(b":method") == Some(b"POST".as_slice())
                                    && value(b":path") == Some(self.path.as_bytes()),
                                "unknown H3 request"
                            );
                            response_pending = true;
                        } else {
                            ensure!(
                                value(b":status") == Some(b"200".as_slice()),
                                "H3 request rejected"
                            );
                        }
                        headers = true;
                    }
                    h3::Event::PriorityUpdate => {
                        ensure!(self.server, "unexpected server priority update");
                        // There is only one request to schedule. Consume the hint
                        // without treating it as a Maverick frame or authorization.
                        self.h3.take_last_priority_update(stream)?;
                    }
                    h3::Event::Data => body_readable = true,
                    h3::Event::Finished => end_in = true,
                    h3::Event::Reset(_) => return Ok(()),
                    _ => bail!("unexpected H3 event"),
                }
            }
            if response_pending {
                match self.h3.send_response(
                    &mut self.conn,
                    0,
                    &[Header::new(b":status", b"200")],
                    false,
                ) {
                    Ok(()) => {
                        response_pending = false;
                        can_send = true;
                    }
                    Err(h3::Error::StreamBlocked | h3::Error::Done) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if can_send && !wire_out.is_empty() {
                match self.h3.send_body(&mut self.conn, 0, &wire_out, end_out) {
                    Ok(written) => {
                        wire_out.advance(written);
                        if wire_out.is_empty() && end_out {
                            fin_sent = true;
                            self.app.outbound.close();
                        }
                    }
                    Err(h3::Error::Done | h3::Error::StreamBlocked) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if pending_in.is_none() && !end_delivered {
                if let Some(frame) = Frame::decode_from(&mut wire_in, self.max_frame_size)? {
                    pending_in = Some(Some(frame));
                } else if headers && body_readable {
                    let mut buf = [0; 16 * 1024];
                    let capacity = buf
                        .len()
                        .min(self.max_frame_size + FRAME_HEADER_LEN - wire_in.len());
                    match self.h3.recv_body(&mut self.conn, 0, &mut buf[..capacity]) {
                        Ok(0) | Err(h3::Error::Done) => {
                            body_readable = false;
                            continue;
                        }
                        Ok(len) => {
                            wire_in.extend_from_slice(&buf[..len]);
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else if end_in {
                    ensure!(wire_in.is_empty(), "truncated Maverick frame");
                    pending_in = Some(None);
                }
            }
            // A peer close can arrive while application delivery is backpressured.
            // Drain complete buffered frames and the HTTP EOF before dropping them.
            if (self.conn.is_closed() || self.conn.is_draining())
                && pending_in.is_none()
                && !body_readable
            {
                ensure!(
                    wire_in.is_empty(),
                    "H3 transport closed with an incomplete frame"
                );
                return Ok(());
            }
            self.io.flush(&mut self.conn).await?;
            // quiche 0.30 collects an opened bidirectional stream only after its
            // receive FIN is consumed and all sent bytes are ACKed. Merely
            // stream_closed()/send_body(fin=true) does not establish delivery.
            // Put FIN on the final nonempty DATA write so its last byte and FIN
            // are acknowledged together, then use the public collected-state API.
            if fin_sent
                && app_finished
                && matches!(
                    self.conn.stream_capacity(0),
                    Err(quiche::Error::InvalidStreamState(0))
                )
            {
                let _ = self.conn.close(true, 0x100, b"");
                self.io.flush(&mut self.conn).await?;
                return Ok(());
            }
            let wait = self.conn.timeout().unwrap_or(Duration::from_secs(1));
            tokio::select! {
                _ = async {
                    match &mut stop {
                        Some(stop) => { let _ = stop.await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let _ = self.conn.close(true, 0x100, b"");
                    self.io.flush(&mut self.conn).await?;
                    return Ok(());
                }
                _ = inbound.closed(), if fin_sent && !app_finished => app_finished = true,
                received = self.io.recv() => {
                    self.io.receive(&mut self.conn, &mut received?)?;
                    self.io.receive_ready(&mut self.conn)?;
                }
                _ = tokio::time::sleep(wait) => self.conn.on_timeout(),
                frame = self.app.outbound.recv(), if wire_out.is_empty() && !end_out => {
                    match frame {
                        Some((frame, end)) => { wire_out = frame.encode(self.max_frame_size)?; end_out = end; }
                        None => {
                            let _ = self.conn.close(true, 0x10c, b"");
                            self.io.flush(&mut self.conn).await?;
                            return Ok(());
                        }
                    }
                }
                permit = inbound.reserve(), if pending_in.is_some() => {
                    match permit {
                        Ok(permit) => {
                            let frame = pending_in.take().expect("pending frame");
                            end_delivered = frame.is_none();
                            permit.send(Ok(frame));
                        }
                        Err(_) => { pending_in = None; end_delivered = true; }
                    }
                }
            }
        }
    }
}
