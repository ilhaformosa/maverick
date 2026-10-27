//! One locally controlled QUIC connection per TCP tunnel. No public listener
//! or automatic transport selection is installed by this experiment.

use anyhow::{bail, ensure, Result};
use bytes::{Buf, Bytes, BytesMut};
use maverick_core::auth::TlsChannelBinding;
use maverick_core::frame::{Frame, FRAME_HEADER_LEN};
use maverick_core::h3_channel::{self, FrameChannel, TransportChannel};
use quiche::h3::{self, Header, NameValue};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::{loopback, tls};

pub struct LocalConnection {
    pub client: FrameChannel,
    pub server: FrameChannel,
    pub client_binding: TlsChannelBinding,
    pub server_binding: TlsChannelBinding,
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub transport: Transport,
}

pub struct Transport {
    stops: Vec<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<Result<()>>>,
    fixture: Option<TempDir>,
}

impl Transport {
    pub async fn shutdown(mut self) -> Result<()> {
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        let mut result = Ok(());
        for task in self.tasks.drain(..) {
            let joined = task.await.map_err(anyhow::Error::from).and_then(|r| r);
            if result.is_ok() {
                result = joined;
            }
        }
        if let Some(fixture) = self.fixture.take() {
            fixture.close()?;
        }
        result
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Synthetic peer behavior for the isolated local test package.
#[derive(Clone, Copy, Debug, Default)]
pub enum PeerInput {
    #[default]
    None,
    ServerGoAway(u64),
    ClientPriority,
    ClientPushControls,
    ServerPushPromise,
}

pub async fn connect(path: &str, max_frame_size: usize) -> Result<LocalConnection> {
    connect_with_peer_input(path, max_frame_size, PeerInput::None).await
}

pub async fn connect_with_server_goaway(
    path: &str,
    max_frame_size: usize,
    id: u64,
) -> Result<LocalConnection> {
    connect_with_peer_input(path, max_frame_size, PeerInput::ServerGoAway(id)).await
}

pub async fn connect_with_peer_input(
    path: &str,
    max_frame_size: usize,
    peer_input: PeerInput,
) -> Result<LocalConnection> {
    let (mut pair, client_binding, server_binding) = tokio::task::spawn_blocking(|| {
        let mut pair = tls::pair(tls::Peer::Valid)?;
        pair.handshake()?;
        let client_binding = tls::binding(&mut pair.client.conn)?;
        let server_binding = tls::binding(&mut pair.server.conn)?;
        Ok::<_, anyhow::Error>((pair, client_binding, server_binding))
    })
    .await??;
    let mut config = h3::Config::new()?;
    config.set_max_field_section_size(4096);
    let mut client_h3 = h3::Connection::with_transport(&mut pair.client.conn, &config)?;
    let mut server_h3 = h3::Connection::with_transport(&mut pair.server.conn, &config)?;
    if let PeerInput::ServerGoAway(id) = peer_input {
        server_h3.send_goaway(&mut pair.server.conn, id)?;
    }
    let stream = client_h3.send_request(
        &mut pair.client.conn,
        &[
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"content-type", b"application/octet-stream"),
        ],
        false,
    )?;
    ensure!(stream == 0, "unexpected first H3 stream");
    match peer_input {
        PeerInput::ClientPriority => client_h3.send_priority_update_for_request(
            &mut pair.client.conn,
            0,
            &h3::Priority::new(3, true),
        )?,
        PeerInput::ClientPushControls => {
            // MAX_PUSH_ID(1), CANCEL_PUSH(1), push-form PRIORITY_UPDATE(3, u=3).
            let frames = [
                0x0d, 1, 1, 0x03, 1, 1, 0x80, 0x0f, 0x07, 1, 4, 3, b'u', b'=', b'3',
            ];
            ensure!(
                pair.client.conn.stream_send(2, &frames, false)? == frames.len(),
                "partial synthetic control write"
            );
        }
        PeerInput::ServerPushPromise => {
            // QUIC must first see request stream 0 before the server can write it.
            pair = tokio::task::spawn_blocking(move || {
                while !pair.server.conn.stream_readable(0) {
                    pair.advance()?;
                }
                // PUSH_PROMISE(1), QPACK prefix and static :method GET.
                let frame = [5, 4, 1, 0, 0, 0xd1];
                ensure!(
                    pair.server.conn.stream_send(0, &frame, false)? == frame.len(),
                    "partial synthetic promise write"
                );
                Ok::<_, anyhow::Error>(pair)
            })
            .await??;
        }
        _ => {}
    }
    let (client, server, fixture) = pair.into_parts();
    let client_addr = client.address;
    let server_addr = server.address;
    let cert_path = fixture.path().join("cert.pem");
    let key_path = fixture.path().join("key.pem");
    let (client, client_transport) = endpoint(client, client_h3, false, path, max_frame_size)?;
    let (server, server_transport) = endpoint(server, server_h3, true, path, max_frame_size)?;
    Ok(LocalConnection {
        client,
        server,
        client_binding,
        server_binding,
        client_addr,
        server_addr,
        cert_path,
        key_path,
        transport: Transport {
            stops: vec![client_transport.0, server_transport.0],
            tasks: vec![client_transport.1, server_transport.1],
            fixture: Some(fixture),
        },
    })
}

type RunningEndpoint = (oneshot::Sender<()>, JoinHandle<Result<()>>);

fn endpoint(
    endpoint: loopback::Endpoint,
    h3: h3::Connection,
    server: bool,
    path: &str,
    max_frame_size: usize,
) -> Result<(FrameChannel, RunningEndpoint)> {
    let socket = UdpSocket::from_std(endpoint.socket)?;
    let (channel, transport) = h3_channel::channel();
    let (stop, stopped) = oneshot::channel();
    let driver = Driver {
        conn: endpoint.conn,
        socket,
        local: endpoint.address,
        peer: endpoint.peer,
        h3,
        app: transport,
        server,
        path: path.to_owned(),
        max_frame_size,
    };
    Ok((channel, (stop, tokio::spawn(driver.run(stopped)))))
}

struct Driver {
    conn: quiche::Connection,
    socket: UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    h3: h3::Connection,
    app: TransportChannel,
    server: bool,
    path: String,
    max_frame_size: usize,
}

impl Driver {
    async fn flush(&mut self) -> Result<()> {
        let mut packet = [0; 1350];
        loop {
            match self.conn.send(&mut packet) {
                Ok((len, info)) => {
                    ensure!(info.to == self.peer, "unexpected QUIC peer");
                    self.socket.send_to(&packet[..len], info.to).await?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn run(mut self, mut stop: oneshot::Receiver<()>) -> Result<()> {
        let mut packet = [0; 1351];
        let mut wire_in = BytesMut::new();
        let mut pending_in = None;
        let mut wire_out = Bytes::new();
        let mut end_out = false;
        let mut fin_sent = false;
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
            if self.conn.is_closed() || self.conn.is_draining() {
                return Ok(());
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
                match self.h3.send_body(&mut self.conn, 0, &wire_out, false) {
                    Ok(written) => wire_out.advance(written),
                    Err(h3::Error::Done | h3::Error::StreamBlocked) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if can_send && wire_out.is_empty() && end_out && !fin_sent {
                match self.h3.send_body(&mut self.conn, 0, &[], true) {
                    Ok(_) => {
                        fin_sent = true;
                        self.app.outbound.close();
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
            self.flush().await?;
            let wait = self.conn.timeout().unwrap_or(Duration::from_secs(1));
            tokio::select! {
                _ = &mut stop => {
                    let _ = self.conn.close(true, 0x100, b"");
                    self.flush().await?;
                    return Ok(());
                }
                read = self.socket.recv_from(&mut packet) => {
                    let (len, peer) = read?;
                    ensure!(peer == self.peer && len <= 1350, "unexpected UDP packet");
                    match self.conn.recv(&mut packet[..len], quiche::RecvInfo { from: peer, to: self.local }) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                _ = tokio::time::sleep(wait) => self.conn.on_timeout(),
                frame = self.app.outbound.recv(), if wire_out.is_empty() && !end_out => {
                    match frame {
                        Some((frame, end)) => { wire_out = frame.encode(self.max_frame_size)?; end_out = end; }
                        None => {
                            let _ = self.conn.close(true, 0x10c, b"");
                            self.flush().await?;
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
