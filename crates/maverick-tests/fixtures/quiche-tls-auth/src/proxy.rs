//! One locally controlled QUIC connection per TCP tunnel. No public listener
//! or automatic transport selection is installed by this experiment.

use anyhow::{ensure, Result};
use maverick_core::auth::TlsChannelBinding;
use maverick_core::h3_channel::FrameChannel;
use quiche::h3::{self, Header};
use std::net::SocketAddr;
use std::path::PathBuf;
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
    maverick_quiche::spawn_established(maverick_quiche::EstablishedEndpoint {
        conn: endpoint.conn,
        socket: UdpSocket::from_std(endpoint.socket)?,
        h3,
        peer: endpoint.peer,
        server,
        path: path.to_owned(),
        max_frame_size,
    })
}
