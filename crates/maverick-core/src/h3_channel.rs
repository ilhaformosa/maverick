//! Bounded frame handoff for the opt-in H3 experiment. The transport owns
//! TLS, HTTP/3, byte framing, and stream completion; sessions own policy.

use crate::{Error, Frame, FrameType, Result};
use bytes::Bytes;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{mpsc, watch};

pub const MAX_NATIVE_UDP_PAYLOAD: usize = 1200;
pub const DATAGRAM_QUEUE: usize = 64;

pub struct DatagramChannel {
    pub outbound: mpsc::Sender<Bytes>,
    pub inbound: mpsc::Receiver<Bytes>,
    pub available: watch::Receiver<Option<usize>>,
    enabled: Arc<AtomicBool>,
}

impl DatagramChannel {
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    pub async fn ready(&mut self) -> Result<usize> {
        loop {
            if let Some(size) = *self.available.borrow_and_update() {
                return Ok(size);
            }
            self.available
                .changed()
                .await
                .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe.into()))?;
        }
    }
}

pub struct DatagramTransport {
    pub outbound: mpsc::Receiver<Bytes>,
    pub inbound: mpsc::Sender<Bytes>,
    pub available: watch::Sender<Option<usize>>,
    pub enabled: Arc<AtomicBool>,
}

pub type FrameSender = mpsc::Sender<(Frame, bool)>;
pub type FrameReceiver = mpsc::Receiver<Result<Option<Frame>>>;

pub struct FrameChannel {
    pub outbound: FrameSender,
    pub inbound: FrameReceiver,
    pub datagrams: DatagramChannel,
}

pub struct TransportChannel {
    pub outbound: mpsc::Receiver<(Frame, bool)>,
    pub inbound: mpsc::Sender<Result<Option<Frame>>>,
    pub datagrams: DatagramTransport,
}

pub fn channel() -> (FrameChannel, TransportChannel) {
    let (send, outbound) = mpsc::channel(1);
    let (inbound, recv) = mpsc::channel(1);
    let (dgram_send, dgram_outbound) = mpsc::channel(DATAGRAM_QUEUE);
    let (dgram_inbound, dgram_recv) = mpsc::channel(DATAGRAM_QUEUE);
    let (available_tx, available_rx) = watch::channel(None);
    let enabled = Arc::new(AtomicBool::new(false));
    (
        FrameChannel {
            outbound: send,
            inbound: recv,
            datagrams: DatagramChannel {
                outbound: dgram_send,
                inbound: dgram_recv,
                available: available_rx,
                enabled: Arc::clone(&enabled),
            },
        },
        TransportChannel {
            outbound,
            inbound,
            datagrams: DatagramTransport {
                outbound: dgram_outbound,
                inbound: dgram_inbound,
                available: available_tx,
                enabled,
            },
        },
    )
}

impl FrameChannel {
    pub async fn send(&self, frame: Frame, end_stream: bool, max_frame_size: usize) -> Result<()> {
        send_frame(&self.outbound, frame, end_stream, max_frame_size).await
    }

    pub async fn read(&mut self, max_frame_size: usize) -> Result<Option<Frame>> {
        read_frame(&mut self.inbound, max_frame_size).await
    }
}

pub async fn send_frame(
    sender: &FrameSender,
    frame: Frame,
    end_stream: bool,
    max_frame_size: usize,
) -> Result<()> {
    if frame.payload.len() > max_frame_size {
        return Err(Error::FrameTooLarge {
            length: frame.payload.len(),
            max: max_frame_size,
        });
    }
    sender
        .send((frame, end_stream))
        .await
        .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe.into()))
}

pub async fn read_frame(
    receiver: &mut FrameReceiver,
    max_frame_size: usize,
) -> Result<Option<Frame>> {
    loop {
        let frame = receiver
            .recv()
            .await
            .ok_or_else(|| Error::Io(std::io::ErrorKind::UnexpectedEof.into()))??;
        let Some(frame) = frame else { return Ok(None) };
        if frame.payload.len() > max_frame_size {
            return Err(Error::FrameTooLarge {
                length: frame.payload.len(),
                max: max_frame_size,
            });
        }
        if frame.frame_type != FrameType::Padding {
            return Ok(Some(frame));
        }
    }
}
