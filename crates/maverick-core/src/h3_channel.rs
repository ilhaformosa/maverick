//! Bounded frame handoff for the opt-in H3 experiment. The transport owns
//! TLS, HTTP/3, byte framing, and stream completion; sessions own policy.

use crate::{Error, Frame, FrameType, Result};
use tokio::sync::mpsc;

pub type FrameSender = mpsc::Sender<(Frame, bool)>;
pub type FrameReceiver = mpsc::Receiver<Result<Option<Frame>>>;

pub struct FrameChannel {
    pub outbound: FrameSender,
    pub inbound: FrameReceiver,
}

pub struct TransportChannel {
    pub outbound: mpsc::Receiver<(Frame, bool)>,
    pub inbound: mpsc::Sender<Result<Option<Frame>>>,
}

pub fn channel() -> (FrameChannel, TransportChannel) {
    let (send, outbound) = mpsc::channel(1);
    let (inbound, recv) = mpsc::channel(1);
    (
        FrameChannel {
            outbound: send,
            inbound: recv,
        },
        TransportChannel { outbound, inbound },
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
