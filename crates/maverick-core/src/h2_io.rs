//! Bounded byte-stream view of one HTTP/2 request/response body.
//! Used only beneath the origin-authenticated inner TLS connection.

use bytes::{Buf, Bytes};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const CONTENT_TYPE: &str = "application/octet-stream";

pub struct H2Io {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    pending: Bytes,
    ended: bool,
}

impl H2Io {
    pub fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            pending: Bytes::new(),
            ended: false,
        }
    }
}

impl AsyncRead for H2Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while this.pending.is_empty() {
            match ready!(this.recv.poll_data(cx)) {
                Some(Ok(bytes)) => this.pending = bytes,
                Some(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
                None => return Poll::Ready(Ok(())),
            }
        }
        let count = output.remaining().min(this.pending.len());
        output.put_slice(&this.pending[..count]);
        this.pending.advance(count);
        this.recv
            .flow_control()
            .release_capacity(count)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = bytes.len().min(16 * 1024);
        this.send.reserve_capacity(wanted);
        while this.send.capacity() == 0 {
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let count = wanted.min(this.send.capacity());
        this.send
            .send_data(Bytes::copy_from_slice(&bytes[..count]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // send_data queues bounded bytes for the independently polled H2 driver.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.ended {
            this.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            this.ended = true;
        }
        Poll::Ready(Ok(()))
    }
}
