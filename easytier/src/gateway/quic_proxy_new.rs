use bytes::Bytes;
use futures::{ready, SinkExt};
use quinn_proto::{ConnectionHandle, StreamId};
use std::cmp::min;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

#[derive(Debug)]
pub enum QuicCmd {
    PacketReceived {
        src: SocketAddr,
        data: Bytes,
    },
    StreamWrite {
        conn_handle: ConnectionHandle,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
    CloseConnection {
        conn_handle: ConnectionHandle,
        error_code: u64,
    },
    Connect {
        dst: SocketAddr,
        tx: oneshot::Sender<Result<(ConnectionHandle, StreamId), anyhow::Error>>,
    },
}

#[derive(Debug)]
pub enum QuicEvent {
    Data(Bytes),
    Closed,
    Reset(anyhow::Error),
}

pub struct QuicStream {
    conn_handle: ConnectionHandle,
    stream_id: StreamId,

    event_rx: mpsc::Receiver<QuicEvent>,
    cmd_tx: PollSender<QuicCmd>,

    pending: Option<Bytes>,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(mut pending) = self.pending.take() {
                let len = min(pending.len(), buf.remaining());
                buf.put_slice(&pending.split_to(len));
                if !pending.is_empty() {
                    self.pending = Some(pending);
                }
                return Poll::Ready(Ok(()));
            }

            match self.event_rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => match event {
                    QuicEvent::Data(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.pending = Some(data);
                    }
                    QuicEvent::Closed => return Poll::Ready(Ok(())),
                    QuicEvent::Reset(e) => {
                        return Poll::Ready(Err(Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            e,
                        )))
                    }
                },
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

macro_rules! check_tx {
    ($e:expr) => {
        match $e {
            Ok(_) => Poll::Ready(Ok::<(), Error>(())),
            Err(_) => {
                return Poll::Ready(Err(Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "actor closed",
                )))
            }
        }
    };
}

macro_rules! ready_tx {
    ($e:expr) => {
        let _ = check_tx!(ready!($e));
    };
}

impl QuicStream {
    #[inline]
    fn mk_write_cmd(&self, data: Bytes, fin: bool) -> QuicCmd {
        QuicCmd::StreamWrite {
            conn_handle: self.conn_handle,
            stream_id: self.stream_id,
            data,
            fin,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx));
        let cmd = self.mk_write_cmd(Bytes::copy_from_slice(buf), false);
        let _ = check_tx!(self.cmd_tx.start_send_unpin(cmd));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx));
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx));
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx));
        let cmd = self.mk_write_cmd(Bytes::new(), true);
        check_tx!(self.cmd_tx.start_send_unpin(cmd))
    }
}
