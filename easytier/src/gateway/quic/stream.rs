use crate::gateway::quic::cmd::{QuicCmd, QuicCmdTx};
use crate::gateway::quic::evt::{QuicStreamEvt, QuicStreamEvtRx};
use crate::gateway::quic::QuicBufferPool;
use bytes::{Bytes, BytesMut};
use futures::SinkExt;
use quinn_proto::{ConnectionHandle, StreamId};
use std::cmp::min;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::PollSender;

macro_rules! check_tx {
    ($e:expr) => {
        $e.map_err(|e| {
            Error::new(
                ErrorKind::BrokenPipe,
                format!("Failed to send command to quic driver: {:?}", e),
            )
        })
    };
}

macro_rules! ready_tx {
    ($e:expr) => {
        check_tx!(ready!($e))
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicStreamHandle {
    pub(super) conn_handle: ConnectionHandle,
    pub(super) stream_id: StreamId,
}

impl From<(ConnectionHandle, StreamId)> for QuicStreamHandle {
    #[inline]
    fn from((conn_handle, stream_id): (ConnectionHandle, StreamId)) -> Self {
        Self {
            conn_handle,
            stream_id,
        }
    }
}

impl From<QuicStreamHandle> for (ConnectionHandle, StreamId) {
    #[inline]
    fn from(stream_handle: QuicStreamHandle) -> Self {
        (stream_handle.conn_handle, stream_handle.stream_id)
    }
}

#[derive(Debug)]
pub struct QuicStream {
    stream_handle: QuicStreamHandle,

    evt_rx: QuicStreamEvtRx,
    cmd_tx: PollSender<QuicCmd>,

    read_pending: Option<Bytes>,
    write_pool: QuicBufferPool,

    shutdown: bool,
}

impl QuicStream {
    pub fn handle(&self) -> QuicStreamHandle {
        self.stream_handle
    }
}

impl QuicStream {
    pub(super) fn new(
        stream_handle: QuicStreamHandle,
        evt_rx: QuicStreamEvtRx,
        cmd_tx: QuicCmdTx,
    ) -> Self {
        Self {
            stream_handle,
            evt_rx,
            cmd_tx: PollSender::new(cmd_tx),
            read_pending: None,
            write_pool: QuicBufferPool::new(8192),
            shutdown: false,
        }
    }

    pub async fn reset(&mut self, error_code: u32) -> Result<(), Error> {
        check_tx!(
            self.cmd_tx
            .send(QuicCmd::ResetStream {
                stream_handle: self.stream_handle,
                error_code,
            })
            .await
        )
    }
}

impl QuicStream {
    pub fn put_back(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }

        self.read_pending = match self.read_pending.take() {
            Some(pending) => {
                let mut new_pending = BytesMut::with_capacity(data.len() + pending.len());
                new_pending.extend_from_slice(&data);
                new_pending.extend_from_slice(&pending);
                Some(new_pending.freeze())
            }
            None => Some(data),
        };
    }
}

impl QuicStream {
    fn new_write_cmd(&self, data: Bytes, fin: bool) -> QuicCmd {
        QuicCmd::StreamWrite {
            stream_handle: self.stream_handle,
            data,
            fin,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut written: bool = false;

        loop {
            if let Some(mut pending) = self.read_pending.take() {
                let len = min(pending.len(), buf.remaining());
                buf.put_slice(&pending.split_to(len));
                written = true;
                if !pending.is_empty() {
                    self.read_pending = Some(pending);
                    return Poll::Ready(Ok(()));
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            match self.evt_rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => match event {
                    QuicStreamEvt::Data(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.read_pending = Some(data);
                    }
                    QuicStreamEvt::Fin => return Poll::Ready(Ok(())),
                    QuicStreamEvt::Reset(e) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, e)))
                    }
                },
                Poll::Pending if !written => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx))?;
        let data = self.write_pool.buf(buf, (0, 0).into()).freeze();
        let cmd = self.new_write_cmd(data, false);
        check_tx!(self.cmd_tx.start_send_unpin(cmd))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx)).into()
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }

        ready_tx!(self.cmd_tx.poll_flush_unpin(cx))?;
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx))?;
        let cmd = self.new_write_cmd(Bytes::new(), true);
        check_tx!(self.cmd_tx.start_send_unpin(cmd))?;
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx))?;
        
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}
