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

const QUIC_STREAM_FLUSH_THRESHOLD: usize = 1200;
const QUIC_STREAM_WRITE_BUFFER_CAPACITY: usize = 2 * QUIC_STREAM_FLUSH_THRESHOLD;

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

    ready: bool,

    read_pending: Option<Bytes>,
    write_buf: BytesMut,

    fin_sent: bool,
    fin_received: bool,
}

impl QuicStream {
    #[inline]
    pub fn handle(&self) -> QuicStreamHandle {
        self.stream_handle
    }
}

impl QuicStream {
    pub(super) fn new(
        stream_handle: QuicStreamHandle,
        evt_rx: QuicStreamEvtRx,
        cmd_tx: QuicCmdTx,
        ready: bool,
    ) -> Self {
        Self {
            stream_handle,
            evt_rx,
            cmd_tx: PollSender::new(cmd_tx),
            ready,
            read_pending: None,
            write_buf: BytesMut::with_capacity(QUIC_STREAM_WRITE_BUFFER_CAPACITY),
            fin_sent: false,
            fin_received: false,
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

    pub async fn ready(&mut self) -> Result<(), Error> {
        if self.ready {
            return Ok(());
        }

        let evt = self.evt_rx.recv().await.ok_or_else(|| {
            Error::new(
                ErrorKind::UnexpectedEof,
                "Quic stream event channel closed before ready",
            )
        })?;

        match evt {
            QuicStreamEvt::Ready => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unexpected event {:?} before ready", evt),
                ))
            }
        }

        self.ready = true;
        Ok(())
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

            if self.fin_received {
                return Poll::Ready(Ok(()));
            }

            match self.evt_rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => match event {
                    QuicStreamEvt::Data(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.read_pending = Some(data);
                    }
                    QuicStreamEvt::Fin => self.fin_received = true,
                    QuicStreamEvt::Reset(e) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, e)))
                    }
                    _ => continue,
                },
                Poll::Pending if !written => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl QuicStream {
    #[inline]
    fn send_write_cmd(mut self: Pin<&mut Self>, data: Bytes, fin: bool) -> Result<(), Error> {
        let cmd = QuicCmd::StreamWrite {
            stream_handle: self.stream_handle,
            data,
            fin,
        };
        check_tx!(self.cmd_tx.start_send_unpin(cmd))
    }

    #[inline]
    fn send_write_buf(mut self: Pin<&mut Self>) -> Result<(), Error> {
        let data = self.write_buf.split().freeze();
        self.write_buf.reserve(QUIC_STREAM_WRITE_BUFFER_CAPACITY);
        self.send_write_cmd(data, false)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx))?;
        self.write_buf.extend_from_slice(buf);
        if self.write_buf.len() >= QUIC_STREAM_FLUSH_THRESHOLD {
            self.as_mut().send_write_buf()?;
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if !self.write_buf.is_empty() {
            ready_tx!(self.cmd_tx.poll_ready_unpin(cx))?;
            self.as_mut().send_write_buf()?;
        }
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx))?;

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.fin_sent {
            return Poll::Ready(Ok(()));
        }

        ready!(self.as_mut().poll_flush(cx))?;
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx))?;
        self.as_mut().send_write_cmd(Bytes::new(), true)?;
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx))?;

        self.fin_sent = true;

        Poll::Ready(Ok(()))
    }
}
