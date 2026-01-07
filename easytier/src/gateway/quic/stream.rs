use crate::gateway::quic::cmd::{QuicCmd, QuicCmdTx};
use crate::gateway::quic::evt::{QuicStreamEvt, QuicStreamEvtRx};
use bytes::{Bytes, BytesMut};
use derive_more::{From, Into};
use futures::SinkExt;
use quinn_proto::{ConnectionHandle, StreamId};
use std::cmp::min;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::task::ready;
use std::task::{Context, Poll};
use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::PollSender;

const QUIC_STREAM_WRITE_BUFFER_FLUSH_THRESHOLD: usize = 1200;
const QUIC_STREAM_WRITE_BUFFER_RESERVE_THRESHOLD: usize =
    2 * QUIC_STREAM_WRITE_BUFFER_FLUSH_THRESHOLD;
const QUIC_STREAM_WRITE_BUFFER_CAPACITY: usize = 64 * QUIC_STREAM_WRITE_BUFFER_FLUSH_THRESHOLD;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, From, Into)]
pub struct QuicStreamHdl {
    pub(super) conn_hdl: ConnectionHandle,
    pub(super) stream_id: StreamId,
}

#[derive(Debug)]
pub(super) struct QuicStreamFlowCtrl {
    blocked: AtomicBool,
    waker: AtomicWaker,
}

impl QuicStreamFlowCtrl {
    pub fn new() -> Self {
        Self {
            blocked: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }
}

#[derive(Debug, From, Into)]
pub(super) struct QuicStreamCtx {
    pub(super) hdl: QuicStreamHdl,
    pub(super) rx: QuicStreamEvtRx,
    pub(super) ctrl: Arc<QuicStreamFlowCtrl>,
}

#[derive(Debug)]
pub struct QuicStream {
    ctx: QuicStreamCtx,
    
    cmd_tx: PollSender<QuicCmd>,

    ready: bool,

    read_pending: Option<Bytes>,
    write_buf: BytesMut,

    fin_sent: bool,
    fin_received: bool,
}

impl QuicStream {
    #[inline]
    pub fn handle(&self) -> QuicStreamHdl {
        self.ctx.hdl
    }
}

impl QuicStream {
    pub(super) fn new(
        ctx: QuicStreamCtx,
        cmd_tx: QuicCmdTx,
        ready: bool,
    ) -> Self {
        Self {
            ctx,
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
                    stream_hdl: self.ctx.hdl,
                    error_code,
                })
                .await
        )
    }

    pub async fn ready(&mut self) -> Result<(), Error> {
        if self.ready {
            return Ok(());
        }

        let evt = self.ctx.rx.recv().await.ok_or_else(|| {
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

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut written: bool = false;

        loop {
            let mut chunk = if let Some(pending) = self.read_pending.take() {
                pending
            } else {
                if self.fin_received {
                    return Poll::Ready(Ok(()));
                }

                loop {
                    match self.ctx.rx.poll_recv(cx) {
                        Poll::Ready(Some(QuicStreamEvt::Fin)) | Poll::Ready(None) => {
                            self.fin_received = true;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Some(event)) => match event {
                            QuicStreamEvt::Data(data) => {
                                if data.is_empty() {
                                    continue;
                                }
                                break data;
                            }
                            QuicStreamEvt::Reset(e) => {
                                return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, e)));
                            }
                            _ => continue,
                        },
                        Poll::Pending if !written => return Poll::Pending,
                        _ => return Poll::Ready(Ok(())),
                    }
                }
            };

            let len = min(chunk.len(), buf.remaining());
            buf.put_slice(&chunk.split_to(len));
            written = true;
            if !chunk.is_empty() {
                self.read_pending = Some(chunk);
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl QuicStream {
    #[inline]
    fn send_write_cmd(mut self: Pin<&mut Self>, data: Bytes, fin: bool) -> Result<(), Error> {
        let cmd = QuicCmd::StreamWrite {
            stream_hdl: self.ctx.hdl,
            data,
            fin,
        };
        check_tx!(self.cmd_tx.start_send_unpin(cmd))
    }

    #[inline]
    fn send_write_buf(mut self: Pin<&mut Self>) -> Result<(), Error> {
        let data = self.write_buf.split().freeze();
        if self.write_buf.capacity() < QUIC_STREAM_WRITE_BUFFER_RESERVE_THRESHOLD {
            self.write_buf.reserve(QUIC_STREAM_WRITE_BUFFER_CAPACITY);
        }
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
