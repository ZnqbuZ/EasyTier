use crate::gateway::quic::cmd::{QuicCmd, QuicCmdTx};
use crate::gateway::quic::evt::{QuicStreamEvt, QuicStreamEvtRx};
use async_stream::stream;
use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use derive_more::{From, Into};
use futures::{SinkExt, Stream};
use quinn_proto::{ConnectionHandle, StreamId};
use std::fmt::Debug;
use std::io::{Error, ErrorKind};
use std::mem::replace;
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::StreamReader;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, From, Into)]
pub struct QuicStreamHandle {
    pub(super) conn_handle: ConnectionHandle,
    pub(super) stream_id: StreamId,
}

type BoxedQuicStream = Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send + Sync>>;
type QuicStreamReader = StreamReader<BoxedQuicStream, Bytes>;

#[derive(From)]
enum QuicStreamReady {
    Yes(QuicStreamReader),
    No(QuicStreamEvtRx),
    None,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct QuicStream {
    stream_handle: QuicStreamHandle,
    #[derivative(Debug = "ignore")]
    stream_reader: QuicStreamReady,

    cmd_tx: PollSender<QuicCmd>,

    write_buf: BytesMut,

    fin_sent: bool,
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
        let stream_reader = if ready {
            Self::build_reader(evt_rx).into()
        } else {
            evt_rx.into()
        };

        Self {
            stream_handle,
            stream_reader,
            cmd_tx: PollSender::new(cmd_tx),
            write_buf: BytesMut::with_capacity(QUIC_STREAM_WRITE_BUFFER_CAPACITY),
            fin_sent: false,
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
        if let QuicStreamReady::Yes(_) = self.stream_reader {
            return Ok(());
        }
        if let QuicStreamReady::None = self.stream_reader {
            return Err(Error::other("Stream is in invalid state"));
        }

        match replace(&mut self.stream_reader, QuicStreamReady::None) {
            QuicStreamReady::No(mut evt_rx) => {
                let evt = evt_rx.recv().await.ok_or_else(|| {
                    Error::new(
                        ErrorKind::UnexpectedEof,
                        "Quic stream event channel closed before ready",
                    )
                })?;

                match evt {
                    QuicStreamEvt::Ready => {
                        self.stream_reader = QuicStreamReady::Yes(Self::build_reader(evt_rx));
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Unexpected event {:?} before ready", evt),
                        ));
                    }
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl QuicStream {
    fn build_reader(mut evt_rx: QuicStreamEvtRx) -> QuicStreamReader {
        let stream = stream! {
            while let Some(evt) = evt_rx.recv().await {match evt {
                    QuicStreamEvt::Data(data) => {
                        if !data.is_empty() {
                            yield Ok(data);
                        }
                    }
                    QuicStreamEvt::Fin => {
                        return;
                    }
                    QuicStreamEvt::Reset(e) => {
                        yield Err(Error::new(ErrorKind::ConnectionReset, e));
                        return;
                    }
                    _ => continue,
                }
            }
        };

        StreamReader::new(Box::pin(stream) as BoxedQuicStream)
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if let QuicStreamReady::Yes(stream_reader) = &mut self.get_mut().stream_reader {
            Pin::new(stream_reader).poll_read(cx, buf)
        } else {
            Err(Error::other("Stream is not ready. Did you call ready()?")).into()
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
