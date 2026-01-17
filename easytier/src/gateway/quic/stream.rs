use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use quinn_proto::{FinishError, ReadError, ReadableError, StreamId, WriteError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::trace;
use crate::gateway::quic::conn::{ConnCtrl, ConnState};
use crate::gateway::quic::utils::{BufPool, SwitchedReceiver, SwitchedSender};

pub(crate) type QuicStreamTx = SwitchedSender<QuicStream>;
pub type QuicStreamRx = SwitchedReceiver<QuicStream>;

#[derive(Debug)]
pub struct QuicStream {
    pub(crate) id: StreamId,
    ctrl: ConnCtrl,
    pool: BufPool,
}

impl QuicStream {
    pub(super) fn new(id: StreamId, ctrl: ConnCtrl) -> Self {
        Self {
            id,
            ctrl,
            pool: BufPool::new(2048),
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut data = Vec::new();
        let mut len = 0;
        let mut state = self.ctrl.state.lock();
        let ConnState {
            ref mut conn,
            ref mut readers,
            ..
        } = *state;
        let mut stream = conn.recv_stream(self.id);
        let mut chunks = match stream.read(true) {
            Ok(chunks) => chunks,
            Err(ReadableError::ClosedStream) => return Poll::Ready(Ok(())),
            Err(ReadableError::IllegalOrderedRead) => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::InvalidData,
                    "QUIC illegal ordered read",
                )));
            }
        };

        while len < buf.remaining() {
            let chunk = match chunks.next(buf.remaining() - len) {
                Ok(Some(chunk)) => chunk.bytes,
                Ok(None) => return Poll::Ready(Ok(())), // ChunksState::Finished 流关闭
                Err(ReadError::Blocked) => {
                    if len == 0 {
                        readers.insert(self.id, cx.waker().clone());
                        return Poll::Pending;
                    } else {
                        break;
                    }
                }
                Err(ReadError::Reset(err)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionReset,
                        format!("QUIC stream reset: {}", err),
                    )));
                }
            };
            len += chunk.len();
            data.push(chunk);
        }

        let transmit = chunks.finalize().should_transmit();

        drop(state);

        trace!("poll_read stream_id={} len={}", self.id, len);

        for data in data.drain(..) {
            buf.put_slice(&data);
        }
        if transmit {
            self.ctrl.notify.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        trace!("poll_write stream_id={} len={}", self.id, buf.len());
        let data = self.pool.buf(buf, (0, 0).into()).freeze();
        let mut state = self.ctrl.state.lock();
        let ConnState {
            ref mut conn,
            ref mut writers,
            ..
        } = *state;
        match conn.send_stream(self.id).write_chunks(&mut [data]) {
            Ok(written) => {
                drop(state);
                self.ctrl.notify.notify_one();
                Poll::Ready(Ok(written.bytes))
            }
            Err(WriteError::Blocked) => {
                writers.insert(self.id, cx.waker().clone());
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "QUIC stream closed or stopped by peer",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.ctrl.notify.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let finish = self.ctrl.state.lock().conn.send_stream(self.id).finish();
        match finish {
            Ok(()) => {
                self.ctrl.notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Err(FinishError::ClosedStream) => Poll::Ready(Ok(())),
            Err(FinishError::Stopped(error)) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                format!("QUIC stream has been stopped by peer: {:?}", error),
            ))),
        }
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        self.ctrl.close(self.id);
    }
}
