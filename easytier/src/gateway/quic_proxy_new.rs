use bytes::Bytes;
use futures::{ready, SinkExt};
use quinn_plaintext::{client_config, server_config};
use quinn_proto::congestion::BbrConfig;
use quinn_proto::{ConnectionError, ConnectionHandle, Endpoint, EndpointConfig, StreamId, TransportConfig, VarInt};
use std::cmp::min;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

#[derive(Debug)]
pub enum QuicCmd {
    // From NIC
    PacketIncoming {
        src: SocketAddr,
        data: Bytes,
    },
    // From TCP proxy
    StreamWrite {
        conn_handle: ConnectionHandle,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
    CloseConnection {
        conn_handle: ConnectionHandle,
        error_code: u32,
        reason: Bytes,
    },
    Connect {
        dst: SocketAddr,
        tx: oneshot::Sender<Result<(ConnectionHandle, StreamId), anyhow::Error>>,
    },
}

#[derive(Debug)]
pub enum QuicEvt {
    Data(Bytes),
    Closed,
    Reset(ConnectionError),
}

pub struct QuicStream {
    conn_handle: ConnectionHandle,
    stream_id: StreamId,

    evt_rx: mpsc::Receiver<QuicEvt>,
    cmd_tx: PollSender<QuicCmd>,

    pending: Option<Bytes>,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        loop {
            if let Some(mut pending) = self.pending.take() {
                let len = min(pending.len(), buf.remaining());
                buf.put_slice(&pending.split_to(len));
                if !pending.is_empty() {
                    self.pending = Some(pending);
                }
                return Poll::Ready(Ok(()));
            }

            match self.evt_rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => match event {
                    QuicEvt::Data(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.pending = Some(data);
                    }
                    QuicEvt::Closed => return Poll::Ready(Ok(())),
                    QuicEvt::Reset(error) => {
                        return Poll::Ready(Err(Error::from(error)))
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

struct QuicActor {
    endpoint: Endpoint,
    cmd_rx: mpsc::Receiver<QuicCmd>,
}

impl QuicActor {
    pub fn new() -> Self {
        let mut server_config = server_config();
        server_config.transport = {
            let mut config = TransportConfig::default();

            config.stream_receive_window(VarInt::from_u32(10 * 1024 * 1024));
            config.receive_window(VarInt::from_u32(15 * 1024 * 1024));

            config.max_concurrent_bidi_streams(VarInt::from_u32(1024));
            config.max_concurrent_uni_streams(VarInt::from_u32(1024));

            config.congestion_controller_factory(Arc::new(BbrConfig::default()));

            config.keep_alive_interval(Some(Duration::from_secs(5)));
            config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

            Arc::new(config)
        };

        let endpoint_config = EndpointConfig::default();
    }
}
