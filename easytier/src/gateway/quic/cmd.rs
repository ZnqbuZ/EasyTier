use crate::gateway::quic::packet::QuicPacket;
use crate::gateway::quic::stream::QuicStreamHdl;
use crate::gateway::quic::QuicStreamCtx;
use anyhow::Error;
use bytes::Bytes;
use quinn_proto::ConnectionHandle;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

// TODO: add more commands
#[derive(Debug)]
pub(super) enum QuicCmd {
    // Net
    InputPacket(QuicPacket),
    // Connection
    OpenBiStream {
        addr: SocketAddr,
        data: Option<Bytes>,
        stream_tx: oneshot::Sender<Result<QuicStreamCtx, Error>>,
    },
    CloseConnection {
        conn_hdl: ConnectionHandle,
        error_code: u32,
        reason: Bytes,
    },
    // Stream
    StreamWrite {
        stream_hdl: QuicStreamHdl,
        data: Bytes,
        fin: bool,
    },
    StopStream {
        stream_hdl: QuicStreamHdl,
        error_code: u32,
    },
    ResetStream {
        stream_hdl: QuicStreamHdl,
        error_code: u32,
    },
}

pub(super) type QuicCmdTx = mpsc::Sender<QuicCmd>;
pub(super) type QuicCmdRx = mpsc::Receiver<QuicCmd>;
