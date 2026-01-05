use crate::gateway::quic::evt::QuicStreamEvtRx;
use crate::gateway::quic::packet::QuicPacket;
use crate::gateway::quic::stream::QuicStreamHandle;
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
        stream_tx: oneshot::Sender<Result<(QuicStreamHandle, QuicStreamEvtRx), Error>>,
    },
    CloseConnection {
        conn_handle: ConnectionHandle,
        error_code: u32,
        reason: Bytes,
    },
    // Stream
    StreamWrite {
        stream_handle: QuicStreamHandle,
        data: Bytes,
        fin: bool,
    },
    StopStream {
        stream_handle: QuicStreamHandle,
        error_code: u32,
    },
    ResetStream {
        stream_handle: QuicStreamHandle,
        error_code: u32,
    },
}

pub(super) type QuicCmdTx = mpsc::Sender<QuicCmd>;
pub(super) type QuicCmdRx = mpsc::Receiver<QuicCmd>;
