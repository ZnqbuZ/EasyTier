use crate::gateway::quic::evt::QuicStreamEvtReceiver;
use anyhow::Error;
use bytes::Bytes;
use quinn_proto::{ConnectionHandle, StreamId};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy)]
pub struct QuicStreamInfo {
    pub conn_handle: ConnectionHandle,
    pub stream_id: StreamId,
}

#[derive(Debug)]
pub enum QuicCmd {
    // Net
    PacketIncoming(QuicPacket),
    // Connection
    OpenBiStream {
        addr: SocketAddr,
        stream_tx: oneshot::Sender<Result<(QuicStreamInfo, QuicStreamEvtReceiver), Error>>,
    },
    CloseConnection {
        conn_handle: ConnectionHandle,
        error_code: u32,
        reason: Bytes,
    },
    // Stream
    StreamWrite {
        stream_info: QuicStreamInfo,
        data: Bytes,
        fin: bool,
    },
    StopStream {
        stream_info: QuicStreamInfo,
        error_code: u32,
    },
    ResetStream {
        stream_info: QuicStreamInfo,
        error_code: u32,
    },
}

pub type QuicCmdSender = mpsc::Sender<QuicCmd>;
pub type QuicCmdReceiver = mpsc::Receiver<QuicCmd>;
