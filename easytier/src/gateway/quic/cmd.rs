use crate::gateway::quic::evt::QuicStreamEvtReceiver;
use anyhow::Error;
use bytes::{Bytes, BytesMut};
use quinn_proto::{ConnectionHandle, StreamId};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub data: BytesMut,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct QuicStreamInfo {
    pub(super) conn_handle: ConnectionHandle,
    pub(super) stream_id: StreamId,
}

#[derive(Debug)]
pub(super) enum QuicCmd {
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

pub(super) type QuicCmdSender = mpsc::Sender<QuicCmd>;
pub(super) type QuicCmdReceiver = mpsc::Receiver<QuicCmd>;
