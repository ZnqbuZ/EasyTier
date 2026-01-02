use bytes::Bytes;
use tokio::sync::mpsc;
use crate::gateway::quic::cmd::QuicPacket;

#[derive(Debug)]
pub(super) enum QuicNetEvt {
    PacketOutgoing(QuicPacket),
}

pub type QuicNetEvtTx = mpsc::Sender<QuicNetEvt>;
pub type QuicNetEvtRx = mpsc::Receiver<QuicNetEvt>;

#[derive(Debug)]
pub(super) enum QuicStreamEvt {
    Data(Bytes),
    Fin,
    Reset(String),
}

pub type QuicStreamEvtTx = mpsc::Sender<QuicStreamEvt>;
pub type QuicStreamEvtRx = mpsc::Receiver<QuicStreamEvt>;
