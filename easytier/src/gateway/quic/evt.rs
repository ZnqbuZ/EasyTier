use bytes::Bytes;
use tokio::sync::mpsc;
use crate::gateway::quic::cmd::QuicPacket;

#[derive(Debug)]
pub(crate) enum QuicNetEvt {
    PacketOutgoing(QuicPacket),
}

pub type QuicNetEvtSender = mpsc::Sender<QuicNetEvt>;
pub type QuicNetEvtReceiver = mpsc::Receiver<QuicNetEvt>;

#[derive(Debug)]
pub(crate) enum QuicStreamEvt {
    Data(Bytes),
    Fin,
    Reset(String),
}

pub type QuicStreamEvtSender = mpsc::Sender<QuicStreamEvt>;
pub type QuicStreamEvtReceiver = mpsc::Receiver<QuicStreamEvt>;
