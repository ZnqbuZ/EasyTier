use std::net::SocketAddr;
use bytes::BytesMut;
use derive_more::{Constructor, Deref, DerefMut};
use quinn_proto::Transmit;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{SendError, TrySendError};
use crate::gateway::quic::utils::{QuicBufferMargins, QuicBufferPool};

#[derive(Debug, Constructor)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = QuicBufferMargins;

#[derive(Deref, DerefMut, Debug)]
pub(super) struct QuicPacketTx {
    #[deref]
    #[deref_mut]
    tx: mpsc::Sender<QuicPacket>,
    pool: QuicBufferPool,
    margins: QuicPacketMargins,
}

impl QuicPacketTx {
    pub(super) fn new(tx: mpsc::Sender<QuicPacket>, margins: QuicPacketMargins) -> Self {
        Self {
            tx,
            pool: QuicBufferPool::new(margins.header + margins.trailer),
            margins,
        }
    }

    pub(super) fn pack(&mut self, addr: SocketAddr, data: &[u8]) -> QuicPacket {
        QuicPacket {
            addr,
            payload: self.pool.buf(data, self.margins),
        }
    }

    pub(super) fn pack_transmit(&mut self, transmit: Transmit, buf: &Vec<u8>) -> QuicPacket {
        self.pack(transmit.destination, &buf[..transmit.size])
    }

    pub(super) async fn send_transmit(
        &mut self,
        transmit: Transmit,
        buf: &Vec<u8>,
    ) -> Result<(), SendError<QuicPacket>> {
        let packet = self.pack_transmit(transmit, buf);
        self.send(packet).await
    }

    pub(super) fn try_send_transmit(
        &mut self,
        transmit: Transmit,
        buf: &Vec<u8>,
    ) -> std::result::Result<(), TrySendError<QuicPacket>> {
        let packet = self.pack_transmit(transmit, buf);
        self.try_send(packet)
    }
}

impl Clone for QuicPacketTx {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            pool: QuicBufferPool::new(self.pool.min_capacity),
            margins: self.margins.clone(),
        }
    }
}

pub type QuicPacketRx = mpsc::Receiver<QuicPacket>;