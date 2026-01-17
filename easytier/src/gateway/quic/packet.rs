use std::net::SocketAddr;
use bytes::BytesMut;
use derive_more::{Constructor, Deref, DerefMut};
use quinn_proto::Transmit;
use tokio::sync::mpsc;
use crate::gateway::quic::utils::{BufMargins, BufPool};

const PACKET_POOL_MIN_CAPACITY: usize = 65536;

#[derive(Debug, Constructor)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = BufMargins;

#[derive(Debug)]
pub(super) struct PacketPool(BufPool);

impl PacketPool {
    pub(super) fn new() -> Self {
        Self(BufPool::new(PACKET_POOL_MIN_CAPACITY))
    }

    pub(super) fn pack(&mut self, addr: SocketAddr, data: &[u8], margins: QuicPacketMargins) -> QuicPacket {
        QuicPacket {
            addr,
            payload: self.0.buf(data, margins),
        }
    }

    pub(super) fn pack_transmit(&mut self, transmit: Transmit, buf: &[u8], margins: QuicPacketMargins) -> QuicPacket {
        self.pack(transmit.destination, &buf[..transmit.size], margins)
    }
}

#[derive(Debug, Clone, Deref, DerefMut, Constructor)]
pub(super) struct QuicPacketTx {
    #[deref]
    #[deref_mut]
    packet: mpsc::Sender<QuicPacket>,
    pub(super) margins: QuicPacketMargins,
}

pub type QuicPacketRx = mpsc::Receiver<QuicPacket>;