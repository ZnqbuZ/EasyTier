use crate::gateway::quic::QuicBufferMargins;
use bytes::BytesMut;
use derive_more::Constructor;
use std::net::SocketAddr;

#[derive(Debug, Constructor)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = QuicBufferMargins;
