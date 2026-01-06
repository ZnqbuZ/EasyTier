use crate::gateway::quic::QuicBufferMargins;
use bytes::BytesMut;
use std::net::SocketAddr;
use derive_more::Constructor;

#[derive(Debug, Constructor)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = QuicBufferMargins;
