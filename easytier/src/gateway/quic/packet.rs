use crate::gateway::quic::QuicBufferMargins;
use bytes::BytesMut;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = QuicBufferMargins;
