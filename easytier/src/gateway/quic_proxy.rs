use crate::gateway::quic::{QuicController, QuicPacket};
use crate::peers::PeerPacketFilter;
use crate::tunnel::packet_def::{PacketType, ZCPacket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use crate::common::PeerId;

fn peer_id_to_socket_addr<T: Into<PeerId>>(peer_id: T) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(peer_id.into().into()), 0)
}

fn socket_addr_to_peer_id(addr: SocketAddr) -> Option<PeerId> {
    if let IpAddr::V4(ipv4) = addr.ip() {
        Some(ipv4.into())
    } else {
        None
    }
}

struct QuicEndpointFilter {
    quic_ctrl: Arc<QuicController>,
    is_src: bool,
}

#[async_trait::async_trait]
impl PeerPacketFilter for QuicEndpointFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header().unwrap();
        let t = header.packet_type;
        let peer_id;
        if t == PacketType::QuicSrc as u8 && !self.is_src {
            // src packet, but we are dst
            peer_id = header.to_peer_id.get();
        } else if t == PacketType::QuicDst as u8 && self.is_src {
            // dst packet, but we are src
            peer_id = header.from_peer_id.get();
        } else {
            return Some(packet);
        }

        let _ = self
            .quic_ctrl
            .send(QuicPacket {
                addr: peer_id_to_socket_addr(peer_id),
                data: packet.payload_bytes(),
            })
            .await;

        None
    }
}
