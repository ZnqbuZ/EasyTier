use crate::common::acl_processor::PacketInfo;
use crate::common::global_ctx::GlobalCtx;
use crate::common::PeerId;
use crate::gateway::quic::{QuicController, QuicPacket, QuicPacketRx, QuicStream};
use crate::gateway::tcp_proxy::NatDstConnector;
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::peers::PeerPacketFilter;
use crate::proto::api::instance::TcpProxyEntryTransportType;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket};
use anyhow::{Context, Error};
use bytes::{Bytes, BytesMut};
use pnet::packet::ipv4::Ipv4Packet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::select;
use tokio::task::JoinSet;

#[derive(Debug)]
enum QuicProxyRole {
    Src,
    Dst,
}

impl QuicProxyRole {
    const fn incoming(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicDst,
            QuicProxyRole::Dst => PacketType::QuicSrc,
        }
    }
    const fn outgoing(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicSrc,
            QuicProxyRole::Dst => PacketType::QuicDst,
        }
    }
}

#[derive(Debug)]
struct QuicPacketMeta {
    peer_id: PeerId,
    packet_type: PacketType,
}

impl QuicPacketMeta {
    fn new(peer_id: PeerId, packet_type: PacketType) -> Self {
        Self {
            peer_id,
            packet_type,
        }
    }

    fn pack(self, data: BytesMut) -> QuicPacket {
        QuicPacket {
            addr: self.into(),
            data,
        }
    }

    fn unpack(packet: QuicPacket) -> Option<(Self, BytesMut)> {
        let packet_info = packet.addr.try_into().ok()?;
        Some((packet_info, packet.data))
    }
}

impl From<QuicPacketMeta> for SocketAddr {
    fn from(meta: QuicPacketMeta) -> Self {
        SocketAddr::new(IpAddr::V4(meta.peer_id.into()), meta.packet_type as u16)
    }
}

impl TryFrom<SocketAddr> for QuicPacketMeta {
    type Error = ();

    fn try_from(value: SocketAddr) -> Result<Self, Self::Error> {
        let IpAddr::V4(ipv4) = value.ip() else {
            return Err(());
        };
        let peer_id = ipv4.into();

        let packet_type = match value.port() {
            p if p == PacketType::QuicSrc as u16 => PacketType::QuicSrc,
            p if p == PacketType::QuicDst as u16 => PacketType::QuicDst,
            _ => return Err(()),
        };

        Ok(Self {
            peer_id,
            packet_type,
        })
    }
}

// Receive packets from peers and forward them to the QUIC endpoint
#[derive(Debug)]
struct QuicPacketReceiver {
    quic_ctrl: Arc<QuicController>,
    role: QuicProxyRole,
}

#[async_trait::async_trait]
impl PeerPacketFilter for QuicPacketReceiver {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header().unwrap();

        if header.packet_type != self.role.incoming() as u8 {
            return Some(packet);
        }

        let _ = self
            .quic_ctrl
            .send(
                QuicPacketMeta::new(header.from_peer_id.get().into(), self.role.outgoing())
                    .pack(packet.payload_bytes()),
            )
            .await;

        None
    }
}

// Receive packets from QUIC endpoint and forward them to peers
#[derive(Debug)]
struct QuicPacketSender {
    peer_mgr: Arc<PeerManager>,
    packet_rx: QuicPacketRx,
}

impl QuicPacketSender {
    #[tracing::instrument]
    pub async fn run(&mut self) {
        while let Some(packet) = self.packet_rx.recv().await {
            let (packet_info, payload) = QuicPacketMeta::unpack(packet).unwrap();

            let peer_id = packet_info.peer_id;
            let packet_type = packet_info.packet_type;

            let mut packet = ZCPacket::new_with_payload(&*payload.freeze());
            packet.fill_peer_manager_hdr(self.peer_mgr.my_peer_id(), peer_id, packet_type as u8);

            if let Err(e) = self.peer_mgr.send_msg_for_proxy(packet, peer_id).await {
                tracing::error!("failed to send QUIC packet to peer: {:?}", e);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatDstQuicConnector {
    pub(crate) quic_ctrl: Arc<QuicController>,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQuicConnector {
    type DstStream = QuicStream;

    async fn connect(
        &self,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> crate::common::error::Result<Self::DstStream> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let Some(dst_peer_id) = (match nat_dst {
            SocketAddr::V4(addr) => peer_mgr.get_peer_map().get_peer_id_by_ipv4(addr.ip()).await,
            SocketAddr::V6(_) => return Err(anyhow::anyhow!("ipv6 is not supported").into()),
        }) else {
            return Err(anyhow::anyhow!("no peer found for nat dst: {}", nat_dst).into());
        };

        tracing::trace!("kcp nat dst: {:?}, dst peers: {:?}", nat_dst, dst_peer_id);

        let mut connect_tasks: JoinSet<Result<QuicStream, Error>> = JoinSet::new();
        let mut retry_remain = 5;
        loop {
            select! {
                Some(Ok(Ok(stream))) = connect_tasks.join_next() => {
                    // just wait for the previous connection to finish
                    return Ok(stream);
                }
                _ = tokio::time::sleep(Duration::from_millis(200)), if !connect_tasks.is_empty() && retry_remain > 0 => {
                    // no successful connection yet, trigger another connection attempt
                }
                else => {
                    // got error in connect_tasks, continue to retry
                    if retry_remain == 0 && connect_tasks.is_empty() {
                        break;
                    }
                }
            }

            // create a new connection task
            if retry_remain == 0 {
                continue;
            }
            retry_remain -= 1;

            let quic_ctrl = self.quic_ctrl.clone();
            let my_peer_id = peer_mgr.my_peer_id();

            connect_tasks.spawn(async move {
                let mut stream = quic_ctrl
                    .connect(QuicPacketMeta::new(dst_peer_id, PacketType::QuicSrc).into())
                    .await
                    .with_context(|| format!("failed to connect to nat dst: {}", nat_dst))?;
                todo!();
                Ok(stream)
            });
        }

        Err(anyhow::anyhow!("failed to connect to nat dst: {}", nat_dst).into())
    }

    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool {
        true
    }

    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Packet,
        real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        todo!()
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        todo!()
    }
}
