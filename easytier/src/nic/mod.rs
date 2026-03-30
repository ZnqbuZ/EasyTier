use crate::nic::controller::{Controller, NicController, PlatformController};
use crate::nic::creator::NicCreator;
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, log},
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{peer_manager::PeerManager, recv_packet_from_chan, PacketRecvChanReceiver},
    tunnel::{
        common::{reserve_buf, FramedWriter, TunnelWrapper, ZCPacketToBytes},
        packet_def::{ZCPacket, ZCPacketType, TAIL_RESERVED_SIZE},
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
    },
};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{SinkExt, StreamExt};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};
use tokio::sync::RwLock;
use tokio::{
    sync::{Mutex, Notify},
    task::JoinSet,
};
use ::tun::AbstractDevice;

mod controller;
pub mod creator;
mod route;
mod tun;

pub struct NicPeersForwarder {
    peer_mgr: Arc<PeerManager>,
    close_notifier: Arc<Notify>,

    stream: Pin<Box<dyn ZCPacketStream>>,
}

impl NicPeersForwarder {
    async fn forward_ipv4(peer_mgr: &PeerManager, ret: ZCPacket) {
        if let Some(ipv4) = Ipv4Packet::new(ret.payload()) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
                return;
            }
            let dst_ipv4 = ipv4.get_destination();
            let src_ipv4 = ipv4.get_source();
            let my_ipv4 = peer_mgr.get_global_ctx().get_ipv4().map(|x| x.address());
            tracing::trace!(
                ?ret,
                ?src_ipv4,
                ?dst_ipv4,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // Subnet A is proxied as 10.0.0.0/24, and Subnet B is also proxied as 10.0.0.0/24.
            //
            // Subnet A has received a route advertised by Subnet B. As a result, A can reach
            // the physical subnet 10.0.0.0/24 directly and has also added a virtual route for
            // the same subnet 10.0.0.0/24. However, the physical route has a higher priority
            // (lower metric) than the virtual one.
            //
            // When A sends a UDP packet to a non-existent IP within this subnet, the packet
            // cannot be delivered on the physical network and is instead routed to the virtual
            // network interface.
            //
            // The virtual interface receives the packet and forwards it to itself, which triggers
            // the subnet proxy logic. The subnet proxy then attempts to send another packet to
            // the same destination address, causing the same process to repeat and creating an
            // infinite loop. Therefore, we must avoid re-sending packets back to ourselves
            // when the subnet proxy itself is the originator of the packet.
            //
            // However, there is a special scenario to consider: when A acts as a gateway,
            // packets from devices behind A may be forwarded by the OS to the ET (e.g., an
            // eBPF or tunneling component), which happens to proxy the subnet. In this case,
            // the packet’s source IP is not A’s own IP, and we must allow such packets to be
            // sent to the virtual interface (i.e., "sent to ourselves") to maintain correct
            // forwarding behavior. Thus, loop prevention should only apply when the source IP
            // belongs to the local host.
            let send_ret = peer_mgr
                .send_msg_by_ip(ret, IpAddr::V4(dst_ipv4), Some(src_ipv4) == my_ipv4)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    async fn forward_ipv6(peer_mgr: &PeerManager, ret: ZCPacket) {
        if let Some(ipv6) = Ipv6Packet::new(ret.payload()) {
            if ipv6.get_version() != 6 {
                tracing::info!("[USER_PACKET] not ipv6 packet: {:?}", ipv6);
                return;
            }
            let src_ipv6 = ipv6.get_source();
            let dst_ipv6 = ipv6.get_destination();
            let my_ipv6 = peer_mgr.get_global_ctx().get_ipv6().map(|x| x.address());
            tracing::trace!(
                ?ret,
                ?src_ipv6,
                ?dst_ipv6,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            if src_ipv6.is_unicast_link_local() && Some(src_ipv6) != my_ipv6 {
                // do not route link local packet to other nodes unless the address is assigned by user
                return;
            }

            // TODO: use zero-copy
            let send_ret = peer_mgr
                .send_msg_by_ip(ret, IpAddr::V6(dst_ipv6), Some(src_ipv6) == my_ipv6)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv6 packet");
        }
    }

    async fn forward(peer_mgr: &PeerManager, ret: ZCPacket) {
        let payload = ret.payload();
        if payload.is_empty() {
            return;
        }

        match payload[0] >> 4 {
            4 => Self::forward_ipv4(peer_mgr, ret).await,
            6 => Self::forward_ipv6(peer_mgr, ret).await,
            _ => {
                tracing::warn!(?ret, "[USER_PACKET] unknown IP version");
            }
        }
    }

    async fn run(mut self) {
        while let Some(ret) = self.stream.next().await {
            let Ok(ret) = ret else {
                tracing::error!("read from nic failed: {:?}", ret);
                break;
            };
            Self::forward(self.peer_mgr.as_ref(), ret).await;
        }
        self.close_notifier.notify_one();
        tracing::error!("nic closed when recving from it");
    }
}

pub struct PeersNicForwarder {
    packet_recv_chan_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    close_notifier: Arc<Notify>,

    sink: Pin<Box<dyn ZCPacketSink>>,
}

impl PeersNicForwarder {
    async fn run(mut self) {
        // unlock until coroutine finished
        let mut channel = self.packet_recv_chan_receiver.lock().await;
        while let Ok(packet) = recv_packet_from_chan(&mut channel).await {
            tracing::trace!(
                "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                packet
            );
            if let Err(e) = self.sink.send(packet).await {
                tracing::error!("forward packet from peers to nic sink error: {:?}", e);
            }
        }
        self.close_notifier.notify_one();
        tracing::error!("nic closed when sending to it");
    }
}

pub struct Nic {
    ctrl: NicController,
    global_ctx: ArcGlobalCtx,
    tunnel: Box<dyn Tunnel>,
    name: String,
    tasks: JoinSet<()>,
}

impl Nic {
    // TODO: used by magic DNS, REMOVE THIS!
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Nic {
    pub(super) fn new(global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>, name: String) -> Self {
        Self {
            ctrl: Controller::new(name.clone()),
            global_ctx,
            tunnel,
            name,
            tasks: JoinSet::new(),
        }
    }

    pub fn ctrl(&self) -> NicController {
        self.ctrl.clone()
    }

    pub async fn run(
        &mut self,
        peer_mgr: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
        ipv4_addr: Option<Ipv4Inet>,
        ipv6_addr: Option<Ipv6Inet>,
    ) -> Result<(), Error> {
        let (stream, sink) = self.tunnel.split();

        self.tasks.spawn(
            NicPeersForwarder {
                peer_mgr: peer_mgr.clone(),
                close_notifier: close_notifier.clone(),
                stream,
            }
            .run(),
        );

        self.tasks.spawn(
            PeersNicForwarder {
                packet_recv_chan_receiver: peer_packet_receiver,
                close_notifier: close_notifier.clone(),
                sink,
            }
            .run(),
        );

        let mut ctrl = self.ctrl.write().await;

        ctrl.wait_interface_show().await?;

        // TODO: run route manager

        {
            let _g = self.global_ctx.net_ns.guard();

            // Assign IPv4 address if provided
            if let Some(ipv4_addr) = ipv4_addr {
                ctrl.remove_ipv4_ip(None).await?;
                ctrl.add_ipv4_ip(ipv4_addr.address(), ipv4_addr.network_length())
                    .await?;
            }

            // Assign IPv6 address if provided
            if let Some(ipv6_addr) = ipv6_addr {
                ctrl.remove_ipv6_ip(None).await?;
                ctrl.add_ipv6_ip(ipv6_addr.address(), ipv6_addr.network_length())
                    .await?;
            }

            // TODO: publish route here
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for Nic {
    fn drop(&mut self) {
        let ifname = &self.name;
        // Try to clean up firewall rules, but don't panic in destructor
        if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
            log::warn!(
                %error,
                "failed to remove firewall rules for interface {}",
                ifname
            );
        }
    }
}
