use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;
use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        ifcfg,
        ifcfg::IfConfiger,
        log,
    },
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{peer_manager::PeerManager, recv_packet_from_chan, PacketRecvChanReceiver},
    tunnel::{
        common::{reserve_buf, FramedWriter, TunnelWrapper, ZCPacketToBytes},
        packet_def::{ZCPacket, ZCPacketType, TAIL_RESERVED_SIZE},
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
    },
};
use byteorder::WriteBytesExt as _;
use bytes::{BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{lock::BiLock, ready, SinkExt, Stream, StreamExt};
use pin_project_lite::pin_project;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
use ::tun::platform::Device;
use ::tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use zerocopy::{NativeEndian, NetworkEndian};

mod platform;
mod route;
mod tun;
use tun::{TunAsyncWrite, TunStream, TunZCPacketToBytes};

pub struct VirtualNic {
    global_ctx: ArcGlobalCtx,

    ifname: Option<String>,
    ifcfg: IfConfiger,
}

impl Drop for VirtualNic {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref ifname) = self.ifname {
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
    }
}

impl VirtualNic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            ifname: None,
            ifcfg: ifcfg::get(),
        }
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ipv4_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ipv6_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }
}

pub struct Nic {
    global_ctx: ArcGlobalCtx,
    pub nic: Arc<Mutex<VirtualNic>>,
    tasks: JoinSet<()>,
}

impl Nic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Nic {
            global_ctx: global_ctx.clone(),
            nic: Arc::new(Mutex::new(VirtualNic::new(global_ctx))),
            tasks: JoinSet::new(),
        }
    }

    pub async fn ifname(&self) -> Option<String> {
        let nic = self.nic.lock().await;
        nic.ifname.as_ref().map(|s| s.to_owned())
    }

    pub async fn assign_ipv4_to_tun_device(&self, ipv4_addr: cidr::Ipv4Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ip(None).await?;
        nic.add_ip(ipv4_addr.address(), ipv4_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_route(ipv4_addr.first_address(), ipv4_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_to_tun_device(&self, ipv6_addr: cidr::Ipv6Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ipv6(None).await?;
        nic.add_ipv6(ipv6_addr.address(), ipv6_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
        }
        Ok(())
    }

    async fn apply_route_changes(
        ifcfg: IfConfiger,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
        added: Vec<cidr::Ipv4Cidr>,
        removed: Vec<cidr::Ipv4Cidr>,
    ) {
        tracing::debug!(?added, ?removed, "applying proxy_cidrs route changes");

        // Remove routes
        for cidr in removed {
            if !cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv4_route(ifname, cidr.first_address(), cidr.network_length())
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "remove route failed.",
                );
            }
            cur_proxy_cidrs.remove(&cidr);
        }

        // Add routes
        for cidr in added {
            if cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv4_route(ifname, cidr.first_address(), cidr.network_length(), None)
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "add route failed.",
                );
            }
            cur_proxy_cidrs.insert(cidr);
        }
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = ifcfg::get();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::<cidr::Ipv4Cidr>::new();

            // Initial sync: get current proxy_cidrs state and apply routes
            let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                peer_mgr.as_ref(),
                &global_ctx,
                &cur_proxy_cidrs,
            )
            .await;
            Self::apply_route_changes(
                ifcfg,
                &ifname,
                &net_ns,
                &mut cur_proxy_cidrs,
                added,
                removed,
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("event bus closed, stopping proxy_cidrs route updater");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "event bus lagged in proxy_cidrs route updater, doing full sync"
                        );
                        event_receiver = event_receiver.resubscribe();
                        // Full sync after lagged to recover consistent state
                        let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_mgr.as_ref(),
                            &global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        GlobalCtxEvent::ProxyCidrsUpdated(added, removed)
                    }
                };

                // Only handle ProxyCidrsUpdated events
                let (added, removed) = match event {
                    GlobalCtxEvent::ProxyCidrsUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_route_changes(
                    ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_proxy_cidrs,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    pub async fn run(
        &mut self,
        peer_mgr: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
        ipv4_addr: Option<Ipv4Inet>,
        ipv6_addr: Option<Ipv6Inet>,
    ) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev().await {
                Ok(ret) => {
                    #[cfg(target_os = "windows")]
                    {
                        let dev_name = self.global_ctx.get_flags().dev_name;
                        let _ = RegistryManager::reg_change_catrgory_in_profile(&dev_name);
                    }

                    #[cfg(any(
                        all(target_os = "macos", not(feature = "macos-ne")),
                        target_os = "freebsd"
                    ))]
                    {
                        // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
                        let _ = nic
                            .ifcfg
                            .remove_ipv4_route(nic.ifname(), "10.0.0.0".parse().unwrap(), 24)
                            .await;
                    }

                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        let (stream, sink) = tunnel.split();

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

        // Assign IPv4 address if provided
        if let Some(ipv4_addr) = ipv4_addr {
            self.assign_ipv4_to_tun_device(ipv4_addr).await?;
        }

        // Assign IPv6 address if provided
        if let Some(ipv6_addr) = ipv6_addr {
            self.assign_ipv6_to_tun_device(ipv6_addr).await?;
        }

        self.run_proxy_cidrs_route_updater().await?;

        Ok(())
    }

    #[cfg(mobile)]
    pub async fn run_for_mobile(&mut self, tun_fd: std::os::fd::RawFd) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev_for_mobile(tun_fd).await {
                Ok(ret) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        self.do_forward_peers_to_nic(sink);

        Ok(())
    }
}

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
