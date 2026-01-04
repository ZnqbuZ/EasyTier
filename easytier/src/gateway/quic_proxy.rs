use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::PeerId;
use crate::gateway::kcp_proxy::{ProxyAclHandler, TcpProxyForKcpSrcTrait};
use crate::gateway::quic::{
    QuicController, QuicEndpoint, QuicPacket, QuicPacketRx, QuicStream, QuicStreamHandle,
    QuicStreamRx,
};
use crate::gateway::tcp_proxy::{NatDstConnector, TcpProxy};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::peers::PeerPacketFilter;
use crate::proto::api::instance::{ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState, TcpProxyEntryTransportType, TcpProxyRpc};
use crate::proto::peer_rpc::KcpConnData;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket, ZCPacketType};
use anyhow::{anyhow, Context, Error};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use derivative::Derivative;
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::task::JoinSet;
use tracing::{debug, error, instrument, trace};
use crate::common::acl_processor::PacketInfo;
use crate::proto::acl::{ChainType, Protocol};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;

//This helper class encodes/decodes peer_id and packet_type into/from SocketAddr.
#[derive(Debug)]
struct QuicPacketMeta {
    peer_id: PeerId,
    packet_type: PacketType,
}

impl QuicPacketMeta {
    #[inline]
    fn new(peer_id: PeerId, packet_type: PacketType) -> Self {
        Self {
            peer_id,
            packet_type,
        }
    }

    #[inline]
    fn pack(self, data: BytesMut) -> QuicPacket {
        QuicPacket {
            addr: self.into(),
            payload: data,
        }
    }

    #[inline]
    fn unpack(packet: QuicPacket) -> Option<(Self, BytesMut)> {
        let packet_info = packet.addr.try_into().ok()?;
        Some((packet_info, packet.payload))
    }
}

impl From<QuicPacketMeta> for SocketAddr {
    #[inline]
    fn from(meta: QuicPacketMeta) -> Self {
        SocketAddr::new(IpAddr::V4(meta.peer_id.into()), meta.packet_type as u16)
    }
}

impl TryFrom<SocketAddr> for QuicPacketMeta {
    type Error = ();

    #[inline]
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

type QuicConnData = KcpConnData;

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

        trace!("quic nat dst: {:?}, dst peers: {:?}", nat_dst, dst_peer_id);

        let header = {
            let conn_data = QuicConnData {
                src: Some(src.into()),
                dst: Some(nat_dst.into()),
            };

            let len = conn_data.encoded_len();
            if len > (u16::MAX as usize) {
                return Err(anyhow!("conn data too large: {:?}", len).into());
            }

            let mut buf = BytesMut::with_capacity(2 + len);

            buf.put_u16(len as u16);
            conn_data.encode(&mut buf).unwrap();

            buf.freeze()
        };

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
            let conn_data = header.clone();

            connect_tasks.spawn(async move {
                let mut stream = quic_ctrl
                    .connect(QuicPacketMeta::new(dst_peer_id, PacketType::QuicSrc).into())
                    .await
                    .with_context(|| format!("failed to connect to nat dst: {}", nat_dst))?;

                stream.write_all(&conn_data).await?;

                Ok(stream)
            });
        }

        Err(anyhow!("failed to connect to nat dst: {}", nat_dst).into())
    }

    #[inline]
    fn check_packet_from_peer_fast(&self, _cidr_set: &CidrSet, _global_ctx: &GlobalCtx) -> bool {
        true
    }

    #[inline]
    fn check_packet_from_peer(
        &self,
        _cidr_set: &CidrSet,
        _global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        _ipv4: &Ipv4Packet,
        _real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        hdr.from_peer_id == hdr.to_peer_id && hdr.is_kcp_src_modified()
    } //TODO: Can we use the same flag?

    #[inline]
    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Quic
    }
}

#[derive(Clone)]
struct TcpProxyForQuicSrc(Arc<TcpProxy<NatDstQuicConnector>>);

//TODO: rename & move this trait
#[async_trait::async_trait]
impl TcpProxyForKcpSrcTrait for TcpProxyForQuicSrc {
    type Connector = NatDstQuicConnector;

    #[inline]
    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    #[inline]
    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool {
        self.0
            .get_peer_manager()
            .check_allow_quic_to_dst(&IpAddr::V4(*dst_ip))
            .await
    }
}

#[derive(Debug)]
enum QuicProxyRole {
    Src,
    Dst,
}

impl QuicProxyRole {
    #[inline]
    const fn incoming(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicDst,
            QuicProxyRole::Dst => PacketType::QuicSrc,
        }
    }

    #[inline]
    const fn outgoing(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicSrc,
            QuicProxyRole::Dst => PacketType::QuicDst,
        }
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
                QuicPacketMeta::new(header.from_peer_id.get(), self.role.outgoing())
                    .pack(packet.payload_bytes()),
            )
            .await;

        None
    }
}

// Send to peers packets received from the QUIC endpoint
#[derive(Debug)]
struct QuicPacketSender {
    peer_mgr: Arc<PeerManager>,
    packet_rx: QuicPacketRx,

    header: Bytes,
    zc_packet_type: ZCPacketType,
}

impl QuicPacketSender {
    #[instrument]
    pub async fn run(mut self) {
        while let Some(packet) = self.packet_rx.recv().await {
            let (packet_info, mut payload) = match QuicPacketMeta::unpack(packet) {
                Some(v) => v,
                None => {
                    error!("failed to extract metadata from quic packet");
                    continue;
                }
            };

            payload[..self.header.len()].copy_from_slice(&self.header);
            let mut packet = ZCPacket::new_from_buf(payload, self.zc_packet_type);

            let peer_id = packet_info.peer_id;
            let packet_type = packet_info.packet_type;
            packet.fill_peer_manager_hdr(self.peer_mgr.my_peer_id(), peer_id, packet_type as u8);

            if let Err(e) = self.peer_mgr.send_msg_for_proxy(packet, peer_id).await {
                error!("failed to send QUIC packet to peer: {:?}", e);
            }
        }
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
struct QuicStreamContext {
    global_ctx: ArcGlobalCtx,
    proxy_entries: Arc<DashMap<QuicStreamHandle, TcpProxyEntry>>,
    cidr_set: Arc<CidrSet>,
    #[derivative(Debug = "ignore")]
    route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
}

impl QuicStreamContext {
    fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let global_ctx = peer_mgr.get_global_ctx();
        Self {
            global_ctx: global_ctx.clone(),
            proxy_entries: Arc::new(DashMap::new()),
            cidr_set: Arc::new(CidrSet::new(global_ctx.clone())),
            route: Arc::new(peer_mgr.get_route()),
        }
    }
}

struct QuicStreamReceiver {
    stream_rx: QuicStreamRx,
    stream_ctx: Arc<QuicStreamContext>,
}

impl QuicStreamReceiver {
    async fn run(mut self) {
        while let Some(stream) = self.stream_rx.recv().await {
            let stream_ctx = self.stream_ctx.clone();
            tokio::spawn(Self::establish_stream(stream, stream_ctx));
        }
    }

    #[instrument(ret)]
    async fn establish_stream(mut stream: QuicStream, stream_ctx: Arc<QuicStreamContext>) -> crate::common::error::Result<()> {
        let conn_data_len = {
            let mut header_len =[0u8; 2];
            stream.read_exact(&mut header_len).await.context("failed to read length of quic stream header")?;
            u16::from_be_bytes(header_len) as usize
        };

        let mut conn_data = vec![0u8; conn_data_len];
        stream.read_exact(&mut conn_data).await.context("failed to read quic stream header")?;
        let conn_data_parsed = QuicConnData::decode(&mut conn_data.as_slice()).context("failed to decode quic stream header")?;

        let proxy_entries = &stream_ctx.proxy_entries;
        let handle = stream.handle();
        proxy_entries.insert(
            handle,
            TcpProxyEntry {
                src: conn_data_parsed.src,
                dst: conn_data_parsed.dst,
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Quic.into(),
            },
        );
        crate::defer! {
            proxy_entries.remove(&handle);
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        }

        let src_socket: SocketAddr = conn_data_parsed.src.ok_or_else(|| anyhow!("missing src addr in quic stream header"))?.into();
        let mut dst_socket: SocketAddr = conn_data_parsed.dst.ok_or_else(|| anyhow!("missing dst addr in quic stream header"))?.into();

        let src_ip = src_socket.ip();
        let dst_ip = dst_socket.ip();

        let route = stream_ctx.route.clone();
        let (src_groups, dst_groups) = tokio::join!(
            route.get_peer_groups_by_ip(&src_ip),
            route.get_peer_groups_by_ip(&dst_ip)
        );

        let global_ctx = stream_ctx.global_ctx.clone();
        let send_to_self =
            Some(dst_socket.ip()) == global_ctx.get_ipv4().map(|ip| IpAddr::V4(ip.address()));

        if send_to_self && global_ctx.no_tun() {
            if global_ctx.is_port_in_running_listeners(dst_socket.port(), false)
                && global_ctx.is_ip_in_same_network(&src_ip)
            {
                return Err(anyhow::anyhow!(
                    "dst socket {:?} is in running listeners, ignore it",
                    dst_socket
                )
                    .into());
            }
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse().unwrap();
        }

        let acl_handler = ProxyAclHandler {
            acl_filter: global_ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip,
                dst_ip,
                src_port: Some(src_socket.port()),
                dst_port: Some(dst_socket.port()),
                protocol: Protocol::Tcp,
                packet_size: conn_data.len(),
                src_groups,
                dst_groups,
            },
            chain_type: if send_to_self {
                ChainType::Inbound
            } else {
                ChainType::Forward
            },
        };
        acl_handler.handle_packet(&conn_data)?;

        debug!("quic connect to dst socket: {:?}", dst_socket);

        let _g = global_ctx.net_ns.guard();
        let connector = crate::gateway::tcp_proxy::NatDstTcpConnector {};
        let ret = connector
            .connect("0.0.0.0:0".parse().unwrap(), dst_socket)
            .await?;

        if let Some(mut e) = proxy_entries.get_mut(&handle) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        acl_handler
            .copy_bidirection_with_acl(stream, ret)
            .await?;

        Ok(())
    }
}

pub struct QuicProxy {
    endpoint: QuicEndpoint,
    peer_mgr: Arc<PeerManager>,

    src: Option<QuicProxySrc>,
    dst: Option<QuicProxyDst>,

    tasks: JoinSet<()>,
}

impl QuicProxy {
    #[inline]
    pub fn src(&self) -> Option<&QuicProxySrc> {
        self.src.as_ref()
    }

    #[inline]
    pub fn dst(&self) -> Option<&QuicProxyDst> {
        self.dst.as_ref()
    }
}

impl QuicProxy {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            endpoint: QuicEndpoint::new(),
            peer_mgr,
            src: None,
            dst: None,
            tasks: JoinSet::new(),
        }
    }

    pub async fn run(&mut self, src: bool, dst: bool) {
        trace!("quic proxy starting");

        let (header, zc_packet_type) = {
            let header = ZCPacket::new_with_payload(&[]);
            let zc_packet_type = header.packet_type();
            let payload_offset = header.payload_offset();
            (
                header.inner().split_to(payload_offset).freeze(),
                zc_packet_type,
            )
        };
        let (packet_rx, stream_rx) = self
            .endpoint
            .run((header.len(), 0).into())
            .expect("failed to start quic endpoint");
        let peer_mgr = self.peer_mgr.clone();
        self.tasks.spawn(
            QuicPacketSender {
                peer_mgr,
                packet_rx,
                header,
                zc_packet_type,
            }
            .run(),
        );

        let peer_mgr = self.peer_mgr.clone();
        let quic_ctrl = self.endpoint.ctrl().unwrap();

        if src {
            let tcp_proxy = TcpProxyForQuicSrc(TcpProxy::new(
                peer_mgr.clone(),
                NatDstQuicConnector {
                    quic_ctrl: quic_ctrl.clone(),
                    peer_mgr: Arc::downgrade(&peer_mgr),
                },
            ));

            let src = QuicProxySrc {
                quic_ctrl: quic_ctrl.clone(),
                peer_mgr: peer_mgr.clone(),
                tcp_proxy,
            };
            src.run().await;

            self.src = Some(src);
        }

        stream_rx.switch().set(dst);
        if dst {
            let stream_ctx = Arc::new(QuicStreamContext::new(peer_mgr.clone()));

            let dst = QuicProxyDst {
                quic_ctrl: quic_ctrl.clone(),
                peer_mgr: peer_mgr.clone(),
                stream_ctx: stream_ctx.clone(),
            };
            dst.run().await;

            self.tasks.spawn(
                QuicStreamReceiver {
                    stream_rx,
                    stream_ctx,
                }
                .run(),
            );

            self.dst = Some(dst);
        }
    }
}

pub struct QuicProxySrc {
    quic_ctrl: Arc<QuicController>,
    peer_mgr: Arc<PeerManager>,

    tcp_proxy: TcpProxyForQuicSrc,
}

impl QuicProxySrc {
    #[inline]
    pub fn get_tcp_proxy(&self) -> Arc<TcpProxy<NatDstQuicConnector>> {
        self.tcp_proxy.get_tcp_proxy().clone()
    }
}

impl QuicProxySrc {
    async fn run(&self) {
        trace!("quic proxy src starting");
        self.peer_mgr
            .add_nic_packet_process_pipeline(Box::new(self.tcp_proxy.clone()))
            .await;
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(self.tcp_proxy.0.clone()))
            .await;
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(QuicPacketReceiver {
                quic_ctrl: self.quic_ctrl.clone(),
                role: QuicProxyRole::Src,
            }))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }
}

pub struct QuicProxyDst {
    quic_ctrl: Arc<QuicController>,
    peer_mgr: Arc<PeerManager>,

    stream_ctx: Arc<QuicStreamContext>,
}

impl QuicProxyDst {
    async fn run(&self) {
        trace!("quic proxy dst starting");
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(QuicPacketReceiver {
                quic_ctrl: self.quic_ctrl.clone(),
                role: QuicProxyRole::Dst,
            }))
            .await;
    }
}

#[derive(Clone)]
pub struct QuicProxyDstRpcService(Weak<DashMap<QuicStreamHandle, TcpProxyEntry>>);

impl QuicProxyDstRpcService {
    pub fn new(quic_proxy_dst: &QuicProxyDst) -> Self {
        Self(Arc::downgrade(&quic_proxy_dst.stream_ctx.proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for QuicProxyDstRpcService {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.0.upgrade() {
            for item in tcp_proxy.iter() {
                reply.entries.push(*item.value());
            }
        }
        Ok(reply)
    }
}
