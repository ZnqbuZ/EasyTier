use crate::common::acl_processor::PacketInfo;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::PeerId;
use crate::gateway::kcp_proxy::{ProxyAclHandler, TcpProxyForKcpSrcTrait};
use crate::gateway::quic::{QuicEndpoint, QuicOutputRx, QuicPacketRx, QuicStreamRx};
use crate::gateway::tcp_proxy::{NatDstConnector, TcpProxy};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::peers::PeerPacketFilter;
use crate::proto::acl::{ChainType, Protocol};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::peer_rpc::KcpConnData;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket, ZCPacketType};
use anyhow::{anyhow, Context, Error};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use derivative::Derivative;
use derive_more::{Constructor, Deref, DerefMut, From, Into};
use parking_lot::Mutex;
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Connecting, Endpoint, RecvStream, SendStream, UdpPoller};
use quinn_proto::{ConnectError, StreamId};
use std::future::Future;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{join, AsyncReadExt, Join};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};
use tokio::{join, pin, select};
use tokio_util::sync::PollSender;
use tracing::{debug, error, instrument, trace, warn};

//region packet
#[derive(Debug, Constructor)]
struct QuicPacket {
    addr: SocketAddr,
    payload: BytesMut,
    ecn: Option<EcnCodepoint>,
}
//endregion

//region socket
#[derive(Debug)]
pub struct QuicSocketPoller {
    tx: PollSender<QuicPacket>,
}

impl UdpPoller for QuicSocketPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .tx
            .poll_reserve(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }
}

#[derive(Debug)]
pub struct QuicSocket {
    addr: SocketAddr,
    rx: Mutex<Receiver<QuicPacket>>,
    tx: Sender<QuicPacket>,
}

impl AsyncUdpSocket for QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::into_pin(Box::new(QuicSocketPoller {
            tx: PollSender::new(self.tx.clone()),
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        match transmit.destination {
            SocketAddr::V4(addr) => {
                trace!(
                    "{:?} sending {:?} bytes to {:?}",
                    self.addr,
                    transmit.contents.len(),
                    addr
                );
                if self.tx.capacity() > 0
                    && self
                        .tx
                        .try_send(QuicPacket {
                            addr: transmit.destination,
                            payload: BytesMut::from(transmit.contents),
                            ecn: transmit.ecn,
                        })
                        .is_ok()
                {
                    Ok(())
                } else {
                    //Err(std::io::ErrorKind::WouldBlock.into())
                    //TODO avoid fake send success, need to implement awake mechanism
                    Ok(())
                }
            }
            _ => Err(std::io::ErrorKind::ConnectionRefused.into()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let mut rx = self.rx.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if bufs.is_empty() || meta.is_empty() {
                    return Poll::Ready(Ok(0));
                }

                let len = packet.payload.len();
                if len > bufs[0].len() {
                    warn!(
                        "buffer too small for packet: {:?} < {:?}, dropping",
                        bufs[0].len(),
                        len,
                    );
                    return Poll::Pending;
                }
                trace!(
                    "{} received {} bytes from {:?}",
                    self.addr,
                    len,
                    packet.addr
                );
                bufs[0].deref_mut()[0..len].copy_from_slice(&packet.payload);
                meta[0] = RecvMeta {
                    addr: packet.addr,
                    len,
                    stride: len,
                    ecn: packet.ecn,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "socket closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}
//endregion

//region addr
#[derive(Debug, Clone, Constructor)]
struct QuicAddr {
    peer_id: PeerId,
    packet_type: PacketType,
}

impl From<QuicAddr> for SocketAddr {
    #[inline]
    fn from(value: QuicAddr) -> Self {
        SocketAddr::new(IpAddr::V4(value.peer_id.into()), value.packet_type as u16)
    }
}

impl TryFrom<SocketAddr> for QuicAddr {
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
//endregion

type QuicStreamInner = Join<RecvStream, SendStream>;
#[derive(Debug, Deref, DerefMut, From, Into)]
struct QuicStream {
    #[deref]
    #[deref_mut]
    inner: QuicStreamInner,
}

impl QuicStream {
    fn id(&self) -> (StreamId, StreamId) {
        (self.reader().id(), self.writer().id())
    }
}

impl From<(SendStream, RecvStream)> for QuicStream {
    fn from(value: (SendStream, RecvStream)) -> Self {
        join(value.1, value.0).into()
    }
}

type QuicConnData = KcpConnData;

#[derive(Debug, Clone)]
pub struct NatDstQuicConnector {
    pub(crate) endpoint: Endpoint,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQuicConnector {
    type DstStream = QuicStreamInner;

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

        let addr = QuicAddr::new(dst_peer_id, PacketType::QuicSrc).into();
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

        let mut connect_tasks = JoinSet::<Result<QuicStream, Error>>::new();
        let connect = |tasks: &mut JoinSet<_>| {
            let endpoint = self.endpoint.clone();
            let header = header.clone();

            tasks.spawn(async move {
                let connection = endpoint.connect(addr, "")?.await?;
                let mut stream: QuicStream = connection.open_bi().await?.into();
                stream.writer_mut().write_chunk(header).await?;
                Ok(stream)
            });
        };

        connect(&mut connect_tasks);

        let timer = tokio::time::sleep(Duration::from_millis(200));
        pin!(timer);

        let mut retry_remain = 5;
        loop {
            select! {
                Some(result) = connect_tasks.join_next() => {
                    match result {
                        Ok(Ok(stream)) => return Ok(stream.into()),
                        _ => {
                            if connect_tasks.is_empty() {
                                if retry_remain == 0 {
                                    return Err(anyhow!("failed to connect to nat dst: {}", nat_dst).into())
                                }

                                retry_remain -= 1;
                                connect(&mut connect_tasks);
                                timer.as_mut().reset(Instant::now() + Duration::from_millis(200))
                            }
                        }
                    }
                }
                _ = &mut timer, if retry_remain > 0 => {
                    retry_remain -= 1;
                    connect(&mut connect_tasks);
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(200));
                }
            }
        }
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
        TcpProxyEntryTransportType::Kcp
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
    tx: Sender<QuicPacket>,
    role: QuicProxyRole,
}

#[async_trait::async_trait]
impl PeerPacketFilter for QuicPacketReceiver {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header().unwrap();

        if header.packet_type != self.role.incoming() as u8 {
            return Some(packet);
        }

        let addr = QuicAddr::new(header.from_peer_id.get(), self.role.outgoing());

        if let Err(e) = self
            .tx
            .send(QuicPacket::new(addr.into(), packet.payload_bytes(), None))
            .await
        {
            debug!("failed to send quic packet to endpoint: {:?}", e);
        }

        None
    }
}

// Send to peers packets received from the QUIC endpoint
#[derive(Debug)]
struct QuicPacketSender {
    peer_mgr: Arc<PeerManager>,
    rx: Receiver<QuicPacket>,

    header: Bytes,
    zc_packet_type: ZCPacketType,
}

impl QuicPacketSender {
    #[instrument]
    pub async fn run(mut self) {
        while let Some(packet) = self.rx.recv().await {
            let Some(addr) = QuicAddr::try_from(packet.addr) else {
                error!("invalid quic packet addr: {:?}", packet.addr);
                continue;
            };

            let payload = packet.payload;
            payload[..self.header.len()].copy_from_slice(&self.header);
            let mut packet = ZCPacket::new_from_buf(payload, self.zc_packet_type);

            packet.fill_peer_manager_hdr(
                self.peer_mgr.my_peer_id(),
                addr.peer_id,
                addr.packet_type as u8,
            );

            if let Err(e) = self.peer_mgr.send_msg_for_proxy(packet, addr.peer_id).await {
                error!("failed to send QUIC packet to peer: {:?}", e);
            }
        }
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
struct QuicStreamContext {
    global_ctx: ArcGlobalCtx,
    proxy_entries: Arc<DashMap<(StreamId, StreamId), TcpProxyEntry>>,
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
    endpoint: Endpoint,
    tasks: JoinSet<()>,
    ctx: Arc<QuicStreamContext>,
}

impl QuicStreamReceiver {
    async fn run(mut self) {
        while let Some(incoming) = self.endpoint.accept().await {
            let connection = match incoming.accept() {
                Ok(connection) => connection,
                Err(e) => {
                    error!(
                        "failed to accept quic connection from {:?}: {:?}",
                        incoming.remote_address(),
                        e
                    );
                    continue;
                }
            };

            let connection = match connection.await {
                Ok(connection) => connection,
                Err(e) => {
                    error!(
                        "failed to accept quic connection from {:?}: {:?}",
                        connection.remote_address(),
                        e
                    );
                    continue;
                }
            };

            let ctx = self.ctx.clone();
            self.tasks.spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    let stream = select! {
                        stream = connection.accept_bi() => {
                            match stream {
                                Ok(stream) => stream.into(),
                                Err(e) => {
                                    warn!("failed to accept bi stream from {:?}: {:?}", connection.remote_address(), e);
                                    continue;
                                }
                            }
                        }

                        stream = connection.accept_uni() => {
                            warn!("uni stream is not supported (stream from {:?}): {:?}", connection.remote_address(), stream);
                            continue;
                        }
                    };

                    match Self::establish_stream(stream, &mut tasks, ctx.clone()).await {
                        Ok(stream) => drop(tasks.spawn(stream)),
                        Err(e) => warn!("failed to establish quic stream from {:?}: {:?}", connection.remote_address(), e),
                    }
                }
            });
        }
    }

    async fn read_stream_header(stream: &mut QuicStream) -> Result<Bytes, Error> {
        let len = stream.read_u16().await?;
        let mut header = Vec::with_capacity(len as usize);
        stream
            .reader_mut()
            .take(len as u64)
            .read_to_end(&mut header)
            .await?;
        Ok(header.into())
    }

    async fn establish_stream(
        mut stream: QuicStream,
        tasks: &mut JoinSet<()>,
        ctx: Arc<QuicStreamContext>,
    ) -> Result<impl Future<Output = crate::common::error::Result<()>>, Error> {
        let conn_data = Self::read_stream_header(&mut stream).await?;
        let conn_data_parsed = QuicConnData::decode(conn_data.as_ref())
            .context("failed to decode quic stream header")?;

        let handle = stream.id();
        let proxy_entries = &ctx.proxy_entries;
        proxy_entries.insert(
            handle,
            TcpProxyEntry {
                src: conn_data_parsed.src,
                dst: conn_data_parsed.dst,
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Kcp.into(),
            },
        );
        crate::defer! {
            proxy_entries.remove(&handle);
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        }

        let src_socket: SocketAddr = conn_data_parsed
            .src
            .ok_or_else(|| anyhow!("missing src addr in quic stream header"))?
            .into();
        let mut dst_socket: SocketAddr = conn_data_parsed
            .dst
            .ok_or_else(|| anyhow!("missing dst addr in quic stream header"))?
            .into();

        if let IpAddr::V4(dst_v4_ip) = dst_socket.ip() {
            let mut real_ip = dst_v4_ip;
            if ctx.cidr_set.contains_v4(dst_v4_ip, &mut real_ip) {
                dst_socket.set_ip(real_ip.into());
            }
        };

        let src_ip = src_socket.ip();
        let dst_ip = dst_socket.ip();

        let route = ctx.route.clone();
        let (src_groups, dst_groups) = join!(
            route.get_peer_groups_by_ip(&src_ip),
            route.get_peer_groups_by_ip(&dst_ip)
        );

        let global_ctx = ctx.global_ctx.clone();
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
        let ret = connector.connect("0.0.0.0:0".parse()?, dst_socket).await?;

        if let Some(mut e) = proxy_entries.get_mut(&handle) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        Ok(async move {
            acl_handler
                .copy_bidirection_with_acl(stream.inner, ret)
                .await
        })
    }
}

pub struct QuicProxy {
    endpoint: Arc<Mutex<QuicEndpoint>>,
    peer_mgr: Arc<PeerManager>,

    rx: Option<QuicOutputRx>,

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
        let (endpoint, rx) =
            QuicEndpoint::new((ZCPacket::new_with_payload(&[]).payload_offset(), 0).into());
        Self {
            endpoint: Arc::new(Mutex::new(endpoint)),
            peer_mgr,
            rx: Some(rx),
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
        let QuicOutputRx {
            packet: packet_rx,
            stream: stream_rx,
        } = self.rx.take().unwrap();
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

        if src {
            let tcp_proxy = TcpProxyForQuicSrc(TcpProxy::new(
                peer_mgr.clone(),
                NatDstQuicConnector {
                    endpoint: self.endpoint.clone(),
                    peer_mgr: Arc::downgrade(&peer_mgr),
                },
            ));

            let src = QuicProxySrc {
                endpoint: self.endpoint.clone(),
                peer_mgr: peer_mgr.clone(),
                tcp_proxy,
            };
            src.run().await;

            self.src = Some(src);
        }

        stream_rx.switch().store(dst, Ordering::Relaxed);
        if dst {
            let stream_ctx = Arc::new(QuicStreamContext::new(peer_mgr.clone()));

            let dst = QuicProxyDst {
                endpoint: self.endpoint.clone(),
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
    endpoint: Arc<Mutex<QuicEndpoint>>,
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
                endpoint: self.endpoint.clone(),
                role: QuicProxyRole::Src,
            }))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }
}

pub struct QuicProxyDst {
    endpoint: Arc<Mutex<QuicEndpoint>>,
    peer_mgr: Arc<PeerManager>,

    stream_ctx: Arc<QuicStreamContext>,
}

impl QuicProxyDst {
    async fn run(&self) {
        trace!("quic proxy dst starting");
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(QuicPacketReceiver {
                endpoint: self.endpoint.clone(),
                role: QuicProxyRole::Dst,
            }))
            .await;
    }
}

#[derive(Clone)]
pub struct QuicProxyDstRpcService(Weak<DashMap<StreamId, TcpProxyEntry>>);

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
