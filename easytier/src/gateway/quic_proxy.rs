use anyhow::Context;
use dashmap::DashMap;
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message as _;
use quinn::congestion::BbrConfig;
use quinn::{
    Connection, Endpoint, EndpointConfig, Incoming, RecvStream, SendStream, TokioRuntime,
    TransportConfig, VarInt,
};
use quinn_plaintext::{client_config, server_config};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{copy_bidirectional_with_sizes, join, AsyncReadExt, Join};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::info;
use crate::common::config::ConfigLoader;
use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;
use crate::defer;
use crate::gateway::kcp_proxy::{ProxyAclHandler, TcpProxyForKcpSrcTrait};
use crate::gateway::tcp_proxy::{NatDstConnector, NatDstTcpConnector, TcpProxy};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::proto::acl::{ChainType, Protocol};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::common::ProxyDstInfo;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::common::setup_sokcet2;
use crate::tunnel::packet_def::PeerManagerHeader;
use crate::utils::MonitoredStream;

type QuicStreamInner = Join<RecvStream, SendStream>;

#[derive(Debug, Clone)]
pub struct NatDstQUICConnector {
    pub(crate) peer_mgr: Weak<PeerManager>,
    endpoint: Endpoint,
    connections: DashMap<SocketAddr, Connection>,
}

impl NatDstQUICConnector {
    async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        if let Some(connection) = self.connections.get(&addr) {
            Ok(connection.clone())
        } else {
            let peer_mgr = self
                .peer_mgr
                .upgrade()
                .ok_or(anyhow::anyhow!("peer manager is not available"))?;
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            let connection = self
                .endpoint
                .connect(addr, "localhost")
                .map_err(anyhow::Error::from)?
                .await
                .map_err(anyhow::Error::from)?;
            self.connections.insert(addr, connection.clone());
            Ok(connection)
        }
    }
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQUICConnector {
    type DstStream = QuicStreamInner;

    #[tracing::instrument(skip(self), level = "debug", name = "NatDstQUICConnector::connect")]
    async fn connect(&self, src: SocketAddr, nat_dst: SocketAddr) -> Result<Self::DstStream> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let IpAddr::V4(dst_ipv4) = nat_dst.ip() else {
            return Err(anyhow::anyhow!("src must be an IPv4 address").into());
        };

        let Some(dst_peer) = peer_mgr.get_peer_map().get_peer_id_by_ipv4(&dst_ipv4).await else {
            return Err(anyhow::anyhow!("no peer found for dst: {}", nat_dst).into());
        };

        let Some(dst_peer_info) = peer_mgr.get_peer_map().get_route_peer_info(dst_peer).await
        else {
            return Err(anyhow::anyhow!("no peer info found for dst peer: {}", dst_peer).into());
        };

        let Some(dst_ipv4): Option<Ipv4Addr> = dst_peer_info.ipv4_addr.map(Into::into) else {
            return Err(anyhow::anyhow!("no ipv4 found for dst peer: {}", dst_peer).into());
        };

        let Some(quic_port) = dst_peer_info.quic_port else {
            return Err(anyhow::anyhow!("no quic port found for dst peer: {}", dst_peer).into());
        };

        // connect to server
        let connection = self
            .connect(SocketAddr::new(dst_ipv4.into(), quic_port as u16))
            .await
            .with_context(|| {
                format!(
                    "failed to connect to NAT destination {} from {}, real dst: {}",
                    nat_dst, src, dst_ipv4
                )
            })?;

        let (mut w, r) = connection
            .open_bi()
            .await
            .with_context(|| "open_bi failed")?;

        let proxy_dst_info = ProxyDstInfo {
            dst_addr: Some(nat_dst.into()),
        };
        let proxy_dst_info_buf = proxy_dst_info.encode_to_vec();
        let buf_len = proxy_dst_info_buf.len() as u8;
        w.write(&buf_len.to_le_bytes())
            .await
            .with_context(|| "failed to write proxy dst info buf len to QUIC stream")?;
        w.write(&proxy_dst_info_buf)
            .await
            .with_context(|| "failed to write proxy dst info to QUIC stream")?;

        Ok(join(r, w))
    }

    fn check_packet_from_peer_fast(&self, _cidr_set: &CidrSet, _global_ctx: &GlobalCtx) -> bool {
        true
    }

    fn check_packet_from_peer(
        &self,
        _cidr_set: &CidrSet,
        _global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        _ipv4: &Ipv4Packet,
        _real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        hdr.from_peer_id == hdr.to_peer_id && !hdr.is_kcp_src_modified()
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Quic
    }
}

#[derive(Clone)]
struct TcpProxyForQUICSrc(Arc<TcpProxy<NatDstQUICConnector>>);

#[async_trait::async_trait]
impl TcpProxyForKcpSrcTrait for TcpProxyForQUICSrc {
    type Connector = NatDstQUICConnector;

    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool {
        let Some(peer_manager) = self.0.get_peer_manager() else {
            return false;
        };
        let peer_map: Arc<crate::peers::peer_map::PeerMap> = peer_manager.get_peer_map();
        let Some(dst_peer_id) = peer_map.get_peer_id_by_ipv4(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = peer_map.get_route_peer_info(dst_peer_id).await else {
            return false;
        };
        tracing::debug!(
            "check dst {} allow quic input, peer info: {:?}",
            dst_ip,
            peer_info
        );
        let Some(quic_port) = peer_info.quic_port else {
            return false;
        };
        quic_port > 0
    }
}

fn transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();

    // TODO: subject to change
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));

    // transport_config.stream_receive_window(VarInt::from_u32(64 * 1024 * 1024));
    // transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 1024));
    // transport_config.send_window(1024 * 1024 * 1024);
    //
    // transport_config.datagram_receive_buffer_size(None);
    //
    // transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    // transport_config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    //
    // transport_config.initial_mtu(1200);
    // transport_config.min_mtu(1200);
    //
    // transport_config.enable_segmentation_offload(false);

    transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));

    Arc::new(transport_config)
}

pub struct QUICProxySrc {
    peer_manager: Arc<PeerManager>,
    tcp_proxy: TcpProxyForQUICSrc,
}

impl QUICProxySrc {
    pub async fn new(peer_manager: Arc<PeerManager>) -> Self {
        let mut client_config = client_config();
        client_config.transport_config(transport_config());
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);

        let tcp_proxy = TcpProxy::new(
            peer_manager.clone(),
            NatDstQUICConnector {
                peer_mgr: Arc::downgrade(&peer_manager),
                endpoint,
                connections: DashMap::new(),
            },
        );

        Self {
            peer_manager,
            tcp_proxy: TcpProxyForQUICSrc(tcp_proxy),
        }
    }

    pub async fn start(&self) {
        self.peer_manager
            .add_nic_packet_process_pipeline(Box::new(self.tcp_proxy.clone()))
            .await;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.tcp_proxy.0.clone()))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }

    pub fn get_tcp_proxy(&self) -> Arc<TcpProxy<NatDstQUICConnector>> {
        self.tcp_proxy.0.clone()
    }
}

pub struct QUICProxyDst {
    global_ctx: Arc<GlobalCtx>,
    endpoint: Endpoint,
    proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
    route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
}

impl QUICProxyDst {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
    ) -> Result<Self> {
        let _g = global_ctx.net_ns.guard();
        let bind_addr = format!("0.0.0.0:{}", global_ctx.config.get_flags().quic_listen_port)
            .parse()
            .map_err::<anyhow::Error, _>(Into::into)?;
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(bind_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        setup_sokcet2(&socket2_socket, &bind_addr)?;
        let socket = std::net::UdpSocket::from(socket2_socket);
        let mut server_config = server_config();
        server_config.transport_config(transport_config());
        let endpoint_config = EndpointConfig::default();
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "QUICProxyDst tasks".to_string());
        Ok(Self {
            global_ctx,
            endpoint,
            proxy_entries: Arc::new(DashMap::new()),
            tasks,
            route,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let tasks = Arc::downgrade(&self.tasks.clone());
        let ctx = self.global_ctx.clone();
        let cidr_set = Arc::new(CidrSet::new(ctx.clone()));
        let proxy_entries = self.proxy_entries.clone();
        let route = self.route.clone();

        let task = async move {
            loop {
                match endpoint.accept().await {
                    Some(conn) => {
                        let Some(tasks) = tasks.upgrade() else {
                            tracing::warn!(
                                "QUICProxyDst tasks is not available, stopping accept loop"
                            );
                            return;
                        };
                        tasks
                            .lock()
                            .unwrap()
                            .spawn(Self::handle_connection_with_timeout(
                                conn,
                                ctx.clone(),
                                cidr_set.clone(),
                                proxy_entries.clone(),
                                route.clone(),
                            ));
                    }
                    None => {
                        return;
                    }
                }
            }
        };

        self.tasks.lock().unwrap().spawn(task);

        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(Into::into)
    }

    async fn handle_connection_with_timeout(
        conn: Incoming,
        ctx: Arc<GlobalCtx>,
        cidr_set: Arc<CidrSet>,
        proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
        route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
    ) {
        let remote_addr = conn.remote_address();
        defer!(
            proxy_entries.remove(&remote_addr);
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        );
        let ret = timeout(Duration::from_secs(10), conn).await;

        match ret {
            Ok(Ok(conn)) => {
                let mut tasks = JoinSet::new();
                while let Ok(stream) = conn.accept_bi().await {
                    tasks.spawn(Self::handle_connection(
                        stream,
                        ctx.clone(),
                        cidr_set.clone(),
                        remote_addr,
                        proxy_entries.clone(),
                        route.clone(),
                    ));
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to handle QUIC connection: {}", e);
            }
            Err(_) => {
                tracing::warn!("Timeout while handling QUIC connection");
            }
        }
    }

    async fn handle_connection(
        stream: (SendStream, RecvStream),
        ctx: ArcGlobalCtx,
        cidr_set: Arc<CidrSet>,
        addr: SocketAddr,
        proxy_entries: Arc<DashMap<SocketAddr, TcpProxyEntry>>,
        route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
    ) -> Result<()> {
        info!("incoming connection from {addr}");

        let (w, mut r) = stream;
        let len = r
            .read_u8()
            .await
            .with_context(|| "failed to read proxy dst info buf len")?;
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)
            .await
            .with_context(|| "failed to read proxy dst info")?;

        let proxy_dst_info =
            ProxyDstInfo::decode(&buf[..]).with_context(|| "failed to decode proxy dst info")?;

        let dst_socket: SocketAddr = proxy_dst_info
            .dst_addr
            .map(Into::into)
            .ok_or_else(|| anyhow::anyhow!("no dst addr in proxy dst info"))?;

        let SocketAddr::V4(mut dst_socket) = dst_socket else {
            return Err(anyhow::anyhow!("NAT destination must be an IPv4 address").into());
        };

        let mut real_ip = *dst_socket.ip();
        if cidr_set.contains_v4(*dst_socket.ip(), &mut real_ip) {
            dst_socket.set_ip(real_ip);
        }

        let src_ip = addr.ip();
        let dst_ip = *dst_socket.ip();
        let (src_groups, dst_groups) = tokio::join!(
            route.get_peer_groups_by_ip(&src_ip),
            route.get_peer_groups_by_ipv4(&dst_ip)
        );

        if ctx.should_deny_proxy(&dst_socket.into(), false) {
            return Err(anyhow::anyhow!(
                "dst socket {:?} is in running listeners, ignore it",
                dst_socket
            )
            .into());
        }

        let send_to_self = ctx.is_ip_local_virtual_ip(&dst_ip.into());
        if send_to_self && ctx.no_tun() {
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse().unwrap();
        }

        proxy_entries.insert(
            addr,
            TcpProxyEntry {
                src: Some(addr.into()),
                dst: Some(SocketAddr::V4(dst_socket).into()),
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Quic.into(),
            },
        );

        let connector = NatDstTcpConnector {};

        let dst_stream = {
            let _g = ctx.net_ns.guard();
            connector
                .connect("0.0.0.0:0".parse().unwrap(), dst_socket.into())
                .await?
        };

        if let Some(mut e) = proxy_entries.get_mut(&addr) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        let mut src = MonitoredStream::new(join(r, w), format!("QUIC FROM {:?}", addr).as_str());
        let mut dst = MonitoredStream::new(dst_stream, format!("QUIC TO {:?}", dst_socket).as_str());

        copy_bidirectional_with_sizes(&mut src, &mut dst, 1 << 20, 1 << 20).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct QUICProxyDstRpcService(Weak<DashMap<SocketAddr, TcpProxyEntry>>);

impl QUICProxyDstRpcService {
    pub fn new(quic_proxy_dst: &QUICProxyDst) -> Self {
        Self(Arc::downgrade(&quic_proxy_dst.proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for QUICProxyDstRpcService {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.0.upgrade() {
            for item in tcp_proxy.iter() {
                reply.entries.push(*item.value());
            }
        }
        Ok(reply)
    }
}
