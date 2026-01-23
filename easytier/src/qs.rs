use anyhow::{Context, Result};
use bytes::BytesMut;
use chrono::Utc;
use cidr::Ipv4Inet;
use clap::{Parser, Subcommand};
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use derive_more::{From, Into};
use easytier::common::stun::StunTransport::Tcp;
use easytier::gateway::tcp_proxy::{AddrConnSockMap, NatDstEntry, SynSockMap};
use easytier::instance::virtual_nic::{NicCtx, TunAsyncWrite, TunStream, TunZCPacketToBytes};
use easytier::peers::NicPacketFilter;
use easytier::proto::common::ProxyDstInfo;
use easytier::tunnel::common::{FramedWriter, TunnelWrapper};
use easytier::tunnel::packet_def::ZCPacket;
use easytier::tunnel::Tunnel;
use easytier::utils::{run_stream_monitor, Content, Monitored};
use futures::lock::BiLock;
use futures::{Sink, SinkExt, StreamExt};
use netlink_sys::AsyncSocketExt;
use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder};
use once_cell::sync::Lazy;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use prost::Message;
use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::ClientConfig;
use quinn::EndpointConfig;
use quinn::QlogConfig;
use quinn::ServerConfig;
use quinn::TokioRuntime;
use quinn::TransportConfig;
use quinn::VarInt;
use rand::distributions::Alphanumeric;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use smoltcp::phy::PcapSink;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info};
use tun::Layer;

const QLOG: bool = false;

pub fn transport_config() -> Arc<TransportConfig> {
    let qlog_stream = if !QLOG {
        None
    } else {
        let qlog_path = format!(
            "/home/luna/qlog/qs-{}-{}.qlog",
            Utc::now().format("%H%M%S.%3f"),
            thread_rng()
                .sample_iter(Alphanumeric)
                .take(4)
                .map(char::from)
                .collect::<String>()
        );
        let qlog_path = Path::new(&qlog_path);
        let qlog_file = Box::new(File::create(&*qlog_path).unwrap());
        let mut qlog_config = QlogConfig::default();
        qlog_config.writer(qlog_file);
        Some(qlog_config.into_stream().unwrap())
    };

    // TODO: subject to change
    let mut config = TransportConfig::default();

    config
        // .qlog_stream(qlog_stream)
        .stream_receive_window(VarInt::from_u32(64 * 1024 * 1024))
        .receive_window(VarInt::from_u32(1024 * 1024 * 1024))
        .send_window(1024 * 1024 * 1024)
        .max_concurrent_bidi_streams(VarInt::from_u32(1024))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(VarInt::from_u32(30_000).into()))
        .initial_mtu(1200)
        .min_mtu(1200)
        .enable_segmentation_offload(true)
        .congestion_controller_factory(Arc::new(BbrConfig::default()))
        .datagram_receive_buffer_size(Some(1024 * 1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024 * 1024);

    Arc::new(config)
}

pub fn server_config() -> ServerConfig {
    let mut config = quinn_plaintext::server_config();
    config.transport_config(transport_config());
    config
}

pub fn client_config() -> ClientConfig {
    let mut config = quinn_plaintext::client_config();
    config.transport_config(transport_config());
    config
}

pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(65527).unwrap();
    config
}

// 定义 CLI 结构
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 运行服务端模式
    Server {
        /// 监听地址 (例如: 0.0.0.0:4433)
        #[arg(short, long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
    },
    /// 运行客户端模式
    Client {
        /// 服务端地址 (例如: 127.0.0.1:4433)
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        server: SocketAddr,

        /// 本地监听的 TCP 端口 (例如: 127.0.0.1:8080)
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        local: SocketAddr,

        /// 想要转发到的远程目标 TCP 地址 (例如: google.com:80)
        #[arg(short, long)]
        target: String,
    },
    /// 运行服务端 (VPN 模式)
    /// 需 Root 权限: sudo ./target/release/proxy vpn-server --tun-ip 10.0.0.1
    VpnServer {
        #[arg(short, long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
        #[arg(long, default_value = "10.0.0.1")]
        tun_ip: Ipv4Addr,
        #[arg(long, default_value = "false")]
        smoltcp: bool,
    },
    /// 运行客户端 (VPN 模式)
    /// 需 Root 权限: sudo ./target/release/proxy vpn-client --server <SERVER_IP>:4433 --tun-ip 10.0.0.2
    VpnClient {
        #[arg(short, long)]
        server: SocketAddr,
        #[arg(long, default_value = "10.0.0.2")]
        tun_ip: Ipv4Addr,
        #[arg(long, default_value = "false")]
        smoltcp: bool,
        #[arg(long, default_value = "false")]
        test: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { .. } => unimplemented!(),
        Commands::Client { .. } => unimplemented!(),
        Commands::VpnServer {
            listen,
            tun_ip,
            smoltcp,
        } => run_vpn_server(listen, tun_ip, smoltcp).await,
        Commands::VpnClient {
            server,
            tun_ip,
            smoltcp,
            test,
        } => run_vpn_client(server, tun_ip, smoltcp, test).await,
    }
}

const TUN_MTU: u16 = 1120;

// ==========================================
// 辅助函数：简单的私有协议 (传输目标地址)
// 格式: [Length: u16] [Address String: bytes]
// ==========================================

async fn write_dst_addr<W: AsyncWriteExt + Unpin>(writer: &mut W, addr: &str) -> Result<()> {
    let addr_bytes = addr.as_bytes();
    let len = addr_bytes.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(addr_bytes).await?;
    Ok(())
}

async fn read_dst_addr<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut addr_buf = vec![0u8; len];
    reader.read_exact(&mut addr_buf).await?;
    let addr_str = String::from_utf8_lossy(&addr_buf).to_string();
    Ok(addr_str)
}

// --- VPN 服务端 ---
async fn run_vpn_server(listen_addr: SocketAddr, tun_ip: Ipv4Addr, smoltcp: bool) -> Result<()> {
    run_stream_monitor();

    // 1. 创建 TUN
    let mut config = tun::Configuration::default();
    config
        .address(tun_ip)
        .netmask((255, 255, 255, 0))
        .mtu(TUN_MTU)
        .up();

    let tun_dev = tun::create_as_async(&config).context("创建 TUN 失败 (需要 root?)")?;
    println!("🚀 Server TUN 启动: {}", tun_ip);
    println!("⚠️  请确保开启了内核转发: sysctl -w net.ipv4.ip_forward=1");
    println!("⚠️  请设置 NAT: iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j MASQUERADE");

    // 2. 启动 QUIC
    let socket = UdpSocket::bind(listen_addr)?;
    let mut endpoint = quinn::Endpoint::new(
        endpoint_config(),
        Some(server_config()),
        socket,
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config());
    println!("🎧 等待客户端连接...");

    // 简单起见，这里只接受一个客户端连接，或者需要为每个客户端创建不同的 TUN/路由逻辑
    // 为了演示 IP over QUIC，我们假设是一对一，或者所有客户端共享这个 TUN (都在 10.0.0.x 子网)
    if let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        let remote_addr = connection.remote_address();
        println!("+ 客户端已连接: {}", remote_addr);

        // 进入隧道模式
        if smoltcp {
            println!("✨ 模式: 启用 smoltcp (TCP over Streams)");
            // === TCP over QUIC Streams (代理模式) ===
            // 持续接受来自客户端的 Stream
            loop {
                match connection.accept_bi().await {
                    Ok((send_stream, mut recv_stream)) => {
                        tokio::spawn(async move {
                            // 1. 读取客户端想去的目标地址
                            let target_addr = match read_dst_addr(&mut recv_stream).await {
                                Ok(addr) => addr,
                                Err(e) => {
                                    eprintln!("读取目标地址失败: {}", e);
                                    return;
                                }
                            };

                            println!("  -> Proxy Request: {}", target_addr);

                            // 2. 服务端代替客户端连接真实目标
                            match tokio::net::TcpStream::connect(&target_addr).await {
                                Ok(real_tcp) => {
                                    let mut real_tcp = Monitored::new(
                                        real_tcp,
                                        format!("TCP TO: {}", target_addr).as_str(),
                                        Content::Byte,
                                    );

                                    let quic_stream = join(recv_stream, send_stream);
                                    let mut quic_stream = Monitored::new(
                                        quic_stream,
                                        format!("QUIC FROM: {}", remote_addr).as_str(),
                                        Content::Byte,
                                    );

                                    // 3. 双向转发
                                    if let Err(e) = tokio::io::copy_bidirectional(
                                        &mut quic_stream,
                                        &mut real_tcp,
                                    )
                                    .await
                                    {
                                        // 这是一个常见的错误 (连接断开)，debug 级别即可
                                        debug!("代理连接断开 {}: {}", target_addr, e);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("  ! 连接目标 {} 失败: {}", target_addr, e);
                                    // 可以选择写回一个错误给客户端，这里直接关闭
                                }
                            }
                        });
                    }
                    Err(e) => {
                        println!("Client 连接结束: {}", e);
                        break;
                    }
                }
            }
        } else {
            panic!("✨ 模式: 原生转发 (All over Datagrams)");
        }
    }

    Ok(())
}

struct TcpProxy {
    smoltcp_stack_sender: Option<mpsc::Sender<ZCPacket>>,
    smoltcp_stack_receiver: AtomicCell<Option<mpsc::Receiver<ZCPacket>>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    local_inet: Ipv4Inet,
    syn_map: SynSockMap,
}

#[derive(Debug, From, Into, Clone, Copy, Eq, Hash, PartialEq)]
struct FlowKey((SocketAddr, SocketAddr));

impl From<(&Ipv4Packet<'_>, &TcpPacket<'_>)> for FlowKey {
    fn from(packet: (&Ipv4Packet<'_>, &TcpPacket<'_>)) -> Self {
        let (ip_packet, tcp_packet) = packet;
        let src_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_source(),
            tcp_packet.get_source(),
        ));
        let dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));
        (src_addr, dst_addr).into()
    }
}

// 定义每个流的状态
struct FlowState {
    // 下一个期望接收的序列号
    expected_seq: u32,
    // 乱序缓冲：Key=Seq, Value=Packet
    buffer: BTreeMap<u32, ZCPacket>,
    // 熔断标志：true 表示进入直通模式，不再缓冲，直到 expected_seq 恢复
    passthrough: bool,
    // 是否已初始化（看到过 SYN 或者决定开始追踪）
    initialized: bool,
}

impl FlowState {
    fn new() -> Self {
        Self {
            expected_seq: 0,
            buffer: BTreeMap::new(),
            passthrough: true, // 默认先直通，直到看到 SYN 或者是我们确定的序列
            initialized: false,
        }
    }
}

// 缓冲区最大容量，超过这个数说明丢包严重，触发熔断
const MAX_BUFFER_CAPACITY: usize = 1 << 20;

impl TcpProxy {
    fn run(
        &self,
        mut stack_sink: Pin<
            Box<impl Sink<AnyIpPktFrame, Error = std::io::Error> + Send + ?Sized + 'static>,
        >,
    ) {
        let counter = Arc::new(AtomicUsize::new(0));
        let smoltcp_rx_count = counter.clone();

        let mut smoltcp_stack_receiver = self.smoltcp_stack_receiver.take().unwrap();

        self.tasks.lock().unwrap().spawn(async move {
            // 使用 HashMap 追踪多个流的状态
            let mut conntrack = HashMap::<FlowKey, FlowState>::new();

            while let Some(packet) = smoltcp_stack_receiver.recv().await {
                // 1. 解析包头
                let ip_packet = match Ipv4Packet::new(packet.payload()) {
                    Some(p) => p,
                    None => continue, // 非 IPv4 包忽略
                };

                let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
                    Some(p) => p,
                    None => continue, // 非 TCP 包忽略
                };

                // 2. 提取流 Key
                let flow_key = (&ip_packet, &tcp_packet).into();

                // 3. 计算包的逻辑长度 (Payload + SYN + FIN)
                let payload_len = (ip_packet.get_total_length() as u32)
                    .saturating_sub((ip_packet.get_header_length() as u32) * 4)
                    .saturating_sub((tcp_packet.get_data_offset() as u32) * 4);

                let is_syn = (tcp_packet.get_flags() & TcpFlags::SYN) != 0;
                let is_fin = (tcp_packet.get_flags() & TcpFlags::FIN) != 0;
                let segment_len = payload_len + (if is_syn { 1 } else { 0 }) + (if is_fin { 1 } else { 0 });
                let seq = tcp_packet.get_sequence();

                // 4. 获取或创建流状态
                let state = conntrack.entry(flow_key).or_insert_with(FlowState::new);

                // 如果是 SYN，重置状态
                if is_syn {
                    state.expected_seq = seq;
                    state.buffer.clear();
                    state.initialized = true;
                    println!("New Strict Flow: {:?}", flow_key);
                }

                if !state.initialized {
                    // 没有 SYN 的流，无法得知 expected_seq，只能丢弃或者冒险透传。
                    // 为了绝对不干扰 CC，这里建议直接丢弃，直到捕获到 SYN 或者重置链接。
                    // 但如果是长连接中途截获，这里必须做特殊处理（比较复杂），
                    // 假设我们总能捕获到 SYN，或者你愿意在这里冒险透传一次直到同步。
                    continue;
                }

                let expected = state.expected_seq;

                // =========================================================
                //  严格序列化逻辑 (Strict Serialization)
                // =========================================================

                if seq == expected {
                    // --- Case A: 完美的顺序包 ---
                    // 只有这种包允许通过！

                    // 1. 发送当前包
                    if let Err(e) = stack_sink.send(packet.payload_bytes().into()).await {
                        tracing::error!("send failed: {:?}", e);
                        // 发送失败属于严重错误，这里可能需要断开流
                        continue;
                    }

                    // 2. 推进 expected
                    state.expected_seq = expected.wrapping_add(segment_len);

                    // 3. 极速清理缓冲区 (Drain Buffer)
                    // 既然补上了缺口，后面缓存的一连串包都可以发了
                    while let Some(entry) = state.buffer.first_entry() {
                        if *entry.key() == state.expected_seq {
                            let buffered_pkt = entry.remove();

                            // 解析长度 (需优化：最好在 insert 时就存好长度，避免重复解析)
                            let b_ip = Ipv4Packet::new(buffered_pkt.payload()).unwrap();
                            let b_tcp = TcpPacket::new(b_ip.payload()).unwrap();
                            let b_payload_len = (b_ip.get_total_length() as u32)
                                .saturating_sub((b_ip.get_header_length() as u32) * 4)
                                .saturating_sub((b_tcp.get_data_offset() as u32) * 4);
                            let b_flags_len = if (b_tcp.get_flags() & (TcpFlags::SYN | TcpFlags::FIN)) != 0 { 1 } else { 0 };
                            let b_len = b_payload_len + b_flags_len;

                            if let Err(e) = stack_sink.send(buffered_pkt.payload_bytes().into()).await {
                                tracing::error!("send buffered failed: {:?}", e);
                            } else {
                                state.expected_seq = state.expected_seq.wrapping_add(b_len);
                            }
                        } else {
                            // 链条断了，等待下一个缺口被补齐
                            break;
                        }
                    }

                } else if seq.wrapping_sub(expected) > 0x7FFFFFFF {
                    // --- Case B: 旧包 / 重复包 (Seq < Expected) ---

                    // 【绝对静默】：
                    // 如果我们转发旧包，smoltcp 会回一个 "ACK=expected" 的包。
                    // 上游收到这个 ACK，发现和之前收到的 ACK 一样，就会判定为 DupACK。
                    // 积累 3 个 DupACK 就会降速。
                    // 所以：必须丢弃，假装没看见。

                    println!("Silently dropping old packet seq: {}", seq);
                    continue;

                } else {
                    // --- Case C: 未来的包 (Seq > Expected) ---

                    // 【死都不发】：
                    // 只要不是 expected，就绝对不能发给 smoltcp。
                    // 必须存起来。

                    // 检查容量防止 OOM (针对本地可靠链路，容量给大点)
                    // if current_buffer_size > MAX_LIMIT { 
                    //    这里是个死局。如果缓冲区满了，说明缺口一直没补上。
                    //    选项1 (为了不触发CC): 停止读取 input (Backpressure)。
                    //    选项2 (为了保命): 丢弃这个包。上游会超时重传 (RTO)。
                    //    
                    //    推荐：丢弃这个包 (Drop Tail)。
                    //    因为如果是本地链路，极少会出现缓冲几百兆还没补齐缺口的情况。
                    //    如果真出现了，说明连接已经坏了，触发 RTO 是合理的。
                    // }

                    state.buffer.insert(seq, packet);
                }
            }
        });
    }

    pub fn get_local_inet(&self) -> Option<Ipv4Inet> {
        Some(self.local_inet)
    }

    fn is_smoltcp_enabled(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl NicPacketFilter for TcpProxy {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        debug!(
            "[try_process_packet_from_nic] filtering packet: {:?}",
            zc_packet
        );

        let Some(my_ipv4_inet) = self.get_local_inet() else {
            return false;
        };
        let my_ipv4 = my_ipv4_inet.address();

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_source() != my_ipv4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

        let mut src_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_source(),
            tcp_packet.get_source(),
        ));
        let mut dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));

        if self.is_smoltcp_enabled() {
            let src = src_addr;

            let is_tcp_syn = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0;
            let is_tcp_ack = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::ACK != 0;
            if is_tcp_syn && !is_tcp_ack {
                let dest_ip = ip_packet.get_destination();
                let dest_port = tcp_packet.get_destination();
                let mapped_dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));
                let real_dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));

                let old_val = self
                    .syn_map
                    .insert(src, Arc::new(NatDstEntry::new(src, real_dst, mapped_dst)));
                tracing::info!(src = ?src, ?real_dst, ?mapped_dst, old_entry = ?old_val, "tcp syn received");
            }

            if let Some(sender) = &self.smoltcp_stack_sender {
                debug!("[ShortCircuit] {:?}", zc_packet);
                let mut packet = ZCPacket::new_with_payload(&[]);
                mem::swap(zc_packet, &mut packet);
                if let Err(e) = sender.send(packet).await {
                    tracing::error!("[ShortCircuit] failed to send packet to smoltcp: {:?}", e);
                }
                return true;
            }

            unreachable!()
        }

        unreachable!()
    }
}

pub fn spin(duration: Duration) {
    let start = Instant::now();
    while start.elapsed() < duration {
        std::hint::spin_loop();
    }
}

// --- VPN 客户端 ---
async fn run_vpn_client(
    server_addr: SocketAddr,
    tun_ip: Ipv4Addr,
    smoltcp: bool,
    test: bool,
) -> Result<()> {
    // run_stream_monitor();

    // 1. 创建 TUN
    let mut config = tun::Configuration::default();
    config
        .layer(Layer::L3)
        .tun_name("qs-client")
        .address(tun_ip)
        .netmask((255, 255, 255, 0))
        .mtu(TUN_MTU)
        .up();

    let tun_dev = tun::create_as_async(&config).context("创建 TUN 失败")?;
    println!("🚀 Client TUN 启动: {}", tun_ip);

    // 2. 连接 QUIC
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(addr)?;
    let mut endpoint = quinn::Endpoint::new(
        endpoint_config(),
        Some(server_config()),
        socket,
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config());

    println!("⏳ 连接服务端 {}...", server_addr);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    println!("✅ 连接成功，开始转发 IP 包...");

    // 3. 配置路由 (提示用户)
    println!("⚠️  现在请手动修改路由表，将流量指向 TUN 网卡，例如:");
    println!("   ip route add 8.8.8.8 dev tun0 (测试用)");
    println!("   或者配置默认路由 (小心不要把连 VPS 的流量也路由进去了!)");

    if smoltcp {
        println!("✨ 模式: 启用 smoltcp (TCP over Streams, UDP over Datagrams)");

        // =========================================================
        // 新增代码：配置 netstack-smoltcp
        // =========================================================

        // 1. 构建网络栈
        // enable_tcp: 拦截并处理 TCP
        // enable_icmp: 允许 ping 通 tun 网卡 (可选)
        // enable_udp: 暂时关闭，除非你也要处理 UDP socket
        let (stack, runner, _udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_icmp(true)
            .enable_udp(false)
            // stack_buffer_size 对应 Stack 内部的 channel，不要设太大，1024-2048 足够
            .stack_buffer_size(2048)
            // tcp_buffer_size 对应每个 Socket 的接收窗口，大流量下建议加大
            .tcp_buffer_size(1024 * 1024)
            .build()
            .context("构建网络栈失败")?;

        // 2. 启动栈的驱动器 (Runner)
        // 这是一个必须在后台运行的 Future，用于驱动 smoltcp 的 poll 循环
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        // 3. 获取 TCP 监听器 (拦截到的所有 TCP 连接都会出现在这里)
        let mut tcp_listener = tcp_listener.context("TCP 未启用")?;

        // 4. 建立数据泵 (Data Pump): 连接 TUN 和 Stack
        // TUN 和 Stack 都需要拆分成 Read/Write (Stream/Sink)
        let has_packet_info = cfg!(target_os = "macos");
        let (tun_read, tun_write) = BiLock::new(tun_dev);
        let fd = TunnelWrapper::new(
            TunStream::new(tun_read, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: tun_write },
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );
        let mut fd = Box::new(fd) as Box<dyn Tunnel>;
        let (mut tun_stream, mut tun_sink) = fd.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);
        let tcp_proxy = TcpProxy {
            smoltcp_stack_sender: Some(smoltcp_stack_sender),
            smoltcp_stack_receiver: AtomicCell::new(Some(smoltcp_stack_receiver)),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            local_inet: Ipv4Inet::new(tun_ip.into(), 24)?,
            syn_map: SynSockMap::new(DashMap::new()),
        };

        let stack_sink: Box<dyn Sink<AnyIpPktFrame, Error = std::io::Error> + Send + Unpin> =
            Box::new(stack_sink);
        tcp_proxy.run(stack_sink.into());

        let tcp_proxy = Arc::new(tcp_proxy);

        // 任务 A: TUN -> Stack (读取操作系统发来的 IP 包 -> 写入用户态协议栈)
        tokio::spawn(async move {
            let stream = tun_stream;
            const MAX_CONCURRENT_PACKETS: usize = 2048;

            stream
                .for_each_concurrent(MAX_CONCURRENT_PACKETS, |ret| {
                    let tcp_proxy = tcp_proxy.clone();
                    async move {
                        // parallel: sensible to random latency
                        sleep(Duration::from_micros(
                            StdRng::from_entropy().gen_range(0..=3_000),
                        ))
                        .await;
                        // sleep(Duration::from_micros(3_000)).await;
                        match ret {
                            Ok(mut packet) => {
                                if tcp_proxy.try_process_packet_from_nic(&mut packet).await {
                                    return;
                                }
                                unreachable!();
                            }
                            Err(e) => {
                                // 读取错误通常是致命的或者偶发的，记录日志即可
                                tracing::error!("read from nic failed: {:?}", e);
                            }
                        }
                    }
                })
                .await;
        });

        // tokio::spawn(async move {
        //     let mut stream = tun_stream;
        //     let tcp_proxy = tcp_proxy.clone();
        //
        //     while let Some(Ok(mut packet)) = stream.next().await {
        //         // serial: extremely sensible to latency, fixed or random
        //         // tokio::task::yield_now().await;
        //         // sleep(Duration::from_micros(1)).await;
        //         spin(Duration::from_micros(1));
        //         if tcp_proxy.try_process_packet_from_nic(&mut packet).await {
        //             continue;
        //         }
        //         unreachable!();
        //     }
        // });

        // tokio::spawn(async move {
        //     const BUFFER_SIZE: usize = 2048;
        //     let mut stream = tun_stream;
        //     let tcp_proxy = tcp_proxy.clone();
        //
        //     stream
        //         .map(|ret| {
        //             let tcp_proxy = tcp_proxy.clone();
        //
        //             async move {
        //                 let Ok(mut packet) = ret else {
        //                     return;
        //                 };
        //
        //                 // buffered serial: sensible to random latency
        //                 sleep(Duration::from_micros(StdRng::from_entropy().gen_range(0..=3_000))).await;
        //                 if tcp_proxy.try_process_packet_from_nic(&mut packet).await {
        //                     return;
        //                 }
        //
        //                 unreachable!();
        //             }
        //         })
        //         .buffered(BUFFER_SIZE)
        //         .for_each(|_| async {})
        //         .await;
        // });

        let (nic_channel, peer_packet_receiver) = channel(128); // unused

        let mut tasks = JoinSet::new();
        let peer_packet_receiver = Mutex::new(peer_packet_receiver);
        let peer_packet_counter = AtomicU64::new(0);
        let (nic_channel_2, peer_packet_receiver_2) = channel(128);
        let peer_packet_receiver_2 = Mutex::new(peer_packet_receiver_2);
        let peer_packet_counter_2 = AtomicU64::new(0);

        // 任务 B: Stack -> TUN (协议栈产生的 IP 包，如 SYN-ACK -> 写入 TUN 让操作系统接收)
        tokio::spawn(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(frame) => {
                        let packet = ZCPacket::new_with_payload(frame.as_ref());
                        if let Err(e) = nic_channel_2.send(packet).await {
                            eprintln!("写入 channel 失败: {}", e);
                            break;
                        }
                    }
                    Err(e) => eprintln!("Stack 读取错误: {}", e),
                }
            }
        });

        NicCtx::do_forward_peers_to_nic_inner(
            tun_sink.into(),
            &mut tasks,
            peer_packet_counter.into(),
            peer_packet_counter_2.into(),
            peer_packet_receiver.into(),
            peer_packet_receiver_2.into(),
        );

        // 5. 处理拦截到的 TCP 连接
        // 这个循环会源源不断地吐出新的 TcpStream
        while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
            // local_addr: 发起请求的源地址 (例如 10.0.0.2:54321)
            // remote_addr: 用户想要访问的目标地址 (例如 1.1.1.1:80)

            println!("^ 捕获 TCP: {} -> {}", local_addr, remote_addr);

            let stream = Monitored::new(
                stream,
                format!("TCP FROM: {}", local_addr).as_str(),
                Content::Byte,
            );

            let connection = connection.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client_stream(connection, stream, remote_addr, test).await {
                    eprintln!("流处理错误: {}", e);
                }
            });
        }

        Ok(())
    } else {
        panic!("✨ 模式: 原生转发 (All over Datagrams)");
    }
}

// 抽离出的流处理逻辑
async fn handle_client_stream(
    conn: quinn::Connection,
    mut tun_stream: impl AsyncRead + AsyncWrite + Unpin,
    target_addr: SocketAddr,
    test: bool,
) -> Result<()> {
    // 1. 在 QUIC 隧道中开启一个新的流
    let (mut send_quic, recv_quic) = conn.open_bi().await?;

    if test {
        // === 模式 B: 测试 quic_proxy 逻辑 ===
        // 构造 ProxyDstInfo
        let proxy_info = ProxyDstInfo {
            dst_addr: Some(target_addr.into()),
        };
        // 序列化
        let mut buf = Vec::new();
        proxy_info.encode(&mut buf)?;

        let len = buf.len() as u8; // 注意：quic_proxy 使用 u8 长度前缀

        // 发送: [u8 Length] [Protobuf Bytes]
        send_quic
            .write_u8(len)
            .await
            .context("failed to write len")?;
        send_quic
            .write_all(&buf)
            .await
            .context("failed to write proxy dst info")?;

        println!("  -> [Test] Sent ProxyDstInfo to {}", target_addr);
    } else {
        // === 模式 A: 原始 qs 逻辑 ===
        // 2. 握手: 告诉服务端目标地址
        write_dst_addr(&mut send_quic, &target_addr.to_string()).await?;
    }

    // 3. 双向转发
    // NetstackTcpStream 实现了 Tokio AsyncRead/AsyncWrite，可以直接 copy
    let quic_stream = join(recv_quic, send_quic);
    let mut quic_stream = Monitored::new(
        quic_stream,
        format!("QUIC TO: {}", target_addr).as_str(),
        Content::Byte,
    );

    // netstack-smoltcp 的流完全兼容 tokio，不需要 compat()
    let _ = tokio::io::copy_bidirectional(&mut tun_stream, &mut quic_stream).await?;

    Ok(())
}
