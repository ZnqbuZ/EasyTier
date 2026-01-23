use anyhow::{Context, Result};
use bytes::BytesMut;
use chrono::Utc;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use easytier::instance::virtual_nic::{NicCtx, TunAsyncWrite, TunStream, TunZCPacketToBytes};
use easytier::proto::common::ProxyDstInfo;
use easytier::tunnel::common::{FramedWriter, TunnelWrapper};
use easytier::tunnel::packet_def::ZCPacket;
use easytier::utils::{run_stream_monitor, Content, Monitored};
use futures::lock::BiLock;
use futures::{Sink, SinkExt, StreamExt};
use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder};
use once_cell::sync::Lazy;
use prost::Message;
use quinn::congestion::BbrConfig;
use quinn::ClientConfig;
use quinn::EndpointConfig;
use quinn::QlogConfig;
use quinn::ServerConfig;
use quinn::TokioRuntime;
use quinn::TransportConfig;
use quinn::VarInt;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng, SeedableRng};
use smoltcp::phy::PcapSink;
use std::fs::File;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{ Arc};
use std::task::Poll;
use std::time::Duration;
use cidr::Ipv4Inet;
use crossbeam::atomic::AtomicCell;
use netlink_sys::AsyncSocketExt;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;
use rand::rngs::StdRng;
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info};
use tun::Layer;
use easytier::common::stun::StunTransport::Tcp;
use easytier::gateway::tcp_proxy::{AddrConnSockMap, NatDstEntry, SynSockMap};
use easytier::peers::NicPacketFilter;
use easytier::tunnel::Tunnel;

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
        Commands::Server { listen } => run_server(listen).await,
        Commands::Client {
            server,
            local,
            target,
        } => run_client(server, local, target).await,
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

impl TcpProxy {
    fn run(&self, mut stack_sink: Pin<Box<impl Sink<AnyIpPktFrame, Error = std::io::Error> + Send + ?Sized + 'static>>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let smoltcp_rx_count = counter.clone();

        let mut smoltcp_stack_receiver = self.smoltcp_stack_receiver.take().unwrap();
        self.tasks.lock().unwrap().spawn(async move {
            while let Some(packet) = smoltcp_stack_receiver.recv().await {
                if let Err(e) = stack_sink.send(packet.payload_bytes().into()).await {
                    tracing::error!("send to smoltcp stack failed: {:?}", e);
                } else {
                    smoltcp_rx_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                return true
            }

            unreachable!()
        }

        unreachable!()
    }
}

// --- VPN 客户端 ---
async fn run_vpn_client(
    server_addr: SocketAddr,
    tun_ip: Ipv4Addr,
    smoltcp: bool,
    test: bool,
) -> Result<()> {
    run_stream_monitor();

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
        /*
        tokio::spawn(async move {
            let stream = tun_stream;
            const MAX_CONCURRENT_PACKETS: usize = 2048;

            stream.for_each_concurrent(MAX_CONCURRENT_PACKETS, |ret| {
                let tcp_proxy = tcp_proxy.clone();
                async move {
                    sleep(Duration::from_micros(StdRng::from_entropy().gen_range(1_000..=3_000))).await;
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
            }).await;
        });
        */

        tokio::spawn(async move {
            let mut stream = tun_stream;
            let tcp_proxy = tcp_proxy.clone();

            while let Some(Ok(mut packet)) = stream.next().await {
                sleep(Duration::from_micros(StdRng::from_entropy().gen_range(1_000..=3_000))).await;
                if tcp_proxy.try_process_packet_from_nic(&mut packet).await {
                    continue;
                }
                unreachable!();
            }
        });

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

// --- 服务端逻辑 ---

async fn run_server(addr: SocketAddr) -> Result<()> {
    // 2. 创建 QUIC Endpoint
    let endpoint = quinn::Endpoint::server(server_config(), addr)?;
    println!("🚀 服务端监听于 UDP: {}", addr);

    // 3. 接受连接
    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            let remote_addr = conn.remote_address();
            println!("+ 新连接来自: {}", remote_addr);

            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("连接握手失败: {}", e);
                    return;
                }
            };

            // 4. 处理该连接中的流
            while let Ok((send_stream, mut recv_stream)) = connection.accept_bi().await {
                tokio::spawn(async move {
                    // 读取协议头：目标地址长度 (u16)
                    let mut len_buf = [0u8; 2];
                    if recv_stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;

                    // 读取目标地址字符串
                    let mut addr_buf = vec![0u8; len];
                    if recv_stream.read_exact(&mut addr_buf).await.is_err() {
                        return;
                    }
                    let target_str = String::from_utf8_lossy(&addr_buf).to_string();

                    println!("  -> 请求代理到: {}", target_str);

                    // 连接目标 TCP
                    match tokio::net::TcpStream::connect(&target_str).await {
                        Ok(mut tcp_stream) => {
                            // if let Err(e) = tcp_stream.set_nodelay(true) {
                            //     eprintln!("  ! 警告: 无法设置 TCP_NODELAY: {}", e);
                            // }

                            // 双向拷贝数据
                            // split TCP stream to use allow separate read/write in copy_bidirectional
                            let mut quic_stream = join(recv_stream, send_stream);

                            // 代理数据：TCP <-> QUIC
                            let _ = tokio::io::copy_bidirectional_with_sizes(
                                &mut tcp_stream,
                                &mut quic_stream,
                                1 << 20,
                                1 << 20,
                            )
                            .await;
                        }
                        Err(e) => {
                            eprintln!("  ! 无法连接到目标 TCP {}: {}", target_str, e);
                        }
                    }
                });
            }
        });
    }

    Ok(())
}

// --- 客户端逻辑 ---

async fn run_client(server_addr: SocketAddr, local_addr: SocketAddr, target: String) -> Result<()> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config());

    println!("⏳ 正在连接到服务端 QUIC {}...", server_addr);

    // 2. 建立 QUIC 连接
    // 在这个简单示例中，我们建立一个长连接供所有 TCP 使用
    // 如果连接断开，需要重启客户端 (生产环境需要重连逻辑)
    let connection = endpoint
        .connect(server_addr, "localhost")?
        .await
        .context("无法连接到服务端")?;

    println!("✅ QUIC 连接已建立");
    println!("🎧 本地 TCP 监听于 {}", local_addr);
    println!("👉 流量转发目标: {}", target);

    // 3. 监听本地 TCP
    let listener = tokio::net::TcpListener::bind(local_addr).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;
        // if let Err(e) = socket.set_nodelay(true) {
        //     eprintln!("无法设置本地 TCP_NODELAY: {}", e);
        // }

        let connection = connection.clone();
        let target = target.clone();

        tokio::spawn(async move {
            // 4. 为每个 TCP 连接打开一个新的 QUIC 流
            match connection.open_bi().await {
                Ok((mut send_stream, recv_stream)) => {
                    // 发送自定义协议头: [len(u16)][address_bytes]
                    let target_bytes = target.as_bytes();
                    let len = target_bytes.len() as u16;

                    if let Err(e) = send_stream.write_all(&len.to_be_bytes()).await {
                        eprintln!("写入长度失败: {}", e);
                        return;
                    }
                    if let Err(e) = send_stream.write_all(target_bytes).await {
                        eprintln!("写入地址失败: {}", e);
                        return;
                    }

                    // 5. 进行双向转发
                    let mut quic_stream = join(recv_stream, send_stream);

                    let _ = tokio::io::copy_bidirectional_with_sizes(
                        &mut socket,
                        &mut quic_stream,
                        1 << 20,
                        1 << 20,
                    )
                    .await;
                }
                Err(e) => eprintln!("打开 QUIC 流失败: {}", e),
            }
        });
    }
}
