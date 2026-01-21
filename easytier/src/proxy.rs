use anyhow::{Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, Subcommand};
use futures::lock::BiLock;
use futures::{Sink, SinkExt, Stream, StreamExt};
use netstack_smoltcp::{AnyIpPktFrame, StackBuilder, TcpStream as NetstackTcpStream};
use pin_project_lite::pin_project;
use prost::Message;
use quinn::TokioRuntime;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Poll};
use std::time::Duration;
use tokio::io::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::channel;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::poll_write_buf;

use chrono::Utc;
use quinn::congestion::BbrConfig;
use quinn::ClientConfig;
use quinn::EndpointConfig;
use quinn::ServerConfig;
use quinn::TransportConfig;
use quinn::VarInt;
use quinn::QlogConfig;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tracing::{debug, info};
use easytier::instance::virtual_nic::{TunAsyncWrite, TunStream, TunZCPacketToBytes};
use easytier::proto::common::ProxyDstInfo;
use easytier::tunnel::common::FramedWriter;
use easytier::tunnel::packet_def::{ZCPacket, ZCPacketType};
use smoltcp::phy::PcapSink;

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

static NEXT_STREAM_ID: AtomicUsize = AtomicUsize::new(0);
pub static STREAM_MONITOR: Lazy<DashMap<usize, Arc<StreamStats>>> = Lazy::new(|| DashMap::new());

pub fn run_stream_monitor() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            interval.tick().await;

            if STREAM_MONITOR.is_empty() {
                continue;
            }

            println!("--- 实时速率监控 (活跃流: {}) ---", STREAM_MONITOR.len());

            let mut snapshot = Vec::new();

            for item in STREAM_MONITOR.iter() {
                let stats = item.value();
                let curr_rx = stats.total_rx.load(Ordering::Relaxed);
                let curr_tx = stats.total_tx.load(Ordering::Relaxed);
                let curr_pending = stats.total_write_pending.load(Ordering::Relaxed);

                let prev_rx = stats.last_rx.swap(curr_rx, Ordering::Relaxed);
                let prev_tx = stats.last_tx.swap(curr_tx, Ordering::Relaxed);
                let prev_pending = stats.last_write_pending.swap(curr_pending, Ordering::Relaxed);

                let rate_rx = curr_rx.saturating_sub(prev_rx);
                let rate_tx = curr_tx.saturating_sub(prev_tx);
                let delta_pending = curr_pending.saturating_sub(prev_pending);


                snapshot.push((stats.id, stats.name.clone(), rate_rx + rate_tx, rate_rx, rate_tx, delta_pending));
            }

            snapshot.sort_by_key(|k| k.0);

            let to_mbps = |bytes: u64| -> String {
                let bits = bytes as f64 * 8.0;
                let mbps = bits / 1_000_000.0; // 网络常用 1000 进制，如果习惯系统进制可用 1024.0 * 1024.0
                if mbps < 0.01 && bytes > 0 {
                    format!("{:.4} Mbps", mbps) // 极小流量保留更多小数
                } else {
                    format!("{:.2} Mbps", mbps) // 正常保留两位小数
                }
            };

            for (_, tag, total, rx, tx, pending) in snapshot {
                println!("[{}]: {} (Rx: {}, Tx: {}) | Write Blocked: {} s^-1", tag, to_mbps(total), to_mbps(rx), to_mbps(tx), pending);
            }
            println!("--------------------------------");
        }
    });
}

#[derive(Debug)]
pub struct StreamStats {
    pub id: usize,
    pub name: String,        // 标识：如 "192.168.1.5 <-> 8.8.8.8"
    pub total_rx: AtomicU64, // 总接收字节
    pub total_tx: AtomicU64, // 总发送字节
    pub last_rx: AtomicU64,  // 上一次采样的接收字节（用于算速率）
    pub last_tx: AtomicU64,  // 上一次采样的发送字节
    pub total_write_pending: AtomicUsize, // 总共遇到了多少次写阻塞
    pub last_write_pending: AtomicUsize,  // 上一次采样的阻塞次数（用于计算增量）
}

pub struct MonitoredStream<T> {
    inner: T,
    stats: Arc<StreamStats>,
}

impl<T> MonitoredStream<T> {
    pub fn new(inner: T, name: &str) -> Self {
        let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        let stats = Arc::new(StreamStats {
            id,
            name: name.to_string(),
            total_rx: AtomicU64::new(0),
            total_tx: AtomicU64::new(0),
            last_rx: AtomicU64::new(0),
            last_tx: AtomicU64::new(0),
            total_write_pending: AtomicUsize::new(0),
            last_write_pending: AtomicUsize::new(0),
        });
        STREAM_MONITOR.insert(id, stats.clone());
        Self { inner, stats }
    }
}

impl<T> Drop for MonitoredStream<T> {
    fn drop(&mut self) {
        info!("Stream dropped, stats: {:?}", self.stats);
        STREAM_MONITOR.remove(&self.stats.id);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for MonitoredStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        match poll {
            Poll::Ready(Ok(())) => {
                let n = (buf.filled().len() - before) as u64;
                self.stats.total_rx.fetch_add(n, Ordering::Relaxed);
            }
            Poll::Pending => {
                self.stats.total_write_pending.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MonitoredStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.stats.total_tx.fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
                                    let mut real_tcp = MonitoredStream::new(
                                        real_tcp,
                                        format!("TCP TO: {}", target_addr).as_str(),
                                    );

                                    let quic_stream = join(recv_stream, send_stream);
                                    let mut quic_stream = MonitoredStream::new(
                                        quic_stream,
                                        format!("QUIC FROM: {}", remote_addr).as_str(),
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
        let mut tun_read = TunStream::new(tun_read, has_packet_info);
        let mut tun_write = FramedWriter::new_with_converter(
            TunAsyncWrite { l: tun_write },
            TunZCPacketToBytes::new(has_packet_info),
        );
        let (mut stack_sink, mut stack_stream) = stack.split();

        let (packet_tx, packet_rx) = channel(128);

        // 任务 A: TUN -> Stack (读取操作系统发来的 IP 包 -> 写入用户态协议栈)
        tokio::spawn(async move {
            loop {
                match tun_read.next().await {
                    Some(Ok(buf)) => {
                        // stack_sink 需要 Vec<u8>
                        if let Err(e) = packet_tx.send(buf).await {
                            eprintln!("写入 Stack 失败: {}", e);
                            break;
                        }
                    }
                    _ => {
                        eprintln!("读取 TUN 失败");
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            let stream = ReceiverStream::new(packet_rx);
            let mut stream = stream
                .map(|frame| async move {
                    sleep(Duration::from_millis(1)).await;
                    frame
                })
                .buffer_unordered(2048);
            while let Some(frame) = stream.next().await {
                if let Err(e) = stack_sink.send(AnyIpPktFrame::from(frame.payload())).await {
                    eprintln!("写入 channel 失败: {}", e);
                    break;
                }
            }
        });

        let (packet_tx, packet_rx) = channel(128);

        // 任务 B: Stack -> TUN (协议栈产生的 IP 包，如 SYN-ACK -> 写入 TUN 让操作系统接收)
        tokio::spawn(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(frame) => {
                        let packet = ZCPacket::new_with_payload(frame.as_ref());
                        if let Err(e) = packet_tx.send(packet).await {
                            eprintln!("写入 channel 失败: {}", e);
                            break;
                        }
                    }
                    Err(e) => eprintln!("Stack 读取错误: {}", e),
                }
            }
        });

        tokio::spawn(async move {
            let stream = ReceiverStream::new(packet_rx);
            let mut stream = stream
                .map(|frame| async move {
                    sleep(Duration::from_millis(1)).await;
                    frame
                })
                .buffer_unordered(2048);
            while let Some(frame) = stream.next().await {
                if let Err(e) = tun_write.send(frame).await {
                    eprintln!("写入 channel 失败: {}", e);
                    break;
                }
            }
        });

        // 5. 处理拦截到的 TCP 连接
        // 这个循环会源源不断地吐出新的 TcpStream
        while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
            // local_addr: 发起请求的源地址 (例如 10.0.0.2:54321)
            // remote_addr: 用户想要访问的目标地址 (例如 1.1.1.1:80)

            println!("^ 捕获 TCP: {} -> {}", local_addr, remote_addr);

            let stream = MonitoredStream::new(stream, format!("TCP FROM: {}", local_addr).as_str());

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
    let mut quic_stream =
        MonitoredStream::new(quic_stream, format!("QUIC TO: {}", target_addr).as_str());

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
