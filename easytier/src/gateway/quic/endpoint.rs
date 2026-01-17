use crate::gateway::quic::conn::ConnCtrl;
use crate::gateway::quic::packet::{PacketPool, QuicPacketMargins, QuicPacketRx, QuicPacketTx};
use crate::gateway::quic::runner::Runner;
use crate::gateway::quic::stream::{QuicStream, QuicStreamRx, QuicStreamTx};
use crate::gateway::quic::utils::switched_channel;
use crate::gateway::quic::QuicPacket;
use bytes::BytesMut;
use dashmap::DashMap;
use derive_more::Debug;
use derive_more::{Constructor, Deref, DerefMut};
use parking_lot::Mutex;
use quinn_plaintext::{client_config, server_config};
use quinn_proto::congestion::BbrConfig;
use quinn_proto::{
    AcceptError, ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Incoming, TransportConfig, VarInt,
};
use std::cell::RefCell;
use std::io::{Error, ErrorKind, Result};
use std::mem::take;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, trace};

type RunnerTx = mpsc::UnboundedSender<RunnerGuard>;
type RunnerRx = mpsc::UnboundedReceiver<RunnerGuard>;

#[derive(Debug, Constructor)]
struct RunnerGuard {
    hdl: ConnectionHandle,
    #[debug(skip)]
    ctrls: Arc<DashMap<ConnectionHandle, ConnCtrl>>,
    addr: SocketAddr,
    #[debug(skip)]
    conns: Arc<DashMap<SocketAddr, ConnectionHandle>>,
    runner: Runner,
}

impl Drop for RunnerGuard {
    fn drop(&mut self) {
        self.ctrls.remove(&self.hdl);
        self.conns.remove(&self.addr);
    }
}

#[derive(Debug)]
struct Driver {
    tasks: JoinSet<()>,
    rx: RunnerRx,
}

impl Driver {
    fn new() -> (RunnerTx, Self) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            tx,
            Self {
                tasks: JoinSet::new(),
                rx,
            },
        )
    }
    async fn run(&mut self) {
        while let Some(mut guard) = self.rx.recv().await {
            self.tasks.spawn(async move {
                let res = guard.runner.run().await;
                if let Err(e) = res {
                    if !guard.runner.shutdown.load(Ordering::Relaxed) {
                        error!("Runner exited with error: {:?}", e);
                    }
                }
            });
        }
        info!("Driver exited.");
    }
}

#[derive(Debug)]
pub struct QuicOutputRx {
    pub packet: QuicPacketRx,
    pub stream: QuicStreamRx,
}

#[derive(Debug, Clone)]
pub(super) struct QuicOutputTx {
    pub(super) packet: QuicPacketTx,
    pub(super) stream: QuicStreamTx,
}

thread_local! {
    pub(super) static BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(65535));
    pub(super) static PACKET_POOL: RefCell<PacketPool> = RefCell::new(PacketPool::new());
}

#[derive(Deref, DerefMut)]
struct BufferGuard(Vec<u8>);

impl BufferGuard {
    fn new() -> Self {
        let mut buf = BUFFER.take();
        buf.clear();
        Self(buf)
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        BUFFER.set(take(&mut self.0));
    }
}

#[derive(Debug)]
pub struct QuicEndpoint {
    endpoint: Mutex<Endpoint>,
    client_config: ClientConfig,
    driver: RunnerTx,
    ctrls: Arc<DashMap<ConnectionHandle, ConnCtrl>>,
    conns: Arc<DashMap<SocketAddr, ConnectionHandle>>,
    output: QuicOutputTx,
}

impl QuicEndpoint {
    pub fn new(packet_margins: QuicPacketMargins) -> (Self, QuicOutputRx) {
        let mut transport_config = TransportConfig::default();

        transport_config.initial_mtu(1200);
        transport_config.min_mtu(1200);

        transport_config.stream_receive_window(VarInt::from_u32(10 * 1024 * 1024));
        transport_config.receive_window(VarInt::from_u32(15 * 1024 * 1024));

        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1024));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(1024));

        transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));

        transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
        transport_config.max_idle_timeout(Some(VarInt::from_u32(3_000).into()));

        transport_config.enable_segmentation_offload(false);

        transport_config.mtu_discovery_config(None);

        let transport_config = Arc::new(transport_config);

        let mut server_config = server_config();
        server_config.transport = transport_config.clone();

        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.max_udp_payload_size(1200).unwrap();

        let endpoint = Endpoint::new(
            Arc::from(endpoint_config),
            Some(Arc::from(server_config)),
            false,
            None,
        );

        let mut client_config = client_config();
        client_config.transport_config(transport_config.clone());

        Self::with_endpoint(endpoint, client_config, packet_margins)
    }

    #[inline]
    pub fn with_endpoint(
        endpoint: Endpoint,
        client_config: ClientConfig,
        packet_margins: QuicPacketMargins,
    ) -> (Self, QuicOutputRx) {
        let (packet_tx, packet_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = switched_channel(512);
        let output_tx = QuicOutputTx {
            packet: QuicPacketTx::new(packet_tx, packet_margins),
            stream: stream_tx,
        };
        let output_rx = QuicOutputRx {
            packet: packet_rx,
            stream: stream_rx,
        };

        let (runner_tx, mut driver) = Driver::new();
        tokio::spawn(async move { driver.run().await });

        (
            Self {
                endpoint: endpoint.into(),
                client_config,
                driver: runner_tx,
                ctrls: DashMap::new().into(),
                conns: DashMap::new().into(),
                output: output_tx,
            },
            output_rx,
        )
    }

    fn establish(&self, hdl: ConnectionHandle, conn: Connection) -> Result<ConnCtrl> {
        let addr = conn.remote_address();
        let (ctrl, runner) = Runner::new(conn, self.output.clone());
        self.driver
            .send(RunnerGuard::new(
                hdl,
                self.ctrls.clone(),
                addr,
                self.conns.clone(),
                runner,
            ))
            .map_err(|e| Error::other(format!("Failed to send runner to driver: {:?}", e)))?;
        self.ctrls.insert(hdl, ctrl.clone());
        self.conns.insert(addr, hdl);
        Ok(ctrl)
    }

    fn accept(&self, incoming: Incoming) -> Result<()> {
        let addr = incoming.remote_address();
        trace!("Incoming connection from {:?}", addr);
        let mut buf = BufferGuard::new();
        let accept = self
            .endpoint
            .lock()
            .accept(incoming, Instant::now(), &mut buf, None);
        match accept {
            Ok((hdl, conn)) => {
                trace!("Accepted new connection({:?}) from {:?}", hdl, addr);
                self.establish(hdl, conn)?;
                Ok(())
            }
            Err(AcceptError { cause, response }) => {
                if let Some(transmit) = response {
                    let packet = PACKET_POOL.with(|pool| {
                        pool.borrow_mut()
                            .pack_transmit(transmit, &buf, self.output.packet.margins)
                    });
                    let _ = self.output.packet.try_send(packet);
                }
                Err(Error::other(format!(
                    "Failed to accept incoming connection: {:?}",
                    cause
                )))
            }
        }
    }

    fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<ConnCtrl> {
        if let Some(entry) = self.conns.get(&addr) {
            let hdl = *entry;
            drop(entry);
            if let Some(conn) = self.ctrls.get(&hdl) {
                return Ok(conn.clone());
            }
        }

        let (hdl, conn) = self
            .endpoint
            .lock()
            .connect(
                Instant::now(),
                self.client_config.clone(),
                addr,
                server_name,
            )
            .map_err(|e| Error::other(format!("Failed to connect to {:?}: {:?}", addr, e)))?;

        self.establish(hdl, conn)
    }

    pub async fn open(&self, addr: SocketAddr, header: Option<BytesMut>) -> Result<QuicStream> {
        let ctrl = self.connect(addr, "")?;
        let mut stream = ctrl.open(Dir::Bi).await?;
        if let Some(header) = header {
            stream.write_all(&header).await?;
        }
        Ok(stream)
    }

    pub async fn send(&self, addr: SocketAddr, payload: BytesMut) -> Result<()> {
        let now = Instant::now();
        let mut buf = BufferGuard::new();
        let event = self
            .endpoint
            .lock()
            .handle(now, addr, None, None, payload, &mut buf);
        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                if !self.output.stream.switch().load(Ordering::Relaxed) {
                    trace!("Incoming stream channel is closed. Connection dropped.");
                    return Ok(());
                }
                self.accept(incoming)
                    .map_err(|e| Error::other(format!("Failed to accept connection: {:?}", e)))
            }

            Some(DatagramEvent::ConnectionEvent(hdl, evt)) => {
                if let Some(ctrl) = self.ctrls.get(&hdl).map(|ctrl| ctrl.clone()) {
                    ctrl.send(evt);
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::NotFound,
                        format!("Connection handle {:?} not found", hdl),
                    ))
                }
            }

            Some(DatagramEvent::Response(transmit)) => {
                let packet = PACKET_POOL.with(|pool| {
                    pool.borrow_mut()
                        .pack_transmit(transmit, &buf, self.output.packet.margins)
                });
                self.output
                    .packet
                    .send(packet)
                    .await
                    .map_err(|e| Error::other(format!("Failed to send QUIC response: {:?}", e)))
            }

            None => Ok(()),
        }
    }

    // 提取 accept 逻辑，使其接受 &mut Endpoint，以便在持有锁时调用
    fn accept_internal(
        &self,
        endpoint: &mut Endpoint,
        incoming: Incoming,
        buf: &mut Vec<u8>,
    ) -> Result<Option<QuicPacket>> {
        let addr = incoming.remote_address();
        trace!("Incoming connection from {:?}", addr);
        // buf 由调用者提供，以复用内存

        let accept = endpoint.accept(incoming, Instant::now(), buf, None);
        match accept {
            Ok((hdl, conn)) => {
                trace!("Accepted new connection({:?}) from {:?}", hdl, addr);
                self.establish(hdl, conn)?;
                Ok(None)
            }
            Err(AcceptError { cause, response }) => {
                if let Some(transmit) = response {
                    let packet = PACKET_POOL.with(|pool| {
                        pool.borrow_mut()
                            .pack_transmit(transmit, buf, self.output.packet.margins)
                    });
                    return Ok(Some(packet));
                }
                Err(Error::other(format!(
                    "Failed to accept incoming connection: {:?}",
                    cause
                )))
            }
        }
    }

    // 新增：批量发送方法
    pub async fn send_batch(&self, packets: impl IntoIterator<Item = QuicPacket>) -> Result<()> {
        let mut responses = Vec::new();
        let mut buf_guard = BufferGuard::new();
        let buf = &mut buf_guard.0;
        let mut notify = Vec::new();

        // 作用域：持有 endpoint 锁
        {
            let mut endpoint = self.endpoint.lock();
            let now = Instant::now();

            for pkt in packets {
                let event = endpoint.handle(now, pkt.addr, None, None, pkt.payload, buf);
                match event {
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        if !self.output.stream.switch().load(Ordering::Relaxed) {
                            trace!("Incoming stream channel is closed. Connection dropped.");
                            continue;
                        }
                        // 使用 internal 版本，复用锁和 buffer
                        match self.accept_internal(&mut endpoint, incoming, buf) {
                            Ok(Some(resp)) => responses.push(resp),
                            Err(e) => error!("Failed to accept connection in batch: {:?}", e),
                            _ => {}
                        }
                    }
                    Some(DatagramEvent::ConnectionEvent(hdl, evt)) => {
                        if let Some(ctrl) = self.ctrls.get(&hdl).map(|ctrl| ctrl.clone()) {
                            let _ = ctrl.inbox.push(evt);
                            notify.push(hdl);
                        } else {
                            trace!("Connection handle {:?} not found during batch send", hdl);
                        }
                    }
                    Some(DatagramEvent::Response(transmit)) => {
                        let packet = PACKET_POOL.with(|pool| {
                            pool.borrow_mut().pack_transmit(
                                transmit,
                                buf,
                                self.output.packet.margins,
                            )
                        });
                        responses.push(packet);
                    }
                    None => {}
                }
            }
        } // 锁释放

        for hdl in notify {
            if let Some(ctrl) = self.ctrls.get(&hdl).map(|ctrl| ctrl.clone()) {
                ctrl.notify.notify_one();
            }
        }

        // 异步发送所有响应包
        for pkt in responses {
            self.output
                .packet
                .send(pkt)
                .await
                .map_err(|e| Error::other(format!("Failed to send QUIC response: {:?}", e)))?;
        }
        Ok(())
    }
}

impl Drop for QuicEndpoint {
    fn drop(&mut self) {
        self.ctrls.alter_all(|_, ctrl| {
            ctrl.shutdown();
            ctrl
        })
    }
}
