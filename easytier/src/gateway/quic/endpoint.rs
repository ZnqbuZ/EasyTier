use crate::gateway::quic::conn::ConnCtrl;
use crate::gateway::quic::packet::{QuicPacket, QuicPacketMargins, QuicPacketRx, QuicPacketTx};
use crate::gateway::quic::runner::{Runner, RunnerDropRx, RunnerDropTx};
use crate::gateway::quic::stream::{QuicStream, QuicStreamRx, QuicStreamTx};
use crate::gateway::quic::utils::switched_channel;
use bytes::{Bytes, BytesMut};
use quinn_plaintext::{client_config, server_config};
use quinn_proto::congestion::BbrConfig;
use quinn_proto::{
    AcceptError, ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Incoming, TransportConfig, VarInt,
};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::trace;

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

#[derive(Debug)]
pub struct QuicEndpoint {
    endpoint: Endpoint,
    client_config: ClientConfig,
    ctrls: HashMap<ConnectionHandle, ConnCtrl>,
    conns: HashMap<SocketAddr, ConnectionHandle>,
    tasks: JoinSet<std::io::Result<()>>,
    drop_tx: RunnerDropTx,
    drop_rx: RunnerDropRx,
    tx: QuicOutputTx,
    buf: Vec<u8>,
}

impl QuicEndpoint {
    pub fn new(packet_margins: QuicPacketMargins) -> (Self, QuicOutputRx) {
        let mut server_config = server_config();
        server_config.transport = {
            let mut config = TransportConfig::default();

            config.stream_receive_window(VarInt::from_u32(10 * 1024 * 1024));
            config.receive_window(VarInt::from_u32(15 * 1024 * 1024));

            config.max_concurrent_bidi_streams(VarInt::from_u32(1024));
            config.max_concurrent_uni_streams(VarInt::from_u32(1024));

            config.congestion_controller_factory(Arc::new(BbrConfig::default()));

            config.keep_alive_interval(Some(Duration::from_secs(5)));
            config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

            Arc::new(config)
        };

        let endpoint_config = EndpointConfig::default();

        let endpoint = Endpoint::new(
            Arc::from(endpoint_config),
            Some(Arc::from(server_config)),
            false,
            None,
        );

        Self::with_endpoint(endpoint, client_config(), packet_margins)
    }

    #[inline]
    pub fn with_endpoint(
        endpoint: Endpoint,
        client_config: ClientConfig,
        packet_margins: QuicPacketMargins,
    ) -> (Self, QuicOutputRx) {
        let (packet_tx, packet_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = switched_channel(512);
        let tx = QuicOutputTx {
            packet: QuicPacketTx::new(packet_tx, packet_margins),
            stream: stream_tx,
        };
        let rx = QuicOutputRx {
            packet: packet_rx,
            stream: stream_rx,
        };
        let (drop_tx, drop_rx) = mpsc::channel(128);

        (
            Self {
                endpoint,
                client_config,
                ctrls: HashMap::new(),
                conns: HashMap::new(),
                tasks: JoinSet::new(),
                drop_tx,
                drop_rx,
                tx,
                buf: Vec::new(),
            },
            rx,
        )
    }

    fn establish(&mut self, hdl: ConnectionHandle, conn: Connection) -> ConnCtrl {
        let addr = conn.remote_address();
        let (ctrl, runner) = Runner::new(hdl, conn, self.tx.clone(), self.drop_tx.clone());
        self.ctrls.insert(hdl, ctrl.clone());
        self.conns.insert(addr, hdl);
        self.tasks.spawn(runner.run());
        ctrl
    }

    fn accept(&mut self, incoming: Incoming) -> std::io::Result<()> {
        let addr = incoming.remote_address();
        trace!("Incoming connection from {:?}", addr);
        match self
            .endpoint
            .accept(incoming, Instant::now(), &mut self.buf, None)
        {
            Ok((hdl, conn)) => {
                trace!("Accepted new connection({:?}) from {:?}", hdl, addr);
                self.establish(hdl, conn);
                Ok(())
            }
            Err(AcceptError { cause, response }) => {
                if let Some(transmit) = response {
                    let _ = self.tx.packet.try_send_transmit(transmit, &self.buf);
                }
                Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to accept incoming connection: {:?}", cause),
                ))
            }
        }
    }

    fn connect(&mut self, addr: SocketAddr, server_name: &str) -> Result<ConnCtrl, Error> {
        if let Some(&hdl) = self.conns.get(&addr) {
            if let Some(conn) = self.ctrls.get(&hdl).cloned() {
                return Ok(conn);
            }
        }

        let (hdl, conn) = self
            .endpoint
            .connect(
                Instant::now(),
                self.client_config.clone(),
                addr,
                server_name,
            )
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("Failed to connect to {:?}: {:?}", addr, e),
                )
            })?;

        Ok(self.establish(hdl, conn))
    }

    pub fn open(
        &mut self,
        addr: SocketAddr,
        header: Option<BytesMut>,
    ) -> std::io::Result<QuicStream> {
        let ctrl = self.connect(addr, "")?;
        let stream = ctrl.open(Dir::Bi)?;
        header
            .map(|h| self.send(addr, h))
            .transpose()
            .map_err(|e| {
                ctrl.close(stream.id);
                e
            })?;
        Ok(stream)
    }

    pub fn send(&mut self, addr: SocketAddr, payload: BytesMut) -> std::io::Result<()> {
        let now = Instant::now();
        self.buf.clear();
        match self
            .endpoint
            .handle(now, addr, None, None, payload, &mut self.buf)
        {
            Some(DatagramEvent::NewConnection(incoming)) => {
                if !self.tx.stream.switch().load(Ordering::Relaxed) {
                    trace!("Incoming stream channel is closed. Connection dropped.");
                    return Ok(());
                }
                self.accept(incoming).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to accept connection: {:?}", e),
                    )
                })
            }

            Some(DatagramEvent::ConnectionEvent(hdl, evt)) => {
                if let Some(ctrl) = self.ctrls.get_mut(&hdl).cloned() {
                    ctrl.send(evt);
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::NotFound,
                        format!("Connection handle {:?} not found", hdl),
                    ))
                }
            }

            Some(DatagramEvent::Response(transmit)) => self
                .tx
                .packet
                .try_send_transmit(transmit, &self.buf)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to send QUIC response: {:?}", e),
                    )
                }),

            None => Ok(()),
        }
    }
}
