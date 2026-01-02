use crate::gateway::quic::cmd::{QuicCmd, QuicPacket, QuicStreamInfo};
use crate::gateway::quic::evt::{
    QuicNetEvt, QuicNetEvtSender, QuicStreamEvt, QuicStreamEvtReceiver, QuicStreamEvtSender,
};
use anyhow::{anyhow, Error};
use bytes::{Bytes, BytesMut};
use quinn_plaintext::client_config;
use quinn_proto::{
    ClientConfig, ConnectError, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, Event,
    ReadError, StreamEvent, StreamId,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::log::trace;
use tracing::{error, warn};

const QUIC_STREAM_EVT_BUFFER: usize = 2048;

pub type QuicStreamPartsSender = mpsc::Sender<(QuicStreamInfo, QuicStreamEvtReceiver)>;
pub type QuicStreamPartsReceiver = mpsc::Receiver<(QuicStreamInfo, QuicStreamEvtReceiver)>;

pub(super) struct QuicDriver {
    conns: HashMap<ConnectionHandle, (Connection, HashMap<StreamId, QuicStreamEvtSender>)>,
    endpoint: Endpoint,
    net_evt_tx: QuicNetEvtSender,
    incoming_stream_tx: QuicStreamPartsSender,
    client_config: ClientConfig,
    buf: Vec<u8>,
}

impl QuicDriver {
    pub fn new(
        endpoint: Endpoint,
        net_evt_tx: QuicNetEvtSender,
        incoming_stream_tx: QuicStreamPartsSender,
    ) -> Self {
        Self {
            conns: HashMap::new(),
            endpoint,
            net_evt_tx,
            incoming_stream_tx,
            client_config: client_config(),
            buf: Vec::with_capacity(2048),
        }
    }

    pub fn execute(&mut self, cmd: QuicCmd) {
        match cmd {
            QuicCmd::PacketIncoming(packet) => {
                self.handle_packet_incoming(packet);
            }

            QuicCmd::OpenBiStream { addr, stream_tx } => {
                if let Err(e) = stream_tx.send(self.open_stream(addr, Dir::Bi)) {
                    error!("Failed to send opened stream: {:?}", e);
                }
            }

            QuicCmd::StreamWrite {
                stream_info,
                data,
                fin,
            } => {
                self.write_stream(stream_info, data, fin);
            }

            _ => {}
        }
    }
}

macro_rules! emit_transmit {
    ($drv:expr, $transmit:expr) => {
        $drv.net_evt_tx
            .try_send(QuicNetEvt::PacketOutgoing(QuicPacket {
                addr: $transmit.destination,
                data: Bytes::copy_from_slice(&$drv.buf[0..$transmit.size]),
            }))
    };
}

impl QuicDriver {
    fn handle_packet_incoming(&mut self, packet: QuicPacket) {
        let now = Instant::now();

        self.buf.clear();
        match self.endpoint.handle(
            now,
            packet.addr,
            None,
            None,
            BytesMut::from(packet.data),
            &mut self.buf,
        ) {
            Some(DatagramEvent::NewConnection(incoming)) => {
                trace!("New connection from {:?}", incoming.remote_address());

                match self.endpoint.accept(incoming, now, &mut self.buf, None) {
                    Ok((conn_handle, conn)) => {
                        trace!("Accepted connection {:?}", conn_handle);
                        self.conns.insert(conn_handle, (conn, HashMap::new()));
                        self.process_conn(conn_handle);
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e);
                    }
                }
            }

            Some(DatagramEvent::ConnectionEvent(conn_handle, event)) => {
                if let Some((conn, _)) = self.conns.get_mut(&conn_handle) {
                    conn.handle_event(event);
                    self.process_conn(conn_handle);
                }
            }

            Some(DatagramEvent::Response(transmit)) => {
                emit_transmit!(self, transmit).ok();
            }

            None => {}
        }
    }

    fn connect(&mut self, addr: SocketAddr) -> Result<ConnectionHandle, ConnectError> {
        if let Some((conn_handle, _)) = self
            .conns
            .iter()
            .find(|(_, (conn, _))| conn.remote_address() == addr)
        {
            return Ok(*conn_handle);
        }

        let (conn_handle, conn) =
            self.endpoint
                .connect(Instant::now(), self.client_config.clone(), addr, "")?;
        self.conns.insert(conn_handle, (conn, HashMap::new()));
        self.process_conn(conn_handle);
        Ok(conn_handle)
    }

    fn open_stream(
        &mut self,
        addr: SocketAddr,
        dir: Dir,
    ) -> Result<(QuicStreamInfo, QuicStreamEvtReceiver), Error> {
        let conn_handle = self.connect(addr)?;
        let (conn, streams) = self
            .conns
            .get_mut(&conn_handle)
            .ok_or_else(|| anyhow!("Failed to find connection {:?}", conn_handle))?;
        let stream_id = conn
            .streams()
            .open(dir)
            .ok_or_else(|| anyhow!("Failed to open stream"))?;

        let (evt_tx, evt_rx) = mpsc::channel(QUIC_STREAM_EVT_BUFFER);
        streams.insert(stream_id, evt_tx);
        Ok((
            QuicStreamInfo {
                conn_handle,
                stream_id,
            },
            evt_rx,
        ))
    }

    fn write_stream(&mut self, stream_info: QuicStreamInfo, data: Bytes, fin: bool) {
        let conn_handle = stream_info.conn_handle;

        let (conn, _) = match self.conns.get_mut(&conn_handle) {
            Some(c) => c,
            None => {
                warn!(
                    "write_stream ignored: connection {:?} not found",
                    conn_handle
                );
                return;
            }
        };

        let mut stream = conn.send_stream(stream_info.stream_id);

        match stream.write(&*data) {
            Ok(n) if n == data.len() => {
                if fin {
                    if let Err(e) = stream.finish() {
                        error!("Failed to finish stream {:?}: {:?}", stream_info, e);
                    }
                }
            }

            Ok(n) => {
                //TODO: flow control
                error!(
                    "Stream {:?} flow control limit reached ({} < {}), resetting",
                    stream_info,
                    n,
                    data.len()
                );
                stream.reset(0u32.into()).ok();
            }

            Err(e) => {
                error!("Failed to write to stream {:?}: {:?}", stream_info, e);
                stream.reset(0u32.into()).ok();
            }
        }

        self.process_conn(conn_handle);
    }
}

impl QuicDriver {
    fn process_conn(&mut self, conn_handle: ConnectionHandle) {
        let mut rm_conn = false;

        let (conn, streams) = match self.conns.get_mut(&conn_handle) {
            Some(c) => c,
            None => return,
        };

        while let Some(evt) = conn.poll() {
            match evt {
                Event::Connected => {
                    trace!("Connection established {:?}", conn_handle);
                }

                Event::ConnectionLost { reason } => {
                    error!("Connection lost: {:?}", reason);
                    rm_conn = true;
                    for tx in streams.values() {
                        tx.try_send(QuicStreamEvt::Reset(format!(
                            "Connection lost: {:?}",
                            reason.to_string()
                        )))
                        .ok();
                    }
                }

                Event::Stream(stream_evt) => match stream_evt {
                    StreamEvent::Opened { dir } => {
                        while let Some(stream_id) = conn.streams().accept(dir) {
                            trace!(
                                "Accepted new stream: {:?} on connection {:?}",
                                stream_id,
                                conn_handle
                            );

                            let (evt_tx, evt_rx) = mpsc::channel(QUIC_STREAM_EVT_BUFFER);
                            if let Err(e) = self.incoming_stream_tx.try_send((
                                QuicStreamInfo {
                                    conn_handle,
                                    stream_id,
                                },
                                evt_rx,
                            )) {
                                error!("Failed to hand off stream: {:?}", e);
                            } else {
                                streams.insert(stream_id, evt_tx);
                            }
                        }
                    }

                    StreamEvent::Readable { id } => {
                        if let Some(tx) = streams.get_mut(&id) {
                            let mut stream = conn.recv_stream(id);
                            let mut chunks = match stream.read(true) {
                                Ok(chunks) => chunks,
                                Err(e) => {
                                    error!("Stream is not readable: {:?}", e);
                                    continue;
                                }
                            };
                            loop {
                                match chunks.next(usize::MAX) {
                                    Ok(Some(chunk)) => {
                                        tx.try_send(QuicStreamEvt::Data(chunk.bytes)).ok();
                                    }

                                    Ok(None) => break,

                                    Err(e) => {
                                        if let ReadError::Reset(code) = e {
                                            tx.try_send(QuicStreamEvt::Reset(format!(
                                                "Failed to read from stream. Error code: {code}"
                                            )))
                                            .ok();
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    StreamEvent::Finished { id } => {
                        if let Some(tx) = streams.get_mut(&id) {
                            tx.try_send(QuicStreamEvt::Fin).ok();
                        }
                    }

                    StreamEvent::Stopped { id, error_code } => {
                        if let Some(tx) = streams.get_mut(&id) {
                            let _ = tx.try_send(QuicStreamEvt::Reset(format!(
                                "Remote stop: {error_code}"
                            )));
                        }
                    }

                    _ => {}
                },

                _ => {}
            }
        }

        let now = Instant::now();
        loop {
            self.buf.clear();
            if let Some(transmit) = conn.poll_transmit(now, 1, &mut self.buf) {
                emit_transmit!(self, transmit).ok();
            } else {
                break;
            }
        }

        if rm_conn {
            self.conns.remove(&conn_handle);
        }
    }
}

impl QuicDriver {
    pub fn handle_timeout(&mut self) {
        let now = Instant::now();

        let expired_handles: Vec<_> = self
            .conns
            .iter_mut()
            .filter_map(|(conn_handle, (conn, _))| {
                conn.poll_timeout()
                    .and_then(|t| if t <= now { Some(*conn_handle) } else { None })
            })
            .collect();

        for conn_handle in expired_handles {
            if let Some((conn, _)) = self.conns.get_mut(&conn_handle) {
                conn.handle_timeout(now);
            }

            self.process_conn(conn_handle);
        }
    }

    pub fn min_timeout(&mut self) -> Option<Instant> {
        self.conns
            .values_mut()
            .filter_map(|(conn, _)| conn.poll_timeout())
            .min()
    }
}
