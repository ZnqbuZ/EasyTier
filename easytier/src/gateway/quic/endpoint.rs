use crate::gateway::quic::cmd::{QuicCmd, QuicCmdSender, QuicPacket};
use crate::gateway::quic::driver::{QuicDriver, QuicStreamPartsReceiver};
use crate::gateway::quic::evt::{QuicNetEvt, QuicNetEvtReceiver};
use crate::gateway::quic::stream::QuicStream;
use anyhow::Error;
use quinn_plaintext::server_config;
use quinn_proto::congestion::BbrConfig;
use quinn_proto::{Endpoint, EndpointConfig, TransportConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::spawn;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

#[derive(Clone)]
struct QuicController {
    cmd_tx: QuicCmdSender,
}

impl QuicController {
    pub fn send(self, packet: QuicPacket) -> Result<(), TrySendError<QuicCmd>> {
        self.cmd_tx.try_send(QuicCmd::PacketIncoming(packet))
    }

    pub async fn connect(self, addr: SocketAddr) -> Result<QuicStream, Error> {
        let (stream_tx, stream_rx) = oneshot::channel();
        self.cmd_tx
            .send(QuicCmd::OpenBiStream { addr, stream_tx })
            .await?;
        let (stream_info, evt_rx) = stream_rx.await??;
        Ok(QuicStream::new(stream_info, evt_rx, self.cmd_tx.clone()))
    }
}

struct QuicPacketReceiver {
    net_evt_rx: QuicNetEvtReceiver,
}

impl QuicPacketReceiver {
    pub async fn recv(mut self) -> Option<QuicPacket> {
        match self.net_evt_rx.recv().await? {
            QuicNetEvt::PacketOutgoing(packet) => Some(packet),
        }
    }
}

struct QuicStreamReceiver {
    cmd_tx: QuicCmdSender,
    incoming_stream_rx: QuicStreamPartsReceiver,
}

impl QuicStreamReceiver {
    pub async fn recv(mut self) -> Option<QuicStream> {
        let (stream_info, evt_rx) = self.incoming_stream_rx.recv().await?;
        Some(QuicStream::new(stream_info, evt_rx, self.cmd_tx.clone()))
    }
}

struct QuicEndpoint {
    endpoint: Option<Endpoint>,
}

impl QuicEndpoint {
    pub fn new() -> Self {
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

        Self {
            endpoint: Some(endpoint),
        }
    }

    pub fn run(&mut self) -> Option<(QuicController, QuicPacketReceiver, QuicStreamReceiver)> {
        self.endpoint.as_ref()?;

        let (cmd_tx, mut cmd_rx) = mpsc::channel(2048);
        let (net_evt_tx, net_evt_rx) = mpsc::channel(2048);
        let (incoming_stream_tx, incoming_stream_rx) = mpsc::channel(128);

        let ctrl = QuicController {
            cmd_tx: cmd_tx.clone(),
        };
        let packet_rx = QuicPacketReceiver { net_evt_rx };
        let stream_rx = QuicStreamReceiver {
            cmd_tx: cmd_tx.clone(),
            incoming_stream_rx,
        };

        let mut drv = QuicDriver::new(
            self.endpoint.take().unwrap(),
            net_evt_tx.clone(),
            incoming_stream_tx.clone(),
        );

        spawn(async move {
            loop {
                match cmd_rx.recv().await {
                    Some(cmd) => match cmd {
                        QuicCmd::PacketIncoming(packet) => {
                            drv.handle_packet_incoming(packet);
                        }

                        QuicCmd::OpenBiStream { addr, stream_tx } => {
                            if let Err(e) = stream_tx
                                .send(drv.open_stream(addr, quinn_proto::Dir::Bi)) {
                                error!("Failed to send opened stream: {:?}", e);
                            }
                        }

                        QuicCmd::StreamWrite { stream_info, data, fin } => {
                            drv.write_stream(stream_info, data, fin);
                        }

                        _ => {}
                    },
                    None => {}
                }
            }
        });

        Some((ctrl, packet_rx, stream_rx))
    }
}
