use std::io::{Error, ErrorKind};
use std::mem::swap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use derive_more::{Deref, DerefMut};
use quinn_proto::{Connection, ConnectionHandle, Event, StreamEvent, StreamId};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::time::sleep;
use tracing::trace;
use crate::gateway::quic::conn::ConnCtrl;
use crate::gateway::quic::endpoint::QuicOutputTx;
use crate::gateway::quic::packet::QuicPacketTx;
use crate::gateway::quic::stream::{QuicStream, QuicStreamTx, StreamDropRx};

pub(super) type RunnerDropTx = mpsc::Sender<ConnectionHandle>;
pub(super) type RunnerDropRx = mpsc::Receiver<ConnectionHandle>;

#[derive(Deref, DerefMut)]
pub(super) struct Runner {
    #[deref]
    #[deref_mut]
    ctrl: ConnCtrl,

    hdl: ConnectionHandle,
    drop_rx: StreamDropRx,
    output: QuicOutputTx,
    drop_tx: RunnerDropTx,
}

impl Runner {
    pub(super) fn new(hdl: ConnectionHandle, conn: Connection, output: QuicOutputTx, drop_tx: RunnerDropTx) -> (ConnCtrl, Self) {
        let (stream_drop_tx, stream_drop_rx) = mpsc::channel(128);
        let ctrl = ConnCtrl::new(conn, stream_drop_tx);
        (
            ctrl.clone(),
            Self {
                ctrl,
                hdl,
                drop_rx: stream_drop_rx,
                output,
                drop_tx,
            },
        )
    }
}

impl Runner {
    pub(super) async fn run(mut self) -> std::io::Result<()> {
        let mut pending_streams = Vec::new();
        let mut pending_packets = Vec::new();
        let mut pending_wakers = Vec::new();
        let mut inbox = Vec::new();
        let mut buf = Vec::new();

        let mut sleep = Box::pin(sleep(Duration::MAX));
        let mut timeout = false;

        loop {
            let is_timeout = select! {
                _ = self.ctrl.notify.notified() => false,
                _ = sleep.as_mut(), if timeout => true,
            };

            swap(&mut *self.inbox.lock(), &mut inbox);

            {
                let mut state = self.ctrl.state.lock();

                for evt in inbox.drain(..) {
                    state.conn.handle_event(evt);
                }

                if is_timeout {
                    state.conn.handle_timeout(Instant::now());
                }

                loop {
                    let id = self.drop_rx.try_recv();
                    match id {
                        Ok(id) => state.close(id),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            return Err(Error::new(
                                ErrorKind::Other,
                                "QUIC stream drop channel disconnected",
                            ));
                        }
                    }
                }

                // === 修复的核心部分开始 ===

                let addr = state.conn.remote_address();

                while let Some(evt) = state.conn.poll() {
                    match evt {
                        Event::HandshakeDataReady => {}
                        Event::Connected => {
                            trace!("Connection to {:?} established", addr);
                        }
                        Event::ConnectionLost { .. } => {
                            return Err(Error::new(
                                ErrorKind::ConnectionReset,
                                "QUIC connection lost",
                            ));
                        }
                        Event::Stream(stream_evt) => match stream_evt {
                            StreamEvent::Opened { dir } => {
                                if !self.output.stream.switch().load(Ordering::Relaxed) {
                                    continue;
                                }
                                while let Some(id) = state.conn.streams().accept(dir) {
                                    trace!(
                                        "Accepted new stream: {:?} on connection to {:?}",
                                        id, addr
                                    );
                                    // 放入待发送队列，稍后异步发送
                                    pending_streams.push(id);
                                }
                            }
                            StreamEvent::Readable { id } => {
                                if let Some(waker) = state.readers.remove(&id) {
                                    pending_wakers.push(waker);
                                }
                            }
                            StreamEvent::Writable { id } => {
                                if let Some(waker) = state.writers.remove(&id) {
                                    pending_wakers.push(waker);
                                }
                            }
                            _ => {}
                        },
                        Event::DatagramReceived => {}
                        Event::DatagramsUnblocked => {}
                    }
                }

                while let Some(transmit) = {
                    buf.clear();
                    state.conn.poll_transmit(Instant::now(), 1, &mut buf)
                } {
                    let packet = self.output.packet.pack_transmit(transmit, &mut buf);
                    pending_packets.push(packet);
                }

                match state.conn.poll_timeout() {
                    Some(deadline) => {
                        sleep.as_mut().reset(deadline.into());
                        timeout = true;
                    }
                    None => {
                        timeout = false;
                    }
                }
            }

            // 3. 异步块：无锁状态，执行 await 操作
            for id in pending_streams.drain(..) {
                if let Err(e) = self
                    .output
                    .stream
                    .try_send(QuicStream::new(id, self.ctrl.clone()))
                {
                    trace!("Failed to send QUIC stream to network: {:?}", e);
                }
            }

            for waker in pending_wakers.drain(..) {
                waker.wake();
            }

            for packet in pending_packets.drain(..) {
                if let Err(e) = self.output.packet.try_send(packet) {
                    trace!("Failed to send QUIC packet to network: {:?}", e);
                }
            }
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.drop_tx.try_send(self.hdl);
    }
}