use crate::gateway::quic::conn::ConnCtrl;
use crate::gateway::quic::endpoint::QuicOutputTx;
use crate::gateway::quic::stream::QuicStream;
use crate::gateway::quic::utils::BufAcc;
use crate::gateway::quic::QuicPacket;
use derive_more::{Deref, DerefMut};
use quinn_proto::{Connection, Event, StreamEvent};
use std::collections::VecDeque;
use std::io::{Error, ErrorKind};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::select;
use tokio::task::yield_now;
use tokio::time::sleep;
use tracing::error;

#[derive(Debug, Deref, DerefMut)]
pub(super) struct Runner {
    #[deref]
    #[deref_mut]
    ctrl: ConnCtrl,

    output: QuicOutputTx,
}

impl Runner {
    pub(super) fn new(conn: Connection, output: QuicOutputTx) -> (ConnCtrl, Self) {
        let ctrl = ConnCtrl::new(conn);
        (
            ctrl.clone(),
            Self {
                ctrl,
                output,
            },
        )
    }
}

impl Runner {
    pub(super) async fn run(&mut self) -> std::io::Result<()> {
        let mut pending_streams = VecDeque::new();
        let mut pending_wakers = Vec::new();
        let mut pending_transmits = VecDeque::new();
        let mut pending_chunks = VecDeque::new();

        let mut timer = Box::pin(sleep(Duration::MAX));
        let mut timeout: Option<Instant> = None;
        let mut handle_timeout = false;

        // 启动时强制唤醒一次，确保发送握手包
        self.ctrl.notify.notify_one();

        loop {
            let mut worked = false;

            // 2. --- 核心逻辑：处理状态机 ---
            // [修复] 移除之前的 if !inbox.is_empty() || timeout 判断
            // 只要醒来，就必须检查状态机，因为可能需要发送握手包或者重传
            {
                let mut state = self.ctrl.state.lock();
                let now = Instant::now();

                // 处理收到的包
                while let Some(evt) = self.ctrl.inbox.pop() {
                    state.conn.handle_event(evt);
                    worked = true;
                }

                // [Fix]: 即使 select! 没触发，只要时间到了，就必须处理超时
                // 这是修复 "Connection Lost" 的关键：防止在高吞吐下的时间饥饿
                if handle_timeout || timeout.is_some_and(|t| t <= now) {
                    state.conn.handle_timeout(now);
                    handle_timeout = false;
                    worked = true; // 标记为工作过，防止 cpu 空转
                }

                // 处理流开启
                while let Some((dir, tx)) = self.ctrl.open.pop() {
                    let id = state.conn.streams().open(dir).ok_or(Error::other("Failed to open new QUIC stream: exhausted"));
                    if let Err(e) = tx.send(id) {
                        error!("Failed to send stream ID to ctrl: {:?}", e);
                    }
                }

                // 处理流关闭
                while let Some(id) = self.ctrl.close.pop() {
                    state.close(id, false);
                }

                // 驱动状态机 (处理握手、流开启等)
                while let Some(evt) = state.conn.poll() {
                    worked = true; // 状态机有变动，标记为工作过
                    match evt {
                        Event::Stream(StreamEvent::Opened { dir }) => {
                            if self.output.stream.switch().load(Ordering::Relaxed) {
                                while let Some(id) = state.conn.streams().accept(dir) {
                                    pending_streams.push_back(id);
                                }
                            }
                        }
                        Event::Stream(StreamEvent::Readable { id }) => {
                            if let Some(waker) = state.readers.remove(&id) {
                                pending_wakers.push(waker);
                            }
                        }
                        Event::Stream(StreamEvent::Writable { id }) => {
                            if let Some(waker) = state.writers.remove(&id) {
                                pending_wakers.push(waker);
                            }
                        }
                        Event::ConnectionLost { reason } => {
                            return Err(Error::new(ErrorKind::ConnectionReset, format!("Connection lost: {:?}", reason)));
                        }
                        _ => {}
                    }
                }

                // 生成待发送数据包
                let margins = self.output.packet.margins;
                let mut chunk = BufAcc::new(256 * 1200);
                loop {
                    let mut buf = match chunk.buf(
                        state.conn.current_mtu() as usize,
                        margins,
                    ) {
                        Some(buf) => buf,
                        None => {
                            pending_chunks.push_back(chunk.renew());
                            chunk
                                .buf(
                                    state.conn.current_mtu() as usize,
                                    margins,
                                )
                                .unwrap()
                        }
                    };
                    let transmit = state.conn.poll_transmit(Instant::now(), 1, &mut buf);
                    match transmit {
                        None => {
                            if !chunk.is_empty() {
                                pending_chunks.push_back(chunk.take());
                            }
                            break;
                        }
                        Some(transmit) => {
                            buf.commit();
                            pending_transmits.push_back(transmit);
                        }
                    }
                }

                timeout = state.conn.poll_timeout();
            } // 释放 state 锁

            // 3. --- 唤醒应用层 Wakers ---
            for waker in pending_wakers.drain(..) {
                waker.wake();
            }

            // 4. --- 发送阶段：带“接收抢占”的发送 ---
            let (header, trailer) = self.output.packet.margins.into();
            while !pending_transmits.is_empty() || !pending_streams.is_empty() {
                select! {
                    biased;

                    // 发送 Packet
                    res = self.output.packet.reserve(), if !pending_transmits.is_empty() => {
                        match res {
                            Ok(permit) => {
                                let transmit = pending_transmits.pop_front().unwrap();
                                let chunk = pending_chunks.front_mut().unwrap();
                                let data = chunk.split_to(header + transmit.size + trailer);
                                if chunk.is_empty() {
                                    pending_chunks.pop_front();
                                }
                                let packet = QuicPacket::new(transmit.destination, data);
                                permit.send(packet);
                                worked = true;
                            }
                            Err(_) => return Err(Error::new(ErrorKind::BrokenPipe, "Packet channel closed")),
                        }
                    }

                    // 发送 Stream
                    res = self.output.stream.reserve(), if !pending_streams.is_empty() => {
                        match res {
                            Ok(permit) => {
                                permit.send(QuicStream::new(pending_streams.pop_front().unwrap(), self.ctrl.clone()));
                                worked = true;
                            }
                            Err(_) => return Err(Error::new(ErrorKind::BrokenPipe, "Stream channel closed")),
                        }
                    }

                    // 监听接收事件：如果有新包入队，立即停止发送，回去处理接收
                    _ = self.ctrl.notify.notified() => {
                        worked = true;
                        break;
                    }
                }
            }

            yield_now().await;

            // 5. --- 休眠等待 ---
            // 只有当这一轮什么都没干（没发包，没收包，没状态变更）时才睡觉
            if !worked {
                let sleep = match timeout {
                    None => false,
                    Some(deadline) => {
                        if deadline <= Instant::now() {
                            handle_timeout = true;
                            continue; // 直接进入下一轮循环处理超时
                        }
                        timer.as_mut().reset(deadline.into());
                        true
                    }
                };

                select! {
                    _ = self.ctrl.notify.notified() => {}, // 醒来，下一轮循环处理
                    _ = timer.as_mut(), if sleep => handle_timeout = true,
                }
            }
        }
    }
}
