use crate::gateway::quic::stream::QuicStream;
use crossbeam::queue::{ArrayQueue, SegQueue};
use parking_lot::Mutex;
use quinn_proto::{Connection, ConnectionEvent, Dir, StreamId, VarInt};
use std::collections::HashMap;
use std::io::{Error, Result};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::task::Waker;
use std::time::Instant;
use tokio::sync::{oneshot, Notify};

#[derive(Debug)]
pub(super) struct ConnState {
    pub(super) conn: Connection,
    pub(super) readers: HashMap<StreamId, Waker>,
    pub(super) writers: HashMap<StreamId, Waker>,
}

impl ConnState {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            readers: HashMap::new(),
            writers: HashMap::new(),
        }
    }

    pub(super) fn open(&mut self, dir: Dir) -> Result<StreamId> {
        self.conn.streams().open(dir).ok_or(Error::other(format!(
            "Failed to open new QUIC stream in direction {:?}: exhausted",
            dir
        )))
    }

    pub(super) fn accept(&mut self, dir: Dir) -> Result<StreamId> {
        self.conn.streams().accept(dir).ok_or(Error::other(format!(
            "Failed to accept new QUIC stream in direction {:?}: no incoming",
            dir
        )))
    }

    pub(super) fn close(&mut self, id: StreamId, reset: bool) {
        let _ = self.conn.recv_stream(id).stop(VarInt::from_u32(0));
        if let Some(waker) = self.readers.remove(&id) {
            waker.wake();
        }
        if reset {
            let _ = self.conn.send_stream(id).reset(VarInt::from_u32(0));
        }
        if let Some(waker) = self.writers.remove(&id) {
            waker.wake();
        }
    }

    pub(crate) fn clear(&mut self) {
        for (_, waker) in self.readers.drain().chain(self.writers.drain()) {
            waker.wake();
        }
    }

    pub(crate) fn destroy(&mut self) {
        self.conn.close(
            Instant::now(),
            VarInt::from_u32(1),
            "QUIC connection destroyed".into(),
        );
        self.clear();
    }
}

impl Drop for ConnState {
    fn drop(&mut self) {
        self.destroy();
    }
}

type SharedConnState = Arc<Mutex<ConnState>>;

impl From<ConnState> for SharedConnState {
    fn from(state: ConnState) -> Self {
        Arc::new(Mutex::new(state))
    }
}

// type ConnEvtQueue = Arc<ArrayQueue<ConnectionEvent>>;
type ConnEvtQueue = Arc<SegQueue<ConnectionEvent>>;
type StreamOpenQueue = Arc<SegQueue<(Dir, oneshot::Sender<Result<StreamId>>)>>;
type StreamCloseQueue = Arc<SegQueue<StreamId>>;

const QUIC_CONN_EVT_QUEUE_CAPACITY: usize = 1024;

#[derive(Debug, Clone)]
pub(super) struct ConnCtrl {
    pub(super) state: SharedConnState,
    pub(super) inbox: ConnEvtQueue,
    pub(super) open: StreamOpenQueue,
    pub(super) close: StreamCloseQueue,
    pub(super) notify: Arc<Notify>,
    pub(super) shutdown: Arc<AtomicBool>,
}

impl ConnCtrl {
    pub(super) fn new(conn: Connection) -> Self {
        Self {
            state: ConnState::new(conn).into(),
            // inbox: ArrayQueue::new(QUIC_CONN_EVT_QUEUE_CAPACITY).into(),
            inbox: SegQueue::new().into(),
            open: SegQueue::new().into(),
            close: SegQueue::new().into(),
            notify: Arc::new(Notify::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn send(&self, evt: ConnectionEvent) {
        let _ = self.inbox.push(evt);
        self.notify.notify_one();
    }

    pub(super) async fn open(&self, dir: Dir) -> Result<QuicStream> {
        let (tx, rx) = oneshot::channel();
        self.open.push((dir, tx));
        self.notify.notify_one();
        let id = rx.await.map_err(|e| Error::other(format!("Failed to receive stream ID from runner: {:?}", e)))??;
        Ok(QuicStream::new(id, self.clone()))
    }

    pub(super) fn close(&self, id: StreamId) {
        self.close.push(id);
        self.notify.notify_one();
    }

    pub(super) fn shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_one();
    }
}
