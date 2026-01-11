use quinn_proto::{Connection, ConnectionEvent, Dir, StreamId, VarInt};
use std::collections::HashMap;
use std::io::{Result, Error, ErrorKind};
use std::iter::chain;
use std::sync::Arc;
use std::task::Waker;
use std::time::Instant;
use derive_more::{Deref, DerefMut};
use parking_lot::Mutex;
use tokio::sync::Notify;
use crate::gateway::quic::stream::{QuicStream, StreamDropTx};

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
        self.conn.streams().open(dir).ok_or(Error::new(
            ErrorKind::Other,
            format!(
                "Failed to open new QUIC stream in direction {:?}: exhausted",
                dir
            ),
        ))
    }

    pub(super) fn accept(&mut self, dir: Dir) -> Result<StreamId> {
        self.conn.streams().accept(dir).ok_or(Error::new(
            ErrorKind::Other,
            format!(
                "Failed to accept new QUIC stream in direction {:?}: no incoming",
                dir
            ),
        ))
    }

    pub(super) fn close(&mut self, id: StreamId) {
        let _ = self.conn.recv_stream(id).stop(VarInt::from_u32(0));
        if let Some(waker) = self.readers.remove(&id) {
            waker.wake();
        }
        let _ = self.conn.send_stream(id).reset(VarInt::from_u32(0));
        if let Some(waker) = self.writers.remove(&id) {
            waker.wake();
        }
    }

    pub(super) fn clear(&mut self) {
        for (_, waker) in chain(self.readers.drain(), self.writers.drain()) {
            waker.wake();
        }
    }

    pub(super) fn destroy(&mut self) {
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

#[derive(Debug, Clone, Deref, DerefMut)]
pub(super) struct SharedConnInbox(Arc<Mutex<Vec<ConnectionEvent>>>);

impl From<Vec<ConnectionEvent>> for SharedConnInbox {
    fn from(inbox: Vec<ConnectionEvent>) -> Self {
        SharedConnInbox(Arc::new(Mutex::new(inbox)))
    }
}

const QUIC_CONN_INBOX_CAPACITY: usize = 1024;

#[derive(Debug, Clone)]
pub(super) struct ConnCtrl {
    pub(super) state: SharedConnState,
    pub(super) inbox: SharedConnInbox,
    pub(super) notify: Arc<Notify>,
    drop_tx: StreamDropTx,
}

impl ConnCtrl {
    pub(super) fn new(conn: Connection, drop_tx: StreamDropTx) -> Self {
        Self {
            state: ConnState::new(conn).into(),
            inbox: SharedConnInbox::from(Vec::with_capacity(QUIC_CONN_INBOX_CAPACITY)),
            notify: Arc::new(Notify::new()),
            drop_tx,
        }
    }

    pub(super) fn send(&self, evt: ConnectionEvent) {
        if let Some(mut inner) = self.state.try_lock() {
            inner.conn.handle_event(evt);
        } else {
            let mut inbox = self.inbox.lock();
            if inbox.len() >= QUIC_CONN_INBOX_CAPACITY {
                return;
            }
            inbox.push(evt);
        }
        self.notify.notify_one();
    }

    pub(super) fn open(&self, dir: Dir) -> Result<QuicStream> {
        let id = self.state.lock().open(dir)?;
        self.notify.notify_one();
        Ok(QuicStream::new(id, self.clone()))
    }

    pub(super) fn close(&self, id: StreamId) {
        match self.state.try_lock() {
            Some(mut state) => state.close(id),
            None => {
                let _ = self.drop_tx.try_send(id);
            }
        }
        self.notify.notify_one();
    }
}
