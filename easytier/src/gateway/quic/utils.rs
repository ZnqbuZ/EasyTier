use bytes::BytesMut;
use std::cmp::max;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct AtomicSwitch(AtomicBool);

impl AtomicSwitch {
    #[inline]
    pub fn new(value: bool) -> Self {
        Self(AtomicBool::new(value))
    }

    #[inline]
    pub fn set(&self, value: bool) {
        self.0.store(value, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn switch(&self) {
        self.0.fetch_xor(true, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct Switched<T> {
    inner: T,
    pub switch: Arc<AtomicSwitch>,
}

impl<T> Deref for Switched<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Switched<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub type SwitchedReceiver<T> = Switched<mpsc::Receiver<T>>;
pub type SwitchedSender<T> = Switched<mpsc::Sender<T>>;

pub fn switched_channel<T>(buffer: usize) -> (SwitchedSender<T>, SwitchedReceiver<T>) {
    let (tx, rx) = mpsc::channel(buffer);
    let switch = Arc::new(AtomicSwitch::new(true));

    (
        SwitchedSender {
            inner: tx,
            switch: switch.clone(),
        },
        SwitchedReceiver {
            inner: rx,
            switch: switch.clone(),
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub struct QuicBufferMargins {
    pub header: usize,
    pub trailer: usize,
}

impl From<(usize, usize)> for QuicBufferMargins {
    #[inline]
    fn from(tuple: (usize, usize)) -> Self {
        Self {
            header: tuple.0,
            trailer: tuple.1,
        }
    }
}

impl From<QuicBufferMargins> for (usize, usize) {
    #[inline]
    fn from(margins: QuicBufferMargins) -> Self {
        (margins.header, margins.trailer)
    }
}

#[derive(Debug)]
pub(super) struct QuicBufferPool {
    pool: BytesMut,
    min_capacity: usize,
}

impl QuicBufferPool {
    #[inline]
    pub(super) fn new(min_capacity: usize) -> Self {
        Self {
            pool: BytesMut::new(),
            min_capacity,
        }
    }

    pub(super) fn buf(&mut self, data: &[u8], margins: QuicBufferMargins) -> BytesMut {
        let (header, trailer) = margins.into();

        let len = header + data.len() + trailer;
        
        if len > self.pool.capacity() {
            let additional = max(len * 4, self.min_capacity);
            self.pool.reserve(additional);
            unsafe {
                self.pool.set_len(self.pool.len() + self.pool.capacity());
            }
        }
        
        let mut buf = self.pool.split_to(len);
        buf[header..len - trailer].copy_from_slice(data);
        buf
    }
}
