use bytes::BytesMut;
use derive_more::{Deref, DerefMut, From, Into};
use std::cmp::max;
use std::mem::ManuallyDrop;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct Tagged<I, T> {
    #[deref]
    #[deref_mut]
    pub inner: I,
    pub tag: T,
}

pub(crate) type TaggedSender<I, T> = Tagged<mpsc::Sender<I>, T>;
pub(crate) type TaggedReceiver<I, T> = Tagged<mpsc::Receiver<I>, T>;

#[macro_export]
macro_rules! tagged_channel {
    ($tag:expr, $size:expr) => {{
        let (tx, rx) = tokio::sync::mpsc::channel($size);
        (
            TaggedSender {
                inner: tx,
                tag: $tag,
            },
            TaggedReceiver {
                inner: rx,
                tag: $tag,
            },
        )
    }};
}

pub type SwitchedSender<I> = TaggedSender<I, Arc<AtomicBool>>;
pub type SwitchedReceiver<I> = TaggedReceiver<I, Arc<AtomicBool>>;

impl<I> Tagged<I, Arc<AtomicBool>> {
    pub fn switch(&self) -> &Arc<AtomicBool> {
        &self.tag
    }
}

pub fn switched_channel<I>(size: usize) -> (SwitchedSender<I>, SwitchedReceiver<I>) {
    let switch = Arc::new(AtomicBool::new(true));
    tagged_channel!(switch.clone(), size)
}

#[derive(Debug, Clone, Copy, From, Into)]
pub struct BufMargins {
    pub header: usize,
    pub trailer: usize,
}

impl BufMargins {
    pub fn len(&self) -> usize {
        self.header + self.trailer
    }
}

#[derive(Debug)]
pub(super) struct BufPool {
    pool: BytesMut,
    pub(super) min_capacity: usize,
}

impl BufPool {
    #[inline]
    pub(super) fn new(min_capacity: usize) -> Self {
        Self {
            pool: BytesMut::new(),
            min_capacity,
        }
    }

    pub(super) fn buf(&mut self, data: &[u8], margins: BufMargins) -> BytesMut {
        let len = margins.len() + data.len();

        if len > self.pool.capacity() {
            let additional = max(len * 4, self.min_capacity);
            self.pool.reserve(additional);
            unsafe {
                self.pool.set_len(self.pool.capacity());
            }
        }

        let mut buf = self.pool.split_to(len);
        let (header, trailer) = margins.into();
        buf[header..len - trailer].copy_from_slice(data);
        buf
    }
}

#[derive(Debug, Deref)]
pub(super) struct BufAcc {
    #[deref]
    acc: BytesMut,
    pub(super) capacity: usize,
}

impl BufAcc {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            acc: BytesMut::with_capacity(capacity),
            capacity,
        }
    }

    pub(super) fn buf(&mut self, capacity: usize, margins: BufMargins) -> Option<BufAccWriter<'_>> {
        if self.acc.len() + margins.len() + capacity >= self.acc.capacity() {
            return None;
        }

        let buf = unsafe {
            let ptr = self
                .acc
                .as_mut_ptr()
                .add(self.acc.len())
                .add(margins.header);
            ManuallyDrop::new(Vec::from_raw_parts(ptr, 0, capacity))
        };

        Some(BufAccWriter {
            acc: &mut self.acc,
            ptr: buf.as_ptr(),
            buf,
            capacity,
            margins,
        })
    }

    pub(super) fn renew(&mut self) -> BytesMut {
        std::mem::replace(&mut self.acc, BytesMut::with_capacity(self.capacity))
    }

    pub(super) fn take(self) -> BytesMut {
        self.acc
    }
}

impl From<BufAcc> for BytesMut {
    fn from(value: BufAcc) -> Self {
        value.acc
    }
}

#[derive(Debug, Deref, DerefMut)]
pub(super) struct BufAccWriter<'t> {
    acc: &'t mut BytesMut,
    ptr: *const u8,
    #[deref]
    #[deref_mut]
    buf: ManuallyDrop<Vec<u8>>,
    capacity: usize,
    margins: BufMargins,
}

impl<'t> BufAccWriter<'t> {
    pub(super) fn commit(self) {
        debug_assert!(self.buf.as_ptr() == self.ptr);
        let written = self.buf.len();
        debug_assert!(written <= self.capacity);
        unsafe {
            self.acc
                .set_len(self.acc.len() + self.margins.len() + written)
        };
    }
}
