use bytes::{Bytes, BytesMut};
use derive_more::{Deref, DerefMut, From, Into};
use std::cmp::{max, min};
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct Tagged<I, T> {
    #[deref]
    #[deref_mut]
    pub inner: I,
    pub tag: T,
}

pub(super) type TaggedSender<I, T> = Tagged<mpsc::Sender<I>, T>;
pub(super) type TaggedReceiver<I, T> = Tagged<mpsc::Receiver<I>, T>;

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
pub struct QuicBufferMargins {
    pub header: usize,
    pub trailer: usize,
}

#[derive(Debug)]
pub(super) struct QuicBufferPool {
    pool: BytesMut,
    pub(crate) min_capacity: usize,
}

impl QuicBufferPool {
    #[inline]
    pub(crate) fn new(min_capacity: usize) -> Self {
        Self {
            pool: BytesMut::new(),
            min_capacity,
        }
    }

    pub(crate) fn buf(&mut self, data: &[u8], margins: QuicBufferMargins) -> BytesMut {
        let (header, trailer) = margins.into();

        let len = header + data.len() + trailer;

        if len > self.pool.capacity() {
            let additional = max(len * 4, self.min_capacity);
            self.pool.reserve(additional);
            unsafe {
                self.pool.set_len(self.pool.capacity());
            }
        }

        let mut buf = self.pool.split_to(len);
        buf[header..len - trailer].copy_from_slice(data);
        buf
    }
}

#[derive(Debug)]
pub(super) struct QuicBytesRingBuf<const length: usize, const size: usize> {
    inner: [MaybeUninit<Bytes>; length],
    head: usize,
    tail: usize,
    pub bytes: usize,
}

impl<const length: usize, const size: usize> QuicBytesRingBuf<length, size> {
    pub fn new() -> Self {
        const { assert!(length > 0 && length <= size); }

        Self {
            inner: unsafe { MaybeUninit::uninit().assume_init() },
            head: 0,
            tail: 0,
            bytes: 0,
        }
    }

    pub fn new_boxed() -> Box<Self> {
        const { assert!(length > 0 && length <= size); }

        let mut b: Box<MaybeUninit<Self>> = Box::new_uninit();
        unsafe {
            b.as_mut_ptr().write(Self {
                inner: MaybeUninit::uninit().assume_init(),
                head: 0,
                tail: 0,
                bytes: 0,
            });
            b.assume_init()
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        if self.head == self.tail {
            debug_assert!(self.bytes == 0);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        (self.tail + 1) % length == self.head || self.bytes >= size
    }

    #[inline]
    pub fn pop_front(&mut self) -> Bytes {
        debug_assert!(!self.is_empty());

        let chunk = unsafe { self.inner[self.head].assume_init_read() };
        self.bytes -= chunk.len();
        self.head = (self.head + 1) % length;
        chunk
    }

    #[inline]
    pub fn pop_back(&mut self) -> Bytes {
        debug_assert!(!self.is_empty());

        self.tail = (self.tail + length - 1) % length;
        let chunk = unsafe { self.inner[self.tail].assume_init_read() };
        self.bytes -= chunk.len();
        chunk
    }

    #[inline]
    pub fn push_front(&mut self, data: Bytes) {
        debug_assert!(!self.is_full());

        self.bytes += data.len();
        self.head = (self.head + length - 1) % length;
        self.inner[self.head].write(data);
    }

    #[inline]
    pub fn push_back(&mut self, data: Bytes) {
        debug_assert!(!self.is_full());

        self.bytes += data.len();
        self.inner[self.tail].write(data);
        self.tail = (self.tail + 1) % length;
    }

    pub fn read(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let bytes = self.bytes;
        while !self.is_empty() && buf.remaining() > 0 {
            let chunk = unsafe { self.inner[self.head].assume_init_mut() };
            let len = min(chunk.len(), buf.remaining());
            self.bytes -= len;
            buf.put_slice(&chunk.split_to(len));
            if chunk.is_empty() {
                self.pop_front();
            } else {
                break;
            }
        }

        bytes - self.bytes
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        if self.is_full() {
            return 0;
        }
        let len = min(buf.len(), size - self.bytes);
        self.push_back(Bytes::copy_from_slice(&buf[..len]));
        len
    }
}

impl<const length: usize, const size: usize> Drop for QuicBytesRingBuf<length, size> {
    #[inline]
    fn drop(&mut self) {
        while !self.is_empty() {
            let _ = self.pop_front();
        }
    }
}
