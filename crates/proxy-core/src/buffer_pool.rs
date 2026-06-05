use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref GLOBAL_BUFFER_POOL: BufferPool = BufferPool::new();
}

pub struct BufferPool {
    small: ArrayQueue<BytesMut>,
    medium: ArrayQueue<BytesMut>,
    large: ArrayQueue<BytesMut>,
}

const SMALL_MAX: usize = 2_048;
const MEDIUM_MAX: usize = 32_768;
const LARGE_MAX: usize = 524_288;

const SMALL_DEPTH: usize = 64;
const MEDIUM_DEPTH: usize = 64;
const LARGE_DEPTH: usize = 16;

impl BufferPool {
    pub fn new() -> Self {
        Self {
            small: ArrayQueue::new(SMALL_DEPTH),
            medium: ArrayQueue::new(MEDIUM_DEPTH),
            large: ArrayQueue::new(LARGE_DEPTH),
        }
    }

    pub fn acquire(&self, size_hint: usize) -> BytesMut {
        let (pool, min_cap) = if size_hint <= SMALL_MAX {
            (&self.small, SMALL_MAX.max(size_hint))
        } else if size_hint <= MEDIUM_MAX {
            (&self.medium, MEDIUM_MAX.max(size_hint))
        } else {
            (&self.large, size_hint)
        };

        match pool.pop() {
            Some(mut buf) if buf.capacity() >= size_hint => {
                buf.clear();
                buf
            },
            _ => BytesMut::with_capacity(min_cap),
        }
    }

    pub fn release(&self, mut buffer: BytesMut) {
        buffer.clear();
        let cap = buffer.capacity();

        if cap <= SMALL_MAX {
            let _ = self.small.push(buffer);
        } else if cap <= MEDIUM_MAX {
            let _ = self.medium.push(buffer);
        } else if cap <= LARGE_MAX {
            let _ = self.large.push(buffer);
        }
        // If cap > LARGE_MAX, buffer is dropped (not cached)
    }

    pub fn depths(&self) -> (usize, usize, usize) {
        (self.small.len(), self.medium.len(), self.large.len())
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}
