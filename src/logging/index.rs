use std::sync::atomic::{AtomicU64, Ordering};

pub struct Index {
    entries: AtomicU64,
    bytes_written: AtomicU64,
}

impl Index {
    pub fn new() -> Self {
        Self {
            entries: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    pub fn record_append(&self, bytes: u64) {
        self.entries.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.entries.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
    }
}
