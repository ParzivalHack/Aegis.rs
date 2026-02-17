use std::sync::atomic::{AtomicU64, Ordering};

pub struct Compactor {
    rotations: AtomicU64,
}

impl Compactor {
    pub fn new() -> Self {
        Self {
            rotations: AtomicU64::new(0),
        }
    }

    pub fn record_rotation(&self) {
        self.rotations.fetch_add(1, Ordering::Relaxed);
    }
}
