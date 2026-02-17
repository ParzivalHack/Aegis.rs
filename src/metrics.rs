use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

pub struct Metrics {
    requests_per_second: Arc<RwLock<f64>>,
    latency_samples: Arc<RwLock<VecDeque<(Instant, u64)>>>,
    total_requests: Arc<RwLock<u64>>,
    blocked_requests: Arc<RwLock<u64>>,
    flagged_requests: Arc<RwLock<u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_per_second: Arc::new(RwLock::new(0.0)),
            latency_samples: Arc::new(RwLock::new(VecDeque::new())),
            total_requests: Arc::new(RwLock::new(0)),
            blocked_requests: Arc::new(RwLock::new(0)),
            flagged_requests: Arc::new(RwLock::new(0)),
        }
    }

    pub fn record_request(&self, latency_ms: u64, blocked: bool, flagged: bool) {
        let mut total = self.total_requests.write();
        *total += 1;

        if blocked {
            let mut blocked = self.blocked_requests.write();
            *blocked += 1;
        }

        if flagged {
            let mut flagged_count = self.flagged_requests.write();
            *flagged_count += 1;
        }

        let mut samples = self.latency_samples.write();
        let now = Instant::now();
        samples.push_back((now, latency_ms));

        // Keep only last 120 samples
        while samples.len() > 120 {
            samples.pop_front();
        }

        let recent_count = samples
            .iter()
            .filter(|(ts, _)| now.duration_since(*ts) <= Duration::from_secs(1))
            .count() as f64;
        *self.requests_per_second.write() = recent_count;
    }

    pub fn get_avg_latency(&self) -> f64 {
        let samples = self.latency_samples.read();
        if samples.is_empty() {
            return 0.0;
        }

        let sum: u64 = samples.iter().map(|(_, lat)| lat).sum();
        sum as f64 / samples.len() as f64
    }

    pub fn get_total_requests(&self) -> u64 {
        *self.total_requests.read()
    }

    pub fn get_blocked_requests(&self) -> u64 {
        *self.blocked_requests.read()
    }

    pub fn get_requests_per_second(&self) -> f64 {
        *self.requests_per_second.read()
    }

    pub fn get_flagged_requests(&self) -> u64 {
        *self.flagged_requests.read()
    }
}
