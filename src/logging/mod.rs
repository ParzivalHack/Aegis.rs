pub mod index;
pub mod compaction;

use crate::detection::models::{Verdict, AttackType};
use crate::errors::AegisError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub verdict: Verdict,
    pub attack_type: AttackType,
    pub confidence: f64,
    pub reasoning: String,
    pub layer: String,
    pub matched_rules: Vec<String>,
    pub severity: String,
    pub payload: String,
    pub response: Option<String>,
    pub latency_ms: u64,
    pub source_ip: Option<String>,
}

pub struct Logger {
    log_file: Arc<Mutex<BufWriter<File>>>,
    log_path: String,
    max_size: u64,
    current_size: Arc<Mutex<u64>>,
    index: index::Index,
    compactor: compaction::Compactor,
}

impl Logger {
    pub fn new(log_path: &str, max_size: u64) -> Result<Self, AegisError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| AegisError::LoggingError(format!("Failed to open log file: {}", e)))?;

        let current_size = file.metadata()
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(Self {
            log_file: Arc::new(Mutex::new(BufWriter::new(file))),
            log_path: log_path.to_string(),
            max_size,
            current_size: Arc::new(Mutex::new(current_size)),
            index: index::Index::new(),
            compactor: compaction::Compactor::new(),
        })
    }

    pub fn log(&self, entry: &LogEntry) -> Result<(), AegisError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| AegisError::LoggingError(format!("Failed to serialize log entry: {}", e)))?;
        
        let line = format!("{}\n", json);
        let line_size = line.len() as u64;

        let mut file = self.log_file.lock().unwrap();
        file.write_all(line.as_bytes())
            .map_err(|e| AegisError::LoggingError(format!("Failed to write log entry: {}", e)))?;
        file.flush()
            .map_err(|e| AegisError::LoggingError(format!("Failed to flush log: {}", e)))?;
        self.index.record_append(line_size);

        let mut current_size = self.current_size.lock().unwrap();
        *current_size += line_size;

        // Check if rotation is needed
        if *current_size >= self.max_size {
            drop(file);
            drop(current_size);
            self.rotate()?;
        }

        Ok(())
    }

    fn rotate(&self) -> Result<(), AegisError> {
        // Close current file
        drop(self.log_file.lock().unwrap());

        // Rename current log
        let backup_path = format!("{}.1", self.log_path);
        std::fs::rename(&self.log_path, &backup_path)
            .map_err(|e| AegisError::LoggingError(format!("Failed to rotate log: {}", e)))?;

        // Open new file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| AegisError::LoggingError(format!("Failed to open new log file: {}", e)))?;

        let mut log_file = self.log_file.lock().unwrap();
        *log_file = BufWriter::new(file);

        let mut current_size = self.current_size.lock().unwrap();
        *current_size = 0;
        self.index.reset();
        self.compactor.record_rotation();

        log::info!("Log file rotated");
        Ok(())
    }

    pub fn query(&self, filters: LogFilters) -> Result<Vec<LogEntry>, AegisError> {
        use std::io::{BufRead, BufReader};
        
        let file = File::open(&self.log_path)
            .map_err(|e| AegisError::LoggingError(format!("Failed to open log for reading: {}", e)))?;
        
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| AegisError::LoggingError(format!("Failed to read line: {}", e)))?;
            
            if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                if filters.matches(&entry) {
                    entries.push(entry);
                }
            }
        }

        // Apply limit
        if let Some(limit) = filters.limit {
            entries.truncate(limit);
        }

        Ok(entries)
    }
}

#[derive(Debug, Default)]
pub struct LogFilters {
    pub verdict: Option<Verdict>,
    pub attack_type: Option<AttackType>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub search_text: Option<String>,
    pub limit: Option<usize>,
}

impl LogFilters {
    fn matches(&self, entry: &LogEntry) -> bool {
        if let Some(verdict) = &self.verdict {
            if entry.verdict != *verdict {
                return false;
            }
        }

        if let Some(attack_type) = &self.attack_type {
            if entry.attack_type != *attack_type {
                return false;
            }
        }

        if let Some(start) = &self.start_time {
            if entry.timestamp < *start {
                return false;
            }
        }

        if let Some(end) = &self.end_time {
            if entry.timestamp > *end {
                return false;
            }
        }

        if let Some(search) = &self.search_text {
            let search_lower = search.to_lowercase();
            if !entry.payload.to_lowercase().contains(&search_lower) &&
               !entry.reasoning.to_lowercase().contains(&search_lower) {
                return false;
            }
        }

        true
    }
}
