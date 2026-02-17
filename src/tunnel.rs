use crate::config::CloudflareTunnelConfig;
use crate::errors::AegisError;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::io::{BufRead, BufReader};
use std::thread;

pub struct TunnelManager {
    config: CloudflareTunnelConfig,
    process: Arc<Mutex<Option<Child>>>,
    public_url: Arc<Mutex<Option<String>>>,
}

impl TunnelManager {
    pub fn new(config: &CloudflareTunnelConfig) -> Self {
        Self {
            config: config.clone(),
            process: Arc::new(Mutex::new(None)),
            public_url: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(&self) -> Result<(), AegisError> {
        let mut process_guard = self.process.lock().unwrap();
        if process_guard.is_some() {
            return Ok(());
        }

        let cloudflared_path = if self.config.cloudflared_path.is_empty() {
            "cloudflared".to_string()
        } else {
            self.config.cloudflared_path.clone()
        };

        let cloudflared_path_clone = cloudflared_path.clone();
        if std::process::Command::new(&cloudflared_path_clone).arg("--version").output().is_err() {
            return Err(AegisError::TunnelError(format!("cloudflared binary not found at '{}'. Please install it or check the path.", cloudflared_path)));
        }

        // If no token, use quick tunnel (trycloudflare)
        let mut args = vec!["tunnel".to_string()];
        if self.config.token.is_empty() {
            args.push("--url".to_string());
            args.push(self.config.local_url.clone());
        } else {
            args.push("run".to_string());
            args.push("--token".to_string());
            args.push(self.config.token.clone());
        }

        let mut child = Command::new(&cloudflared_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AegisError::TunnelError(format!("Failed to start cloudflared: {}", e)))?;

        let stderr = child.stderr.take().ok_or_else(|| AegisError::TunnelError("Failed to capture stderr".to_string()))?;
        let public_url_arc = self.public_url.clone();

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    log::debug!("cloudflared: {}", line);
                    // Look for the trycloudflare URL - more robust check
                    if line.contains("https://") && line.contains(".trycloudflare.com") {
                        if let Some(start) = line.find("https://") {
                            let remaining = &line[start..];
                            let url = remaining.split_whitespace().next().unwrap_or("");
                            if !url.is_empty() {
                                let mut url_guard = public_url_arc.lock().unwrap();
                                *url_guard = Some(url.to_string());
                                log::info!("Public Tunnel URL captured: {}", url);
                            }
                        }
                    }
                }
            }
        });

        *process_guard = Some(child);
        log::info!("Cloudflare Tunnel initiated");
        Ok(())
    }

    pub fn stop(&self) -> Result<(), AegisError> {
        let mut process = self.process.lock().unwrap();
        if let Some(mut child) = process.take() {
            let _ = child.kill();
            log::info!("Cloudflare Tunnel stopped");
        }
        let mut url_guard = self.public_url.lock().unwrap();
        *url_guard = None;
        Ok(())
    }

    pub fn get_public_url(&self) -> Option<String> {
        self.public_url.lock().unwrap().clone()
    }
    
    pub fn is_active(&self) -> bool {
        self.process.lock().unwrap().is_some()
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
