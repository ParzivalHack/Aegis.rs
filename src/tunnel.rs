use crate::config::ServeoTunnelConfig;
use crate::errors::AegisError;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;

pub struct TunnelManager {
    config: ServeoTunnelConfig,
    process: Arc<Mutex<Option<Child>>>,
    public_url: Arc<Mutex<Option<String>>>,
}

impl TunnelManager {
    pub fn new(config: &ServeoTunnelConfig) -> Self {
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

        // Keep backward compatibility with old default values.
        // If `ssh_path` is empty or still set to "cloudflared", use system ssh.
        let ssh_path = if self.config.ssh_path.trim().is_empty()
            || self.config.ssh_path.trim().eq_ignore_ascii_case("cloudflared")
        {
            "ssh".to_string()
        } else {
            self.config.ssh_path.clone()
        };

        if std::process::Command::new(&ssh_path).arg("-V").output().is_err() {
            return Err(AegisError::TunnelError(format!(
                "ssh binary not found at '{}'. Install OpenSSH client or configure [serveo_tunnel].ssh_path with your ssh path.",
                ssh_path
            )));
        }

        let (local_host, local_port) = parse_local_target(&self.config.local_url)?;
        let desired_subdomain = sanitize_subdomain(&self.config.token);
        let mut candidates = Vec::new();
        if let Some(sub) = desired_subdomain {
            candidates.push(format!("{}:80:{}:{}", sub, local_host, local_port));
        }
        candidates.push(format!("80:{}:{}", local_host, local_port));

        let mut last_start_error = String::new();

        for remote_spec in candidates {
            let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
            let public_url_arc = self.public_url.clone();
            let public_url_arc_err = self.public_url.clone();

            let mut child = Command::new(&ssh_path)
                .arg("-T")
                .arg("-o")
                .arg("ExitOnForwardFailure=yes")
                .arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("ServerAliveInterval=30")
                .arg("-R")
                .arg(&remote_spec)
                .arg("serveo.net")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| AegisError::TunnelError(format!("Failed to start Serveo tunnel via ssh: {}", e)))?;

            let stdout = child.stdout.take().ok_or_else(|| AegisError::TunnelError("Failed to capture ssh stdout".to_string()))?;
            let stderr = child.stderr.take().ok_or_else(|| AegisError::TunnelError("Failed to capture ssh stderr".to_string()))?;
            let url_tx_out = url_tx.clone();

            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        log::debug!("serveo(stdout): {}", line);
                        if let Some(url) = extract_serveo_url(&line) {
                            let mut url_guard = public_url_arc.lock().unwrap();
                            *url_guard = Some(url.clone());
                            let _ = url_tx_out.send(url.clone());
                            log::info!("Serveo tunnel URL captured: {}", url);
                        }
                    }
                }
            });

            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        log::debug!("serveo(stderr): {}", line);
                        if line.to_lowercase().contains("request a particular subdomain") {
                            log::warn!("Serveo custom subdomain requires registered SSH key. Falling back to assigned URL.");
                        }
                        if let Some(url) = extract_serveo_url(&line) {
                            let mut url_guard = public_url_arc_err.lock().unwrap();
                            *url_guard = Some(url.clone());
                            let _ = url_tx.send(url.clone());
                            log::info!("Serveo tunnel URL captured: {}", url);
                        }
                    }
                }
            });

            match url_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(url) => {
                    *process_guard = Some(child);
                    log::info!(
                        "Serveo tunnel initiated ({} -> {}:{}) at {}",
                        remote_spec,
                        local_host,
                        local_port,
                        url
                    );
                    return Ok(());
                }
                Err(_) => {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            last_start_error = format!(
                                "Serveo tunnel exited early with status {} while starting forward {}",
                                status, remote_spec
                            );
                        }
                        Ok(None) => {
                            last_start_error = format!(
                                "Serveo tunnel started but no URL was emitted within timeout for forward {}",
                                remote_spec
                            );
                        }
                        Err(e) => {
                            last_start_error = format!("Failed checking Serveo process state: {}", e);
                        }
                    }

                    let _ = child.kill();
                }
            }
        }

        Err(AegisError::TunnelError(if last_start_error.is_empty() {
            "Unable to establish Serveo tunnel after retries".to_string()
        } else {
            last_start_error
        }))
    }

    pub fn stop(&self) -> Result<(), AegisError> {
        let mut process = self.process.lock().unwrap();
        if let Some(mut child) = process.take() {
            let _ = child.kill();
            log::info!("Serveo tunnel stopped");
        }
        let mut url_guard = self.public_url.lock().unwrap();
        *url_guard = None;
        Ok(())
    }

    pub fn get_public_url(&self) -> Option<String> {
        self.public_url.lock().unwrap().clone()
    }
    
    pub fn is_active(&self) -> bool {
        let mut guard = self.process.lock().unwrap();
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => {
                    *guard = None;
                    let mut url_guard = self.public_url.lock().unwrap();
                    *url_guard = None;
                    false
                }
                Ok(None) => true,
                Err(_) => true,
            }
        } else {
            false
        }
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn parse_local_target(local_url: &str) -> Result<(String, u16), AegisError> {
    let parsed = reqwest::Url::parse(local_url)
        .map_err(|e| AegisError::TunnelError(format!("Invalid local_url '{}': {}", local_url, e)))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| AegisError::TunnelError(format!("local_url '{}' has no host", local_url)))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| AegisError::TunnelError(format!("local_url '{}' has no port", local_url)))?;

    Ok((host, port))
}

fn sanitize_subdomain(raw: &str) -> Option<String> {
    let mut cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_lowercase();

    cleaned = cleaned.trim_matches('-').to_string();

    // Ignore obviously invalid leftovers (e.g. legacy long opaque cloudflared token).
    if cleaned.len() < 3 || cleaned.len() > 40 {
        return None;
    }

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn extract_serveo_url(line: &str) -> Option<String> {
    let plain = strip_ansi(line);
    if !plain.contains("serveo.net") && !plain.contains("serveousercontent.com") {
        return None;
    }

    if let Some(start) = plain.find("https://") {
        let candidate = &plain[start..];
        for token in candidate.split_whitespace() {
            if token.contains(".serveo.net") || token.contains(".serveousercontent.com") {
                let cleaned = token.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '('));
                return Some(cleaned.to_string());
            }
        }
    }

    None
}

fn strip_ansi(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            while let Some(next) = chars.next() {
                // End of ANSI escape sequence command byte.
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}
