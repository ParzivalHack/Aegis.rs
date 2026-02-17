use serde::{Deserialize, Serialize};
use crate::errors::AegisError;
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub detection: DetectionConfig,
    pub ai_judge: AIJudgeConfig,
    #[serde(alias = "cloudflare_tunnel")]
    pub serveo_tunnel: ServeoTunnelConfig,
    pub logging: LoggingConfig,
    pub rules: RulesConfig,
    pub performance: PerformanceConfig,
    pub metrics: MetricsConfig,
    pub dashboard: DashboardConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub dashboard_host: String,
    pub dashboard_port: u16,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub target_url: String,
    pub api_key: String,
    pub api_key_required: bool,
    pub max_body_size_bytes: usize,
    pub read_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub blocked_status_code: u16,
    pub blocked_response_body: String,
    pub log_full_payload: bool,
    pub custom_headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DetectionConfig {
    pub default_ambiguous_policy: String,
    pub heuristic_only_mode: bool,
    pub ai_judge_confidence_threshold: f64,
    pub always_block_categories: Vec<String>,
    pub min_block_severity: String,
    pub normalize_unicode: bool,
    pub case_insensitive: bool,
    pub all_requests_ai_judge: bool,
    pub safe_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AIJudgeConfig {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
    pub max_retries: u32,
    pub base_retry_delay_ms: u64,
    pub system_prompt: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServeoTunnelConfig {
    pub enabled: bool,
    pub token: String,
    #[serde(alias = "cloudflared_path")]
    pub ssh_path: String,
    pub local_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub log_file_path: String,
    pub max_log_size_bytes: u64,
    pub rotation_count: u32,
    pub log_format: String,
    pub retention_days: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RulesConfig {
    pub rules_file_path: String,
    pub hot_reload: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub max_concurrent_requests: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub update_interval_ms: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DashboardConfig {
    pub enabled: bool,
    pub allow_config_editing: bool,
    pub title: String,
    pub session_secret: String,
    pub admin_password_hash: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    pub allowed_ips: Vec<String>,
    pub rate_limit_requests: usize,
    pub rate_limit_window_seconds: u64,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, AegisError> {
        let content = fs::read_to_string(path)
            .map_err(|e| AegisError::ConfigError(format!("Failed to read config file: {}", e)))?;
        
        let config: Config = toml::from_str(&content)
            .map_err(|e| AegisError::ConfigError(format!("Failed to parse config file: {}", e)))?;
        
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<(), AegisError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| AegisError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(path, content)
            .map_err(|e| AegisError::ConfigError(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
}
