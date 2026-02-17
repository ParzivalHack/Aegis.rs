use std::fmt;
use actix_web::{error::ResponseError, HttpResponse, http::StatusCode};
use serde_json::json;

#[derive(Debug)]
pub enum AegisError {
    ConfigError(String),
    LoggingError(String),
    DetectionError(String),
    AIJudgeError(String),
    TunnelError(String),
    RuleLoadError(String),
    ProxyError(String),
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AegisError::ConfigError(e) => write!(f, "Configuration error: {}", e),
            AegisError::LoggingError(e) => write!(f, "Logging error: {}", e),
            AegisError::DetectionError(e) => write!(f, "Detection error: {}", e),
            AegisError::AIJudgeError(e) => write!(f, "AI Judge error: {}", e),
            AegisError::TunnelError(e) => write!(f, "Tunnel error: {}", e),
            AegisError::RuleLoadError(e) => write!(f, "Rule load error: {}", e),
            AegisError::ProxyError(e) => write!(f, "Proxy error: {}", e),
        }
    }
}

impl std::error::Error for AegisError {}

impl ResponseError for AegisError {
    fn status_code(&self) -> StatusCode {
        match self {
            AegisError::ProxyError(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        HttpResponse::build(status).json(json!({
            "error": self.to_string()
        }))
    }
}
