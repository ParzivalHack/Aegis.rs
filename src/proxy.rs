use actix_web::{web, HttpRequest, HttpResponse, Error};
use crate::config::Config;
use crate::detection::DetectionPipeline;
use crate::detection::models::Verdict;
use crate::errors::AegisError;
use crate::logging::{Logger, LogEntry};
use crate::metrics::Metrics;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use std::time::Instant;

use parking_lot::RwLock as ParkingLotRwLock;

pub struct ProxyState {
    pub config: Arc<ParkingLotRwLock<Config>>,
    pub detection_pipeline: Arc<tokio::sync::Mutex<DetectionPipeline>>,
    pub logger: Arc<Logger>,
    pub metrics: Arc<Metrics>,
    pub client: reqwest::Client,
}

pub async fn proxy_handler(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<ProxyState>,
) -> Result<HttpResponse, Error> {
    let start_time = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    
    // Extract source IP
    let source_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    // Convert body to string for analysis
    let payload = String::from_utf8_lossy(&body).to_string();

    // Check body size limit
    if body.len() > state.config.read().proxy.max_body_size_bytes {
        return Ok(HttpResponse::PayloadTooLarge()
            .json(serde_json::json!({
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": "Request body exceeds maximum size"
                }
            })));
    }

    // Run detection pipeline
    let detection_result = {
        let pipeline = state.detection_pipeline.lock().await;
        match pipeline.analyze(&payload).await {
            Ok(result) => result,
            Err(e) => {
                let detection_error = AegisError::DetectionError(e.to_string());
                log::error!("Detection pipeline error: {}", detection_error);
                return Ok(HttpResponse::InternalServerError()
                    .json(serde_json::json!({
                        "error": {
                            "code": "DETECTION_ERROR",
                            "message": "Internal detection error"
                        }
                    })));
            }
        }
    };

    let latency_ms = start_time.elapsed().as_millis() as u64;
    state
        .metrics
        .record_request(
            latency_ms,
            matches!(detection_result.verdict, Verdict::Malicious),
            matches!(detection_result.verdict, Verdict::Ambiguous),
        );

    // Log the event
    let log_entry = LogEntry {
        timestamp: Utc::now(),
        request_id: request_id.clone(),
        verdict: detection_result.verdict,
        attack_type: detection_result.attack_type,
        confidence: detection_result.confidence,
        reasoning: detection_result.reasoning.clone(),
        layer: format!("{:?}", detection_result.layer),
        matched_rules: detection_result.matched_rules.clone(),
        severity: format!("{:?}", detection_result.severity),
        payload: if state.config.read().proxy.log_full_payload {
            payload.clone()
        } else {
            payload.chars().take(200).collect()
        },
        response: None,
        latency_ms,
        source_ip,
    };

    if let Err(e) = state.logger.log(&log_entry) {
        log::error!("Failed to log event: {}", e);
    }

    // Handle verdict
    match detection_result.verdict {
        Verdict::Malicious => {
            log::warn!("Blocked malicious request: {} - {}", request_id, detection_result.reasoning);
            Ok(HttpResponse::build(actix_web::http::StatusCode::from_u16(state.config.read().proxy.blocked_status_code).unwrap())
                .content_type("application/json")
                .body(state.config.read().proxy.blocked_response_body.clone()))
        }
        Verdict::Safe | Verdict::Ambiguous => {
            // Forward to target
            forward_request(&state, &body, &req).await
        }
    }
}

async fn forward_request(
    state: &ProxyState,
    body: &web::Bytes,
    req: &HttpRequest,
) -> Result<HttpResponse, Error> {
    let (target_url, api_key_required, api_key, custom_headers) = {
        let cfg = state.config.read();
        (
            resolve_target_url(&cfg.proxy.target_url, req)?,
            cfg.proxy.api_key_required,
            cfg.proxy.api_key.clone(),
            cfg.proxy.custom_headers.clone(),
        )
    };

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Unsupported method: {}", e)))?;

    let mut request_builder = state.client
        .request(method, target_url)
        .body(body.to_vec());

    // Preserve incoming headers when forwarding, except hop-by-hop headers.
    for (key, value) in req.headers().iter() {
        let key_str = key.as_str();
        if key_str.eq_ignore_ascii_case("host")
            || key_str.eq_ignore_ascii_case("content-length")
            || key_str.eq_ignore_ascii_case("connection")
            || key_str.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            request_builder = request_builder.header(key_str, value_str);
        }
    }

    if !req.headers().contains_key("content-type") {
        request_builder = request_builder.header("Content-Type", "application/json");
    }

    // Add API key if required
    if api_key_required && !api_key.is_empty() {
        request_builder = request_builder.header(
            "Authorization",
            format!("Bearer {}", api_key)
        );
    }

    // Add custom headers
    for (key, value) in &custom_headers {
        request_builder = request_builder.header(key, value);
    }

    // Send request
    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.unwrap_or_default();

            let mut http_response = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap()
            );

            // Copy relevant headers
            for (key, value) in headers.iter() {
                if key != "content-length" && key != "transfer-encoding" {
                    http_response.insert_header((key.clone(), value.clone()));
                }
            }

            Ok(http_response.body(body))
        }
        Err(e) => {
            let proxy_error = AegisError::ProxyError(format!("Failed to reach target endpoint: {}", e));
            log::error!("{}", proxy_error);
            Ok(HttpResponse::BadGateway()
                .json(serde_json::json!({
                    "error": {
                        "code": "PROXY_ERROR",
                        "message": "Failed to reach target endpoint"
                    }
                })))
        }
    }
}

fn resolve_target_url(base_url: &str, req: &HttpRequest) -> Result<String, Error> {
    let mut target_url = reqwest::Url::parse(base_url)
        .map_err(|e| {
            let proxy_error = AegisError::ProxyError(format!("Invalid target_url '{}': {}", base_url, e));
            actix_web::error::ErrorInternalServerError(proxy_error)
        })?;

    let incoming_path = req.uri().path();

    if incoming_path != "/proxy" {
        let rewritten_path = if let Some(stripped) = incoming_path.strip_prefix("/proxy/") {
            format!("/{}", stripped)
        } else {
            incoming_path.to_string()
        };

        target_url.set_path(&rewritten_path);
        target_url.set_query(req.uri().query());
    }

    Ok(target_url.to_string())
}
