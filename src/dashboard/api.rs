use actix_web::{web, HttpResponse, Result, Error, HttpRequest};
use actix_session::Session;
use crate::logging::{Logger, LogFilters};
use crate::config::Config;
use crate::detection::models::{Verdict};
use crate::detection::heuristic::Rule;
use serde::Deserialize;
use std::sync::Arc;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use bcrypt::verify;
// use crate::errors::AegisError;

use parking_lot::RwLock as ParkingLotRwLock;

pub struct ApiState {
    pub config: Arc<ParkingLotRwLock<Config>>,
    pub logger: Arc<Logger>,
    pub heuristic_engine: Arc<crate::detection::heuristic::HeuristicEngine>,
    pub detection_pipeline: Arc<tokio::sync::Mutex<crate::detection::DetectionPipeline>>,
    pub tunnel_manager: Arc<crate::tunnel::TunnelManager>,
    pub geo_client: reqwest::Client,
    pub node_cache: Arc<tokio::sync::RwLock<HashMap<String, NodeCacheEntry>>>,
    pub metrics: Arc<crate::metrics::Metrics>,
}

#[derive(Clone)]
pub struct NodeCacheEntry {
    label: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct GeoIpResponse {
    success: Option<bool>,
    country_code: Option<String>,
    region_code: Option<String>,
    continent_code: Option<String>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/status", web::get().to(get_auth_status))
    )
    .service(
        web::scope("/logs")
            .route("", web::get().to(get_logs))
            .route("/export/{format}", web::get().to(export_logs))
            .route("/action", web::post().to(perform_log_action))
    )
    .service(
        web::scope("/stats")
            .route("", web::get().to(get_stats))
    )
    .service(
        web::scope("/config")
            .route("", web::get().to(get_config))
            .route("", web::post().to(update_config))
    )
    .service(
        web::scope("/rules")
            .route("", web::get().to(get_rules))
            .route("", web::post().to(upsert_rule))
            .route("/reload", web::post().to(reload_rules))
            .route("/{name}", web::delete().to(delete_rule))
    )
    .service(
        web::scope("/tunnel")
            .route("", web::get().to(get_tunnel_status))
            .route("/start", web::post().to(start_tunnel))
            .route("/stop", web::post().to(stop_tunnel))
    );
}

async fn get_tunnel_status(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "active": state.tunnel_manager.is_active(),
        "url": state.tunnel_manager.get_public_url()
    })))
}

async fn start_tunnel(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    state.tunnel_manager.start().map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Tunnel started",
        "active": state.tunnel_manager.is_active(),
        "url": state.tunnel_manager.get_public_url()
    })))
}

async fn stop_tunnel(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    state.tunnel_manager.stop().map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Tunnel stopped",
        "active": false,
        "url": serde_json::Value::Null
    })))
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

async fn login(
    req: web::Json<LoginRequest>,
    session: Session,
    state: web::Data<ApiState>,
) -> Result<HttpResponse, Error> {
    let hashed_password = &state.config.read().dashboard.admin_password_hash;
    
    match verify(&req.password, hashed_password) {
        Ok(true) => {
            session.insert("authenticated", true)?;
            Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Login successful" })))
        }
        _ => Ok(HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Invalid password" }))),
    }
}

async fn logout(session: Session) -> Result<HttpResponse, Error> {
    session.remove("authenticated");
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Logged out" })))
}

async fn get_auth_status(session: Session) -> Result<HttpResponse, Error> {
    let is_auth = session.get::<bool>("authenticated")?.unwrap_or(false);
    Ok(HttpResponse::Ok().json(serde_json::json!({ "authenticated": is_auth })))
}

#[derive(Deserialize)]
struct LogQuery {
    verdict: Option<String>,
    limit: Option<usize>,
    search: Option<String>,
}

async fn get_logs(
    query: web::Query<LogQuery>,
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Unauthorized" })));
    }

    let filters = LogFilters {
        verdict: query.verdict.as_ref().and_then(|v| match v.as_str() {
            "safe" => Some(Verdict::Safe),
            "malicious" => Some(Verdict::Malicious),
            "ambiguous" => Some(Verdict::Ambiguous),
            _ => None,
        }),
        attack_type: None,
        start_time: None,
        end_time: None,
        search_text: query.search.clone(),
        limit: query.limit.or(Some(100)),
    };

    match state.logger.query(filters) {
        Ok(entries) => Ok(HttpResponse::Ok().json(entries)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to query logs: {}", e)
        }))),
    }
}

async fn export_logs(
    path: web::Path<String>,
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let format = path.into_inner();
    let filters = LogFilters::default();
    let logs = state.logger.query(filters).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string(&logs).unwrap();
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", "attachment; filename=\"aegis_logs.json\""))
                .body(json))
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(vec![]);
            for log in logs {
                wtr.serialize(log).unwrap();
            }
            let csv_data = wtr.into_inner().unwrap();
            Ok(HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header(("Content-Disposition", "attachment; filename=\"aegis_logs.csv\""))
                .body(csv_data))
        }
        _ => {
            let mut text = String::new();
            for log in logs {
                text.push_str(&format!("{:?}\n", log));
            }
            Ok(HttpResponse::Ok()
                .content_type("text/plain")
                .insert_header(("Content-Disposition", "attachment; filename=\"aegis_logs.txt\""))
                .body(text))
        }
    }
}

async fn perform_log_action(
    _req: web::Json<serde_json::Value>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    // Implement manual actions like banning IPs here
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Action performed" })))
}

async fn get_stats(req: HttpRequest, state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    let node_label = resolve_node_label(&req, state.get_ref()).await;

    let total = state.metrics.get_total_requests() as usize;
    let blocked = state.metrics.get_blocked_requests() as usize;
    let flagged = state.metrics.get_flagged_requests() as usize;
    let forwarded = total.saturating_sub(blocked);
    let avg_latency_ms = state.metrics.get_avg_latency();
    let requests_per_second = state.metrics.get_requests_per_second();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_requests": total,
        "blocked_requests": blocked,
        "forwarded_requests": forwarded,
        "flagged_requests": flagged,
        "avg_latency_ms": avg_latency_ms,
        "requests_per_second": requests_per_second,
        "node_label": node_label,
    })))
}

async fn get_config(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    
    let is_active = {
        let pipeline = state.detection_pipeline.lock().await;
        pipeline.is_semantic_active()
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "config": &*state.config.read(),
        "semantic_active": is_active
    })))
}

async fn update_config(
    new_config: web::Json<Config>,
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    if !state.config.read().dashboard.allow_config_editing {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Configuration editing is disabled"
        })));
    }

    match new_config.save("./config.toml") {
        Ok(_) => {
            // Update in-memory config
            let config_to_save = new_config.into_inner();
            {
                let mut config = state.config.write();
                *config = config_to_save.clone();
            }
            
            // Refresh detection pipeline
            {
                let mut pipeline = state.detection_pipeline.lock().await;
                pipeline.refresh_configuration(&config_to_save);
            }

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Configuration updated successfully"
            })))
        },
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save config: {}", e)
        }))),
    }
}

async fn get_rules(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    let rules = state.heuristic_engine.get_all_rules();
    Ok(HttpResponse::Ok().json(rules))
}

async fn upsert_rule(
    rule: web::Json<Rule>,
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    state.heuristic_engine.upsert_rule(rule.into_inner())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Rule saved" })))
}

async fn delete_rule(
    name: web::Path<String>,
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    state.heuristic_engine.delete_rule(&name.into_inner())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Rule deleted" })))
}

async fn reload_rules(
    state: web::Data<ApiState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    {
        let mut pipeline = state.detection_pipeline.lock().await;
        pipeline.reload_rules().map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Rules reloaded" })))
}

fn is_authenticated(session: &Session) -> Result<bool, Error> {
    Ok(session.get::<bool>("authenticated")?.unwrap_or(false))
}

async fn resolve_node_label(req: &HttpRequest, state: &ApiState) -> String {
    if let Some(country) = extract_country_hint(req) {
        return format!("{}-{}-01", country_cluster(&country), country);
    }

    let ip = extract_client_ip(req);
    let (cache_key, lookup_ip): (String, Option<String>) = match ip {
        Some(addr) if is_local_ip(&addr) => ("PUBLIC-EGRESS".to_string(), None),
        Some(addr) => {
            let ip_str = addr.to_string();
            (ip_str.clone(), Some(ip_str))
        }
        None => ("PUBLIC-EGRESS".to_string(), None),
    };

    {
        let cache = state.node_cache.read().await;
        if let Some(entry) = cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                return entry.label.clone();
            }
        }
    }

    let label = match fetch_public_node_label(&state.geo_client, lookup_ip.as_deref()).await {
        Some(public_label) => public_label,
        None => "PUBLIC-EDGE-01".to_string(),
    };

    {
        let mut cache = state.node_cache.write().await;
        cache.insert(
            cache_key,
            NodeCacheEntry {
                label: label.clone(),
                expires_at: Instant::now() + Duration::from_secs(30 * 60),
            },
        );
    }

    label
}

fn extract_client_ip(req: &HttpRequest) -> Option<IpAddr> {
    // Most trusted proxy headers first.
    for header_name in ["cf-connecting-ip", "true-client-ip", "x-real-ip"] {
        if let Some(header_value) = req.headers().get(header_name).and_then(|v| v.to_str().ok()) {
            if let Some(ip) = parse_ip(header_value.trim()) {
                return Some(ip);
            }
        }
    }

    if let Some(header_value) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = header_value.split(',').next().map(str::trim) {
            if let Some(ip) = parse_ip(first) {
                return Some(ip);
            }
        }
    }

    if let Some(real_ip) = req.connection_info().realip_remote_addr() {
        if let Some(ip) = parse_ip(real_ip) {
            return Some(ip);
        }
    }

    None
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    if let Ok(ip) = IpAddr::from_str(value) {
        return Some(ip);
    }
    if let Ok(sock) = std::net::SocketAddr::from_str(value) {
        return Some(sock.ip());
    }
    if value.starts_with('[') {
        let trimmed = value.trim_start_matches('[');
        if let Some((ip, _)) = trimmed.split_once(']') {
            if let Ok(parsed) = IpAddr::from_str(ip) {
                return Some(parsed);
            }
        }
    }
    None
}

fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => true,
        IpAddr::V6(v6) if v6.is_loopback() => true,
        IpAddr::V4(v4) if is_private_v4(v4) => true,
        IpAddr::V6(v6) if v6.is_unique_local() => true,
        _ => false,
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
}

fn extract_country_hint(req: &HttpRequest) -> Option<String> {
    for header_name in ["cf-ipcountry", "x-vercel-ip-country", "x-country-code"] {
        if let Some(value) = req.headers().get(header_name).and_then(|v| v.to_str().ok()) {
            if let Some(country) = normalize_segment(Some(value), 2) {
                if country != "XX" {
                    return Some(country);
                }
            }
        }
    }
    None
}

async fn fetch_public_node_label(client: &reqwest::Client, ip: Option<&str>) -> Option<String> {
    let url = match ip {
        Some(ip_addr) => format!("https://ipwho.is/{}", ip_addr),
        None => "https://ipwho.is/".to_string(),
    };
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let geo: GeoIpResponse = response.json().await.ok()?;
    if matches!(geo.success, Some(false)) {
        return None;
    }

    let country = normalize_segment(geo.country_code.as_deref(), 2).unwrap_or_else(|| "XX".to_string());
    let _region = normalize_segment(geo.region_code.as_deref(), 8);
    let cluster = continent_cluster(geo.continent_code.as_deref(), &country);

    Some(format!("{}-{}-01", cluster, country))
}

fn continent_cluster(continent: Option<&str>, country: &str) -> String {
    // Middle East is often encoded as AS by GeoIP providers; classify key countries as EMEA.
    if matches!(
        country,
        "AE" | "SA" | "QA" | "BH" | "OM" | "KW" | "JO" | "IL" | "LB" | "TR" | "EG"
    ) {
        return "EMEA".to_string();
    }

    match continent.unwrap_or("").to_uppercase().as_str() {
        "EU" | "AF" => "EMEA".to_string(),
        "AS" | "OC" => "APAC".to_string(),
        "NA" | "SA" => "AMER".to_string(),
        _ => "GLOBAL".to_string(),
    }
}

fn country_cluster(country: &str) -> &'static str {
    match country {
        "AE" | "AL" | "AM" | "AT" | "AZ" | "BA" | "BE" | "BG" | "BH" | "BY" | "CH" | "CY" | "CZ"
        | "DE" | "DK" | "DZ" | "EE" | "EG" | "ES" | "FI" | "FR" | "GB" | "GE" | "GR" | "HR" | "HU"
        | "IE" | "IL" | "IQ" | "IS" | "IT" | "JO" | "KW" | "KZ" | "LB" | "LT" | "LU" | "LV" | "LY"
        | "MA" | "MD" | "ME" | "MK" | "MT" | "NL" | "NO" | "OM" | "PL" | "PT" | "QA" | "RO" | "RS"
        | "RU" | "SA" | "SE" | "SI" | "SK" | "SM" | "TN" | "TR" | "UA" | "VA" | "XK" | "ZA" => "EMEA",
        "AU" | "BD" | "CN" | "HK" | "ID" | "IN" | "JP" | "KR" | "MY" | "NZ" | "PH" | "PK" | "SG"
        | "TH" | "TW" | "VN" => "APAC",
        "AR" | "BR" | "CA" | "CL" | "CO" | "MX" | "PE" | "US" | "UY" => "AMER",
        _ => "GLOBAL",
    }
}

fn normalize_segment(raw: Option<&str>, max_len: usize) -> Option<String> {
    let value = raw?;
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    if cleaned.is_empty() {
        return None;
    }

    Some(cleaned.chars().take(max_len).collect())
}
