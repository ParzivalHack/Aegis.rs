use actix_web::{web, HttpResponse, Result, Error};
use actix_session::Session;
use crate::logging::{Logger, LogFilters};
use crate::config::Config;
use crate::detection::models::{Verdict};
use crate::detection::heuristic::Rule;
use serde::Deserialize;
use std::sync::Arc;
use bcrypt::verify;
// use crate::errors::AegisError;

use parking_lot::RwLock as ParkingLotRwLock;

pub struct ApiState {
    pub config: Arc<ParkingLotRwLock<Config>>,
    pub logger: Arc<Logger>,
    pub heuristic_engine: Arc<crate::detection::heuristic::HeuristicEngine>,
    pub detection_pipeline: Arc<tokio::sync::Mutex<crate::detection::DetectionPipeline>>,
    pub tunnel_manager: Arc<crate::tunnel::TunnelManager>,
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
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Tunnel started" })))
}

async fn stop_tunnel(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    state.tunnel_manager.stop().map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Tunnel stopped" })))
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

async fn get_stats(state: web::Data<ApiState>, session: Session) -> Result<HttpResponse, Error> {
    if !is_authenticated(&session)? {
        return Ok(HttpResponse::Unauthorized().finish());
    }
    let filters = LogFilters::default();
    
    match state.logger.query(filters) {
        Ok(entries) => {
            let total = entries.len();
            let blocked = entries.iter().filter(|e| matches!(e.verdict, Verdict::Malicious)).count();
            let forwarded = entries.iter().filter(|e| matches!(e.verdict, Verdict::Safe)).count();
            let flagged = entries.iter().filter(|e| matches!(e.verdict, Verdict::Ambiguous)).count();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "total_requests": total,
                "blocked_requests": blocked,
                "forwarded_requests": forwarded,
                "flagged_requests": flagged,
            })))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get stats: {}", e)
        }))),
    }
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

fn is_authenticated(session: &Session) -> Result<bool, Error> {
    Ok(session.get::<bool>("authenticated")?.unwrap_or(false))
}
