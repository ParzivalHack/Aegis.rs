mod config;
mod errors;
mod detection;
mod logging;
mod proxy;
mod dashboard;
mod metrics;
mod tunnel;

use actix_web::{web, App, HttpServer, middleware};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use config::Config;
use tunnel::TunnelManager;
use std::sync::Arc;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger with default Info level
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("Starting Aegis.rs...");

    // Load configuration
    let config = Config::load("./config.toml")
        .expect("Failed to load configuration");
    let config = Arc::new(parking_lot::RwLock::new(config));

    log::info!("Configuration loaded successfully");

    // Initialize logger
    let logger = {
        let cfg = config.read();
        Arc::new(
            logging::Logger::new(
                &cfg.logging.log_file_path,
                cfg.logging.max_log_size_bytes,
            )
            .expect("Failed to initialize logger")
        )
    };

    log::info!("Logger initialized");

    // Initialize detection pipeline
    let detection_pipeline = {
        let cfg = config.read();
        detection::DetectionPipeline::new(&cfg)
            .expect("Failed to initialize detection pipeline")
    };
    let heuristic_engine = detection_pipeline.heuristic_engine.clone();
    let detection_pipeline = Arc::new(tokio::sync::Mutex::new(detection_pipeline));

    log::info!("Detection pipeline initialized");

    // Initialize metrics
    let metrics = Arc::new(metrics::Metrics::new());

    // Initialize Cloudflare Tunnel if configured
    let tunnel_manager = {
        let cfg = config.read();
        Arc::new(TunnelManager::new(&cfg.cloudflare_tunnel))
    };
    
    if config.read().cloudflare_tunnel.enabled {
        tunnel_manager.start().expect("Failed to start Cloudflare Tunnel");
    }

    // Create HTTP client for proxy
    let client = {
        let cfg = config.read();
        reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.proxy.read_timeout_ms))
            .connect_timeout(Duration::from_millis(cfg.proxy.connect_timeout_ms))
            .build()
            .expect("Failed to create HTTP client")
    };

    // Create dedicated HTTP client for lightweight geo lookups used by dashboard.
    let geo_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2500))
        .build()
        .expect("Failed to create geo lookup client");

    // Proxy state
    let proxy_state = web::Data::new(proxy::ProxyState {
        config: config.clone(),
        detection_pipeline: detection_pipeline.clone(),
        logger: logger.clone(),
        metrics: metrics.clone(),
        client,
    });

    // Dashboard API state
    let api_state = web::Data::new(dashboard::api::ApiState {
        config: config.clone(),
        logger: logger.clone(),
        heuristic_engine,
        detection_pipeline: detection_pipeline.clone(),
        tunnel_manager: tunnel_manager.clone(),
        geo_client,
        node_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        metrics: metrics.clone(),
    });

    let (proxy_host, proxy_port, dashboard_host, dashboard_port, session_key) = {
        let cfg = config.read();
        (
            cfg.server.proxy_host.clone(),
            cfg.server.proxy_port,
            cfg.server.dashboard_host.clone(),
            cfg.server.dashboard_port,
            Key::from(cfg.dashboard.session_secret.as_bytes()),
        )
    };

    // Start proxy server
    let proxy_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(proxy_state.clone())
            .route("/{tail:.*}", web::to(proxy::proxy_handler))
    })
    .bind((proxy_host.as_str(), proxy_port))?
    .run();

    log::info!("Proxy server listening on {}:{}", proxy_host, proxy_port);

    // Start dashboard server
    let dashboard_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), session_key.clone()))
            .app_data(api_state.clone())
            .configure(dashboard::configure)
    })
    .bind((dashboard_host.as_str(), dashboard_port))?
    .run();

    log::info!("Dashboard server listening on {}:{}", dashboard_host, dashboard_port);

    // Run both servers
    tokio::try_join!(proxy_server, dashboard_server)?;

    Ok(())
}
