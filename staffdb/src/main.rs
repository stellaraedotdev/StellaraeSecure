// StellaraeSecure staffdb service
// Rust-based account database for managing staff and user accounts

use axum::{
    http::header::CONTENT_TYPE,
    http::StatusCode,
    response::IntoResponse,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};
use stellarae_staffdb::{config::Config, db, logger, api, AppState};

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Health check response
#[derive(serde::Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime: u64,
}

/// Health check endpoint
async fn health() -> (StatusCode, Json<HealthResponse>) {
    let response = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: 0, // TODO: track actual uptime in Phase 5
    };

    (StatusCode::OK, Json(response))
}

/// Ready check endpoint (more detailed health check for orchestration)
async fn ready(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    // Check database connectivity
    let db_ok = db::health_check(&state.db_pool).await.is_ok();

    (
        if db_ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "ready": db_ok,
            "database": if db_ok { "ok" } else { "unavailable" },
            "service": "staffdb"
        })),
    )
}

/// Metrics endpoint (Prometheus text format)
async fn metrics(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> impl IntoResponse {
    let uptime_seconds = PROCESS_START.get_or_init(Instant::now).elapsed().as_secs();
    let body = format!(
        "# HELP service_uptime_seconds Process uptime in seconds\n\
# TYPE service_uptime_seconds gauge\n\
service_uptime_seconds{{service=\"staffdb\"}} {}\n\
# HELP service_info Static service metadata\n\
# TYPE service_info gauge\n\
service_info{{service=\"staffdb\",version=\"{}\",environment=\"{}\"}} 1\n",
        uptime_seconds,
        env!("CARGO_PKG_VERSION"),
        state.config.environment
    );

    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    logger::init_logger();
    tracing::info!("Starting StellaraeSecure staffdb service");

    // Load configuration from environment
    let config = Config::from_env()?;
    tracing::info!(
        host = %config.host,
        port = config.port,
        environment = %config.environment,
        "Configuration loaded"
    );

    // Initialize database connection pool
    let db_pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Database connection pool established");

    // Run migrations
    db::migrations::run_migrations(&db_pool).await?;
    tracing::info!("Database migrations completed");

    // Verify database connectivity
    db::health_check(&db_pool).await?;
    tracing::info!("Database health check passed");

    let state = Arc::new(AppState { config, db_pool });

    // Build router with health check endpoints and API routes
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .nest("/api", api::routes(state.clone()))
        .with_state(state.clone());

    // Bind and run server
    let addr = format!("{}:{}", state.config.host, state.config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %addr, "Server listening");

    axum::serve(listener, app).await?;

    Ok(())
}

