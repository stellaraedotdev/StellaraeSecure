// StellaraeSecure staffdb service
// Rust-based account database for managing staff and user accounts

use axum::{
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use stellarae_staffdb::{config::Config, db, logger, api, AppState};

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
        .nest("/api", api::routes(state.clone()))
        .with_state(state.clone());

    // Bind and run server
    let addr = format!("{}:{}", state.config.host, state.config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %addr, "Server listening");

    axum::serve(listener, app).await?;

    Ok(())
}

