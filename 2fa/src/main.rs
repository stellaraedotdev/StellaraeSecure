mod app;
mod config;
mod error;

use std::net::SocketAddr;

use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(config.log_level.clone())
        .with_target(false)
        .compact()
        .init();

    let app = app::build_app(config.clone()).await?;
    let address = SocketAddr::from((config.host, config.port));
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!(service = %config.service_id, address = %address, "2fa service starting");

    axum::serve(listener, app).await?;
    Ok(())
}
