use std::net::SocketAddr;

use stellarae_oauth2::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    stellarae_oauth2::logger::init_logger(&config.log_level)?;

    let app = stellarae_oauth2::app(&config)?;
    let address = SocketAddr::from((config.host, config.port));
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!(
        service = %config.service_id,
        environment = %config.environment,
        address = %address,
        "oauth2 service starting"
    );

    axum::serve(listener, app).await?;
    Ok(())
}
