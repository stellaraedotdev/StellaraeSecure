use tracing_subscriber::EnvFilter;

pub fn init_logger(level: &str) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .compact()
        .init();

    Ok(())
}
