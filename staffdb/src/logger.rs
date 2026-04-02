// Structured logging setup for staffdb.

use regex::Regex;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize structured logging with tracing.
pub fn init_logger() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(true)
        .with_level(true)
        .json();

    tracing_subscriber::registry().with(env_filter).with(fmt_layer).init();

    tracing::info!("Structured logging initialized");
}

/// Redact common secret keys from JSON-like strings.
pub fn redact_sensitive(input: &str) -> String {
    let re = Regex::new(
        r#"(?i)("(?:password|secret|token|api[_-]?key|authorization)"\s*:\s*")([^"]+)(")"#,
    )
    .expect("valid regex");
    re.replace_all(input, "$1[REDACTED]$3").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_sensitive() {
        let input = r#"{"password": "secret123", "username": "john"}"#;
        let redacted = redact_sensitive(input);
        assert!(!redacted.contains("secret123"));
    }
}
