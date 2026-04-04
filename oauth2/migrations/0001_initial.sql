CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_consents (
    request_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit_events (
    id TEXT PRIMARY KEY,
    actor_account_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_actor ON admin_audit_events(actor_account_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_timestamp ON admin_audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_correlation ON admin_audit_events(correlation_id);

CREATE TABLE IF NOT EXISTS panel_sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_panel_sessions_account ON panel_sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_panel_sessions_expires ON panel_sessions(expires_at);
